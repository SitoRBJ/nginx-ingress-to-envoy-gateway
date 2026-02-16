package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"gopkg.in/yaml.v3"
)

// Config holds the YAML configuration file structure.
type Config struct {
	GatewayMapping      map[string]GatewayConfig      `yaml:"gateway_mapping"`
	OAuthConfig         map[string]OAuthCluster       `yaml:"oauth_config"`
	AnnotationMapping   AnnotationMapping             `yaml:"annotation_mapping"`
	ExcludedAuthPaths   []string                      `yaml:"excluded_auth_paths"`
	OutputStructure     OutputStructure               `yaml:"output_structure"`
	BackendTLSPolicies  map[string]BackendTLSPolicyConfig `yaml:"backend_tls_policies"`
}

type BackendTLSPolicyConfig struct {
	Hostname string `yaml:"hostname"`
	CASecret string `yaml:"ca_secret"`
}

type GatewayConfig struct {
	GatewayName      string `yaml:"gateway_name"`
	GatewayNamespace string `yaml:"gateway_namespace"`
	GatewayClass     string `yaml:"gateway_class"`
}

type OAuthCluster struct {
	SecretName      string                `yaml:"secret_name"`
	SecretNamespace string                `yaml:"secret_namespace"`
	OIDCProviders   map[string]OIDCConfig  `yaml:"oidc_providers"`
}

type OIDCConfig struct {
	Issuer       string   `yaml:"issuer"`
	ClientID     string   `yaml:"client_id"`
	Scopes       []string `yaml:"scopes"`
	LogoutPath   string   `yaml:"logout_path"`
	RefreshToken bool     `yaml:"refresh_token"`
}

type AnnotationMapping struct {
	OAuthAnnotations []string `yaml:"oauth_annotations"`
	FilterAnnotations []string `yaml:"filter_annotations"`
	RouteAnnotations  []string `yaml:"route_annotations"`
}

type OutputStructure struct {
	BasePath            string `yaml:"base_path"`
	TemplatesDir        string `yaml:"templates_dir"`
	AutoDetectStructure bool   `yaml:"auto_detect_structure"`
}

// Migrator handles Ingress migration to Envoy Gateway resources.
type Migrator struct {
	config      *Config
	clientset   *kubernetes.Clientset
	clusterName string
}

func NewMigrator(configPath, kubeContext, clusterName string) (*Migrator, error) {
	// Load configuration
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("error parsing config: %w", err)
	}

	// Set up Kubernetes client
	var kubeconfig string
	if home := homeDir(); home != "" {
		kubeconfig = filepath.Join(home, ".kube", "config")
	}

	// If context not specified, use current kubeconfig context
	var overrides *clientcmd.ConfigOverrides
	if kubeContext != "" {
		overrides = &clientcmd.ConfigOverrides{CurrentContext: kubeContext}
	} else {
		// Use current kubeconfig context (same as kubectl)
		overrides = &clientcmd.ConfigOverrides{}
	}

	configLoader := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		&clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig},
		overrides,
	)

	restConfig, err := configLoader.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("error loading Kubernetes config: %w", err)
	}

	// Get the current context in use
	rawConfig, err := configLoader.RawConfig()
	if err == nil {
		currentContext := rawConfig.CurrentContext
		if kubeContext != "" {
			currentContext = kubeContext
		}
		fmt.Printf("Using Kubernetes context: %s\n", currentContext)
		if currentContext != "" {
			if ctx, exists := rawConfig.Contexts[currentContext]; exists {
				fmt.Printf("  Cluster: %s\n", ctx.Cluster)
			}
		}
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("error creating Kubernetes client: %w", err)
	}

	return &Migrator{
		config:      &config,
		clientset:   clientset,
		clusterName: clusterName,
	}, nil
}

func (m *Migrator) GetIngresses(namespace string) ([]networkingv1.Ingress, error) {
	ctx := context.Background()
	ingresses, err := m.clientset.NetworkingV1().Ingresses(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("error listing Ingress: %w", err)
	}
	return ingresses.Items, nil
}

// ResolveServicePort resolves the numeric port of a Service from its port name.
// Returns 0 if not found.
func (m *Migrator) ResolveServicePort(namespace, serviceName, portName string) int32 {
	if portName == "" {
		return 0
	}

	ctx := context.Background()
	svc, err := m.clientset.CoreV1().Services(namespace).Get(ctx, serviceName, metav1.GetOptions{})
	if err != nil {
		return 0
	}

	for _, p := range svc.Spec.Ports {
		if p.Name == portName {
			return p.Port
		}
	}

	return 0
}

func (m *Migrator) NeedsOAuth(ingress *networkingv1.Ingress) bool {
	annotations := ingress.Annotations
	for _, ann := range m.config.AnnotationMapping.OAuthAnnotations {
		if _, exists := annotations[ann]; exists {
			return true
		}
	}
	return false
}

func (m *Migrator) NeedsFilters(ingress *networkingv1.Ingress) bool {
	annotations := ingress.Annotations
	for _, ann := range m.config.AnnotationMapping.FilterAnnotations {
		if _, exists := annotations[ann]; exists {
			return true
		}
	}
	// Also treat as "filter" the case where snippet blocks /internal/
	if m.hasInternalBlockSnippet(ingress) {
		return true
	}
	// Detect snippets that require filters (server-snippet, configuration-snippet)
	if annotations["nginx.ingress.kubernetes.io/server-snippet"] != "" ||
		annotations["nginx.ingress.kubernetes.io/configuration-snippet"] != "" {
		// Check if they actually contain patterns that generate filters
		serverSnippet := annotations["nginx.ingress.kubernetes.io/server-snippet"]
		configSnippet := annotations["nginx.ingress.kubernetes.io/configuration-snippet"]
		
		// Look for set $http_ patterns in server-snippet
		if serverSnippet != "" {
			re := regexp.MustCompile(`set\s+\$http_([a-zA-Z0-9_-]+)\s+"([^"]+)";`)
			if re.MatchString(serverSnippet) {
				return true
			}
		}
		
		// Look for more_clear_headers patterns in configuration-snippet
		if configSnippet != "" {
			re := regexp.MustCompile(`more_clear_headers\s+"([^"]+)";`)
			if re.MatchString(configSnippet) {
				return true
			}
		}
	}
	return false
}

func (m *Migrator) NeedsCORSPolicy(ingress *networkingv1.Ingress) bool {
	annotations := ingress.Annotations
	// Detect CORS annotations that require SecurityPolicy
	if annotations["nginx.ingress.kubernetes.io/enable-cors"] == "true" {
		return true
	}
	// Also detect cors-allow-origin or cors-allow-methods
	if annotations["nginx.ingress.kubernetes.io/cors-allow-origin"] != "" ||
		annotations["nginx.ingress.kubernetes.io/cors-allow-methods"] != "" {
		return true
	}
	return false
}

func (m *Migrator) NeedsBackendTLSPolicy(ingress *networkingv1.Ingress) bool {
	annotations := ingress.Annotations
	// Detect backend-protocol: HTTPS
	if annotations["nginx.ingress.kubernetes.io/backend-protocol"] == "HTTPS" {
		return true
	}
	return false
}


func (m *Migrator) ExtractExcludedPaths(ingress *networkingv1.Ingress) []string {
	excluded := make(map[string]bool)
	
	// Add default paths
	for _, path := range m.config.ExcludedAuthPaths {
		excluded[path] = true
	}

	// Extract from auth-snippet
	authSnippet := ingress.Annotations["nginx.ingress.kubernetes.io/auth-snippet"]
	if authSnippet != "" {
		// Look for patterns like: if ( $request_uri = "/metrics" ) { return 200; }
		re := regexp.MustCompile(`if\s*\(\s*\$request_uri\s*=\s*"([^"]+)"\s*\)`)
		matches := re.FindAllStringSubmatch(authSnippet, -1)
		for _, match := range matches {
			if len(match) > 1 {
				excluded[match[1]] = true
			}
		}
	}

	result := make([]string, 0, len(excluded))
	for path := range excluded {
		result = append(result, path)
	}
	return result
}

// hasInternalBlockSnippet detects a typical config snippet that blocks /internal/ with 404.
// Example:
//   location ~* /internal/ {
//     return 404;
//   }
func (m *Migrator) hasInternalBlockSnippet(ingress *networkingv1.Ingress) bool {
	snippet := ingress.Annotations["nginx.ingress.kubernetes.io/configuration-snippet"]
	if snippet == "" {
		return false
	}

	re := regexp.MustCompile(`location\s+~\*\s*/internal/\s*\{[^}]*return\s+404;`)
	return re.MatchString(snippet)
}

func (m *Migrator) GetGatewayMapping(ingressClassName string) (*GatewayConfig, error) {
	mapping, exists := m.config.GatewayMapping[ingressClassName]
	if !exists {
		return nil, fmt.Errorf("gateway mapping not found for ingressClassName: %s", ingressClassName)
	}
	return &mapping, nil
}

func (m *Migrator) GetOAuthConfig() (*OAuthCluster, error) {
	config, exists := m.config.OAuthConfig[m.clusterName]
	if !exists {
		return nil, fmt.Errorf("OAuth config not found for cluster: %s", m.clusterName)
	}
	return &config, nil
}

func (m *Migrator) ConvertPathType(pathType networkingv1.PathType) string {
	switch pathType {
	case networkingv1.PathTypeExact:
		return "Exact"
	case networkingv1.PathTypePrefix:
		return "PathPrefix"
	case networkingv1.PathTypeImplementationSpecific:
		return "PathPrefix"
	default:
		return "PathPrefix"
	}
}

func (m *Migrator) GenerateHTTPRoute(ingress *networkingv1.Ingress, outputDir string) error {
	// Get gateway mapping
	ingressClass := ""
	if ingress.Spec.IngressClassName != nil {
		ingressClass = *ingress.Spec.IngressClassName
	}
	
	gatewayMapping, err := m.GetGatewayMapping(ingressClass)
	if err != nil {
		return fmt.Errorf("error getting gateway mapping: %w", err)
	}

	// Build hostnames and rules
	var hostnames []string
	var rules []map[string]interface{}
	usedNames := make(map[string]int) // Ensure unique names

	for _, rule := range ingress.Spec.Rules {
		if rule.Host != "" {
			hostnames = append(hostnames, rule.Host)
		}

		for i, path := range rule.HTTP.Paths {
			pathValue := path.Path

			// Convert PathType handling possible nil values
			var pt networkingv1.PathType
			if path.PathType != nil {
				pt = *path.PathType
			} else {
				pt = networkingv1.PathTypeImplementationSpecific
			}
			pathType := m.ConvertPathType(pt)

			// Generate unique name for the rule
			var sectionName string
			if pathValue == "/metrics" || strings.Contains(pathValue, "/metrics") {
				sectionName = "metrics"
			} else if pathValue == "/" {
				sectionName = "main"
			} else {
				// For specific paths, generate unique name based on path
				// Sanitize path to valid name (no /, replace with dashes)
				cleanPath := strings.TrimPrefix(pathValue, "/")
				cleanPath = strings.ReplaceAll(cleanPath, "/", "-")
				// Strip characters invalid for Kubernetes names
				cleanPath = strings.ReplaceAll(cleanPath, ".", "-")
				cleanPath = strings.ReplaceAll(cleanPath, "_", "-")
				if cleanPath == "" {
					cleanPath = fmt.Sprintf("rule-%d", i)
				}
				sectionName = cleanPath
			}

			// Ensure uniqueness: if name already exists, add numeric suffix
			originalName := sectionName
			counter := usedNames[sectionName]
			usedNames[originalName]++
			if counter > 0 {
				sectionName = fmt.Sprintf("%s-%d", originalName, counter)
			}

			// Create match
			match := map[string]interface{}{
				"path": map[string]interface{}{
					"type":  pathType,
					"value": pathValue,
				},
			}

			// Create backendRef
			backendRef := map[string]interface{}{
				"group":  "",
				"kind":   "Service",
				"name":   path.Backend.Service.Name,
				"weight": 1,
			}

			// Resolve port: if Ingress has numeric port, use it; otherwise resolve name via Service
			if path.Backend.Service.Port.Number > 0 {
				backendRef["port"] = path.Backend.Service.Port.Number
			} else if path.Backend.Service.Port.Name != "" {
				if resolved := m.ResolveServicePort(ingress.Namespace, path.Backend.Service.Name, path.Backend.Service.Port.Name); resolved > 0 {
					backendRef["port"] = resolved
				} else {
					// Fallback: keep port name
					backendRef["port"] = path.Backend.Service.Port.Name
				}
			}

			// NOTE: backend-protocol: HTTPS is handled via separate BackendTLSPolicy,
			// not TLS in backendRef (which would be passthrough, not origination)

			ruleObj := map[string]interface{}{
				"matches":    []map[string]interface{}{match},
				"backendRefs": []map[string]interface{}{backendRef},
				"name":       sectionName,
			}

			// Add timeouts if configured
			timeouts := m.parseTimeouts(ingress)
			if len(timeouts) > 0 {
				ruleObj["timeouts"] = timeouts
			}

			// Add filters if needed
			filters := m.generateRouteFilters(ingress, pathValue)
			if len(filters) > 0 {
				ruleObj["filters"] = filters
			}

			rules = append(rules, ruleObj)
		}
	}

	// If Ingress has a snippet that blocks /internal/ with 404,
	// add an explicit rule for /internal/ that references an external HTTPRouteFilter.
	if m.hasInternalBlockSnippet(ingress) {
		internalRule := map[string]interface{}{
			"matches": []map[string]interface{}{
				{
					"path": map[string]interface{}{
						"type":  "PathPrefix",
						"value": "/internal/",
					},
				},
			},
			"filters": []map[string]interface{}{
				{
					"type": "ExtensionRef",
					"extensionRef": map[string]interface{}{
						"group": "gateway.envoyproxy.io",
						"kind":  "HTTPRouteFilter",
						"name":  fmt.Sprintf("%s-block-internal", ingress.Name),
					},
				},
			},
			"name": "block-internal",
		}

		rules = append([]map[string]interface{}{internalRule}, rules...)
	}

	// Build HTTPRoute
	httproute := map[string]interface{}{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "HTTPRoute",
		"metadata": map[string]interface{}{
			"name":      ingress.Name,
			"namespace": ingress.Namespace,
			"labels":    ingress.Labels,
		},
		"spec": map[string]interface{}{
			"hostnames": hostnames,
			"parentRefs": []map[string]interface{}{
				{
					"group":     "gateway.networking.k8s.io",
					"kind":      "Gateway",
					"name":      gatewayMapping.GatewayName,
					"namespace": gatewayMapping.GatewayNamespace,
				},
			},
			"rules": rules,
		},
	}

	// Generar archivo
	templatesDir := filepath.Join(outputDir, "templates")
	if err := os.MkdirAll(templatesDir, 0755); err != nil {
		return fmt.Errorf("error creating templates directory: %w", err)
	}

	filePath := filepath.Join(templatesDir, "httproute.yaml")
	return m.writeHelmTemplate(filePath, httproute, "httproute.enabled")
}

func (m *Migrator) generateRouteFilters(ingress *networkingv1.Ingress, path string) []map[string]interface{} {
	var filters []map[string]interface{}
	annotations := ingress.Annotations

	// IMPORTANT:
	// - nginx.ingress.kubernetes.io/force-ssl-redirect is NOT modeled here.
	//   It must be done at Gateway level (HTTP/HTTPS listeners) or with separate routes.

	// RequestHeaderModifier: parse server-snippet for "set $http_<header> <value>"
	serverSnippet := annotations["nginx.ingress.kubernetes.io/server-snippet"]
	if serverSnippet != "" {
		// Look for patterns: set $http_<header> "<value>";
		re := regexp.MustCompile(`set\s+\$http_([a-zA-Z0-9_-]+)\s+"([^"]+)";`)
		matches := re.FindAllStringSubmatch(serverSnippet, -1)
		
		if len(matches) > 0 {
			setHeaders := []map[string]interface{}{}
			for _, match := range matches {
				if len(match) >= 3 {
					headerName := match[1]
					headerValue := match[2]
					// Convert from NGINX format (x_request_access_token) to HTTP (X-Request-Access-Token)
					headerName = m.convertNginxHeaderToHTTP(headerName)
					setHeaders = append(setHeaders, map[string]interface{}{
						"name":  headerName,
						"value": headerValue,
					})
				}
			}
			
			if len(setHeaders) > 0 {
				filters = append(filters, map[string]interface{}{
					"type": "RequestHeaderModifier",
					"requestHeaderModifier": map[string]interface{}{
						"set": setHeaders,
					},
				})
			}
		}
	}

	// ResponseHeaderModifier: parse configuration-snippet for "more_clear_headers <header>"
	configSnippet := annotations["nginx.ingress.kubernetes.io/configuration-snippet"]
	if configSnippet != "" {
		// Look for patterns: more_clear_headers "<header>";
		re := regexp.MustCompile(`more_clear_headers\s+"([^"]+)";`)
		matches := re.FindAllStringSubmatch(configSnippet, -1)
		
		if len(matches) > 0 {
			removeHeaders := []string{}
			for _, match := range matches {
				if len(match) >= 2 {
					headerName := match[1]
					// Convert from NGINX format to HTTP
					headerName = m.convertNginxHeaderToHTTP(headerName)
					removeHeaders = append(removeHeaders, headerName)
				}
			}
			
			if len(removeHeaders) > 0 {
				filters = append(filters, map[string]interface{}{
					"type": "ResponseHeaderModifier",
					"responseHeaderModifier": map[string]interface{}{
						"remove": removeHeaders,
					},
				})
			}
		}
	}

	// Rewrite target
	if rewriteTarget := annotations["nginx.ingress.kubernetes.io/rewrite-target"]; rewriteTarget != "" {
		// Simplify: replace $1, $2, etc.
		replacePrefix := strings.ReplaceAll(rewriteTarget, "$1", "")
		replacePrefix = strings.ReplaceAll(replacePrefix, "$2", "")
		if replacePrefix != "" {
			filters = append(filters, map[string]interface{}{
				"type": "URLRewrite",
				"urlRewrite": map[string]interface{}{
					"path": map[string]interface{}{
						"type":              "ReplacePrefixMatch",
						"replacePrefixMatch": replacePrefix,
					},
				},
			})
		}
	}

	// Permanent redirect
	if redirectURL := annotations["nginx.ingress.kubernetes.io/permanent-redirect"]; redirectURL != "" {
		filters = append(filters, map[string]interface{}{
			"type": "RequestRedirect",
			"requestRedirect": map[string]interface{}{
				"statusCode": 301,
				"hostname":   redirectURL,
			},
		})
	}

	return filters
}

// parseTimeouts parses NGINX timeout annotations and converts them to HTTPRoute format.
func (m *Migrator) parseTimeouts(ingress *networkingv1.Ingress) map[string]interface{} {
	annotations := ingress.Annotations
	timeouts := make(map[string]interface{})

	// proxy-read-timeout: backend response wait time
	if readTimeout := annotations["nginx.ingress.kubernetes.io/proxy-read-timeout"]; readTimeout != "" {
		if duration := m.parseTimeoutToDuration(readTimeout); duration != "" {
			timeouts["backendRequest"] = duration
		}
	}

	// proxy-send-timeout: total request time (can map to request)
	if sendTimeout := annotations["nginx.ingress.kubernetes.io/proxy-send-timeout"]; sendTimeout != "" {
		if duration := m.parseTimeoutToDuration(sendTimeout); duration != "" {
			timeouts["request"] = duration
		}
	}

	// proxy-connect-timeout: initial connection time
	// If no backendRequest set, use connect-timeout as fallback
	if connectTimeout := annotations["nginx.ingress.kubernetes.io/proxy-connect-timeout"]; connectTimeout != "" {
		if _, hasBackendRequest := timeouts["backendRequest"]; !hasBackendRequest {
			if duration := m.parseTimeoutToDuration(connectTimeout); duration != "" {
				timeouts["backendRequest"] = duration
			}
		}
	}

	return timeouts
}

// parseTimeoutToDuration converts a timeout value (seconds as string) to Kubernetes duration format.
// Example: "900" -> "900s", "120" -> "120s"
func (m *Migrator) parseTimeoutToDuration(timeoutStr string) string {
	timeoutStr = strings.TrimSpace(timeoutStr)
	if timeoutStr == "" {
		return ""
	}

	// Try to parse as number (seconds)
	if seconds, err := strconv.Atoi(timeoutStr); err == nil {
		return fmt.Sprintf("%ds", seconds)
	}

	// If already in duration format (e.g. "900s", "15m"), return as-is
	// Basic validation: must end in s, m, h, etc.
	if matched, _ := regexp.MatchString(`^\d+[smh]$`, timeoutStr); matched {
		return timeoutStr
	}

	return ""
}

// convertNginxHeaderToHTTP keeps the header name as in the Ingress.
// Preserves underscores and original format for compatibility.
func (m *Migrator) convertNginxHeaderToHTTP(nginxHeader string) string {
	// Keep header exactly as in Ingress (with underscores if present)
	return nginxHeader
}

func (m *Migrator) GenerateCORSPolicy(ingress *networkingv1.Ingress, outputDir string) error {
	if !m.NeedsCORSPolicy(ingress) {
		return nil
	}

	annotations := ingress.Annotations

	// Build CORS config
	corsConfig := map[string]interface{}{}

	// allowOrigins
	// In Envoy Gateway v1alpha1, allowOrigins is []string, not type/value objects.
	allowOriginStr := annotations["nginx.ingress.kubernetes.io/cors-allow-origin"]
	if allowOriginStr == "" {
		allowOriginStr = "*"
	}

	// Parse multiple origins (comma or space separated)
	origins := strings.FieldsFunc(allowOriginStr, func(c rune) bool {
		return c == ',' || c == ' '
	})

	allowOrigins := []string{}
	for _, origin := range origins {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			allowOrigins = append(allowOrigins, origin)
		}
	}

	if len(allowOrigins) > 0 {
		corsConfig["allowOrigins"] = allowOrigins
	}

	// allowMethods
	allowMethodsStr := annotations["nginx.ingress.kubernetes.io/cors-allow-methods"]
	if allowMethodsStr == "" {
		allowMethodsStr = "GET, POST, PUT, DELETE, OPTIONS"
	}

	methods := strings.FieldsFunc(allowMethodsStr, func(c rune) bool {
		return c == ',' || c == ' '
	})
	allowMethods := []string{}
	for _, method := range methods {
		method = strings.TrimSpace(method)
		if method != "" {
			allowMethods = append(allowMethods, method)
		}
	}

	if len(allowMethods) > 0 {
		corsConfig["allowMethods"] = allowMethods
	}

	// allowHeaders
	allowHeadersStr := annotations["nginx.ingress.kubernetes.io/cors-allow-headers"]
	if allowHeadersStr != "" {
		// Explicit case: Ingress defines which headers to allow
		headers := strings.FieldsFunc(allowHeadersStr, func(c rune) bool {
			return c == ',' || c == ' '
		})
		allowHeaders := []string{}
		for _, header := range headers {
			header = strings.TrimSpace(header)
			if header != "" {
				allowHeaders = append(allowHeaders, header)
			}
		}
		if len(allowHeaders) > 0 {
			corsConfig["allowHeaders"] = allowHeaders
		}
	} else if annotations["nginx.ingress.kubernetes.io/enable-cors"] == "true" {
		// Implicit case: enable-cors=true but cors-allow-headers not set.
		// To avoid failing many preflights (Authorization, Content-Type, etc.), allow all headers.
		corsConfig["allowHeaders"] = []string{"*"}
	}

	// allowCredentials
	if allowCreds := annotations["nginx.ingress.kubernetes.io/cors-allow-credentials"]; allowCreds == "true" {
		corsConfig["allowCredentials"] = true
	}

	// maxAge
	if maxAge := annotations["nginx.ingress.kubernetes.io/cors-max-age"]; maxAge != "" {
		corsConfig["maxAge"] = maxAge
	}

	// Build SecurityPolicy with CORS
	securityPolicy := map[string]interface{}{
		"apiVersion": "gateway.envoyproxy.io/v1alpha1",
		"kind":       "SecurityPolicy",
		"metadata": map[string]interface{}{
			"name":      fmt.Sprintf("%s-cors", ingress.Name),
			"namespace": ingress.Namespace,
			"labels":    ingress.Labels,
		},
		"spec": map[string]interface{}{
			"cors": corsConfig,
			"targetRefs": []map[string]interface{}{
				{
					"group": "gateway.networking.k8s.io",
					"kind":  "HTTPRoute",
					"name":  ingress.Name,
				},
			},
		},
	}

	// Write file
	templatesDir := filepath.Join(outputDir, "templates")
	if err := os.MkdirAll(templatesDir, 0755); err != nil {
		return fmt.Errorf("error creating templates directory: %w", err)
	}

	filePath := filepath.Join(templatesDir, "securitypolicy.yaml")
	condition := "and .Values.httproute.enabled .Values.securitypolicy.enabled"
	return m.writeHelmTemplate(filePath, securityPolicy, condition)
}

func (m *Migrator) GenerateSecurityPolicy(ingress *networkingv1.Ingress, outputDir string) error {
	if !m.NeedsOAuth(ingress) {
		return nil
	}

	oauthConfig, err := m.GetOAuthConfig()
	if err != nil {
		return fmt.Errorf("error getting OAuth config: %w", err)
	}

	annotations := ingress.Annotations
	authSignin := annotations["nginx.ingress.kubernetes.io/auth-signin"]

	// Extract redirect URL
	redirectURL := m.extractRedirectURL(authSignin, ingress)

	// Get OIDC config (use first provider)
	var oidcConfig *OIDCConfig
	for _, config := range oauthConfig.OIDCProviders {
		oidcConfig = &config
		break
	}

	if oidcConfig == nil {
		return fmt.Errorf("OIDC config not found")
	}

	// Build SecurityPolicy
	securityPolicy := map[string]interface{}{
		"apiVersion": "gateway.envoyproxy.io/v1alpha1",
		"kind":       "SecurityPolicy",
		"metadata": map[string]interface{}{
			"name":      fmt.Sprintf("%s-oidc", ingress.Name),
			"namespace": ingress.Namespace,
			"labels":    ingress.Labels,
		},
		"spec": map[string]interface{}{
			"oidc": map[string]interface{}{
				"provider": map[string]interface{}{
					"issuer": oidcConfig.Issuer,
				},
				"clientID": oidcConfig.ClientID,
				"clientSecret": map[string]interface{}{
					"group":     "",
					"kind":      "Secret",
					"name":      oauthConfig.SecretName,
					"namespace": oauthConfig.SecretNamespace,
				},
				"redirectURL":  redirectURL,
				"scopes":       oidcConfig.Scopes,
				"refreshToken": oidcConfig.RefreshToken,
			},
			"targetRefs": []map[string]interface{}{
				{
					"group":       "gateway.networking.k8s.io",
					"kind":        "HTTPRoute",
					"name":        ingress.Name,
					"sectionName": "main",
				},
			},
		},
	}

	if oidcConfig.LogoutPath != "" {
		oidc := securityPolicy["spec"].(map[string]interface{})["oidc"].(map[string]interface{})
		oidc["logoutPath"] = oidcConfig.LogoutPath
	}

	// Write file
	templatesDir := filepath.Join(outputDir, "templates")
	if err := os.MkdirAll(templatesDir, 0755); err != nil {
		return fmt.Errorf("error creating templates directory: %w", err)
	}

	filePath := filepath.Join(templatesDir, "securitypolicy-oidc.yaml")
	condition := "and .Values.httproute.enabled .Values.securitypolicy.enabled"
	return m.writeHelmTemplate(filePath, securityPolicy, condition)
}

func (m *Migrator) extractRedirectURL(authSignin string, ingress *networkingv1.Ingress) string {
	if authSignin != "" {
		// Look for rd= parameter in URL
		re := regexp.MustCompile(`rd=([^&]+)`)
		matches := re.FindStringSubmatch(authSignin)
		if len(matches) > 1 {
			// Basic URL decode
			redirectURL := strings.ReplaceAll(matches[1], "%3A", ":")
			redirectURL = strings.ReplaceAll(redirectURL, "%2F", "/")
			return redirectURL
		}
	}

	// If no redirect URL, build from hostname
	if len(ingress.Spec.Rules) > 0 && ingress.Spec.Rules[0].Host != "" {
		host := ingress.Spec.Rules[0].Host
		return fmt.Sprintf("https://%s/oauth2/callback", host)
	}

	return ""
}

func (m *Migrator) GenerateHTTPRouteFilter(ingress *networkingv1.Ingress, outputDir string) (bool, error) {
	if !m.NeedsFilters(ingress) {
		return false, nil
	}

	var filters []map[string]interface{}

	// NOTE: CORS is now generated as SecurityPolicy, not HTTPRouteFilter.
	// Here we generate HTTPRouteFilter for cases like blocking specific routes.

	// 1) Specific case: snippet that blocks /internal/ with 404
	if m.hasInternalBlockSnippet(ingress) {
		blockInternal := map[string]interface{}{
			"apiVersion": "gateway.envoyproxy.io/v1alpha1",
			"kind":       "HTTPRouteFilter",
			"metadata": map[string]interface{}{
				"name":      fmt.Sprintf("%s-block-internal", ingress.Name),
				"namespace": ingress.Namespace,
			},
			"spec": map[string]interface{}{
				"directResponse": map[string]interface{}{
					"statusCode": 404,
					"body": map[string]interface{}{
						"type":   "Inline",
						"inline": "Not Found",
					},
					"contentType": "text/plain",
				},
			},
		}
		filters = append(filters, blockInternal)
	}

	if len(filters) == 0 {
		return false, nil
	}

	// Write files
	templatesDir := filepath.Join(outputDir, "templates")
	if err := os.MkdirAll(templatesDir, 0755); err != nil {
		return false, fmt.Errorf("error creating templates directory: %w", err)
	}

	for i, filter := range filters {
		fileName := "httproutefilter.yaml"
		if len(filters) > 1 {
			fileName = fmt.Sprintf("httproutefilter-%d.yaml", i+1)
		}

		filePath := filepath.Join(templatesDir, fileName)
		if err := m.writeHelmTemplate(filePath, filter, "httproute.enabled"); err != nil {
			return false, err
		}
	}

	return true, nil
}

func (m *Migrator) GenerateBackendTLSPolicy(ingress *networkingv1.Ingress, outputDir string) error {
	if !m.NeedsBackendTLSPolicy(ingress) {
		return nil
	}

	// Find first backend with port to build search key
	var serviceName string
	var servicePort int32
	for _, rule := range ingress.Spec.Rules {
		for _, path := range rule.HTTP.Paths {
			serviceName = path.Backend.Service.Name
			if path.Backend.Service.Port.Number > 0 {
				servicePort = path.Backend.Service.Port.Number
			} else {
				// If port is by name, resolve it
				if path.Backend.Service.Port.Name != "" {
					resolved := m.ResolveServicePort(ingress.Namespace, serviceName, path.Backend.Service.Port.Name)
					if resolved > 0 {
						servicePort = resolved
					}
				}
			}
			break
		}
		if serviceName != "" {
			break
		}
	}

	if serviceName == "" {
		return fmt.Errorf("no service found in Ingress for BackendTLSPolicy")
	}

	// Build search key: namespace/service:port
	searchKey := fmt.Sprintf("%s/%s:%d", ingress.Namespace, serviceName, servicePort)
	
	// Look up config
	var tlsConfig *BackendTLSPolicyConfig
	if m.config.BackendTLSPolicies != nil {
		if config, exists := m.config.BackendTLSPolicies[searchKey]; exists {
			tlsConfig = &config
		}
	}

	// Build BackendTLSPolicy
	labels := make(map[string]string)
	if ingress.Labels != nil {
		for k, v := range ingress.Labels {
			labels[k] = v
		}
	}
	
	backendTLSPolicy := map[string]interface{}{
		"apiVersion": "gateway.networking.k8s.io/v1",
		"kind":       "BackendTLSPolicy",
		"metadata": map[string]interface{}{
			"name":      fmt.Sprintf("%s-upstream-tls", serviceName),
			"namespace": ingress.Namespace,
			"labels":    labels,
		},
		"spec": map[string]interface{}{
			"targetRefs": []map[string]interface{}{
				{
					"group": "",
					"kind":  "Service",
					"name":  serviceName,
				},
			},
		},
	}

	if tlsConfig != nil && tlsConfig.Hostname != "" {
		// Full config found
		validation := map[string]interface{}{
			"hostname": tlsConfig.Hostname,
		}
		
		if tlsConfig.CASecret != "" {
			validation["caCertificateRefs"] = []map[string]interface{}{
				{
					"group": "",
					"kind":  "Secret",
					"name":  tlsConfig.CASecret,
				},
			}
		}
		
		backendTLSPolicy["spec"].(map[string]interface{})["validation"] = validation
	} else {
		// No config: generate template with placeholders for user to complete
		validation := map[string]interface{}{
			"hostname": fmt.Sprintf("TODO-REPLACE-%s.%s.es.local", serviceName, ingress.Namespace),
		}
		
		validation["caCertificateRefs"] = []map[string]interface{}{
			{
				"group": "",
				"kind":  "Secret",
				"name":  fmt.Sprintf("TODO-REPLACE-%s-ca-internal", serviceName),
			},
		}
		
		backendTLSPolicy["spec"].(map[string]interface{})["validation"] = validation
		
		// Add label to indicate config is required
		labels["migration.requires-config"] = "true"
	}

	// Write file
	templatesDir := filepath.Join(outputDir, "templates")
	if err := os.MkdirAll(templatesDir, 0755); err != nil {
		return fmt.Errorf("error creating templates directory: %w", err)
	}

	filePath := filepath.Join(templatesDir, "backendtlspolicy.yaml")
	condition := "httproute.enabled"
	return m.writeHelmTemplate(filePath, backendTLSPolicy, condition)
}

func (m *Migrator) writeHelmTemplate(filePath string, resource map[string]interface{}, condition string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}
	defer file.Close()

	// Write YAML directly without Helm conditionals
	encoder := yaml.NewEncoder(file)
	encoder.SetIndent(2)
	if err := encoder.Encode(resource); err != nil {
		return fmt.Errorf("error writing YAML: %w", err)
	}
	encoder.Close()

	return nil
}

func (m *Migrator) DetectApplicationStructure(namespace, ingressName string) string {
	if !m.config.OutputStructure.AutoDetectStructure {
		return filepath.Join(".", "generated", namespace, ingressName)
	}

	basePath := m.config.OutputStructure.BasePath
	if basePath == "" {
		basePath = "environments"
	}

	// Search in possible directory structures
	possiblePaths := []string{
		filepath.Join(basePath, "test", "applications"),
		filepath.Join(basePath, "staging", "applications"),
		filepath.Join(basePath, "production", "applications"),
	}

	for _, envPath := range possiblePaths {
		if _, err := os.Stat(envPath); os.IsNotExist(err) {
			continue
		}

		// Search recursively
		var foundPath string
		filepath.Walk(envPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			if info.IsDir() {
				dirName := filepath.Base(path)
				if strings.Contains(dirName, ingressName) || strings.Contains(ingressName, dirName) {
					chartPath := filepath.Join(path, "Chart.yaml")
					if _, err := os.Stat(chartPath); err == nil {
						// Found
						foundPath = path
						return filepath.SkipAll
					}
				}
			}
			return nil
		})

		if foundPath != "" {
			return foundPath
		}
	}

	// If not found, use current directory structure
	return filepath.Join(".", "generated", namespace, ingressName)
}

func (m *Migrator) MigrateIngress(ingress *networkingv1.Ingress, outputBase string) error {
	outputDir := outputBase
	if outputDir == "" {
		outputDir = m.DetectApplicationStructure(ingress.Namespace, ingress.Name)
	}

	fmt.Printf("Migrating Ingress: %s/%s\n", ingress.Namespace, ingress.Name)
	fmt.Printf("  Output directory: %s\n", outputDir)

	// Generate HTTPRoute
	if err := m.GenerateHTTPRoute(ingress, outputDir); err != nil {
		return fmt.Errorf("error generating HTTPRoute: %w", err)
	}
	fmt.Printf("  ✓ HTTPRoute generated\n")

	// Generate SecurityPolicy with OAuth if needed
	if m.NeedsOAuth(ingress) {
		if err := m.GenerateSecurityPolicy(ingress, outputDir); err != nil {
			return fmt.Errorf("error generating SecurityPolicy: %w", err)
		}
		fmt.Printf("  ✓ SecurityPolicy (OAuth) generated\n")
	}

	// Generate SecurityPolicy with CORS if needed (and no OAuth)
	// If OAuth is present, CORS is handled in OAuth SecurityPolicy
	if m.NeedsCORSPolicy(ingress) && !m.NeedsOAuth(ingress) {
		if err := m.GenerateCORSPolicy(ingress, outputDir); err != nil {
			return fmt.Errorf("error generating SecurityPolicy (CORS): %w", err)
		}
		fmt.Printf("  ✓ SecurityPolicy (CORS) generated\n")
	}

	// Generate HTTPRouteFilter if needed (only for non-CORS filters)
	if m.NeedsFilters(ingress) {
		generated, err := m.GenerateHTTPRouteFilter(ingress, outputDir)
		if err != nil {
			return fmt.Errorf("error generating HTTPRouteFilter: %w", err)
		}
		if generated {
			fmt.Printf("  ✓ HTTPRouteFilter generated\n")
		}
	}

	// Generate BackendTLSPolicy if needed (for backend-protocol: HTTPS)
	if m.NeedsBackendTLSPolicy(ingress) {
		if err := m.GenerateBackendTLSPolicy(ingress, outputDir); err != nil {
			return fmt.Errorf("error generating BackendTLSPolicy: %w", err)
		}
		fmt.Printf("  ✓ BackendTLSPolicy generated\n")
	}

	return nil
}

func (m *Migrator) MigrateNamespace(namespace, outputBase string) error {
	fmt.Printf("Listing Ingress in namespace: %s\n", namespace)
	ingresses, err := m.GetIngresses(namespace)
	if err != nil {
		return fmt.Errorf("error listing Ingress: %w", err)
	}

	if len(ingresses) == 0 {
		fmt.Printf("No Ingress found in namespace %s\n", namespace)
		return nil
	}

	fmt.Printf("Found %d Ingress\n\n", len(ingresses))

	for i := range ingresses {
		if err := m.MigrateIngress(&ingresses[i], outputBase); err != nil {
			fmt.Printf("  ✗ Error: %v\n", err)
			continue
		}
		fmt.Println()
	}

	return nil
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // Windows
}

func main() {
	var (
		namespace    = flag.String("namespace", "", "Namespace to list Ingress from")
		cluster      = flag.String("cluster", "", "Cluster name (e.g. dev, staging, prod) for OAuth config")
		configFile   = flag.String("config", "", "Path to config YAML file")
		kubeContext  = flag.String("kube-context", "", "Kubernetes context to use")
		output       = flag.String("output", "", "Base output directory (optional)")
	)
	flag.Parse()

	if *namespace == "" || *cluster == "" || *configFile == "" {
		fmt.Println("Usage: migrate_ingress --namespace <namespace> --cluster <cluster> --config <config-file> [--kube-context <context>] [--output <output-dir>]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	migrator, err := NewMigrator(*configFile, *kubeContext, *cluster)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating migrator: %v\n", err)
		os.Exit(1)
	}

	if err := migrator.MigrateNamespace(*namespace, *output); err != nil {
		fmt.Fprintf(os.Stderr, "Error during migration: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n✓ Migration completed")
}
