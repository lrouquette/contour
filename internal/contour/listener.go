// Copyright © 2020 VMware
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package contour

import (
	"sort"
	"sync"
	"time"

	v2 "github.com/envoyproxy/go-control-plane/envoy/api/v2"
	envoy_api_v2_auth "github.com/envoyproxy/go-control-plane/envoy/api/v2/auth"
	envoy_api_v2_listener "github.com/envoyproxy/go-control-plane/envoy/api/v2/listener"
	envoy_api_v2_accesslog "github.com/envoyproxy/go-control-plane/envoy/config/filter/accesslog/v2"
	resource "github.com/envoyproxy/go-control-plane/pkg/resource/v2"
	"github.com/golang/protobuf/proto"
	"github.com/google/go-cmp/cmp"
	"github.com/projectcontour/contour/internal/dag"
	"github.com/projectcontour/contour/internal/envoy"
	"github.com/projectcontour/contour/internal/protobuf"
	"github.com/projectcontour/contour/internal/sorter"
)

const (
	ENVOY_HTTP_LISTENER            = "ingress_http"
	ENVOY_FALLBACK_ROUTECONFIG     = "ingress_fallbackcert"
	ENVOY_HTTPS_LISTENER           = "ingress_https"
	DEFAULT_HTTP_ACCESS_LOG        = "/dev/stdout"
	DEFAULT_HTTP_LISTENER_ADDRESS  = "0.0.0.0"
	DEFAULT_HTTP_LISTENER_PORT     = 8080
	DEFAULT_HTTPS_ACCESS_LOG       = "/dev/stdout"
	DEFAULT_HTTPS_LISTENER_ADDRESS = DEFAULT_HTTP_LISTENER_ADDRESS
	DEFAULT_HTTPS_LISTENER_PORT    = 8443
	DEFAULT_ACCESS_LOG_TYPE        = "envoy"
)

// ListenerVisitorConfig holds configuration parameters for visitListeners.
type ListenerVisitorConfig struct {
	// Envoy's HTTP (non TLS) listener address.
	// If not set, defaults to DEFAULT_HTTP_LISTENER_ADDRESS.
	HTTPAddress string

	// Envoy's HTTP (non TLS) listener port.
	// If not set, defaults to DEFAULT_HTTP_LISTENER_PORT.
	HTTPPort int

	// Envoy's HTTP (non TLS) access log path.
	// If not set, defaults to DEFAULT_HTTP_ACCESS_LOG.
	HTTPAccessLog string

	// Envoy's HTTPS (TLS) listener address.
	// If not set, defaults to DEFAULT_HTTPS_LISTENER_ADDRESS.
	HTTPSAddress string

	// Envoy's HTTPS (TLS) listener port.
	// If not set, defaults to DEFAULT_HTTPS_LISTENER_PORT.
	HTTPSPort int

	// Envoy's HTTPS (TLS) access log path.
	// If not set, defaults to DEFAULT_HTTPS_ACCESS_LOG.
	HTTPSAccessLog string

	// UseProxyProto configures all listeners to expect a PROXY
	// V1 or V2 preamble.
	// If not set, defaults to false.
	UseProxyProto bool

	// MinimumProtocolVersion defines the min tls protocol version to be used
	MinimumProtocolVersion envoy_api_v2_auth.TlsParameters_TlsProtocol

	// DefaultCertificate is the cert to use for the catch-all server
	// if defined, it should be an existing secret of type kubernetes.io/tls
	DefaultCertificate string

	// AccessLogType defines if Envoy logs should be output as Envoy's default or JSON.
	// Valid values: 'envoy', 'json'
	// If not set, defaults to 'envoy'
	AccessLogType string

	// AccessLogFields sets the fields that should be shown in JSON logs.
	// Valid entries are the keys from internal/envoy/accesslog.go:jsonheaders
	// Defaults to a particular set of fields.
	AccessLogFields []string

	// RequestTimeout configures the request_timeout for all Connection Managers.
	RequestTimeout time.Duration
}

// httpAddress returns the port for the HTTP (non TLS)
// listener or DEFAULT_HTTP_LISTENER_ADDRESS if not configured.
func (lvc *ListenerVisitorConfig) httpAddress() string {
	if lvc.HTTPAddress != "" {
		return lvc.HTTPAddress
	}
	return DEFAULT_HTTP_LISTENER_ADDRESS
}

// httpPort returns the port for the HTTP (non TLS)
// listener or DEFAULT_HTTP_LISTENER_PORT if not configured.
func (lvc *ListenerVisitorConfig) httpPort() int {
	if lvc.HTTPPort != 0 {
		return lvc.HTTPPort
	}
	return DEFAULT_HTTP_LISTENER_PORT
}

// httpAccessLog returns the access log for the HTTP (non TLS)
// listener or DEFAULT_HTTP_ACCESS_LOG if not configured.
func (lvc *ListenerVisitorConfig) httpAccessLog() string {
	if lvc.HTTPAccessLog != "" {
		return lvc.HTTPAccessLog
	}
	return DEFAULT_HTTP_ACCESS_LOG
}

// httpsAddress returns the port for the HTTPS (TLS)
// listener or DEFAULT_HTTPS_LISTENER_ADDRESS if not configured.
func (lvc *ListenerVisitorConfig) httpsAddress() string {
	if lvc.HTTPSAddress != "" {
		return lvc.HTTPSAddress
	}
	return DEFAULT_HTTPS_LISTENER_ADDRESS
}

// httpsPort returns the port for the HTTPS (TLS) listener
// or DEFAULT_HTTPS_LISTENER_PORT if not configured.
func (lvc *ListenerVisitorConfig) httpsPort() int {
	if lvc.HTTPSPort != 0 {
		return lvc.HTTPSPort
	}
	return DEFAULT_HTTPS_LISTENER_PORT
}

// httpsAccessLog returns the access log for the HTTPS (TLS)
// listener or DEFAULT_HTTPS_ACCESS_LOG if not configured.
func (lvc *ListenerVisitorConfig) httpsAccessLog() string {
	if lvc.HTTPSAccessLog != "" {
		return lvc.HTTPSAccessLog
	}
	return DEFAULT_HTTPS_ACCESS_LOG
}

// accesslogType returns the access log type that should be configured
// across all listener types or DEFAULT_ACCESS_LOG_TYPE if not configured.
func (lvc *ListenerVisitorConfig) accesslogType() string {
	if lvc.AccessLogType != "" {
		return lvc.AccessLogType
	}
	return DEFAULT_ACCESS_LOG_TYPE
}

// accesslogFields returns the access log fields that should be configured
// for Envoy, or a default set if not configured.
func (lvc *ListenerVisitorConfig) accesslogFields() []string {
	if lvc.AccessLogFields != nil {
		return lvc.AccessLogFields
	}
	return envoy.DefaultFields
}

func (lvc *ListenerVisitorConfig) newInsecureAccessLog() []*envoy_api_v2_accesslog.AccessLog {
	switch lvc.accesslogType() {
	case "json":
		return envoy.FileAccessLogJSON(lvc.httpAccessLog(), lvc.accesslogFields())
	default:
		return envoy.FileAccessLogEnvoy(lvc.httpAccessLog())
	}
}

func (lvc *ListenerVisitorConfig) newSecureAccessLog() []*envoy_api_v2_accesslog.AccessLog {
	switch lvc.accesslogType() {
	case "json":
		return envoy.FileAccessLogJSON(lvc.httpsAccessLog(), lvc.accesslogFields())
	default:
		return envoy.FileAccessLogEnvoy(lvc.httpsAccessLog())
	}
}

// requestTimeout sets any durations in lvc.RequestTimeout <0 to 0 so that Envoy ends up with a positive duration.
// for the request_timeout value we are passing, there are only two valid values:
// 0 - disabled
// >0 duration - the timeout.
// The value may be unset, but we always set it to 0.
func (lvc *ListenerVisitorConfig) requestTimeout() time.Duration {

	if lvc.RequestTimeout < 0 {
		return 0
	}
	return lvc.RequestTimeout
}

// minProtocolVersion returns the requested minimum TLS protocol
// version or envoy_api_v2_auth.TlsParameters_TLSv1_1 if not configured {
func (lvc *ListenerVisitorConfig) minProtoVersion() envoy_api_v2_auth.TlsParameters_TlsProtocol {
	if lvc.MinimumProtocolVersion > envoy_api_v2_auth.TlsParameters_TLSv1_1 {
		return lvc.MinimumProtocolVersion
	}
	return envoy_api_v2_auth.TlsParameters_TLSv1_1
}

// ListenerCache manages the contents of the gRPC LDS cache.
type ListenerCache struct {
	mu           sync.Mutex
	values       map[string]*v2.Listener
	staticValues map[string]*v2.Listener
	Cond
}

// NewListenerCache returns an instance of a ListenerCache
func NewListenerCache(address string, port int) ListenerCache {
	return ListenerCache{
		staticValues: map[string]*v2.Listener{},
	}
}

// Update replaces the contents of the cache with the supplied map.
func (c *ListenerCache) Update(v map[string]*v2.Listener) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.values = v
	c.Cond.Notify()
}

// Contents returns a copy of the cache's contents.
func (c *ListenerCache) Contents() []proto.Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	var values []*v2.Listener
	for _, v := range c.values {
		values = append(values, v)
	}
	for _, v := range c.staticValues {
		values = append(values, v)
	}
	sort.Stable(sorter.For(values))
	return protobuf.AsMessages(values)
}

// Query returns the proto.Messages in the ListenerCache that match
// a slice of strings
func (c *ListenerCache) Query(names []string) []proto.Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	var values []*v2.Listener
	for _, n := range names {
		v, ok := c.values[n]
		if !ok {
			v, ok = c.staticValues[n]
			if !ok {
				// if the listener is not registered in
				// dynamic or static values then skip it
				// as there is no way to return a blank
				// listener because the listener address
				// field is required.
				continue
			}
		}
		values = append(values, v)
	}
	sort.Stable(sorter.For(values))
	return protobuf.AsMessages(values)
}

func (*ListenerCache) TypeURL() string { return resource.ListenerType }

type listenerVisitor struct {
	*ListenerVisitorConfig

	listeners map[string]*v2.Listener
	http      bool // at least one dag.VirtualHost encountered
}

func visitListeners(root dag.Vertex, lvc *ListenerVisitorConfig) map[string]*v2.Listener {
	lv := listenerVisitor{
		ListenerVisitorConfig: lvc,
		listeners: map[string]*v2.Listener{
			ENVOY_HTTPS_LISTENER: envoy.Listener(
				ENVOY_HTTPS_LISTENER,
				lvc.httpsAddress(),
				lvc.httpsPort(),
				append(secureProxyProtocol(lvc.UseProxyProto), CustomListenerFilters()...),
			),
		},
	}

	lv.visit(root)

	if lv.http {
		// Add a listener if there are vhosts bound to http.
		cm := envoy.HTTPConnectionManagerBuilder().
			DefaultFilters().
			RouteConfigName(ENVOY_HTTP_LISTENER).
			MetricsPrefix(ENVOY_HTTP_LISTENER).
			AccessLoggers(lvc.newInsecureAccessLog()).
			RequestTimeout(lvc.requestTimeout()).
			Get()

		lv.listeners[ENVOY_HTTP_LISTENER] = envoy.Listener(
			ENVOY_HTTP_LISTENER,
			lvc.httpAddress(),
			lvc.httpPort(),
			append(proxyProtocol(lvc.UseProxyProto), CustomListenerFilters()...),
			cm,
		)
	}

	// Configure a default/catch all filterchain if a DefaultCertificate exists
	// setting "server_names" to a blank string will catch clients that don't send SNI
	// https://www.envoyproxy.io/docs/envoy/v1.13.1/api-v2/api/v2/listener/listener_components.proto#listener-filterchainmatch
	if lv.ListenerVisitorConfig.DefaultCertificate != "" {
		secrets := visitSecretsAsDag(root)
		if secret, ok := secrets[lv.ListenerVisitorConfig.DefaultCertificate]; ok {
			// filters & alpnProtos are exactly as in visit() below
			filters := envoy.Filters(
				envoy.HTTPConnectionManagerBuilder().
					DefaultFilters().
					RouteConfigName(ENVOY_HTTPS_LISTENER).
					MetricsPrefix(ENVOY_HTTPS_LISTENER).
					AccessLoggers(lv.ListenerVisitorConfig.newSecureAccessLog()).
					RequestTimeout(lv.ListenerVisitorConfig.requestTimeout()).
					Get(),
			)
			alpnProtos := []string{"h2", "http/1.1"}

			fcNoSNI := envoy.FilterChainTLS(
				"", // no "server_names"
				envoy.DownstreamTLSContext(secret, lv.ListenerVisitorConfig.minProtoVersion(), nil, alpnProtos...),
				filters,
			)
			lv.listeners[ENVOY_HTTPS_LISTENER].FilterChains = append(lv.listeners[ENVOY_HTTPS_LISTENER].FilterChains, fcNoSNI)
		}
	}

	// Remove the https listener if there are no vhosts bound to it.
	if len(lv.listeners[ENVOY_HTTPS_LISTENER].FilterChains) == 0 {
		delete(lv.listeners, ENVOY_HTTPS_LISTENER)
	} else {
		// there's some https listeners, we need to sort the filter chains
		// to ensure that the LDS entries are identical.
		sort.Stable(sorter.For(lv.listeners[ENVOY_HTTPS_LISTENER].FilterChains))
	}

	return lv.listeners
}

func proxyProtocol(useProxy bool) []*envoy_api_v2_listener.ListenerFilter {
	if useProxy {
		return envoy.ListenerFilters(
			envoy.ProxyProtocol(),
		)
	}
	return nil
}

func secureProxyProtocol(useProxy bool) []*envoy_api_v2_listener.ListenerFilter {
	return append(proxyProtocol(useProxy), envoy.TLSInspector())
}

func (v *listenerVisitor) visit(vertex dag.Vertex) {
	max := func(a, b envoy_api_v2_auth.TlsParameters_TlsProtocol) envoy_api_v2_auth.TlsParameters_TlsProtocol {
		if a > b {
			return a
		}
		return b
	}

	switch vh := vertex.(type) {
	case *dag.VirtualHost:
		// we only create on http listener so record the fact
		// that we need to then double back at the end and add
		// the listener properly.
		v.http = true
	case *dag.SecureVirtualHost:
		var alpnProtos []string
		var filters []*envoy_api_v2_listener.Filter

		if vh.TCPProxy == nil {
			// Create a uniquely named HTTP connection manager for
			// this vhost, so that the SNI name the client requests
			// only grants access to that host. See RFC 6066 for
			// security advice. Note that we still use the generic
			// metrics prefix to keep compatibility with previous
			// Contour versions since the metrics prefix will be
			// coded into monitoring dashboards.
			filters = envoy.Filters(
				envoy.HTTPConnectionManagerBuilder().
					// Adobe - no sni bindings, no lua filter
					// AddFilter(envoy.FilterMisdirectedRequests(vh.VirtualHost.Name)).
					DefaultFilters().
					// RouteConfigName(path.Join("https", vh.VirtualHost.Name)).
					RouteConfigName(ENVOY_HTTPS_LISTENER).
					MetricsPrefix(ENVOY_HTTPS_LISTENER).
					AccessLoggers(v.ListenerVisitorConfig.newSecureAccessLog()).
					RequestTimeout(v.ListenerVisitorConfig.requestTimeout()).
					Get(),
			)

			alpnProtos = []string{"h2", "http/1.1"}
		} else {
			filters = envoy.Filters(
				envoy.TCPProxy(ENVOY_HTTPS_LISTENER,
					vh.TCPProxy,
					v.ListenerVisitorConfig.newSecureAccessLog()),
			)

			// Do not offer ALPN for TCP proxying, since
			// the protocols will be provided by the TCP
			// backend in its ServerHello.
		}

		var downstreamTLS *envoy_api_v2_auth.DownstreamTlsContext

		// Secret is provided when TLS is terminated and nil when TLS passthrough is used.
		if vh.Secret != nil {
			// Choose the higher of the configured or requested TLS version.
			vers := max(v.ListenerVisitorConfig.minProtoVersion(), vh.MinProtoVersion)

			downstreamTLS = envoy.DownstreamTLSContextAdobe(
				vh.Secret,
				vers,
				maxProtoVersion(vh.MaxProtoVersion),
				vh.DownstreamValidation,
				alpnProtos...)
		}

		// Group filter chain by TransportSocket
		// if a filter chain with the exact same DownstreamTlsContext already exists, just
		// add the vhost name to the existing list
		// EXCEPTION: don't group if TCPProxy filter exists (client-provided)
		fcExists := false
		if vh.TCPProxy == nil && vh.Secret != nil {
			for _, fc := range v.listeners[ENVOY_HTTPS_LISTENER].FilterChains {
				if fc.TransportSocket == nil {
					// No TransportSocket, skip
					continue
				}
				if isTCPProxyFilter(fc.Filters) {
					// TCPProxy filter exists, skip
					continue
				}
				if cmp.Equal(downstreamTLS, envoy.GetDownstreamTLSContext(fc)) {
					fc.FilterChainMatch.ServerNames = append(fc.FilterChainMatch.ServerNames, vh.VirtualHost.Name)
					sort.Strings(fc.FilterChainMatch.ServerNames)
					fcExists = true
					break
				}
			}
		}

		if !fcExists {
			v.listeners[ENVOY_HTTPS_LISTENER].FilterChains = append(v.listeners[ENVOY_HTTPS_LISTENER].FilterChains,
				envoy.FilterChainTLS(vh.VirtualHost.Name, downstreamTLS, filters))
		}

		// If this VirtualHost has enabled the fallback certificate then set a default
		// FilterChain which will allow routes with this vhost to accept non-SNI TLS requests.
		// Note that we don't add the misdirected requests filter on this chain because at this
		// point we don't actually know the full set of server names that will be bound to the
		// filter chain through the ENVOY_FALLBACK_ROUTECONFIG route configuration.
		if vh.FallbackCertificate != nil && !envoy.ContainsFallbackFilterChain(v.listeners[ENVOY_HTTPS_LISTENER].FilterChains) {
			// Construct the downstreamTLSContext passing the configured fallbackCertificate. The TLS minProtocolVersion will use
			// the value defined in the Contour Configuration file if defined.
			downstreamTLS = envoy.DownstreamTLSContext(
				vh.FallbackCertificate,
				v.ListenerVisitorConfig.minProtoVersion(),
				vh.DownstreamValidation,
				alpnProtos...)

			// Default filter chain
			filters = envoy.Filters(
				envoy.HTTPConnectionManagerBuilder().
					RouteConfigName(ENVOY_FALLBACK_ROUTECONFIG).
					MetricsPrefix(ENVOY_HTTPS_LISTENER).
					AccessLoggers(v.ListenerVisitorConfig.newSecureAccessLog()).
					RequestTimeout(v.ListenerVisitorConfig.requestTimeout()).
					Get(),
			)

			v.listeners[ENVOY_HTTPS_LISTENER].FilterChains = append(v.listeners[ENVOY_HTTPS_LISTENER].FilterChains,
				envoy.FilterChainTLSFallback(downstreamTLS, filters))
		}

	default:
		// recurse
		vertex.Visit(v.visit)
	}
}
