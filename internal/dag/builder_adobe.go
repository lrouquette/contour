package dag

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/golang/protobuf/ptypes"
	ingressroutev1 "github.com/projectcontour/contour/apis/contour/v1beta1"
	projcontour "github.com/projectcontour/contour/apis/projectcontour/v1"
	"github.com/projectcontour/contour/internal/annotation"
	"github.com/projectcontour/contour/internal/k8s"
)

// validIngressRoutes returns a slice of *ingressroutev1.IngressRoute objects.
// invalid IngressRoute objects are excluded from the slice and their status
// updated accordingly.
func (b *Builder) validIngressRoutes() []*ingressroutev1.IngressRoute {
	// ensure that a given fqdn is only referenced in a single ingressroute resource
	var valid []*ingressroutev1.IngressRoute
	fqdnIngressroutes := make(map[string][]*ingressroutev1.IngressRoute)
	for _, ir := range b.Source.ingressroutes {
		if ir.Spec.VirtualHost == nil {
			valid = append(valid, ir)
			continue
		}
		fqdnIngressroutes[ir.Spec.VirtualHost.Fqdn] = append(fqdnIngressroutes[ir.Spec.VirtualHost.Fqdn], ir)
	}

	for fqdn, irs := range fqdnIngressroutes {
		switch len(irs) {
		case 1:
			valid = append(valid, irs[0])
		default:
			// multiple irs use the same fqdn. mark them as invalid.
			var conflicting []string
			for _, ir := range irs {
				conflicting = append(conflicting, ir.Namespace+"/"+ir.Name)
			}
			sort.Strings(conflicting) // sort for test stability
			msg := fmt.Sprintf("fqdn %q is used in multiple IngressRoutes: %s", fqdn, strings.Join(conflicting, ", "))
			for _, ir := range irs {
				sw, commit := b.WithObject(ir)
				sw.WithValue("vhost", fqdn).SetInvalid(msg)
				commit()
			}
		}
	}
	return valid
}

func (b *Builder) computeIngressRoutes() {
	for _, ir := range b.validIngressRoutes() {
		b.computeIngressRoute(ir)
	}
}

func (b *Builder) computeIngressRoute(ir *ingressroutev1.IngressRoute) {
	sw, commit := b.WithObject(ir)
	defer commit()

	if ir.Spec.VirtualHost == nil {
		// mark delegate ingressroute orphaned.
		b.setOrphaned(ir)
		return
	}

	// ensure root ingressroute lives in allowed namespace
	if !b.rootAllowed(ir.Namespace) {
		sw.SetInvalid("root IngressRoute cannot be defined in this namespace")
		return
	}

	host := ir.Spec.VirtualHost.Fqdn
	if isBlank(host) {
		sw.SetInvalid("Spec.VirtualHost.Fqdn must be specified")
		return
	}
	sw.WithValue("vhost", host)

	// Adobe - we allow
	// if strings.Contains(host, "*") {
	// 	sw.SetInvalid("Spec.VirtualHost.Fqdn %q cannot use wildcards", host)
	// 	return
	// }

	var enforceTLS, passthrough bool
	if tls := ir.Spec.VirtualHost.TLS; tls != nil {
		// passthrough is true if tls.secretName is not present, and
		// tls.passthrough is set to true.
		passthrough = tls.SecretName == "" && tls.Passthrough

		if !passthrough {
			secretName := splitSecret(tls.SecretName, ir.Namespace)
			sec, err := b.lookupSecret(secretName, validSecret)
			if err != nil {
				sw.SetInvalid("Spec.VirtualHost.TLS Secret %q is invalid: %s", tls.SecretName, err)
				return
			}

			if !b.delegationPermitted(secretName, ir.Namespace) {
				sw.SetInvalid("Spec.VirtualHost.TLS Secret %q certificate delegation not permitted", tls.SecretName)
				return
			}

			svhost := b.lookupSecureVirtualHost(ir.Spec.VirtualHost.Fqdn)
			svhost.Secret = sec
			svhost.MinTLSVersion = annotation.MinTLSVersion(ir.Spec.VirtualHost.TLS.MinimumProtocolVersion)
			svhost.MaxProtoVersion = annotation.MaxProtoVersion(ir.Spec.VirtualHost.TLS.MaximumProtocolVersion)
			enforceTLS = true
		}
	}

	if ir.Spec.TCPProxy != nil && (passthrough || enforceTLS) {
		b.processIngressRouteTCPProxy(sw, ir, nil, host)
	}

	b.processIngressRoutes(sw, ir, "", nil, host, ir.Spec.TCPProxy == nil && enforceTLS)
}

func (b *Builder) processIngressRoutes(sw *ObjectStatusWriter, ir *ingressroutev1.IngressRoute, prefixMatch string, visited []*ingressroutev1.IngressRoute, host string, enforceTLS bool) {
	visited = append(visited, ir)

	for _, route := range ir.Spec.Routes {
		// route cannot both delegate and point to services
		if len(route.Services) > 0 && route.Delegate != nil {
			sw.SetInvalid("route %q: cannot specify services and delegate in the same route", route.Match)
			return
		}

		// base case: The route points to services, so we add them to the vhost
		if len(route.Services) > 0 {
			if !matchesPathPrefix(route.Match, prefixMatch) {
				sw.SetInvalid("the path prefix %q does not match the parent's path prefix %q", route.Match, prefixMatch)
				return
			}

			permitInsecure := route.PermitInsecure && !b.DisablePermitInsecure
			r := &Route{
				PathCondition:   &PrefixCondition{Prefix: route.Match},
				Websocket:       route.EnableWebsockets,
				HTTPSUpgrade:    routeEnforceTLS(enforceTLS, permitInsecure),
				PrefixRewrite:   route.PrefixRewrite,
				TimeoutPolicy:   ingressrouteTimeoutPolicy(route.TimeoutPolicy),
				RetryPolicy:     retryPolicy(route.RetryPolicy),
				HashPolicy:      route.HashPolicy,
				PerFilterConfig: route.PerFilterConfig,
			}

			if route.RequestHeadersPolicy != nil {
				reqHP, err := headersPolicy(route.RequestHeadersPolicy, true /* allow Host */)
				if err != nil {
					sw.SetInvalid(err.Error())
					return
				}
				r.RequestHeadersPolicy = reqHP
			}

			if route.ResponseHeadersPolicy != nil {
				respHP, err := headersPolicy(route.ResponseHeadersPolicy, false /* disallow Host */)
				if err != nil {
					sw.SetInvalid(err.Error())
					return
				}
				r.ResponseHeadersPolicy = respHP
			}

			if route.IdleTimeout != nil {
				if d, err := ptypes.Duration(&route.IdleTimeout.Duration); err == nil {
					if d > time.Hour {
						r.IdleTimeout = ptypes.DurationProto(time.Hour)
					} else if d <= 0 {
						sw.SetInvalid("route %q: idle timeout can not be disabled", route.Match)
						return
					} else {
						r.IdleTimeout = &route.IdleTimeout.Duration
					}
				}
			}

			if route.Timeout != nil {
				if d, err := ptypes.Duration(&route.Timeout.Duration); err == nil {
					if d < 0 {
						sw.SetInvalid("route %q: timeout value must be >= 0", route.Match)
						return
					} else {
						r.Timeout = &route.Timeout.Duration
					}
				}
			}

			if route.Tracing != nil {
				if route.Tracing.ClientSampling > 100 {
					sw.SetInvalid("route %q: tracing clientSampling must be in the range [0,100]", route.Match)
					return
				} else if route.Tracing.RandomSampling > 100 {
					sw.SetInvalid("route %q: tracing randomSampling must be in the range [0,100]", route.Match)
					return
				} else {
					r.Tracing = route.Tracing
				}
			}

			if len(route.HeaderMatch) > 0 {
				// wrap them in a []projcontour.Condition so we can leverage upstream code
				conds := make([]projcontour.Condition, 0, len(route.HeaderMatch))
				for _, hm := range route.HeaderMatch {
					conds = append(conds, projcontour.Condition{
						Header: &hm,
					})
				}
				if err := headerConditionsValid(conds); err != nil {
					sw.SetInvalid("cannot specify duplicate header 'exact match' conditions in the same route")
					return
				}
				r.HeaderConditions = mergeHeaderConditions(conds)
			}

			for _, service := range route.Services {
				if service.Port < 1 || service.Port > 65535 {
					sw.SetInvalid("route %q: service %q: port must be in the range 1-65535", route.Match, service.Name)
					return
				}
				m := k8s.FullName{Name: service.Name, Namespace: ir.Namespace}

				s := b.lookupService(m, intstr.FromInt(service.Port))
				if s == nil {
					sw.SetInvalid("Service [%s:%d] is invalid or missing", service.Name, service.Port)
					return
				}

				var uv *PeerValidationContext
				var err error
				if s.Protocol == "tls" {
					// we can only validate TLS connections to services that talk TLS
					uv, err = b.lookupUpstreamValidation(service.UpstreamValidation, ir.Namespace)
					if err != nil {
						sw.SetInvalid("Service [%s:%d] TLS upstream validation policy error: %s",
							service.Name, service.Port, err)
						return
					}
				}

				c := &Cluster{
					Upstream:              s,
					LoadBalancerPolicy:    service.Strategy,
					Weight:                uint32(service.Weight),
					HTTPHealthCheckPolicy: ingressrouteHealthCheckPolicy(service.HealthCheck),
					UpstreamValidation:    uv,
					Protocol:              s.Protocol,
				}

				if service.IdleTimeout != nil {
					if d, err := ptypes.Duration(&service.IdleTimeout.Duration); err == nil {
						if d > time.Hour {
							c.IdleTimeout = ptypes.DurationProto(time.Hour)
						} else if d <= 0 {
							sw.SetInvalid("route: %q service %q: idle timeout can not be disabled", route.Match, service.Name)
							return
						} else {
							c.IdleTimeout = &service.IdleTimeout.Duration
						}
					}
				}

				r.Clusters = append(r.Clusters, c)
			}

			b.lookupVirtualHost(host).addRoute(r)
			if enforceTLS {
				b.lookupSecureVirtualHost(host).addRoute(r)
			}
			continue
		}

		if route.Delegate == nil {
			// not a delegate route
			continue
		}

		namespace := route.Delegate.Namespace
		if namespace == "" {
			// we are delegating to another IngressRoute in the same namespace
			namespace = ir.Namespace
		}

		if dest, ok := b.Source.ingressroutes[k8s.FullName{Name: route.Delegate.Name, Namespace: namespace}]; ok {
			// Adobe - allow root to root delegation
			// if dest.Spec.VirtualHost != nil {
			// 	sw.SetInvalid("root ingressroute cannot delegate to another root ingressroute")
			// 	return
			// }

			// dest is not an orphaned ingress route, as there is an IR that points to it
			delete(b.orphaned, k8s.FullName{Name: dest.Name, Namespace: dest.Namespace})

			// ensure we are not following an edge that produces a cycle
			var path []string
			for _, vir := range visited {
				path = append(path, fmt.Sprintf("%s/%s", vir.Namespace, vir.Name))
			}
			for _, vir := range visited {
				if dest.Name == vir.Name && dest.Namespace == vir.Namespace {
					path = append(path, fmt.Sprintf("%s/%s", dest.Namespace, dest.Name))
					sw.SetInvalid("route creates a delegation cycle: %s", strings.Join(path, " -> "))
					return
				}
			}

			// follow the link and process the target ingress route
			sw, commit := b.WithObject(dest)
			b.processIngressRoutes(sw, dest, route.Match, visited, host, enforceTLS)
			commit()
		}
	}
	sw.SetValid()
}

func (b *Builder) processIngressRouteTCPProxy(sw *ObjectStatusWriter, ir *ingressroutev1.IngressRoute, visited []*ingressroutev1.IngressRoute, host string) {
	visited = append(visited, ir)

	// tcpproxy cannot both delegate and point to services
	tcpproxy := ir.Spec.TCPProxy
	if len(tcpproxy.Services) > 0 && tcpproxy.Delegate != nil {
		sw.SetInvalid("tcpproxy: cannot specify services and delegate in the same tcpproxy")
		return
	}

	if len(tcpproxy.Services) > 0 {
		var proxy TCPProxy
		for _, service := range tcpproxy.Services {
			m := k8s.FullName{Name: service.Name, Namespace: ir.Namespace}
			s := b.lookupService(m, intstr.FromInt(service.Port))
			if s == nil {
				sw.SetInvalid("tcpproxy: service %s/%s/%d: not found", ir.Namespace, service.Name, service.Port)
				return
			}
			proxy.Clusters = append(proxy.Clusters, &Cluster{
				Upstream:           s,
				LoadBalancerPolicy: service.Strategy,
				Protocol:           s.Protocol,
			})
		}
		b.lookupSecureVirtualHost(host).TCPProxy = &proxy
		sw.SetValid()
		return
	}

	if tcpproxy.Delegate == nil {
		// Not a delegate tcpproxy. Note that we allow a TCPProxy to be
		// empty (no services and no delegates) for IngressRoute backwards
		// compatibility. This is not allowed in HTTPProxy.
		return
	}

	namespace := tcpproxy.Delegate.Namespace
	if namespace == "" {
		// we are delegating to another IngressRoute in the same namespace
		namespace = ir.Namespace
	}

	if dest, ok := b.Source.ingressroutes[k8s.FullName{Name: tcpproxy.Delegate.Name, Namespace: namespace}]; ok {
		// dest is not an orphaned ingress route, as there is an IR that points to it
		delete(b.orphaned, k8s.FullName{Name: dest.Name, Namespace: dest.Namespace})

		// ensure we are not following an edge that produces a cycle
		var path []string
		for _, vir := range visited {
			path = append(path, fmt.Sprintf("%s/%s", vir.Namespace, vir.Name))
		}
		for _, vir := range visited {
			if dest.Name == vir.Name && dest.Namespace == vir.Namespace {
				path = append(path, fmt.Sprintf("%s/%s", dest.Namespace, dest.Name))
				sw.SetInvalid("tcpproxy creates a delegation cycle: %s", strings.Join(path, " -> "))
				return
			}
		}

		// follow the link and process the target ingress route
		sw, commit := sw.WithObject(dest)
		b.processIngressRouteTCPProxy(sw, dest, visited, host)
		commit()
	}
}
