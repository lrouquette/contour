package e2e

import (
	"testing"

	envoy_api_v2_route "github.com/envoyproxy/go-control-plane/envoy/api/v2/route"
	projcontour "github.com/projectcontour/contour/apis/projectcontour/v1"
	"github.com/projectcontour/contour/internal/envoy"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func TestAdobeHTTPProxyRouteHeaderMatch(t *testing.T) {
	rh, cc, done := setup(t)
	defer done()

	rh.OnAdd(&v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ws1",
			Namespace: "default",
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{{
				Protocol:   "TCP",
				Port:       80,
				TargetPort: intstr.FromInt(8080),
			}},
		},
	})

	rh.OnAdd(&v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ws2",
			Namespace: "default",
		},
		Spec: v1.ServiceSpec{
			Ports: []v1.ServicePort{{
				Protocol:   "TCP",
				Port:       81,
				TargetPort: intstr.FromInt(8081),
			}},
		},
	})

	rh.OnAdd(&projcontour.HTTPProxy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "simple",
			Namespace: "default",
		},
		Spec: projcontour.HTTPProxySpec{
			VirtualHost: &projcontour.VirtualHost{Fqdn: "route-headermatch.hello.world"},
			Routes: []projcontour.Route{
				{
					Conditions: []projcontour.Condition{
						{
							Header: &projcontour.HeaderCondition{
								Name:  "my-header",
								Exact: "foo",
							},
						},
					},
					Services: []projcontour.Service{
						{
							Name: "ws1",
							Port: 80,
						},
					},
				},
				{
					Conditions: []projcontour.Condition{
						{
							Header: &projcontour.HeaderCondition{
								Name:  "my-header",
								Exact: "bar",
							},
						},
					},
					Services: []projcontour.Service{
						{
							Name: "ws2",
							Port: 81,
						},
					},
				},
			},
		},
	})

	r1 := &envoy_api_v2_route.Route{
		Match: &envoy_api_v2_route.RouteMatch{
			PathSpecifier: &envoy_api_v2_route.RouteMatch_Prefix{
				Prefix: "/",
			},
			Headers: []*envoy_api_v2_route.HeaderMatcher{{
				Name:                 "my-header",
				HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_ExactMatch{ExactMatch: "foo"},
			}},
		},
		Action: routecluster("default/ws1/80/da39a3ee5e"),
	}

	r2 := &envoy_api_v2_route.Route{
		Match: &envoy_api_v2_route.RouteMatch{
			PathSpecifier: &envoy_api_v2_route.RouteMatch_Prefix{
				Prefix: "/",
			},
			Headers: []*envoy_api_v2_route.HeaderMatcher{{
				Name:                 "my-header",
				HeaderMatchSpecifier: &envoy_api_v2_route.HeaderMatcher_ExactMatch{ExactMatch: "bar"},
			}},
		},
		Action: routecluster("default/ws2/81/da39a3ee5e"),
	}

	assertRDS(t, cc, "1", virtualhosts(
		envoy.VirtualHost("route-headermatch.hello.world", r2, r1),
	), nil)
}
