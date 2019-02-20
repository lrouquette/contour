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

package envoy

import (
	"fmt"
	"sort"
	"time"

	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/route"
	"github.com/gogo/protobuf/types"
	"github.com/heptio/contour/internal/dag"
)

// RouteRoute creates a route.Route_Route for the services supplied.
// If len(services) is greater than one, the route's action will be a
// weighted cluster.
func RouteRoute(r *dag.Route, services []*dag.HTTPService) *route.Route_Route {
	ra := route.RouteAction{
		UseWebsocket:  bv(r.Websocket),
		RetryPolicy:   retryPolicy(r),
		Timeout:       r.Timeout,
		IdleTimeout:   r.IdleTimeout,
		PrefixRewrite: r.PrefixRewrite,
	}

	if len(r.HashPolicy) > 0 {
		ra.HashPolicy = make([]*route.RouteAction_HashPolicy, len(r.HashPolicy))
	}

	for i, policy := range r.HashPolicy {
		if policy.Header != nil {
			ra.HashPolicy[i] = &route.RouteAction_HashPolicy{
				PolicySpecifier: &route.RouteAction_HashPolicy_Header_{
					Header: &route.RouteAction_HashPolicy_Header{
						HeaderName: policy.Header.HeaderName,
					},
				},
			}
		} else if policy.Cookie != nil {
			policySpecifier := &route.RouteAction_HashPolicy_Cookie_{
				Cookie: &route.RouteAction_HashPolicy_Cookie{
					Name: policy.Cookie.Name,
					Path: policy.Cookie.Path,
				},
			}
			if policy.Cookie.Ttl != nil {
				policySpecifier.Cookie.Ttl = &policy.Cookie.Ttl.Duration
			}

			ra.HashPolicy[i] = &route.RouteAction_HashPolicy{
				PolicySpecifier: policySpecifier,
			}
		} else if policy.ConnectionProperties != nil {
			ra.HashPolicy[i] = &route.RouteAction_HashPolicy{
				PolicySpecifier: &route.RouteAction_HashPolicy_ConnectionProperties_{
					ConnectionProperties: &route.RouteAction_HashPolicy_ConnectionProperties{
						SourceIp: policy.ConnectionProperties.SourceIp,
					},
				},
			}
		}

		if ra.HashPolicy[i] != nil {
			ra.HashPolicy[i].Terminal = policy.Terminal
		}
	}

	switch len(services) {
	case 1:
		ra.ClusterSpecifier = &route.RouteAction_Cluster{
			Cluster: Clustername(&services[0].TCPService),
		}
		ra.RequestHeadersToAdd = headers(
			appendHeader("x-request-start", "t=%START_TIME(%s.%3f)%"),
		)
	default:
		ra.ClusterSpecifier = &route.RouteAction_WeightedClusters{
			WeightedClusters: weightedClusters(services),
		}
	}
	return &route.Route_Route{
		Route: &ra,
	}
}

func retryPolicy(r *dag.Route) *route.RouteAction_RetryPolicy {
	if r.RetryOn == "" {
		return nil
	}
	rp := &route.RouteAction_RetryPolicy{
		RetryOn: r.RetryOn,
	}
	if r.NumRetries > 0 {
		rp.NumRetries = u32(r.NumRetries)
	}
	if r.PerTryTimeout > 0 {
		timeout := r.PerTryTimeout
		rp.PerTryTimeout = &timeout
	}
	return rp
}

// UpgradeHTTPS returns a route Action that redirects the request to HTTPS.
func UpgradeHTTPS() *route.Route_Redirect {
	return &route.Route_Redirect{
		Redirect: &route.RedirectAction{
			HttpsRedirect: true,
		},
	}
}

// weightedClusters returns a route.WeightedCluster for multiple services.
func weightedClusters(services []*dag.HTTPService) *route.WeightedCluster {
	var wc route.WeightedCluster
	var total int
	for _, service := range services {
		total += service.Weight
		wc.Clusters = append(wc.Clusters, &route.WeightedCluster_ClusterWeight{
			Name:   Clustername(&service.TCPService),
			Weight: u32(service.Weight),
			RequestHeadersToAdd: headers(
				appendHeader("x-request-start", "t=%START_TIME(%s.%3f)%"),
			),
		})
	}
	// Check if no weights were defined, if not default to even distribution
	if total == 0 {
		for _, c := range wc.Clusters {
			c.Weight.Value = 1
		}
		total = len(services)
	}
	wc.TotalWeight = u32(total)

	sort.Stable(clusterWeightByName(wc.Clusters))
	return &wc
}

// PrefixMatch creates a RouteMatch for the supplied prefix.
func PrefixMatch(prefix string) route.RouteMatch {
	return route.RouteMatch{
		PathSpecifier: &route.RouteMatch_Prefix{
			Prefix: prefix,
		},
	}
}

// VirtualHost creates a new route.VirtualHost.
func VirtualHost(hostname string, port int) route.VirtualHost {
	domains := []string{hostname}
	if hostname != "*" {
		domains = append(domains, fmt.Sprintf("%s:%d", hostname, port))
	}
	return route.VirtualHost{
		Name:    hashname(60, hostname),
		Domains: domains,
	}
}

type clusterWeightByName []*route.WeightedCluster_ClusterWeight

func (c clusterWeightByName) Len() int      { return len(c) }
func (c clusterWeightByName) Swap(i, j int) { c[i], c[j] = c[j], c[i] }
func (c clusterWeightByName) Less(i, j int) bool {
	if c[i].Name == c[j].Name {
		return c[i].Weight.Value < c[j].Weight.Value
	}
	return c[i].Name < c[j].Name

}

func headers(first *core.HeaderValueOption, rest ...*core.HeaderValueOption) []*core.HeaderValueOption {
	return append([]*core.HeaderValueOption{first}, rest...)
}

func appendHeader(key, value string) *core.HeaderValueOption {
	return &core.HeaderValueOption{
		Header: &core.HeaderValue{
			Key:   key,
			Value: value,
		},
		Append: bv(true),
	}
}

func u32(val int) *types.UInt32Value { return &types.UInt32Value{Value: uint32(val)} }

var bvTrue = types.BoolValue{Value: true}

// bv returns a pointer to a true types.BoolValue if val is true,
// otherwise it returns nil.
func bv(val bool) *types.BoolValue {
	if val {
		return &bvTrue
	}
	return nil
}

func duration(d time.Duration) *time.Duration { return &d }

func PerFilterConfig(r *dag.Route) (conf map[string]*types.Struct) {
	if len(r.PerFilterConfig) == 0 {
		return
	}

	conf = make(map[string]*types.Struct)
	for k, v := range r.PerFilterConfig {
		s := new(types.Struct)
		conf[k] = s

		recurseIface(s, v)
	}
	return
}

// recurseIface is *types.Value producing function that recurses into nested
// structures
func recurseIface(s *types.Struct, iface interface{}) (ret *types.Value) {

	switch ifaceVal := iface.(type) {
	case int:
		ret = &types.Value{
			Kind: &types.Value_NumberValue{float64(ifaceVal)},
		}
	case int32:
		ret = &types.Value{
			Kind: &types.Value_NumberValue{float64(ifaceVal)},
		}
	case int64:
		ret = &types.Value{
			Kind: &types.Value_NumberValue{float64(ifaceVal)},
		}
	case uint:
		ret = &types.Value{
			Kind: &types.Value_NumberValue{float64(ifaceVal)},
		}
	case uint32:
		ret = &types.Value{
			Kind: &types.Value_NumberValue{float64(ifaceVal)},
		}
	case uint64:
		ret = &types.Value{
			Kind: &types.Value_NumberValue{float64(ifaceVal)},
		}
	case float32:
		ret = &types.Value{
			Kind: &types.Value_NumberValue{float64(ifaceVal)},
		}
	case float64:
		ret = &types.Value{
			Kind: &types.Value_NumberValue{ifaceVal},
		}
	case string:
		ret = &types.Value{
			Kind: &types.Value_StringValue{ifaceVal},
		}
	case bool:
		ret = &types.Value{
			Kind: &types.Value_BoolValue{ifaceVal},
		}
	case map[string]interface{}:
		if s == nil { // will only be true on the initial call
			s = new(types.Struct)
		}
		if s.Fields == nil {
			s.Fields = make(map[string]*types.Value)
		}

		for k, v := range ifaceVal {
			s.Fields[k] = recurseIface(nil, v)
		}

		ret = &types.Value{
			Kind: &types.Value_StructValue{s},
		}
	case []interface{}:
		lv := new(types.ListValue)
		for _, v := range ifaceVal {
			lv.Values = append(lv.Values, recurseIface(nil, v))
		}
		ret = &types.Value{
			Kind: &types.Value_ListValue{lv},
		}
	default:
		ret = &types.Value{
			Kind: &types.Value_NullValue{},
		}
	}
	return
}
