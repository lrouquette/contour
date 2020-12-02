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

package k8s

import (
	ingressroutev1 "github.com/projectcontour/contour/apis/contour/v1beta1"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/api/networking/v1beta1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	serviceapis "sigs.k8s.io/service-apis/api/v1alpha1"
)

func DefaultResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{
		ingressroutev1.IngressRouteGVR,
		ingressroutev1.TLSCertificateDelegationGVR,
		// Adobe - disable 1.0 CRDs
		// projectcontour.HTTPProxyGVR,
		// projectcontour.TLSCertificateDelegationGVR,
		corev1.SchemeGroupVersion.WithResource("services"),
		v1beta1.SchemeGroupVersion.WithResource("ingresses"),
	}
}

func ServiceAPIResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{
		serviceapis.GroupVersion.WithResource("gatewayclasses"),
		serviceapis.GroupVersion.WithResource("gateways"),
		serviceapis.GroupVersion.WithResource("httproutes"),
		serviceapis.GroupVersion.WithResource("tcproutes"),
	}
}

func SecretsResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{
		corev1.SchemeGroupVersion.WithResource("secrets"),
	}
}

func EndpointsResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{
		corev1.SchemeGroupVersion.WithResource("endpoints"),
	}
}

func ServicesResources() []schema.GroupVersionResource {
	return []schema.GroupVersionResource{
		corev1.SchemeGroupVersion.WithResource("services"),
	}
}
