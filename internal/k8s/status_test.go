// Copyright © 2019 VMware
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
	"errors"
	"fmt"
	"testing"

	"github.com/projectcontour/contour/internal/assert"

	"k8s.io/client-go/dynamic/fake"

	ingressroutev1 "github.com/projectcontour/contour/apis/contour/v1beta1"
	ingressroutev1beta1 "github.com/projectcontour/contour/apis/contour/v1beta1"
	projcontour "github.com/projectcontour/contour/apis/projectcontour/v1"
	projectcontour "github.com/projectcontour/contour/apis/projectcontour/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"
)

func TestSetIngressRouteStatus(t *testing.T) {
	type testcase struct {
		msg           string
		desc          string
		existing      *ingressroutev1beta1.IngressRoute
		expectedPatch string
		expectedVerbs []string
	}

	run := func(t *testing.T, name string, tc testcase) {
		t.SkipNow()
		t.Helper()

		t.Run(name, func(t *testing.T) {
			t.Helper()
			var gotPatchBytes []byte

			s := runtime.NewScheme()
			if err := ingressroutev1.AddToScheme(s); err != nil {
				t.Fatalf("adding to scheme: %s", err)
			}

			client := fake.NewSimpleDynamicClient(s, tc.existing)

			client.PrependReactor("patch", "ingressroutes", func(action k8stesting.Action) (bool, runtime.Object, error) {
				switch patchAction := action.(type) {
				default:
					return true, nil, fmt.Errorf("got unexpected action of type: %T", action)
				case k8stesting.PatchActionImpl:
					gotPatchBytes = patchAction.GetPatch()
					return true, tc.existing, nil
				}
			})

			irs := StatusWriter{
				Client: client,
			}
			if err := irs.SetStatus(tc.msg, tc.desc, tc.existing); err != nil {
				t.Fatal(err)
			}

			if len(client.Actions()) != len(tc.expectedVerbs) {
				t.Fatalf("Expected verbs mismatch: want: %d, got: %d", len(tc.expectedVerbs), len(client.Actions()))
			}

			if tc.expectedPatch != string(gotPatchBytes) {
				t.Fatalf("expected patch: %s, got: %s", tc.expectedPatch, string(gotPatchBytes))
			}
		})
	}

	run(t, "simple update", testcase{
		msg:  "valid",
		desc: "this is a valid IR",
		existing: &ingressroutev1beta1.IngressRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: "default",
			},
			Status: projcontour.Status{
				CurrentStatus: "",
				Description:   "",
			},
		},
		expectedPatch: `{"status":{"currentStatus":"valid","description":"this is a valid IR"}}`,
		expectedVerbs: []string{"patch"},
	})

	run(t, "no update", testcase{
		msg:  "valid",
		desc: "this is a valid IR",
		existing: &ingressroutev1beta1.IngressRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: "default",
			},
			Status: projcontour.Status{
				CurrentStatus: "valid",
				Description:   "this is a valid IR",
			},
		},
		expectedPatch: ``,
		expectedVerbs: []string{},
	})

	run(t, "replace existing status", testcase{
		msg:  "valid",
		desc: "this is a valid IR",
		existing: &ingressroutev1beta1.IngressRoute{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: "default",
			},
			Status: projcontour.Status{
				CurrentStatus: "invalid",
				Description:   "boo hiss",
			},
		},
		expectedPatch: `{"status":{"currentStatus":"valid","description":"this is a valid IR"}}`,
		expectedVerbs: []string{"patch"},
	})
}

func TestSetHTTPProxyStatus(t *testing.T) {
	type testcase struct {
		msg      string
		desc     string
		existing *projectcontour.HTTPProxy
		expected *projectcontour.HTTPProxy
	}

	run := func(t *testing.T, name string, tc testcase) {
		t.Helper()

		t.Run(name, func(t *testing.T) {
			t.Helper()
			var gotObj runtime.Object

			s := runtime.NewScheme()
			if err := projcontour.AddToScheme(s); err != nil {
				t.Fatalf("adding to scheme: %s", err)
			}

			usc, err := NewUnstructuredConverter()
			if err != nil {
				t.Fatal(err)
			}

			client := fake.NewSimpleDynamicClient(s, tc.existing)

			client.PrependReactor("*", "httpproxies", func(action k8stesting.Action) (bool, runtime.Object, error) {
				switch updateAction := action.(type) {
				default:
					return true, nil, fmt.Errorf("got unexpected action of type: %T", action)
				case k8stesting.UpdateActionImpl:
					gotObj = updateAction.GetObject()
					return true, tc.existing, nil
				}
			})

			proxysw := StatusWriter{
				Client:    client,
				Converter: usc,
			}

			if err := proxysw.SetStatus(tc.msg, tc.desc, tc.existing); err != nil {
				t.Fatal(fmt.Errorf("unable to set proxy status: %s", err))
			}

			toProxy, err := usc.FromUnstructured(gotObj)
			if err != nil {
				t.Fatal(err)
			}

			if toProxy == nil && tc.expected == nil {
				return
			}

			assert.Equal(t, toProxy, tc.expected)

			if toProxy == nil && tc.expected != nil {
				t.Fatalf("Did not get expected update, %#v", tc.expected)
			}
		})
	}

	run(t, "simple update", testcase{
		msg:  "valid",
		desc: "this is a valid HTTPProxy",
		existing: &projcontour.HTTPProxy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: "default",
			},
			Status: projcontour.Status{
				CurrentStatus: "",
				Description:   "",
			},
		},
		expected: &projcontour.HTTPProxy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: "default",
			},
			Status: projcontour.Status{
				CurrentStatus: "valid",
				Description:   "this is a valid HTTPProxy",
			},
		},
	})

	run(t, "no update", testcase{
		msg:  "valid",
		desc: "this is a valid HTTPProxy",
		existing: &projcontour.HTTPProxy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: "default",
			},
			Status: projcontour.Status{
				CurrentStatus: "valid",
				Description:   "this is a valid HTTPProxy",
			},
		},
		expected: nil,
	})

	run(t, "replace existing status", testcase{
		msg:  "valid",
		desc: "this is a valid HTTPProxy",
		existing: &projcontour.HTTPProxy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: "default",
			},
			Status: projcontour.Status{
				CurrentStatus: "invalid",
				Description:   "boo hiss",
			},
		},
		expected: &projcontour.HTTPProxy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test",
				Namespace: "default",
			},
			Status: projcontour.Status{
				CurrentStatus: "valid",
				Description:   "this is a valid HTTPProxy",
			},
		},
	})
}

func TestGetStatus(t *testing.T) {
	type testcase struct {
		input          interface{}
		expectedStatus *projcontour.Status
		expectedError  error
	}

	run := func(t *testing.T, name string, tc testcase) {
		t.Helper()

		t.Run(name, func(t *testing.T) {
			t.Helper()

			proxysw := StatusWriter{
				Client: fake.NewSimpleDynamicClient(runtime.NewScheme()),
			}

			status, err := proxysw.GetStatus(tc.input)

			assert.Equal(t, tc.expectedStatus, status)
			assert.Equal(t, tc.expectedError, err)
		})
	}

	run(t, "not implemented", testcase{
		input:          nil,
		expectedStatus: nil,
		expectedError:  errors.New("not implemented"),
	})
}
