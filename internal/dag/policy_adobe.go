package dag

import (
	"time"

	ingressroutev1 "github.com/projectcontour/contour/apis/contour/v1beta1"
	"github.com/projectcontour/contour/internal/annotation"
)

func ingressrouteTimeoutPolicy(tp *ingressroutev1.TimeoutPolicy) *TimeoutPolicy {
	if tp == nil {
		return nil
	}
	return &TimeoutPolicy{
		// due to a misunderstanding the name of the field ingressroute is
		// Request, however the timeout applies to the response resulting from
		// a request.
		ResponseTimeout: annotation.ParseTimeout(tp.Request),
	}
}

func ingressrouteHealthCheckPolicy(hc *ingressroutev1.HealthCheck) *HTTPHealthCheckPolicy {
	if hc == nil {
		return nil
	}
	return &HTTPHealthCheckPolicy{
		Path:               hc.Path,
		Host:               hc.Host,
		Interval:           time.Duration(hc.IntervalSeconds) * time.Second,
		Timeout:            time.Duration(hc.TimeoutSeconds) * time.Second,
		UnhealthyThreshold: uint32(hc.UnhealthyThresholdCount),
		HealthyThreshold:   uint32(hc.HealthyThresholdCount),
	}
}
