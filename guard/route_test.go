package guard

import (
	"testing"

	"github.com/lynx-go/grpcapi/policy"
	"github.com/lynx-go/grpcapi/surface"
)

func routeTestSet(t *testing.T) *policy.Set {
	t.Helper()
	set, err := policy.NewSet(
		policy.Operation{ID: "/test.Svc/Get", Kind: policy.KindGRPC, Exposure: policy.ExposurePublic, Policy: policy.Policy{Anonymous: true}},
		policy.Operation{ID: "GET /healthz", Kind: policy.KindHTTP, Exposure: policy.ExposurePublic, Policy: policy.Policy{Anonymous: true}},
	)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func TestAssertRouteTablePositive(t *testing.T) {
	set := routeTestSet(t)
	routes := []surface.RouteInfo{
		{ID: "/test.Svc/Get", Method: "GET", Path: "/v1/get", FullMethod: "/test.Svc/Get", Source: "proto", Exposure: policy.ExposurePublic, Label: "public"},
		{ID: "GET /healthz", Method: "GET", Path: "/healthz", Source: "extra", Exposure: policy.ExposurePublic, Label: "public"},
	}
	AssertRouteTable(t, routes, RouteTableOptions{Policies: set, MinRoutes: 2})
}

func TestAssertRouteTableRejects(t *testing.T) {
	set := routeTestSet(t)
	base := []surface.RouteInfo{
		{ID: "/test.Svc/Get", Method: "GET", Path: "/v1/get", FullMethod: "/test.Svc/Get", Source: "proto"},
	}

	cases := []struct {
		name   string
		routes []surface.RouteInfo
		opts   RouteTableOptions
	}{
		{
			name:   "empty",
			routes: nil,
			opts:   RouteTableOptions{Policies: set},
		},
		{
			name:   "nil policies",
			routes: base,
			opts:   RouteTableOptions{},
		},
		{
			name:   "min routes",
			routes: base,
			opts:   RouteTableOptions{Policies: set, MinRoutes: 2},
		},
		{
			name: "duplicate",
			routes: []surface.RouteInfo{
				base[0],
				{ID: "GET /healthz", Method: "GET", Path: "/v1/get", Source: "extra"},
			},
			opts: RouteTableOptions{Policies: set},
		},
		{
			name:   "missing policy",
			routes: []surface.RouteInfo{{ID: "/missing", Method: "GET", Path: "/x", FullMethod: "/missing", Source: "proto"}},
			opts:   RouteTableOptions{Policies: set},
		},
		{
			name:   "proto no full method",
			routes: []surface.RouteInfo{{ID: "/test.Svc/Get", Method: "GET", Path: "/x", Source: "proto"}},
			opts:   RouteTableOptions{Policies: set},
		},
		{
			name:   "unknown source",
			routes: []surface.RouteInfo{{ID: "/test.Svc/Get", Method: "GET", Path: "/x", Source: "nope"}},
			opts:   RouteTableOptions{Policies: set},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			expectGuardFatal(t, tc.name, func(_ *testing.T, tb testing.TB) {
				AssertRouteTable(tb, tc.routes, tc.opts)
			})
		})
	}
}
