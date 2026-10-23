package guard

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/lynx-go/grpcapi/policy"
	"github.com/lynx-go/grpcapi/surface"
)

// RouteTableOptions 是 AssertRouteTable 的输入。
type RouteTableOptions struct {
	// Policies 必填：路由表里的每个 ID 都必须能查到策略。
	Policies *policy.Set
	// Surface 可选：提供后校验 proto 路由来源与 extra route 不覆盖 proto 路由。
	Surface *surface.Surface
	// AllowShadow 允许 extra route 与 proto route 同 verb+path（默认 false）。
	AllowShadow bool
	// MinRoutes 防空转下限。
	MinRoutes int
}

// AssertRouteTable 校验 server.Routes() 的装配结果：
//
//   - 非空 / MinRoutes 下限；
//   - 无重复 METHOD+path；
//   - 每个路由 ID 都能在 Policies 中查到；
//   - proto 路由有 FullMethod，且（若提供 Surface）来自 Surface；
//   - extra route 不静默覆盖 proto 路由（除非 AllowShadow）。
func AssertRouteTable(t testing.TB, routes []surface.RouteInfo, o RouteTableOptions) {
	t.Helper()
	if o.Policies == nil {
		t.Fatal("AssertRouteTable: Policies 为 nil：拒绝空转")
	}
	if len(routes) == 0 {
		t.Fatal("AssertRouteTable: 路由表为空：拒绝空转")
	}
	if o.MinRoutes > 0 && len(routes) < o.MinRoutes {
		t.Fatalf("AssertRouteTable: 路由数 %d 低于下限 %d", len(routes), o.MinRoutes)
	}

	surfaceProtoKeys := make(map[string]struct{})
	if o.Surface != nil {
		for _, r := range o.Surface.Routes() {
			surfaceProtoKeys[r.Method+" "+r.Path] = struct{}{}
		}
	}
	// 路由表里的 Path 已叠加 API 前缀；用 proto 路由的实际 Path 检测 extra 覆盖。
	protoFinalKeys := make(map[string]struct{})
	for _, r := range routes {
		if r.Source == "proto" && r.Method != "" && r.Path != "" {
			protoFinalKeys[r.Method+" "+r.Path] = struct{}{}
		}
	}

	seen := make(map[string]surface.RouteInfo, len(routes))
	var errs []string
	for _, r := range routes {
		if r.Method == "" || r.Path == "" {
			errs = append(errs, fmt.Sprintf("route %q: method/path is empty", r.ID))
			continue
		}
		key := r.Method + " " + r.Path
		if prev, dup := seen[key]; dup {
			shadowAllowed := o.AllowShadow && prev.Source == "proto" && r.Source == "extra"
			if !shadowAllowed {
				errs = append(errs, fmt.Sprintf("duplicate route %s (%s and %s)", key, prev.ID, r.ID))
			}
		} else {
			seen[key] = r
		}
		op, ok := o.Policies.Get(r.ID)
		if !ok {
			errs = append(errs, fmt.Sprintf("route %s: policy %q not found", key, r.ID))
		} else if op.Policy.IsZero() {
			errs = append(errs, fmt.Sprintf("route %s: policy %q is empty", key, r.ID))
		}

		switch r.Source {
		case "proto":
			if r.FullMethod == "" {
				errs = append(errs, fmt.Sprintf("route %s: proto route has empty FullMethod", key))
			}
			if o.Surface != nil {
				surfaceKey := key
				if r.ProtoPath != "" {
					surfaceKey = r.Method + " " + r.ProtoPath
				}
				if _, ok := surfaceProtoKeys[surfaceKey]; !ok {
					errs = append(errs, fmt.Sprintf("route %s: not found in Surface", surfaceKey))
				}
			}
		case "extra":
			if r.FullMethod != "" {
				errs = append(errs, fmt.Sprintf("route %s: extra route must not have FullMethod", key))
			}
			if o.Surface != nil && !o.AllowShadow {
				if _, shadow := protoFinalKeys[key]; shadow {
					errs = append(errs, fmt.Sprintf("route %s: extra route shadows a proto route", key))
				}
			}
		default:
			errs = append(errs, fmt.Sprintf("route %s: unknown Source %q", key, r.Source))
		}
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		t.Fatalf("AssertRouteTable: %d violation(s):\n  - %s", len(errs), strings.Join(errs, "\n  - "))
	}
}
