package server

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/lynx-go/grpcapi/gateway"
	"github.com/lynx-go/grpcapi/policy"
	"github.com/lynx-go/grpcapi/surface"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// HTTPRegisterFunc 是生成的 RegisterXxxHandlerClient 的适配形态。
type HTTPRegisterFunc func(context.Context, *runtime.ServeMux, grpc.ClientConnInterface) error

// Registration 是一个 proto Service 的完整装配包。
type Registration struct {
	// API 必须与 proto 的 APISpec.api 一致；空 = 从策略派生。
	API  string
	Name string

	Descriptor   protoreflect.ServiceDescriptor
	RegisterGRPC func(*grpc.Server)
	RegisterHTTP HTTPRegisterFunc
	// AllowAPIMismatch 显式允许 API 面不一致（默认 false）。
	AllowAPIMismatch bool
}

// APIConfig 是单个 API 面的装配配置。
type APIConfig struct {
	Name       string
	Prefix     string
	Services   []Registration
	Middleware []func(http.Handler) http.Handler
	Mux        gateway.MuxOptions
	Docs       fs.FS
}

// ExtraRoute 是 health/webhook/static/OAuth 等少量手写路由。
type ExtraRoute struct {
	ID       string
	Method   string
	Path     string
	Handler  http.Handler
	Policy   *policy.Policy
	IsPublic bool
	Exposure policy.Exposure
	Label    string
}

// GET 构造 GET extra route。
func GET(path string, h http.Handler) ExtraRoute { return Handle(http.MethodGet, path, h) }

// POST 构造 POST extra route。
func POST(path string, h http.Handler) ExtraRoute { return Handle(http.MethodPost, path, h) }

// PUT 构造 PUT extra route。
func PUT(path string, h http.Handler) ExtraRoute { return Handle(http.MethodPut, path, h) }

// PATCH 构造 PATCH extra route。
func PATCH(path string, h http.Handler) ExtraRoute { return Handle(http.MethodPatch, path, h) }

// DELETE 构造 DELETE extra route。
func DELETE(path string, h http.Handler) ExtraRoute { return Handle(http.MethodDelete, path, h) }

// Handle 构造任意 method 的 extra route。
func Handle(method, path string, h http.Handler) ExtraRoute {
	return ExtraRoute{Method: strings.ToUpper(method), Path: surface.NormalizePath(path), Handler: h}
}

// Public 标记公开路由。
func (r ExtraRoute) Public() ExtraRoute {
	r.IsPublic = true
	r.Policy = nil
	return r
}

// Authenticated 要求登录。
func (r ExtraRoute) Authenticated() ExtraRoute {
	return r.Require(policy.Policy{Require: []policy.Requirement{{Kind: "authenticated"}}})
}

// Roles 要求任一角色。
func (r ExtraRoute) Roles(roles ...string) ExtraRoute {
	return r.Require(policy.Policy{Require: []policy.Requirement{{Kind: "role", Match: policy.MatchAny, Values: roles}}})
}

// Permissions 要求全部权限。
func (r ExtraRoute) Permissions(perms ...string) ExtraRoute {
	return r.Require(policy.Policy{Require: []policy.Requirement{{Kind: "permission", Match: policy.MatchAll, Values: perms}}})
}

// Scopes 要求任一 scope。
func (r ExtraRoute) Scopes(scopes ...string) ExtraRoute {
	return r.Require(policy.Policy{Require: []policy.Requirement{{Kind: "scope", Match: policy.MatchAny, Values: scopes}}})
}

// Require 设置完整策略。
func (r ExtraRoute) Require(p policy.Policy) ExtraRoute {
	r.IsPublic = false
	r.Policy = &p
	return r
}

// Internal 标记内部路由（不进公开文档）。
func (r ExtraRoute) Internal() ExtraRoute {
	r.Exposure = policy.ExposureInternal
	return r
}

func (r ExtraRoute) operation() (policy.Operation, error) {
	if r.Handler == nil {
		return policy.Operation{}, fmt.Errorf("extra route %s %s: handler is nil", r.Method, r.Path)
	}
	if r.IsPublic && r.Policy != nil {
		return policy.Operation{}, fmt.Errorf("extra route %s %s: Public and Policy are mutually exclusive", r.Method, r.Path)
	}
	if !r.IsPublic && r.Policy == nil {
		return policy.Operation{}, fmt.Errorf("extra route %s %s: must be Public() or carry a Policy", r.Method, r.Path)
	}
	p := policy.Policy{Anonymous: true}
	if r.Policy != nil {
		p = r.Policy.Clone()
	}
	exposure := r.Exposure
	if exposure == policy.ExposureUnspecified {
		if r.IsPublic {
			exposure = policy.ExposurePublic
		} else {
			exposure = policy.ExposureHidden
		}
	}
	id := r.ID
	if id == "" {
		id = strings.ToUpper(r.Method) + " " + r.Path
	}
	label := r.Label
	if label == "" {
		label = policy.Label(p)
	}
	return policy.Operation{
		ID:       id,
		Kind:     policy.KindHTTP,
		Service:  "http",
		Policy:   p,
		Exposure: exposure,
		Label:    label,
		Metadata: map[string]string{"method": strings.ToUpper(r.Method), "path": r.Path},
	}, nil
}
