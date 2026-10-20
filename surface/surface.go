// Package surface 把 proto Service + google.api.http + policy.Set 组合成
// 统一的 API 接口面 IR。server 用它做装配/断言，guard 用它做文档一致性检查。
package surface

import (
	"fmt"
	"sort"
	"strings"

	"github.com/lynx-go/grpcapi/policy"
	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// HTTPBinding 是单个 google.api.http 绑定。
type HTTPBinding struct {
	Verb         string
	Path         string
	Body         string
	ResponseBody string
	BindingIndex int // 主规则 0；additional_bindings 从 1 起
}

// Operation 是一个 gRPC method 的接口面投影。
type Operation struct {
	Operation  policy.Operation
	Service    protoreflect.ServiceDescriptor
	Descriptor protoreflect.MethodDescriptor
	Input      protoreflect.MessageDescriptor
	Output     protoreflect.MessageDescriptor
	HTTP       []HTTPBinding
	Streaming  bool
}

// RouteInfo 是路由表的稳定投影（供启动日志/守卫/CLI）。
type RouteInfo struct {
	ID         string // policy operation ID
	Method     string
	ProtoPath  string // proto 中声明的路径
	Path       string // 最终部署路径（server 加前缀后覆盖）
	FullMethod string
	API        string
	Exposure   policy.Exposure
	Label      string
	Source     string // "proto" / "extra"
}

// Surface 是不可变接口面。
type Surface struct {
	ops []Operation
	set *policy.Set
}

// Build 从文件描述符收集 service 并构建 Surface。
func Build(files []protoreflect.FileDescriptor, set *policy.Set) (*Surface, error) {
	if set == nil {
		return nil, fmt.Errorf("surface: policy.Set is nil")
	}
	seen := make(map[protoreflect.FullName]struct{})
	var services []protoreflect.ServiceDescriptor
	for _, fd := range files {
		if fd == nil {
			continue
		}
		ss := fd.Services()
		for i := 0; i < ss.Len(); i++ {
			sd := ss.Get(i)
			if _, dup := seen[sd.FullName()]; dup {
				continue
			}
			seen[sd.FullName()] = struct{}{}
			services = append(services, sd)
		}
	}
	return BuildFromServices(services, set)
}

// BuildFromServices 从 service 描述符构建 Surface（server.New 用）。
func BuildFromServices(services []protoreflect.ServiceDescriptor, set *policy.Set) (*Surface, error) {
	if set == nil {
		return nil, fmt.Errorf("surface: policy.Set is nil")
	}
	var (
		ops     []Operation
		seenSvc = make(map[protoreflect.FullName]struct{})
		route   = make(map[string]string)
	)
	for _, sd := range services {
		if sd == nil {
			continue
		}
		if _, dup := seenSvc[sd.FullName()]; dup {
			continue
		}
		seenSvc[sd.FullName()] = struct{}{}
		methods := sd.Methods()
		for i := 0; i < methods.Len(); i++ {
			md := methods.Get(i)
			fullMethod := "/" + string(sd.FullName()) + "/" + string(md.Name())
			op, ok := set.Get(fullMethod)
			if !ok {
				return nil, fmt.Errorf("surface: method %s has no policy", fullMethod)
			}
			bindings, err := bindingsOf(md)
			if err != nil {
				return nil, fmt.Errorf("surface: method %s: %w", fullMethod, err)
			}
			if err := validateExposure(fullMethod, md, op.Exposure, bindings); err != nil {
				return nil, err
			}
			for _, b := range bindings {
				key := b.Verb + " " + b.Path
				if other, dup := route[key]; dup {
					return nil, fmt.Errorf("surface: duplicate HTTP route %s between %s and %s", key, other, fullMethod)
				}
				route[key] = fullMethod
			}
			ops = append(ops, Operation{
				Operation:  op,
				Service:    sd,
				Descriptor: md,
				Input:      md.Input(),
				Output:     md.Output(),
				HTTP:       bindings,
				Streaming:  md.IsStreamingClient() || md.IsStreamingServer(),
			})
		}
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].Operation.ID < ops[j].Operation.ID })
	return &Surface{ops: ops, set: set}, nil
}

func validateExposure(fullMethod string, md protoreflect.MethodDescriptor, exposure policy.Exposure, bindings []HTTPBinding) error {
	switch exposure {
	case policy.ExposurePublic, policy.ExposureDeprecated:
		if len(bindings) == 0 {
			return fmt.Errorf("surface: method %s is %s but has no google.api.http binding", fullMethod, exposure)
		}
	case policy.ExposureInternal:
		if len(bindings) > 0 {
			return fmt.Errorf("surface: method %s is INTERNAL but declares google.api.http", fullMethod)
		}
	case policy.ExposureHidden:
		// 可有/可无 HTTP；但要遵守流式约束。
	default:
		return fmt.Errorf("surface: method %s has unspecified exposure", fullMethod)
	}
	if len(bindings) > 0 && md.IsStreamingClient() {
		return fmt.Errorf("surface: method %s is client/bidi streaming and cannot be exposed over grpc-gateway", fullMethod)
	}
	return nil
}

func bindingsOf(md protoreflect.MethodDescriptor) ([]HTTPBinding, error) {
	opts := md.Options()
	if opts == nil {
		return nil, nil
	}
	ext := proto.GetExtension(opts, annotations.E_Http)
	rule, ok := ext.(*annotations.HttpRule)
	if !ok || rule == nil {
		return nil, nil
	}
	out := make([]HTTPBinding, 0, 1+len(rule.GetAdditionalBindings()))
	main, err := bindingOf(rule, 0)
	if err != nil {
		return nil, err
	}
	out = append(out, main)
	for i, add := range rule.GetAdditionalBindings() {
		b, err := bindingOf(add, i+1)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

func bindingOf(rule *annotations.HttpRule, index int) (HTTPBinding, error) {
	if rule == nil {
		return HTTPBinding{}, fmt.Errorf("nil http rule")
	}
	b := HTTPBinding{Body: rule.GetBody(), ResponseBody: rule.GetResponseBody(), BindingIndex: index}
	switch p := rule.GetPattern().(type) {
	case *annotations.HttpRule_Get:
		b.Verb, b.Path = "GET", p.Get
	case *annotations.HttpRule_Post:
		b.Verb, b.Path = "POST", p.Post
	case *annotations.HttpRule_Put:
		b.Verb, b.Path = "PUT", p.Put
	case *annotations.HttpRule_Delete:
		b.Verb, b.Path = "DELETE", p.Delete
	case *annotations.HttpRule_Patch:
		b.Verb, b.Path = "PATCH", p.Patch
	case *annotations.HttpRule_Custom:
		b.Verb = strings.ToUpper(p.Custom.GetKind())
		b.Path = p.Custom.GetPath()
	default:
		return HTTPBinding{}, fmt.Errorf("http rule has no pattern")
	}
	if b.Path == "" {
		return HTTPBinding{}, fmt.Errorf("http rule has empty path")
	}
	b.Path = NormalizePath(b.Path)
	return b, nil
}

// NormalizePath 折叠重复斜杠、去尾斜杠（根路径除外）。
func NormalizePath(path string) string {
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	for strings.Contains(path, "//") {
		path = strings.ReplaceAll(path, "//", "/")
	}
	if len(path) > 1 {
		path = strings.TrimRight(path, "/")
		if path == "" {
			return "/"
		}
	}
	return path
}

// Operations 返回全部 operation（副本）。
func (s *Surface) Operations() []Operation {
	if s == nil {
		return nil
	}
	out := make([]Operation, len(s.ops))
	copy(out, s.ops)
	return out
}

// OperationsByAPI 返回指定 API 面的 operation。
func (s *Surface) OperationsByAPI(api string) []Operation {
	if s == nil {
		return nil
	}
	var out []Operation
	for _, op := range s.ops {
		if op.Operation.API == api {
			out = append(out, op)
		}
	}
	return out
}

// Services 返回去重后的 service 描述符（按全名排序）。
func (s *Surface) Services() []protoreflect.ServiceDescriptor {
	if s == nil {
		return nil
	}
	seen := make(map[protoreflect.FullName]struct{})
	var out []protoreflect.ServiceDescriptor
	for _, op := range s.ops {
		if _, dup := seen[op.Service.FullName()]; dup {
			continue
		}
		seen[op.Service.FullName()] = struct{}{}
		out = append(out, op.Service)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FullName() < out[j].FullName() })
	return out
}

// Policy 返回构建 Surface 时使用的策略集。
func (s *Surface) Policy() *policy.Set {
	if s == nil {
		return nil
	}
	return s.set
}

// Routes 返回 proto 路由表（最终路径 = proto 路径；server 负责加前缀）。
func (s *Surface) Routes() []RouteInfo {
	if s == nil {
		return nil
	}
	var out []RouteInfo
	for _, op := range s.ops {
		for _, b := range op.HTTP {
			out = append(out, RouteInfo{
				ID:         op.Operation.ID,
				Method:     b.Verb,
				ProtoPath:  b.Path,
				Path:       b.Path,
				FullMethod: op.Operation.ID,
				API:        op.Operation.API,
				Exposure:   op.Operation.Exposure,
				Label:      op.Operation.EffectiveLabel(),
				Source:     "proto",
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out
}
