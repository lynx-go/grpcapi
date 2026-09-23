package authz

import (
	"fmt"
	"sort"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	grpcapiv1 "github.com/lynx-go/grpcapi/genproto/grpcapi/v1"
)

// Options 是 Build 的可选项。
type Options struct {
	// Vocabulary 是项目注册的 scope 资源词表（必填防线：存在 scope 声明而
	// 词表为空 → 构造失败）。
	Vocabulary Vocabulary
	// AllowStreaming 放行流式方法（v1 默认 false：流式 fail-closed，
	// 见 DESIGN.md §9）。
	AllowStreaming bool
	// Assertions 是项目断言钩子（值域白名单、面前缀、不变量等），先逐方法
	// 再逐集合求值，违例聚合进同一 error。
	Assertions []Assertion
}

// Build 从 proto 文件描述符集合构造全量策略注册表。method_auth 优先，access
// 缺省回落 service_auth.default_access；细粒度字段 permissions/admin_roles/
// api_key_scope 仅来自 method_auth（服务级不携带）。END_USER 面权限不做
// 归一化（归一化是项目策略，经 Assertion 钩子注入）。
//
// 内置断言全部 fail-closed 且不可关闭，全部违例聚合为单一 error：
//
//  1. 方法 access 未声明（无 method_auth 且服务无 default_access，或显式
//     UNSPECIFIED）；
//  2. SERVER 面未声明 api_key_scope；
//  3. PERMISSION 面未声明 permissions；
//  4. SYSTEM 档位（v1 禁用）；
//  5. 词表为空但存在 scope 声明（fail-open 防线）；
//  6. scope 资源不在词表（逐条指出）；
//  7. scope 方向未登记；
//  8. 死 scope（词表资源无任何方法引用）；
//  9. 流式方法（除非 AllowStreaming）；
//  10. 项目 Assertions（逐方法、再逐集合）。
//
// 任一断言违例时返回 (nil, err)；仅在全部通过时返回 PolicySet。
func Build(files []protoreflect.FileDescriptor, opts Options) (*PolicySet, error) {
	var (
		policies    []MethodPolicy
		collectErrs []error
	)
	for _, fd := range files {
		if fd == nil {
			continue
		}
		services := fd.Services()
		for i := 0; i < services.Len(); i++ {
			ps, errs := collectService(services.Get(i))
			policies = append(policies, ps...)
			collectErrs = append(collectErrs, errs...)
		}
	}
	set, err := NewPolicySet(policies...)
	if err != nil {
		return nil, fmt.Errorf("build authz policy set: %w", err)
	}
	if err := assertSet(set, opts, collectErrs); err != nil {
		return nil, err
	}
	return set, nil
}

// collectService 收集单个 service 的全部方法策略。收集本身不中断——枚举映射
// 失败等收集级违例进错误清单，与其他违例一起聚合。
func collectService(service protoreflect.ServiceDescriptor) ([]MethodPolicy, []error) {
	var (
		policies []MethodPolicy
		errs     []error
	)
	serviceName := "/" + string(service.FullName())
	serviceDefault := serviceDefaultAccess(service)
	methods := service.Methods()
	for i := 0; i < methods.Len(); i++ {
		p, err := collectMethod(serviceName, methods.Get(i), serviceDefault)
		if err != nil {
			errs = append(errs, err)
		}
		policies = append(policies, p)
	}
	return policies, errs
}

// collectMethod 解析单个方法策略。proto 是策略唯一声明源：method_auth 优先，
// access 缺省回落 service_auth.default_access（method_auth 携带显式
// UNSPECIFIED 亦回落，与 access 之外的细粒度字段无关）。
func collectMethod(serviceName string, method protoreflect.MethodDescriptor, serviceDefault grpcapiv1.AccessLevel) (MethodPolicy, error) {
	p := MethodPolicy{
		Method:        serviceName + "/" + string(method.Name()),
		Service:       serviceName,
		IsStreaming:   method.IsStreamingClient() || method.IsStreamingServer(),
		RequestFields: requestFields(method),
	}
	auth := methodAuthOption(method)
	access := serviceDefault
	if auth != nil && auth.GetAccess() != grpcapiv1.AccessLevel_ACCESS_LEVEL_UNSPECIFIED {
		access = auth.GetAccess()
	}
	level, ok := accessLevelFromProto(access)
	p.Access = level
	if !ok {
		return p, fmt.Errorf("method %s: access level %d is not registered", p.Method, int32(access))
	}
	if auth == nil {
		return p, nil
	}
	p.Permissions = append([]string(nil), auth.GetPermissions()...)
	p.AdminRoles = append([]string(nil), auth.GetAdminRoles()...)
	if scope := auth.GetApiKeyScope(); scope != nil {
		p.Scope = &ScopeRule{
			Resource: scope.GetResource(),
			Op:       scopeOpFromProto(scope.GetOp()),
		}
	}
	return p, nil
}

// methodAuthOption 读取方法上的 method_auth 扩展（未设置返回 nil）。
func methodAuthOption(method protoreflect.MethodDescriptor) *grpcapiv1.MethodAuth {
	opts := method.Options()
	if opts == nil {
		return nil
	}
	ext := proto.GetExtension(opts, grpcapiv1.E_MethodAuth)
	ma, ok := ext.(*grpcapiv1.MethodAuth)
	if !ok || ma == nil {
		return nil
	}
	return ma
}

// ServiceDefaultAccess 读取 service_auth.default_access（未设置返回
// AccessUnspecified，由断言层报缺失）。供 guard.SwaggerAccessMatches 的
// ServiceAccess 回调等镜像消费点直接复用，避免各项目重写扩展解析
// （lynx-clean-template 接入时发现的 API 缺口）。未登记枚举值返回
// false——调用方应 fail-closed。
func ServiceDefaultAccess(service protoreflect.ServiceDescriptor) (AccessLevel, bool) {
	return accessLevelFromProto(serviceDefaultAccess(service))
}

// serviceDefaultAccess 读取 service_auth.default_access（未设置返回
// UNSPECIFIED，由断言层报缺失）。
func serviceDefaultAccess(service protoreflect.ServiceDescriptor) grpcapiv1.AccessLevel {
	opts := service.Options()
	if opts == nil {
		return grpcapiv1.AccessLevel_ACCESS_LEVEL_UNSPECIFIED
	}
	ext := proto.GetExtension(opts, grpcapiv1.E_ServiceAuth)
	sa, ok := ext.(*grpcapiv1.ServiceAuth)
	if !ok || sa == nil {
		return grpcapiv1.AccessLevel_ACCESS_LEVEL_UNSPECIFIED
	}
	return sa.GetDefaultAccess()
}

// accessLevelFromProto 将 proto AccessLevel 按编号转为本包枚举（两者编号一
// 一对应）。未登记值（超出枚举登记范围）返回 false——fail-closed，经收集
// 错误聚合。
func accessLevelFromProto(l grpcapiv1.AccessLevel) (AccessLevel, bool) {
	switch l {
	case grpcapiv1.AccessLevel_ACCESS_LEVEL_UNSPECIFIED:
		return AccessUnspecified, true
	case grpcapiv1.AccessLevel_ACCESS_LEVEL_PUBLIC:
		return AccessPublic, true
	case grpcapiv1.AccessLevel_ACCESS_LEVEL_END_USER:
		return AccessEndUser, true
	case grpcapiv1.AccessLevel_ACCESS_LEVEL_SERVER:
		return AccessServer, true
	case grpcapiv1.AccessLevel_ACCESS_LEVEL_PERMISSION:
		return AccessPermission, true
	case grpcapiv1.AccessLevel_ACCESS_LEVEL_SYSTEM:
		return AccessSystem, true
	default:
		return AccessUnspecified, false
	}
}

// scopeOpFromProto 映射 proto ScopeOp → 本包 ScopeOp；未登记值返回空串
// （空串经词表断言 fail-closed 拒绝）。
func scopeOpFromProto(op grpcapiv1.ScopeOp) ScopeOp {
	switch op {
	case grpcapiv1.ScopeOp_SCOPE_OP_READ:
		return ScopeRead
	case grpcapiv1.ScopeOp_SCOPE_OP_WRITE:
		return ScopeWrite
	case grpcapiv1.ScopeOp_SCOPE_OP_ADMIN:
		return ScopeAdmin
	default:
		return ""
	}
}

// requestFields 返回请求消息全部字段名，字典序（排序投影）。
func requestFields(method protoreflect.MethodDescriptor) []string {
	input := method.Input()
	if input == nil {
		return nil
	}
	fields := input.Fields()
	names := make([]string, 0, fields.Len())
	for i := 0; i < fields.Len(); i++ {
		names = append(names, string(fields.Get(i).Name()))
	}
	sort.Strings(names)
	return names
}
