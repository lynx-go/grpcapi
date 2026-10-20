// Package protopolicy 是 policy.Provider 的默认实现：读取 grpcapi.v1
// (policy.proto) 的文件/服务/方法扩展。
package protopolicy

import (
	"fmt"

	grpcapiv1 "github.com/lynx-go/grpcapi/genproto/grpcapi/v1"
	"github.com/lynx-go/grpcapi/policy"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Options 是默认 Provider 的配置。
type Options struct {
	// AllowUnknownFields 默认 false：扩展消息含未知字段时构建失败，
	// 防止「新字段 + 旧库 = 权限静默变宽」。
	AllowUnknownFields bool
}

type provider struct {
	opts Options
}

// New 构造默认 Provider。
func New(opts Options) policy.Provider {
	return &provider{opts: opts}
}

func (p *provider) File(fd protoreflect.FileDescriptor) (policy.FileSpec, bool, error) {
	opts := fd.Options()
	if opts == nil {
		return policy.FileSpec{}, false, nil
	}
	ext := proto.GetExtension(opts, grpcapiv1.E_Api)
	spec, ok := ext.(*grpcapiv1.APISpec)
	if !ok || spec == nil {
		return policy.FileSpec{}, false, nil
	}
	if err := p.checkUnknown("file "+fd.Path(), spec); err != nil {
		return policy.FileSpec{}, false, err
	}
	return policy.FileSpec{
		API:             spec.GetApi(),
		SchemaVersion:   spec.GetSchemaVersion(),
		DefaultPolicy:   convertPolicy(spec.GetDefaultPolicy()),
		DefaultExposure: convertExposure(spec.GetDefaultExposure()),
	}, true, nil
}

func (p *provider) Service(sd protoreflect.ServiceDescriptor) (policy.ServiceSpec, bool, error) {
	opts := sd.Options()
	if opts == nil {
		return policy.ServiceSpec{}, false, nil
	}
	ext := proto.GetExtension(opts, grpcapiv1.E_Service)
	spec, ok := ext.(*grpcapiv1.ServiceSpec)
	if !ok || spec == nil {
		return policy.ServiceSpec{}, false, nil
	}
	if err := p.checkUnknown("service "+string(sd.FullName()), spec); err != nil {
		return policy.ServiceSpec{}, false, err
	}
	return policy.ServiceSpec{
		DefaultPolicy:   convertPolicy(spec.GetDefaultPolicy()),
		DefaultExposure: convertExposure(spec.GetDefaultExposure()),
		Label:           spec.GetLabel(),
	}, true, nil
}

func (p *provider) Method(md protoreflect.MethodDescriptor) (policy.MethodSpec, bool, error) {
	opts := md.Options()
	if opts == nil {
		return policy.MethodSpec{}, false, nil
	}
	ext := proto.GetExtension(opts, grpcapiv1.E_Method)
	spec, ok := ext.(*grpcapiv1.MethodSpec)
	if !ok || spec == nil {
		return policy.MethodSpec{}, false, nil
	}
	if err := p.checkUnknown("method "+string(md.FullName()), spec); err != nil {
		return policy.MethodSpec{}, false, err
	}
	return policy.MethodSpec{
		Policy:         convertPolicy(spec.GetPolicy()),
		Exposure:       convertExposure(spec.GetExposure()),
		Label:          spec.GetLabel(),
		OperationID:    spec.GetOperationId(),
		InheritDefault: spec.GetInheritDefault(),
		StreamAuth:     convertStreamAuth(spec.GetStreamAuth()),
	}, true, nil
}

func (p *provider) checkUnknown(where string, m proto.Message) error {
	if p.opts.AllowUnknownFields || m == nil {
		return nil
	}
	if raw := m.ProtoReflect().GetUnknown(); len(raw) > 0 {
		return fmt.Errorf("%s: policy extension has %d unknown field byte(s); upgrade grpcapi or regenerate proto", where, len(raw))
	}
	return nil
}

func convertPolicy(in *grpcapiv1.Policy) *policy.Policy {
	if in == nil {
		return nil
	}
	out := &policy.Policy{
		Preset:     in.GetPreset(),
		PresetArgs: cloneStringMap(in.GetPresetArgs()),
		Anonymous:  in.GetAnonymous(),
	}
	if in.GetAuthenticated() {
		out.Require = append(out.Require, policy.Requirement{Kind: "authenticated"})
	}
	if roles := in.GetRoles(); len(roles) > 0 {
		out.Require = append(out.Require, policy.Requirement{Kind: "role", Match: policy.MatchAny, Values: append([]string(nil), roles...)})
	}
	if perms := in.GetPermissions(); len(perms) > 0 {
		out.Require = append(out.Require, policy.Requirement{Kind: "permission", Match: policy.MatchAll, Values: append([]string(nil), perms...)})
	}
	if scopes := in.GetScopes(); len(scopes) > 0 {
		out.Require = append(out.Require, policy.Requirement{Kind: "scope", Match: policy.MatchAny, Values: append([]string(nil), scopes...)})
	}
	for _, r := range in.GetRequire() {
		out.Require = append(out.Require, convertRequirement(r))
	}
	for _, alt := range in.GetAnyOf() {
		out.AnyOf = append(out.AnyOf, convertAlternative(alt))
	}
	for _, r := range in.GetForbid() {
		out.Forbid = append(out.Forbid, convertRequirement(r))
	}
	return out
}

func convertAlternative(in *grpcapiv1.Alternative) []policy.Requirement {
	if in == nil {
		return nil
	}
	var out []policy.Requirement
	if in.GetAuthenticated() {
		out = append(out, policy.Requirement{Kind: "authenticated"})
	}
	if roles := in.GetRoles(); len(roles) > 0 {
		out = append(out, policy.Requirement{Kind: "role", Match: policy.MatchAny, Values: append([]string(nil), roles...)})
	}
	if perms := in.GetPermissions(); len(perms) > 0 {
		out = append(out, policy.Requirement{Kind: "permission", Match: policy.MatchAll, Values: append([]string(nil), perms...)})
	}
	if scopes := in.GetScopes(); len(scopes) > 0 {
		out = append(out, policy.Requirement{Kind: "scope", Match: policy.MatchAny, Values: append([]string(nil), scopes...)})
	}
	for _, r := range in.GetRequire() {
		out = append(out, convertRequirement(r))
	}
	return out
}

func convertRequirement(in *grpcapiv1.Requirement) policy.Requirement {
	if in == nil {
		return policy.Requirement{}
	}
	return policy.Requirement{
		Kind:       in.GetKind(),
		Vocabulary: in.GetVocabulary(),
		Match:      convertMatch(in.GetMatch()),
		Values:     append([]string(nil), in.GetValues()...),
		Params:     cloneStringMap(in.GetParams()),
	}
}

func convertMatch(in grpcapiv1.Match) policy.Match {
	switch in {
	case grpcapiv1.Match_MATCH_ANY:
		return policy.MatchAny
	case grpcapiv1.Match_MATCH_ALL:
		return policy.MatchAll
	default:
		return policy.MatchDefault
	}
}

func convertExposure(in grpcapiv1.Exposure) policy.Exposure {
	switch in {
	case grpcapiv1.Exposure_EXPOSURE_INTERNAL:
		return policy.ExposureInternal
	case grpcapiv1.Exposure_EXPOSURE_PUBLIC:
		return policy.ExposurePublic
	case grpcapiv1.Exposure_EXPOSURE_DEPRECATED:
		return policy.ExposureDeprecated
	case grpcapiv1.Exposure_EXPOSURE_HIDDEN:
		return policy.ExposureHidden
	default:
		return policy.ExposureUnspecified
	}
}

func convertStreamAuth(in grpcapiv1.StreamAuthMode) policy.StreamAuthMode {
	switch in {
	case grpcapiv1.StreamAuthMode_STREAM_AUTH_MODE_PER_MESSAGE:
		return policy.StreamAuthPerMessage
	case grpcapiv1.StreamAuthMode_STREAM_AUTH_MODE_OPEN:
		return policy.StreamAuthOpen
	default:
		return 0
	}
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
