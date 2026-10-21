package policy

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// Options 是 Build 的输入。
type Options struct {
	// Provider 必填：策略来源（默认 protopolicy 读 grpcapi.v1 扩展）。
	Provider Provider
	// Registry 为空时使用 DefaultRegistry()。
	Registry *Registry
	// Vocabulary 是项目词表；nil = 空。
	Vocabulary Vocabulary
	// Presets 是项目命名策略宏。
	Presets []Preset
	// DisableStreaming 为 true 时流式方法构建失败；零值 = 允许。
	DisableStreaming bool
	// Rules 是项目断言钩子。
	Rules []Rule
	// FrameworkExempt 为空时使用 DefaultFrameworkExempt。
	FrameworkExempt func(fullMethod string) bool
	// APIResolver 在 FileSpec.API 为空时按文件推断 API 面。
	APIResolver func(protoreflect.FileDescriptor) string
	// IncludeServices 非空时只构建这些 service。
	IncludeServices []protoreflect.FullName
	// PackagePrefixes 非空时只构建这些 proto package 下的文件。
	PackagePrefixes []string
	// MaxSchemaVersion 默认 1；FileSpec.SchemaVersion 更高时失败。
	MaxSchemaVersion uint32
}

// DefaultFrameworkPrefixes 是不参与业务策略的 gRPC 框架服务。
var DefaultFrameworkPrefixes = []string{
	"grpc.health.v1.",
	"grpc.reflection.",
	"grpc.channelz.v1.",
}

// DefaultFrameworkExempt 判断 fullMethod（"/pkg.Svc/Method"）是否属于框架服务。
func DefaultFrameworkExempt(fullMethod string) bool {
	for _, prefix := range DefaultFrameworkPrefixes {
		if strings.HasPrefix(fullMethod, "/"+prefix) {
			return true
		}
	}
	return false
}

// Validate 用默认 registry 校验单个有效策略（手工构造/ExtraRoute 用）。
func Validate(p Policy) error {
	return ValidateWith(p, DefaultRegistry(), nil)
}

// ValidateWith 用指定 registry/词表校验单个有效策略。
func ValidateWith(p Policy, reg *Registry, vocab Vocabulary) error {
	if reg == nil {
		reg = DefaultRegistry()
	}
	if errs := validatePolicy("policy", p, reg, vocab); len(errs) > 0 {
		return Violations(errs)
	}
	return nil
}

// ValidMatch 报告 Match 是否为已登记值。
func ValidMatch(m Match) bool {
	return m >= MatchDefault && m <= MatchAll
}

// Violations 是聚合的构建错误。
type Violations []error

func (v Violations) Error() string {
	msgs := make([]string, 0, len(v))
	for _, err := range v {
		msgs = append(msgs, err.Error())
	}
	return fmt.Sprintf("policy build failed, %d violation(s):\n  - %s", len(v), strings.Join(msgs, "\n  - "))
}

// Unwrap 支持 errors.Is/As 遍历全部违例。
func (v Violations) Unwrap() []error { return []error(v) }

// Build 从 Source + Provider 构建不可变策略表。所有违例聚合为 Violations。
func Build(ctx context.Context, src Source, opts Options) (*Set, error) {
	if src == nil {
		return nil, fmt.Errorf("policy: Source is nil")
	}
	if opts.Provider == nil {
		return nil, fmt.Errorf("policy: Options.Provider is required (use policy/protopolicy for grpcapi.v1 annotations)")
	}
	if opts.Registry == nil {
		opts.Registry = DefaultRegistry()
	}
	presets, err := newPresetSet(opts.Presets)
	if err != nil {
		return nil, err
	}
	frameworkExempt := opts.FrameworkExempt
	if frameworkExempt == nil {
		frameworkExempt = DefaultFrameworkExempt
	}
	maxVersion := opts.MaxSchemaVersion
	if maxVersion == 0 {
		maxVersion = 1
	}
	include := make(map[protoreflect.FullName]struct{}, len(opts.IncludeServices))
	for _, name := range opts.IncludeServices {
		include[name] = struct{}{}
	}

	files, err := src.Files(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy: load source: %w", err)
	}
	files = dedupeFiles(files)

	var (
		ops        []Operation
		violations []error
		seenVer    uint32
	)
	for _, fd := range files {
		if fd == nil {
			continue
		}
		if len(opts.PackagePrefixes) > 0 && !packageUnderAny(string(fd.Package()), opts.PackagePrefixes) {
			continue
		}
		fs, ok, ferr := opts.Provider.File(fd)
		if ferr != nil {
			violations = append(violations, fmt.Errorf("file %s: %w", fd.Path(), ferr))
			continue
		}
		if !ok {
			fs = FileSpec{}
		}
		ver := fs.SchemaVersion
		if ver == 0 {
			ver = 1
		}
		if seenVer == 0 {
			seenVer = ver
		} else if seenVer != ver {
			violations = append(violations, fmt.Errorf("file %s: schema_version %d differs from %d", fd.Path(), ver, seenVer))
		}
		if ver > maxVersion {
			violations = append(violations, fmt.Errorf("file %s: schema_version %d exceeds supported %d", fd.Path(), ver, maxVersion))
		}
		api := fs.API
		if api == "" && opts.APIResolver != nil {
			api = opts.APIResolver(fd)
		}

		services := fd.Services()
		for i := 0; i < services.Len(); i++ {
			sd := services.Get(i)
			if frameworkExempt("/" + string(sd.FullName()) + "/") {
				continue
			}
			if len(include) > 0 {
				if _, ok := include[sd.FullName()]; !ok {
					continue
				}
			}
			ss, ok, serr := opts.Provider.Service(sd)
			if serr != nil {
				violations = append(violations, fmt.Errorf("service %s: %w", sd.FullName(), serr))
				continue
			}
			if !ok {
				ss = ServiceSpec{}
			}
			defaultPolicy := ss.DefaultPolicy
			if defaultPolicy == nil {
				defaultPolicy = fs.DefaultPolicy
			}
			defaultExposure := ss.DefaultExposure
			if defaultExposure == ExposureUnspecified {
				defaultExposure = fs.DefaultExposure
			}

			methods := sd.Methods()
			for j := 0; j < methods.Len(); j++ {
				md := methods.Get(j)
				fullMethod := "/" + string(sd.FullName()) + "/" + string(md.Name())
				if frameworkExempt(fullMethod) {
					continue
				}
				op, errs := buildOperation(sd, md, api, fullMethod, defaultPolicy, defaultExposure, opts, presets)
				violations = append(violations, errs...)
				if len(errs) == 0 {
					ops = append(ops, op)
				}
			}
		}
	}

	set, err := newSet(opts.Registry, opts.Vocabulary, ops...)
	if err != nil {
		return nil, err
	}
	for _, rule := range opts.Rules {
		if rule == nil {
			continue
		}
		for _, op := range set.Operations() {
			if err := rule.CheckOperation(op); err != nil {
				violations = append(violations, fmt.Errorf("rule %s: operation %s: %w", rule.Name(), op.ID, err))
			}
		}
		if err := rule.CheckSet(set); err != nil {
			violations = append(violations, fmt.Errorf("rule %s: %w", rule.Name(), err))
		}
	}
	if len(violations) > 0 {
		return nil, Violations(violations)
	}
	return set, nil
}

func buildOperation(
	sd protoreflect.ServiceDescriptor,
	md protoreflect.MethodDescriptor,
	api, fullMethod string,
	defaultPolicy *Policy,
	defaultExposure Exposure,
	opts Options,
	presets presetSet,
) (Operation, []error) {
	var violations []error

	ms, ok, err := opts.Provider.Method(md)
	if err != nil {
		return Operation{}, []error{fmt.Errorf("method %s: %w", fullMethod, err)}
	}
	if !ok {
		ms = MethodSpec{}
	}

	var (
		defaultExpanded *Policy
		methodExpanded  *Policy
		expandErr       error
	)
	if defaultPolicy != nil {
		p, err := presets.expand(defaultPolicy.Clone(), nil)
		if err != nil {
			expandErr = err
		} else {
			defaultExpanded = &p
		}
	}
	if ms.Policy != nil {
		p, err := presets.expand(ms.Policy.Clone(), nil)
		if err != nil {
			expandErr = err
		} else {
			methodExpanded = &p
		}
	}

	var policy Policy
	switch {
	case ms.Policy != nil && ms.InheritDefault && defaultExpanded != nil && methodExpanded != nil:
		policy = andPolicy(*defaultExpanded, *methodExpanded)
	case ms.Policy != nil && methodExpanded != nil:
		policy = *methodExpanded
	case defaultExpanded != nil:
		policy = *defaultExpanded
	default:
		if expandErr == nil {
			violations = append(violations, fmt.Errorf("method %s: missing policy (no method policy and no service/file default)", fullMethod))
		}
	}

	presetName := ""
	if methodExpanded != nil {
		presetName = methodExpanded.Preset
	}
	if presetName == "" && defaultExpanded != nil {
		presetName = defaultExpanded.Preset
	}
	// 有效策略不保留 preset 元数据；校验前先清掉，否则 validatePolicy 会
	// 把已展开的策略误判为未展开。
	policy.Preset = ""
	policy.PresetArgs = nil
	if expandErr != nil {
		violations = append(violations, fmt.Errorf("method %s: %w", fullMethod, expandErr))
	} else {
		violations = append(violations, validatePolicy(fullMethod, policy, opts.Registry, opts.Vocabulary)...)
	}

	exposure := ms.Exposure
	if exposure == ExposureUnspecified {
		exposure = defaultExposure
	}
	if exposure == ExposureUnspecified {
		violations = append(violations, fmt.Errorf("method %s: missing exposure (no method/service/file exposure)", fullMethod))
	}

	streaming := md.IsStreamingClient() || md.IsStreamingServer()
	if streaming && opts.DisableStreaming {
		violations = append(violations, fmt.Errorf("method %s: streaming is disabled", fullMethod))
	}
	if streaming && (exposure == ExposurePublic || exposure == ExposureDeprecated) && md.IsStreamingClient() {
		violations = append(violations, fmt.Errorf("method %s: client/bidi streaming cannot be exposed over grpc-gateway; use EXPOSURE_INTERNAL/HIDDEN", fullMethod))
	}

	streamAuth := ms.StreamAuth
	if streamAuth == 0 {
		streamAuth = StreamAuthOpen
	}
	if streamAuth != StreamAuthOpen && streamAuth != StreamAuthPerMessage {
		violations = append(violations, fmt.Errorf("method %s: invalid stream auth mode %d", fullMethod, int(streamAuth)))
	}
	opID := ms.OperationID
	if opID == "" {
		opID = string(sd.Name()) + "_" + string(md.Name())
	}

	label := ms.Label
	if label == "" {
		label = presetName
	}
	var metadata map[string]string
	if presetName != "" {
		metadata = map[string]string{"preset": presetName}
	}
	op := Operation{
		ID:            fullMethod,
		Kind:          KindGRPC,
		Service:       string(sd.FullName()),
		API:           api,
		Policy:        policy,
		Exposure:      exposure,
		Label:         label,
		OperationID:   opID,
		Streaming:     streaming,
		StreamAuth:    streamAuth,
		RequestFields: requestFields(md),
		Metadata:      metadata,
	}
	return op, violations
}

func requestFields(md protoreflect.MethodDescriptor) []string {
	input := md.Input()
	if input == nil {
		return nil
	}
	fields := input.Fields()
	out := make([]string, 0, fields.Len())
	for i := 0; i < fields.Len(); i++ {
		out = append(out, string(fields.Get(i).Name()))
	}
	sort.Strings(out)
	return out
}

func packageUnderAny(pkg string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if nameUnderPrefix(pkg, prefix) {
			return true
		}
	}
	return false
}

func dedupeFiles(files []protoreflect.FileDescriptor) []protoreflect.FileDescriptor {
	seen := make(map[string]struct{}, len(files))
	out := make([]protoreflect.FileDescriptor, 0, len(files))
	for _, fd := range files {
		if fd == nil {
			continue
		}
		if _, dup := seen[fd.Path()]; dup {
			continue
		}
		seen[fd.Path()] = struct{}{}
		out = append(out, fd)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path() < out[j].Path() })
	return out
}

func andPolicy(base, extra Policy) Policy {
	out := Policy{
		Preset:     extra.Preset,
		PresetArgs: cloneStringMap(extra.PresetArgs),
		// AND：base 公开时，extra 只要没有正要求（require/any_of）就仍是
		// 公开 + 额外 forbid；extra 一旦要求认证，结果就必须要求认证。
		Anonymous: base.Anonymous && (extra.Anonymous || (len(extra.Require) == 0 && len(extra.AnyOf) == 0)),
		Require:   append(append([]Requirement(nil), base.Require...), extra.Require...),
		AnyOf:     append(append([][]Requirement(nil), base.AnyOf...), extra.AnyOf...),
		Forbid:    append(append([]Requirement(nil), base.Forbid...), extra.Forbid...),
	}
	return out
}

func validatePolicy(id string, p Policy, reg *Registry, vocab Vocabulary) []error {
	var errs []error
	if p.Preset != "" {
		errs = append(errs, fmt.Errorf("method %s: unexpanded preset %q (use Build or expand before authorizing)", id, p.Preset))
	}
	if p.Anonymous {
		if len(p.Require) > 0 || len(p.AnyOf) > 0 {
			errs = append(errs, fmt.Errorf("method %s: anonymous cannot be combined with require/any_of", id))
		}
	} else if len(p.Require) == 0 && len(p.AnyOf) == 0 {
		errs = append(errs, fmt.Errorf("method %s: empty policy (explicit anonymous or at least one requirement required)", id))
	}
	for _, r := range p.Require {
		errs = append(errs, validateRequirement(id, r, reg, vocab)...)
	}
	for i, group := range p.AnyOf {
		if len(group) == 0 {
			errs = append(errs, fmt.Errorf("method %s: any_of[%d] is empty (would be trivially true)", id, i))
			continue
		}
		for _, r := range group {
			errs = append(errs, validateRequirement(id, r, reg, vocab)...)
		}
	}
	for _, r := range p.Forbid {
		errs = append(errs, validateRequirement(id, r, reg, vocab)...)
	}
	return errs
}

func validateRequirement(id string, req Requirement, reg *Registry, vocab Vocabulary) []error {
	if !ValidMatch(req.Match) {
		return []error{fmt.Errorf("method %s: invalid requirement match value %d", id, int(req.Match))}
	}
	kind, ok := reg.Get(req.Kind)
	if !ok {
		return []error{fmt.Errorf("method %s: unknown requirement kind %q (registered: %s)", id, req.Kind, strings.Join(reg.Names(), ", "))}
	}
	req.Match = effectiveMatch(req, kind.DefaultMatch)
	domain := vocabularyDomain(req, kind)
	if kind.RequiresVocabulary && !vocab.Has(domain) {
		return []error{fmt.Errorf("method %s: %s requires vocabulary domain %q, but it is not registered", id, req.Kind, domain)}
	}
	if kind.Validate != nil {
		if err := kind.Validate(req, vocab); err != nil {
			return []error{fmt.Errorf("method %s: %w", id, err)}
		}
		return nil
	}
	if err := vocab.validateValues(req, domain); err != nil {
		return []error{fmt.Errorf("method %s: %w", id, err)}
	}
	return nil
}

func vocabularyDomain(req Requirement, kind RequirementKind) string {
	if req.Vocabulary != "" {
		return req.Vocabulary
	}
	if kind.Name == "claim" {
		if name := req.Params["name"]; name != "" {
			return "claim:" + name
		}
	}
	return kind.Name
}
