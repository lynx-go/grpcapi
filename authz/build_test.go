package authz

import (
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	grpcapiv1 "github.com/lynx-go/grpcapi/genproto/grpcapi/v1"

	// 真实 FileDescriptor 来源：buf 生成的测试夹具（注册进 protoregistry）。
	_ "github.com/lynx-go/grpcapi/authz/testdata"
)

const (
	fixturePath    = "fixture.proto"
	violationsPath = "violations.proto"
	plainPath      = "plain.proto"
)

// fixtureVocab 与夹具 scope 声明严格对齐：databases/storage 均被引用，无死 scope。
var fixtureVocab = Vocabulary{ScopeResources: []string{"databases", "storage"}}

func mustFile(t *testing.T, path string) protoreflect.FileDescriptor {
	t.Helper()
	fd, err := protoregistry.GlobalFiles.FindFileByPath(path)
	if err != nil {
		t.Fatalf("protoregistry.GlobalFiles.FindFileByPath(%q): %v", path, err)
	}
	return fd
}

// mustBuild 构造失败即 Fatal（合法面测试用）。
func mustBuild(t *testing.T, paths []string, opts Options) *PolicySet {
	t.Helper()
	files := make([]protoreflect.FileDescriptor, 0, len(paths))
	for _, p := range paths {
		files = append(files, mustFile(t, p))
	}
	set, err := Build(files, opts)
	if err != nil {
		t.Fatalf("Build(%v): %v", paths, err)
	}
	return set
}

// wantBuildError 断言构造失败且聚合 error 包含全部期望子串。
func wantBuildError(t *testing.T, paths []string, opts Options, wants []string) {
	t.Helper()
	files := make([]protoreflect.FileDescriptor, 0, len(paths))
	for _, p := range paths {
		files = append(files, mustFile(t, p))
	}
	set, err := Build(files, opts)
	if err == nil {
		t.Fatalf("Build(%v) = success, want error", paths)
	}
	if set != nil {
		t.Fatalf("Build(%v) 违例时必须返回 nil 集合，got %+v", paths, set)
	}
	for _, want := range wants {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("aggregated error must contain %q\ngot: %v", want, err)
		}
	}
}

func TestBuildFixtureGoldenMethods(t *testing.T) {
	set := mustBuild(t, []string{fixturePath}, Options{Vocabulary: fixtureVocab, AllowStreaming: true})

	want := []string{
		"/grpcapi.authz.testdata.v1.FixturePermissionService/PurgeItems",
		"/grpcapi.authz.testdata.v1.FixturePriorityService/GetItem",
		"/grpcapi.authz.testdata.v1.FixturePriorityService/ListItems",
		"/grpcapi.authz.testdata.v1.FixturePublicService/Ping",
		"/grpcapi.authz.testdata.v1.FixtureServerService/CreateItem",
		"/grpcapi.authz.testdata.v1.FixtureServerService/DeleteItem",
		"/grpcapi.authz.testdata.v1.FixtureStreamService/WatchItems",
	}
	methods := set.Methods()
	if len(methods) != len(want) {
		t.Fatalf("Methods() len = %d, want %d", len(methods), len(want))
	}
	for i, p := range methods {
		if p.Method != want[i] {
			t.Fatalf("Methods()[%d] = %s, want %s", i, p.Method, want[i])
		}
	}
}

func TestBuildFixtureMethodAuthOverridesServiceDefault(t *testing.T) {
	set := mustBuild(t, []string{fixturePath}, Options{Vocabulary: fixtureVocab, AllowStreaming: true})

	// method_auth 优先：服务缺省 END_USER 被方法级 SERVER 覆盖。
	p, ok := set.Get("/grpcapi.authz.testdata.v1.FixturePriorityService/GetItem")
	if !ok {
		t.Fatal("GetItem not found")
	}
	if p.Access != AccessServer {
		t.Fatalf("GetItem.Access = %v, want AccessServer（method_auth 必须覆盖 service 缺省档）", p.Access)
	}
	if p.Service != "/grpcapi.authz.testdata.v1.FixturePriorityService" {
		t.Fatalf("GetItem.Service = %q", p.Service)
	}
	if !reflect.DeepEqual(p.AdminRoles, []string{"admin", "owner"}) {
		t.Fatalf("GetItem.AdminRoles = %v, want [admin owner]", p.AdminRoles)
	}
	if p.Scope == nil || *p.Scope != (ScopeRule{Resource: "databases", Op: ScopeRead}) {
		t.Fatalf("GetItem.Scope = %+v, want {databases read}", p.Scope)
	}

	// scope 访问器只对 SERVER 面开放。
	if rule := set.ScopeRule("/grpcapi.authz.testdata.v1.FixturePriorityService/GetItem"); rule == nil || rule.Op != ScopeRead {
		t.Fatalf("ScopeRule(GetItem) = %+v", rule)
	}
}

func TestBuildFixtureServiceFallback(t *testing.T) {
	set := mustBuild(t, []string{fixturePath}, Options{Vocabulary: fixtureVocab, AllowStreaming: true})

	// 无 method_auth，回落 service_auth.default_access（END_USER）；
	// permissions 保持为空——归一化是项目策略，不进库。
	p, ok := set.Get("/grpcapi.authz.testdata.v1.FixturePriorityService/ListItems")
	if !ok {
		t.Fatal("ListItems not found")
	}
	if p.Access != AccessEndUser {
		t.Fatalf("ListItems.Access = %v, want AccessEndUser（service_auth 回落）", p.Access)
	}
	if len(p.Permissions) != 0 {
		t.Fatalf("ListItems.Permissions = %v, want empty（不归一化）", p.Permissions)
	}
	if p.Scope != nil {
		t.Fatalf("ListItems.Scope = %+v, want nil", p.Scope)
	}
}

func TestBuildFixturePolicyProjection(t *testing.T) {
	set := mustBuild(t, []string{fixturePath}, Options{Vocabulary: fixtureVocab, AllowStreaming: true})

	p, _ := set.Get("/grpcapi.authz.testdata.v1.FixtureServerService/CreateItem")
	if p.Access != AccessServer {
		t.Fatalf("CreateItem.Access = %v", p.Access)
	}
	if !reflect.DeepEqual(p.AdminRoles, []string{"member", "admin", "owner"}) {
		t.Fatalf("CreateItem.AdminRoles = %v", p.AdminRoles)
	}
	if p.Scope == nil || *p.Scope != (ScopeRule{Resource: "storage", Op: ScopeWrite}) {
		t.Fatalf("CreateItem.Scope = %+v, want {storage write}", p.Scope)
	}
	// RequestFields 是输入消息全部字段名的字典序投影（声明乱序）。
	if want := []string{"item_id", "project_id", "tags"}; !reflect.DeepEqual(p.RequestFields, want) {
		t.Fatalf("CreateItem.RequestFields = %v, want %v", p.RequestFields, want)
	}
	if p.IsStreaming {
		t.Fatal("CreateItem.IsStreaming = true, want false")
	}

	if p, _ := set.Get("/grpcapi.authz.testdata.v1.FixtureServerService/DeleteItem"); p.Scope == nil || p.Scope.Op != ScopeAdmin {
		t.Fatalf("DeleteItem.Scope = %+v, want databases.admin", p.Scope)
	}

	p, _ = set.Get("/grpcapi.authz.testdata.v1.FixturePermissionService/PurgeItems")
	if p.Access != AccessPermission {
		t.Fatalf("PurgeItems.Access = %v, want AccessPermission", p.Access)
	}
	if !reflect.DeepEqual(p.Permissions, []string{"owner"}) {
		t.Fatalf("PurgeItems.Permissions = %v, want [owner]", p.Permissions)
	}
	if p.RequestFields == nil || !reflect.DeepEqual(p.RequestFields, []string{"confirm"}) {
		t.Fatalf("PurgeItems.RequestFields = %v", p.RequestFields)
	}

	if p, _ := set.Get("/grpcapi.authz.testdata.v1.FixturePublicService/Ping"); p.Access != AccessPublic {
		t.Fatalf("Ping.Access = %v, want AccessPublic", p.Access)
	}

	// 流式标记。
	p, _ = set.Get("/grpcapi.authz.testdata.v1.FixtureStreamService/WatchItems")
	if !p.IsStreaming {
		t.Fatal("WatchItems.IsStreaming = false, want true")
	}

	// 派生词表：被引用资源，去重排序。
	if got, want := set.Vocabulary(), []string{"databases", "storage"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Vocabulary() = %v, want %v", got, want)
	}
}

func TestBuildStreamingGate(t *testing.T) {
	// 默认（AllowStreaming=false）：流式方法 fail-closed，报错说明 v1 不支持。
	wantBuildError(t, []string{fixturePath},
		Options{Vocabulary: fixtureVocab},
		[]string{
			"/grpcapi.authz.testdata.v1.FixtureStreamService/WatchItems",
			"streaming RPC is not supported in v1",
		})
}

func TestBuildMissingPolicy(t *testing.T) {
	// 断言 1 反例一：完全未声明。
	wantBuildError(t, []string{violationsPath},
		Options{Vocabulary: fixtureVocab},
		[]string{"missing auth policy for method /grpcapi.authz.testdata.v1.BadMissingPolicyService/GetMissingPolicy"})
	// 断言 1 反例二：显式 UNSPECIFIED（服务无缺省档可回落）。
	wantBuildError(t, []string{violationsPath},
		Options{Vocabulary: fixtureVocab},
		[]string{"missing auth policy for method /grpcapi.authz.testdata.v1.BadUnspecifiedService/GetUnspecified"})
}

func TestBuildServerRequiresScope(t *testing.T) {
	wantBuildError(t, []string{violationsPath},
		Options{Vocabulary: fixtureVocab},
		[]string{
			"/grpcapi.authz.testdata.v1.BadServerNoScopeService/GetServerNoScope",
			"SERVER access must declare api_key_scope",
		})
}

func TestBuildPermissionRequiresPermissions(t *testing.T) {
	// 同时覆盖回落语义：PERMISSION 来自 service_auth.default_access。
	wantBuildError(t, []string{violationsPath},
		Options{Vocabulary: fixtureVocab},
		[]string{
			"/grpcapi.authz.testdata.v1.BadPermissionNoPermsService/GetPermissionNoPerms",
			"PERMISSION access must declare permissions",
		})
}

func TestBuildSystemDisabled(t *testing.T) {
	wantBuildError(t, []string{violationsPath},
		Options{Vocabulary: fixtureVocab},
		[]string{
			"/grpcapi.authz.testdata.v1.BadSystemService/GetSystem",
			"ACCESS_LEVEL_SYSTEM is disabled in v1",
		})
}

func TestBuildEmptyVocabularyGuard(t *testing.T) {
	// 断言 5：有 scope 声明而词表为空 → 构造失败（fail-open 防线）。
	wantBuildError(t, []string{fixturePath},
		Options{AllowStreaming: true},
		[]string{"vocabulary is empty but methods declare api_key_scope"})
}

func TestBuildScopeResourceNotInVocabulary(t *testing.T) {
	// 断言 6 反例：alien ∉ {databases, storage}。
	wantBuildError(t, []string{violationsPath},
		Options{Vocabulary: fixtureVocab},
		[]string{`scope resource "alien" is not in the vocabulary`})
}

func TestBuildScopeOpUnregistered(t *testing.T) {
	// 断言 7 反例：api_key_scope.op 未声明。
	wantBuildError(t, []string{violationsPath},
		Options{Vocabulary: fixtureVocab},
		[]string{
			"/grpcapi.authz.testdata.v1.BadOplessScopeService/GetOplessScope",
			`scope op "" is not registered`,
		})
}

func TestBuildDeadScope(t *testing.T) {
	// 断言 8：词表内的 projects 无任何方法引用 → 全局违例；且仅为唯一违例。
	files := []protoreflect.FileDescriptor{mustFile(t, fixturePath)}
	_, err := Build(files, Options{
		Vocabulary:     Vocabulary{ScopeResources: []string{"databases", "storage", "projects"}},
		AllowStreaming: true,
	})
	if err == nil {
		t.Fatal("Build = success, want dead scope error")
	}
	if !strings.Contains(err.Error(), `dead scope: resource "projects" is in the vocabulary`) {
		t.Fatalf("error must name dead resource projects, got: %v", err)
	}
	if !strings.Contains(err.Error(), "1 violation(s)") {
		t.Fatalf("dead scope 应为唯一违例，got: %v", err)
	}
}

func TestBuildPlainFileSucceedsWithEmptyVocabulary(t *testing.T) {
	// 断言 8 的跳过支：无 scope 声明 + 空词表 → 正常构造；
	// 同时锁定 END_USER permissions 为空不归一化。
	set := mustBuild(t, []string{plainPath}, Options{})
	if len(set.Methods()) != 2 {
		t.Fatalf("PlainService methods = %d, want 2", len(set.Methods()))
	}
	p, ok := set.Get("/grpcapi.authz.testdata.v1.PlainService/GetMe")
	if !ok {
		t.Fatal("GetMe not found")
	}
	if p.Access != AccessEndUser || len(p.Permissions) != 0 {
		t.Fatalf("GetMe = {Access: %v, Permissions: %v}, want {EndUser, 空（不归一化）}", p.Access, p.Permissions)
	}
}

func TestBuildAggregatesAllViolations(t *testing.T) {
	// 全部违例聚合进单一 error：violations.proto 一次触发 8 条
	//（断言 1×2、2、3、4、6、7、8-storage）。
	wantBuildError(t, []string{violationsPath}, Options{Vocabulary: fixtureVocab}, []string{
		"8 violation(s)",
		"missing auth policy for method /grpcapi.authz.testdata.v1.BadMissingPolicyService/GetMissingPolicy",
		"missing auth policy for method /grpcapi.authz.testdata.v1.BadUnspecifiedService/GetUnspecified",
		"SERVER access must declare api_key_scope",
		"PERMISSION access must declare permissions",
		"ACCESS_LEVEL_SYSTEM is disabled in v1",
		`scope resource "alien" is not in the vocabulary`,
		`scope op "" is not registered`,
		`dead scope: resource "storage" is in the vocabulary`,
	})
}

// sequenceAssertion 记录求值顺序：全部 AssertPolicy 必须先于 AssertSet
// （「逐方法、再逐集合」契约），并校验逐方法覆盖每个方法恰好一次。
type sequenceAssertion struct {
	NoopAssertion
	order []string
}

func (a *sequenceAssertion) AssertPolicy(p MethodPolicy) error {
	a.order = append(a.order, "policy:"+p.Method)
	return nil
}

func (a *sequenceAssertion) AssertSet(s *PolicySet) error {
	a.order = append(a.order, "set")
	return nil
}

// rejectAssertion 与 sequenceAssertion 一起注入，验证项目断言违例聚合。
type rejectAssertion struct {
	NoopAssertion
	policyErr, setErr string
}

func (a *rejectAssertion) AssertPolicy(MethodPolicy) error { return errString(a.policyErr) }
func (a *rejectAssertion) AssertSet(*PolicySet) error      { return errString(a.setErr) }

type errString string

func (e errString) Error() string { return string(e) }

func TestBuildProjectAssertions(t *testing.T) {
	seq := &sequenceAssertion{}
	reject := &rejectAssertion{policyErr: "policy rejected by project rule", setErr: "set rejected by project rule"}
	files := []protoreflect.FileDescriptor{mustFile(t, plainPath)}
	_, err := Build(files, Options{Assertions: []Assertion{NoopAssertion{}, seq, reject}})
	if err == nil {
		t.Fatal("Build = success, want project assertion violations")
	}
	if !strings.Contains(err.Error(), ": policy rejected by project rule") {
		t.Fatalf("error must aggregate per-method assertion violation, got: %v", err)
	}
	if !strings.Contains(err.Error(), "assertion *authz.rejectAssertion: set rejected by project rule") {
		t.Fatalf("error must aggregate set-level assertion violation, got: %v", err)
	}
	// NoopAssertion 不产生违例：rejectAssertion 逐方法 2 条（plain 两个方法）
	// + 逐集合 1 条，plain.proto 自身合法（0 条内置违例），共 3 条。
	if !strings.Contains(err.Error(), "3 violation(s)") {
		t.Fatalf("违例计数不符，got: %v", err)
	}
	// 逐方法先于逐集合；每方法恰好求值一次。
	if len(seq.order) != 3 || seq.order[2] != "set" {
		t.Fatalf("assertion order = %v, want 2×policy then set", seq.order)
	}
	for i, want := range []string{
		"policy:/grpcapi.authz.testdata.v1.PlainService/GetMe",
		"policy:/grpcapi.authz.testdata.v1.PlainService/GetStatus",
	} {
		if seq.order[i] != want {
			t.Fatalf("order[%d] = %s, want %s", i, seq.order[i], want)
		}
	}
}

func TestBuildUnregisteredAccessLevel(t *testing.T) {
	// 未登记枚举值（真实 descriptor 派生 + 篡改枚举数值）→ 收集级违例，
	// fail-closed 且聚合报错。
	fd := mustFile(t, fixturePath)
	fdp := protodesc.ToFileDescriptorProto(fd)
	mutated := false
	for _, svc := range fdp.Service {
		if svc.GetName() != "FixturePublicService" {
			continue
		}
		for _, m := range svc.Method {
			if m.GetName() != "Ping" || m.Options == nil {
				continue
			}
			ext := proto.GetExtension(m.Options, grpcapiv1.E_MethodAuth)
			ma, ok := ext.(*grpcapiv1.MethodAuth)
			if !ok || ma == nil {
				t.Fatal("Ping 缺少 method_auth 扩展，fixture 与测试前提不符")
			}
			ma.Access = grpcapiv1.AccessLevel(99)
			mutated = true
		}
	}
	if !mutated {
		t.Fatal("未找到可篡改的 method_auth，fixture 与测试前提不符")
	}
	newFD, err := protodesc.NewFile(fdp, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatalf("protodesc.NewFile: %v", err)
	}
	_, err = Build([]protoreflect.FileDescriptor{newFD}, Options{Vocabulary: fixtureVocab, AllowStreaming: true})
	if err == nil {
		t.Fatal("Build = success, want unregistered access level error")
	}
	if !strings.Contains(err.Error(), "access level 99 is not registered") {
		t.Fatalf("error must report unregistered value, got: %v", err)
	}
}

func TestBuildDuplicateMethod(t *testing.T) {
	// 同一文件描述符传入两次 → 重复方法 → 构造失败。
	fd := mustFile(t, plainPath)
	_, err := Build([]protoreflect.FileDescriptor{fd, fd}, Options{})
	if err == nil || !strings.Contains(err.Error(), "duplicate method policy") {
		t.Fatalf("Build duplicate = %v, want duplicate method policy error", err)
	}
}

func TestBuildEmptyInput(t *testing.T) {
	set, err := Build(nil, Options{})
	if err != nil {
		t.Fatalf("Build(nil) = %v, want success", err)
	}
	if len(set.Methods()) != 0 || len(set.Vocabulary()) != 0 {
		t.Fatalf("Build(nil) = %d methods, want empty set", len(set.Methods()))
	}
}
