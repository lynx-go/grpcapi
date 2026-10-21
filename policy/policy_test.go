package policy_test

import (
	"context"
	"strings"
	"testing"

	echov1 "github.com/lynx-go/grpcapi/example/echo/v1"
	"github.com/lynx-go/grpcapi/policy"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

type fakeProvider struct {
	file     policy.FileSpec
	services map[protoreflect.FullName]policy.ServiceSpec
	methods  map[protoreflect.FullName]policy.MethodSpec
}

func (p fakeProvider) File(protoreflect.FileDescriptor) (policy.FileSpec, bool, error) {
	return p.file, true, nil
}

func (p fakeProvider) Service(sd protoreflect.ServiceDescriptor) (policy.ServiceSpec, bool, error) {
	s, ok := p.services[sd.FullName()]
	return s, ok, nil
}

func (p fakeProvider) Method(md protoreflect.MethodDescriptor) (policy.MethodSpec, bool, error) {
	s, ok := p.methods[md.FullName()]
	return s, ok, nil
}

func TestBuildInheritanceAndLabels(t *testing.T) {
	provider := fakeProvider{
		file: policy.FileSpec{API: "public", DefaultExposure: policy.ExposurePublic},
		services: map[protoreflect.FullName]policy.ServiceSpec{
			"example.echo.v1.EchoService": {
				DefaultPolicy: &policy.Policy{Require: []policy.Requirement{{Kind: "authenticated"}}},
			},
		},
		methods: map[protoreflect.FullName]policy.MethodSpec{
			"example.echo.v1.EchoService.Shout": {
				Policy: &policy.Policy{Require: []policy.Requirement{{Kind: "role", Match: policy.MatchAny, Values: []string{"admin"}}}},
			},
			"example.echo.v1.EchoService.Ping": {
				Policy: &policy.Policy{Anonymous: true},
			},
		},
	}
	set, err := policy.Build(context.Background(), policy.FromFiles(echov1.File_echo_proto), policy.Options{
		Provider: provider,
		Registry: policy.DefaultRegistry(),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if set.Len() != 3 {
		t.Fatalf("Len = %d, want 3", set.Len())
	}

	shout, ok := set.Get("/example.echo.v1.EchoService/Shout")
	if !ok {
		t.Fatal("Shout missing")
	}
	if got := shout.EffectiveLabel(); got != "role" {
		t.Errorf("Shout label = %q, want role", got)
	}
	if shout.Exposure != policy.ExposurePublic {
		t.Errorf("Shout exposure = %v", shout.Exposure)
	}
	if len(shout.Policy.Require) != 1 || shout.Policy.Require[0].Kind != "role" {
		t.Errorf("Shout policy = %+v", shout.Policy)
	}
	if got := shout.RequestFields; len(got) != 1 || got[0] != "text" {
		t.Errorf("Shout request fields = %v, want [text]", got)
	}

	hear, ok := set.Get("/example.echo.v1.EchoService/Hear")
	if !ok {
		t.Fatal("Hear missing")
	}
	if got := hear.EffectiveLabel(); got != "authenticated" {
		t.Errorf("Hear label = %q, want authenticated", got)
	}

	ping, ok := set.Get("/example.echo.v1.EchoService/Ping")
	if !ok || !ping.Policy.Anonymous {
		t.Fatal("Ping should be anonymous")
	}
	if got := ping.EffectiveLabel(); got != "public" {
		t.Errorf("Ping label = %q, want public", got)
	}
	if !set.IsAnonymous(ping.ID) || set.IsAnonymous(shout.ID) {
		t.Error("IsAnonymous mismatch")
	}
	if apis := set.APIs(); len(apis) != 1 || apis[0] != "public" {
		t.Errorf("APIs = %v", apis)
	}
}

func TestInheritDefault(t *testing.T) {
	provider := fakeProvider{
		file: policy.FileSpec{DefaultExposure: policy.ExposureInternal},
		services: map[protoreflect.FullName]policy.ServiceSpec{
			"example.echo.v1.EchoService": {
				DefaultPolicy: &policy.Policy{Require: []policy.Requirement{{Kind: "authenticated"}}},
			},
		},
		methods: map[protoreflect.FullName]policy.MethodSpec{
			"example.echo.v1.EchoService.Shout": {
				Policy:         &policy.Policy{Require: []policy.Requirement{{Kind: "scope", Values: []string{"notes:write"}}}},
				InheritDefault: true,
			},
		},
	}
	set, err := policy.Build(context.Background(), policy.FromFiles(echov1.File_echo_proto), policy.Options{
		Provider: provider,
		Registry: policy.DefaultRegistry(),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	shout, _ := set.Get("/example.echo.v1.EchoService/Shout")
	if len(shout.Policy.Require) != 2 {
		t.Fatalf("inherited policy = %+v, want authenticated + scope", shout.Policy)
	}
	if shout.Policy.Require[0].Kind != "authenticated" || shout.Policy.Require[1].Kind != "scope" {
		t.Errorf("inherited require order = %+v", shout.Policy.Require)
	}
}

func TestInheritDefaultAnyOfUnionsAlternatives(t *testing.T) {
	// 语义钉死（README「策略速查」）：inherit_default 合并时 require 跨层
	// AND，any_of 各组并入备选列表（组间恒为 OR，不做跨层笛卡尔 AND）。
	provider := fakeProvider{
		file: policy.FileSpec{DefaultExposure: policy.ExposureInternal},
		services: map[protoreflect.FullName]policy.ServiceSpec{
			"example.echo.v1.EchoService": {
				DefaultPolicy: &policy.Policy{AnyOf: [][]policy.Requirement{
					{{Kind: "role", Values: []string{"admin"}}},
				}},
			},
		},
		methods: map[protoreflect.FullName]policy.MethodSpec{
			"example.echo.v1.EchoService.Shout": {
				Policy: &policy.Policy{AnyOf: [][]policy.Requirement{
					{{Kind: "role", Values: []string{"viewer"}}},
				}},
				InheritDefault: true,
			},
		},
	}
	set, err := policy.Build(context.Background(), policy.FromFiles(echov1.File_echo_proto), policy.Options{
		Provider: provider,
		Registry: policy.DefaultRegistry(),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	shout, _ := set.Get("/example.echo.v1.EchoService/Shout")
	if len(shout.Policy.AnyOf) != 2 {
		t.Fatalf("any_of groups = %+v, want both alternatives (admin) and (viewer)", shout.Policy.AnyOf)
	}
	if len(shout.Policy.Require) != 0 {
		t.Errorf("require = %+v, want empty", shout.Policy.Require)
	}
}

func TestBuildValidationErrors(t *testing.T) {
	baseFile := policy.FileSpec{DefaultExposure: policy.ExposurePublic}
	tests := []struct {
		name    string
		policy  *policy.Policy
		vocab   policy.Vocabulary
		opts    policy.Options
		wantSub string
	}{
		{
			name:    "empty policy",
			policy:  &policy.Policy{},
			wantSub: "empty policy",
		},
		{
			name:    "anonymous with require",
			policy:  &policy.Policy{Anonymous: true, Require: []policy.Requirement{{Kind: "authenticated"}}},
			wantSub: "anonymous cannot be combined",
		},
		{
			name:    "unknown kind",
			policy:  &policy.Policy{Require: []policy.Requirement{{Kind: "nope"}}},
			wantSub: "unknown requirement kind",
		},
		{
			name:    "claim missing params",
			policy:  &policy.Policy{Require: []policy.Requirement{{Kind: "claim"}}},
			wantSub: "claim requires params.name",
		},
		{
			name:    "role empty values",
			policy:  &policy.Policy{Require: []policy.Requirement{{Kind: "role"}}},
			wantSub: "role requires at least one value",
		},
		{
			name:    "empty any_of group",
			policy:  &policy.Policy{AnyOf: [][]policy.Requirement{{}}},
			wantSub: "any_of[0] is empty",
		},
		{
			name:    "vocabulary mismatch",
			policy:  &policy.Policy{Require: []policy.Requirement{{Kind: "role", Values: []string{"admin"}}}},
			vocab:   policy.NewVocabulary(map[string][]string{"role": {"operator"}}),
			wantSub: "not in vocabulary",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			provider := fakeProvider{
				file: baseFile,
				methods: map[protoreflect.FullName]policy.MethodSpec{
					"example.echo.v1.EchoService.Shout": {Policy: tc.policy},
				},
			}
			opts := policy.Options{Provider: provider, Registry: policy.DefaultRegistry(), Vocabulary: tc.vocab}
			_, err := policy.Build(context.Background(), policy.FromFiles(echov1.File_echo_proto), opts)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error = %v, want substring %q", err, tc.wantSub)
			}
		})
	}
}

func TestStreaming(t *testing.T) {
	fd := syntheticStreamFile(t, false)
	provider := fakeProvider{
		file: policy.FileSpec{DefaultExposure: policy.ExposureInternal},
		methods: map[protoreflect.FullName]policy.MethodSpec{
			"test.stream.v1.StreamService.Upload": {Policy: &policy.Policy{Anonymous: true}},
		},
	}
	opts := policy.Options{
		Provider:         provider,
		Registry:         policy.DefaultRegistry(),
		DisableStreaming: true,
	}
	_, err := policy.Build(context.Background(), policy.FromFiles(fd), opts)
	if err == nil || !strings.Contains(err.Error(), "streaming is disabled") {
		t.Fatalf("error = %v, want streaming disabled", err)
	}

	opts.DisableStreaming = false
	provider.file.DefaultExposure = policy.ExposurePublic
	set, err := policy.Build(context.Background(), policy.FromFiles(fd), opts)
	if err != nil {
		t.Fatalf("server-streaming public should be allowed: %v", err)
	}
	op, ok := set.Get("/test.stream.v1.StreamService/Upload")
	if !ok || !op.Streaming || op.StreamAuth != policy.StreamAuthOpen {
		t.Fatalf("stream operation = %+v, %v", op, ok)
	}
}

func TestClientStreamingCannotBePublic(t *testing.T) {
	fd := syntheticStreamFile(t, true)
	provider := fakeProvider{
		file: policy.FileSpec{DefaultExposure: policy.ExposurePublic},
		methods: map[protoreflect.FullName]policy.MethodSpec{
			"test.stream.v1.StreamService.Upload": {Policy: &policy.Policy{Anonymous: true}},
		},
	}
	_, err := policy.Build(context.Background(), policy.FromFiles(fd), policy.Options{
		Provider: provider,
		Registry: policy.DefaultRegistry(),
	})
	if err == nil || !strings.Contains(err.Error(), "client/bidi streaming cannot be exposed") {
		t.Fatalf("error = %v, want client/bidi exposure failure", err)
	}
}

func syntheticStreamFile(t *testing.T, clientStreaming bool) protoreflect.FileDescriptor {
	t.Helper()
	fdp := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("test/stream.proto"),
		Package: proto.String("test.stream.v1"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("Req")},
			{Name: proto.String("Resp")},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String("StreamService"),
			Method: []*descriptorpb.MethodDescriptorProto{{
				Name:            proto.String("Upload"),
				InputType:       proto.String(".test.stream.v1.Req"),
				OutputType:      proto.String(".test.stream.v1.Resp"),
				ClientStreaming: proto.Bool(clientStreaming),
				ServerStreaming: proto.Bool(!clientStreaming),
			}},
		}},
	}
	fd, err := protodesc.NewFile(fdp, nil)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	return fd
}

func TestPresetExpansion(t *testing.T) {
	preset := policy.Preset{
		Name: "server",
		Build: func(map[string]string) (policy.Policy, error) {
			return policy.Policy{
				AnyOf: [][]policy.Requirement{
					{{Kind: "role", Match: policy.MatchAny, Values: []string{"admin"}}},
					{{Kind: "scope", Match: policy.MatchAny, Values: []string{"notes:admin"}}},
				},
			}, nil
		},
	}
	provider := fakeProvider{
		file: policy.FileSpec{DefaultExposure: policy.ExposureInternal},
		services: map[protoreflect.FullName]policy.ServiceSpec{
			"example.echo.v1.EchoService": {
				DefaultPolicy: &policy.Policy{Require: []policy.Requirement{{Kind: "authenticated"}}},
			},
		},
		methods: map[protoreflect.FullName]policy.MethodSpec{
			"example.echo.v1.EchoService.Shout": {
				Policy: &policy.Policy{
					Preset:  "server",
					Require: []policy.Requirement{{Kind: "authenticated"}},
				},
			},
			"example.echo.v1.EchoService.Ping": {
				Policy: &policy.Policy{Anonymous: true},
			},
		},
	}
	set, err := policy.Build(context.Background(), policy.FromFiles(echov1.File_echo_proto), policy.Options{
		Provider: provider,
		Registry: policy.DefaultRegistry(),
		Presets:  []policy.Preset{preset},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	op, _ := set.Get("/example.echo.v1.EchoService/Shout")
	if len(op.Policy.AnyOf) != 2 || len(op.Policy.Require) != 1 {
		t.Fatalf("expanded policy = %+v", op.Policy)
	}
	if op.Policy.Preset != "" || op.Policy.PresetArgs != nil {
		t.Fatalf("effective policy should clear preset metadata: %+v", op.Policy)
	}
	if op.EffectiveLabel() != "server" || op.Metadata["preset"] != "server" {
		t.Fatalf("preset provenance/label = %q / %v", op.EffectiveLabel(), op.Metadata)
	}

	bad := policy.Preset{
		Name: "public",
		Build: func(map[string]string) (policy.Policy, error) {
			return policy.Policy{Anonymous: true}, nil
		},
	}
	provider.methods["example.echo.v1.EchoService.Shout"] = policy.MethodSpec{
		Policy: &policy.Policy{Preset: "public", Require: []policy.Requirement{{Kind: "authenticated"}}},
	}
	_, err = policy.Build(context.Background(), policy.FromFiles(echov1.File_echo_proto), policy.Options{
		Provider: provider,
		Registry: policy.DefaultRegistry(),
		Presets:  []policy.Preset{bad},
	})
	if err == nil || !strings.Contains(err.Error(), "expands to anonymous") {
		t.Fatalf("error = %v, want anonymous-preset conflict", err)
	}
}

func TestInheritDefaultExpandsDefaultPreset(t *testing.T) {
	base := policy.Preset{
		Name: "base",
		Build: func(map[string]string) (policy.Policy, error) {
			return policy.Policy{Require: []policy.Requirement{
				{Kind: "permission", Match: policy.MatchAll, Values: []string{"base.read"}},
			}}, nil
		},
	}
	provider := fakeProvider{
		file: policy.FileSpec{DefaultExposure: policy.ExposureInternal},
		services: map[protoreflect.FullName]policy.ServiceSpec{
			"example.echo.v1.EchoService": {
				DefaultPolicy: &policy.Policy{Preset: "base"},
			},
		},
		methods: map[protoreflect.FullName]policy.MethodSpec{
			"example.echo.v1.EchoService.Shout": {
				Policy: &policy.Policy{Require: []policy.Requirement{
					{Kind: "role", Match: policy.MatchAny, Values: []string{"admin"}},
				}},
				InheritDefault: true,
			},
			"example.echo.v1.EchoService.Ping": {
				Policy: &policy.Policy{Anonymous: true},
			},
		},
	}
	set, err := policy.Build(context.Background(), policy.FromFiles(echov1.File_echo_proto), policy.Options{
		Provider: provider,
		Registry: policy.DefaultRegistry(),
		Presets:  []policy.Preset{base},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	op, _ := set.Get("/example.echo.v1.EchoService/Shout")
	if len(op.Policy.Require) != 2 {
		t.Fatalf("inherited policy = %+v, want base.read + admin", op.Policy)
	}
	if op.Policy.Require[0].Kind != "permission" || op.Policy.Require[1].Kind != "role" {
		t.Fatalf("inherited requirements = %+v", op.Policy.Require)
	}
}

func TestInheritDefaultAnonymousForbid(t *testing.T) {
	provider := fakeProvider{
		file: policy.FileSpec{
			DefaultPolicy:   &policy.Policy{Anonymous: true},
			DefaultExposure: policy.ExposurePublic,
		},
		methods: map[protoreflect.FullName]policy.MethodSpec{
			"example.echo.v1.EchoService.Shout": {
				Policy: &policy.Policy{Forbid: []policy.Requirement{
					{Kind: "role", Match: policy.MatchAny, Values: []string{"banned"}},
				}},
				InheritDefault: true,
			},
		},
	}
	set, err := policy.Build(context.Background(), policy.FromFiles(echov1.File_echo_proto), policy.Options{
		Provider: provider,
		Registry: policy.DefaultRegistry(),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	op, ok := set.Get("/example.echo.v1.EchoService/Shout")
	if !ok {
		t.Fatal("Shout missing")
	}
	if !op.Policy.Anonymous || len(op.Policy.Forbid) != 1 {
		t.Fatalf("Shout policy = %+v, want anonymous + forbid", op.Policy)
	}
}

func TestSetConstructorsValidatePolicies(t *testing.T) {
	bad := policy.Operation{
		ID: "/pkg.Svc/Get", Kind: policy.KindGRPC,
		Exposure: policy.ExposureInternal,
		Policy:   policy.Policy{Require: []policy.Requirement{{Kind: "role"}}},
	}
	if _, err := policy.NewSetWithRegistry(policy.DefaultRegistry(), bad); err == nil {
		t.Fatal("NewSetWithRegistry accepted empty role values")
	}
	set, err := policy.NewSet(policy.Operation{
		ID: "/pkg.Svc/OK", Kind: policy.KindGRPC, Exposure: policy.ExposureInternal,
		Policy: policy.Policy{Anonymous: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.WithOperations(bad); err == nil {
		t.Fatal("WithOperations accepted empty role values")
	}
	if _, err := policy.NewSet(policy.Operation{
		ID: "/pkg.Svc/Custom", Kind: policy.KindGRPC, Exposure: policy.ExposureInternal,
		Policy: policy.Policy{Require: []policy.Requirement{{Kind: "tenant"}}},
	}); err == nil {
		t.Fatal("NewSet should reject custom kind without its registry")
	}
	reg, err := policy.NewRegistry(policy.RequirementKind{Name: "tenant", DefaultMatch: policy.MatchAny})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.NewSetWithRegistry(reg, policy.Operation{
		ID: "/pkg.Svc/Custom", Kind: policy.KindGRPC, Exposure: policy.ExposureInternal,
		Policy: policy.Policy{Require: []policy.Requirement{{Kind: "tenant", Values: []string{"acme"}}}},
	}); err != nil {
		t.Fatalf("custom kind registry rejected: %v", err)
	}
}

func TestInheritDefaultAnonymousAndRequirement(t *testing.T) {
	provider := fakeProvider{
		file: policy.FileSpec{
			DefaultPolicy:   &policy.Policy{Anonymous: true},
			DefaultExposure: policy.ExposurePublic,
		},
		methods: map[protoreflect.FullName]policy.MethodSpec{
			"example.echo.v1.EchoService.Shout": {
				Policy: &policy.Policy{Require: []policy.Requirement{
					{Kind: "role", Match: policy.MatchAny, Values: []string{"admin"}},
				}},
				InheritDefault: true,
			},
		},
	}
	set, err := policy.Build(context.Background(), policy.FromFiles(echov1.File_echo_proto), policy.Options{
		Provider: provider,
		Registry: policy.DefaultRegistry(),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	op, ok := set.Get("/example.echo.v1.EchoService/Shout")
	if !ok {
		t.Fatal("Shout missing")
	}
	if op.Policy.Anonymous {
		t.Fatalf("AND(anonymous, role) must not be anonymous: %+v", op.Policy)
	}
	if len(op.Policy.Require) != 1 || op.Policy.Require[0].Kind != "role" {
		t.Fatalf("Shout policy = %+v, want role requirement", op.Policy)
	}
}

func TestSetMergeFilterManifest(t *testing.T) {
	ops := []policy.Operation{
		{ID: "GET /v1/health", Kind: policy.KindHTTP, API: "public", Exposure: policy.ExposurePublic, Policy: policy.Policy{Anonymous: true}},
		{ID: "/pkg.Svc/Method", Kind: policy.KindGRPC, API: "internal", Exposure: policy.ExposureInternal, Policy: policy.Policy{Require: []policy.Requirement{{Kind: "authenticated"}}}},
	}
	set, err := policy.NewSet(ops...)
	if err != nil {
		t.Fatalf("NewSet: %v", err)
	}
	if _, err := policy.NewSet(ops[0], ops[0]); err == nil {
		t.Fatal("duplicate operation should fail")
	}
	merged, err := set.WithOperations(policy.Operation{
		ID: "POST /v1/hook", Kind: policy.KindHTTP, API: "public",
		Exposure: policy.ExposurePublic, Policy: policy.Policy{Anonymous: true},
	})
	if err != nil {
		t.Fatalf("WithOperations: %v", err)
	}
	if merged.Len() != 3 || set.Len() != 2 {
		t.Fatalf("merge mutated original: merged=%d original=%d", merged.Len(), set.Len())
	}
	public := merged.FilterAPI("public")
	if public.Len() != 2 {
		t.Fatalf("FilterAPI = %d, want 2", public.Len())
	}
	manifest := merged.Manifest()
	data, err := manifest.JSON()
	if err != nil {
		t.Fatalf("Manifest JSON: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, `"version": 1`) || !strings.Contains(text, `"id": "GET /v1/health"`) {
		t.Fatalf("manifest = %s", text)
	}
	internal, ok := set.Get("/pkg.Svc/Method")
	if !ok {
		t.Fatal("internal operation missing")
	}
	if !strings.Contains(policy.Format(internal.Policy), "authenticated") {
		t.Fatal("Format should include authenticated")
	}
}
