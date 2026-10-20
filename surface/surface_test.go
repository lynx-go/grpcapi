package surface_test

import (
	"context"
	"strings"
	"testing"

	echov1 "github.com/lynx-go/grpcapi/example/echo/v1"
	"github.com/lynx-go/grpcapi/policy"
	"github.com/lynx-go/grpcapi/policy/protopolicy"
	"github.com/lynx-go/grpcapi/surface"
	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

func exampleSurface(t *testing.T) *surface.Surface {
	t.Helper()
	set, err := policy.Build(context.Background(), policy.FromFiles(echov1.File_echo_proto), policy.Options{
		Provider: protopolicy.New(protopolicy.Options{}),
		Registry: policy.DefaultRegistry(),
	})
	if err != nil {
		t.Fatalf("policy.Build: %v", err)
	}
	s, err := surface.Build([]protoreflect.FileDescriptor{echov1.File_echo_proto}, set)
	if err != nil {
		t.Fatalf("surface.Build: %v", err)
	}
	return s
}

func TestExampleSurface(t *testing.T) {
	s := exampleSurface(t)
	if len(s.Operations()) != 3 {
		t.Fatalf("operations = %d", len(s.Operations()))
	}
	if len(s.OperationsByAPI("public")) != 3 {
		t.Fatalf("public operations = %d", len(s.OperationsByAPI("public")))
	}
	if len(s.Services()) != 1 || s.Services()[0].FullName() != "example.echo.v1.EchoService" {
		t.Fatalf("services = %v", s.Services())
	}
	routes := s.Routes()
	want := map[string]bool{
		"POST /v1/echo:shout": false,
		"GET /v1/echo":        false,
		"GET /v1/echo:ping":   false,
	}
	for _, r := range routes {
		key := r.Method + " " + r.Path
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("route %s missing", k)
		}
	}
}

func TestPublicWithoutHTTPFails(t *testing.T) {
	fd := syntheticFile(t, policy.ExposurePublic, false, false, "GET", "/v1/a", "GET", "/v1/b")
	_, err := surface.Build([]protoreflect.FileDescriptor{fd}, syntheticSet(t, fd, policy.ExposurePublic))
	if err == nil || !strings.Contains(err.Error(), "no google.api.http") {
		t.Fatalf("error = %v", err)
	}
}

func TestInternalWithHTTPFails(t *testing.T) {
	fd := syntheticFile(t, policy.ExposureInternal, false, true, "GET", "/v1/a", "GET", "/v1/b")
	_, err := surface.Build([]protoreflect.FileDescriptor{fd}, syntheticSet(t, fd, policy.ExposureInternal))
	if err == nil || !strings.Contains(err.Error(), "INTERNAL") {
		t.Fatalf("error = %v", err)
	}
}

func TestClientStreamingHTTPFails(t *testing.T) {
	fd := syntheticFile(t, policy.ExposurePublic, true, true, "GET", "/v1/a", "GET", "/v1/b")
	_, err := surface.Build([]protoreflect.FileDescriptor{fd}, syntheticSet(t, fd, policy.ExposurePublic))
	if err == nil || !strings.Contains(err.Error(), "client/bidi streaming") {
		t.Fatalf("error = %v", err)
	}
}

func TestDuplicateRouteFails(t *testing.T) {
	fd := syntheticFile(t, policy.ExposurePublic, false, true, "GET", "/v1/same", "GET", "/v1/same")
	_, err := surface.Build([]protoreflect.FileDescriptor{fd}, syntheticSet(t, fd, policy.ExposurePublic))
	if err == nil || !strings.Contains(err.Error(), "duplicate HTTP route") {
		t.Fatalf("error = %v", err)
	}
}

func TestMultipleBindingsAcrossMethods(t *testing.T) {
	fd := syntheticFile(t, policy.ExposurePublic, false, true, "GET", "/v1/a", "POST", "/v1/a")
	s := syntheticSet(t, fd, policy.ExposurePublic)
	surf, err := surface.Build([]protoreflect.FileDescriptor{fd}, s)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := len(surf.Routes()); got != 2 {
		t.Fatalf("routes = %d, want 2", got)
	}
}

func syntheticSet(t *testing.T, fd protoreflect.FileDescriptor, exposure policy.Exposure) *policy.Set {
	t.Helper()
	var ops []policy.Operation
	services := fd.Services()
	for i := 0; i < services.Len(); i++ {
		svc := services.Get(i)
		methods := svc.Methods()
		for j := 0; j < methods.Len(); j++ {
			md := methods.Get(j)
			ops = append(ops, policy.Operation{
				ID:       "/" + string(svc.FullName()) + "/" + string(md.Name()),
				Kind:     policy.KindGRPC,
				Service:  string(svc.FullName()),
				API:      "public",
				Exposure: exposure,
				Policy:   policy.Policy{Anonymous: true},
			})
		}
	}
	set, err := policy.NewSet(ops...)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func syntheticFile(t *testing.T, exposure policy.Exposure, clientStreaming, withHTTP bool, method1, path1, method2, path2 string) protoreflect.FileDescriptor {
	t.Helper()
	opts := func(method, path string) *descriptorpb.MethodOptions {
		o := &descriptorpb.MethodOptions{}
		if withHTTP {
			rule := &annotations.HttpRule{}
			switch method {
			case "GET":
				rule.Pattern = &annotations.HttpRule_Get{Get: path}
			case "POST":
				rule.Pattern = &annotations.HttpRule_Post{Post: path}
			}
			proto.SetExtension(o, annotations.E_Http, rule)
		}
		return o
	}
	fdp := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("test/surface.proto"),
		Package: proto.String("test.surface.v1"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("Req")}, {Name: proto.String("Resp")},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String("Svc"),
			Method: []*descriptorpb.MethodDescriptorProto{
				{Name: proto.String("A"), InputType: proto.String(".test.surface.v1.Req"), OutputType: proto.String(".test.surface.v1.Resp"), ClientStreaming: proto.Bool(clientStreaming), Options: opts(method1, path1)},
				{Name: proto.String("B"), InputType: proto.String(".test.surface.v1.Req"), OutputType: proto.String(".test.surface.v1.Resp"), Options: opts(method2, path2)},
			},
		}},
	}
	_ = exposure
	fd, err := protodesc.NewFile(fdp, nil)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	return fd
}
