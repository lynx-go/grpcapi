package main

import (
	"os"
	"path/filepath"
	"testing"

	echov1 "github.com/lynx-go/grpcapi/example/echo/v1"
	grpcapiv1 "github.com/lynx-go/grpcapi/genproto/grpcapi/v1"
	"google.golang.org/protobuf/compiler/protogen"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/pluginpb"
)

// codeGenRequest 以 root（含全部传递依赖、deps-first 拓扑序）构造
// protogen 输入——与 buf/protoc 传给插件的 CodeGeneratorRequest 同构。
func codeGenRequest(t *testing.T, root protoreflect.FileDescriptor, parameter string) *pluginpb.CodeGeneratorRequest {
	t.Helper()
	var ordered []*descriptorpb.FileDescriptorProto
	seen := make(map[protoreflect.FileDescriptor]bool)
	var collect func(fd protoreflect.FileDescriptor)
	collect = func(fd protoreflect.FileDescriptor) {
		if seen[fd] {
			return
		}
		seen[fd] = true
		for i := 0; i < fd.Imports().Len(); i++ {
			collect(fd.Imports().Get(i).FileDescriptor)
		}
		ordered = append(ordered, protodesc.ToFileDescriptorProto(fd))
	}
	collect(root)

	return &pluginpb.CodeGeneratorRequest{
		FileToGenerate: []string{root.Path()},
		Parameter:      proto.String(parameter),
		ProtoFile:      ordered,
	}
}

func runPlugin(t *testing.T, root protoreflect.FileDescriptor, parameter string) map[string]string {
	t.Helper()
	gen, err := protogen.Options{}.New(codeGenRequest(t, root, parameter))
	if err != nil {
		t.Fatalf("protogen.New: %v", err)
	}
	if err := generateInto(gen); err != nil {
		t.Fatalf("generateInto: %v", err)
	}
	resp := gen.Response()
	out := make(map[string]string, len(resp.File))
	for _, f := range resp.File {
		out[f.GetName()] = f.GetContent()
	}
	return out
}

// TestGolden 钉住生成物形态：生成代码入库即活文档，任何输出变化都必须
// 显式 review（改插件或 protogen 版本时跑 UPDATE_GOLDEN=1 重新落盘）。
func TestGolden(t *testing.T) {
	out := runPlugin(t, echov1.File_echo_proto, "module=github.com/lynx-go/grpcapi")
	content, ok := out["example/echo/v1/echo_grpcapi.pb.go"]
	if !ok {
		t.Fatalf("missing echo_grpcapi.pb.go, got files %v", keys(out))
	}
	golden := filepath.Join("testdata", "echo_grpcapi.pb.go.golden")
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(golden, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (首次请 UPDATE_GOLDEN=1 go test 生成): %v", err)
	}
	if string(want) != content {
		t.Fatalf("生成物与 golden 漂移：请 review 后 UPDATE_GOLDEN=1 重新落盘，或还原插件改动")
	}
}

// TestNoServicesEmitsNothing：无 service 的 proto（如 policy.proto）不产文件。
func TestNoServicesEmitsNothing(t *testing.T) {
	gen, err := protogen.Options{}.New(codeGenRequest(t, grpcapiv1.File_grpcapi_v1_policy_proto, ""))
	if err != nil {
		t.Fatalf("protogen.New: %v", err)
	}
	if err := generateInto(gen); err != nil {
		t.Fatal(err)
	}
	resp := gen.Response()
	if len(resp.File) != 0 {
		t.Fatalf("policy.proto 不应产出文件，得到 %d 个", len(resp.File))
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
