package protopolicy

import (
	"strings"
	"testing"

	grpcapiv1 "github.com/lynx-go/grpcapi/genproto/grpcapi/v1"
	"github.com/lynx-go/grpcapi/policy"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestProviderReadsExtensions(t *testing.T) {
	fileOpts := &descriptorpb.FileOptions{}
	proto.SetExtension(fileOpts, grpcapiv1.E_Api, &grpcapiv1.APISpec{
		Api:             "public",
		SchemaVersion:   1,
		DefaultExposure: grpcapiv1.Exposure_EXPOSURE_PUBLIC,
	})
	svcOpts := &descriptorpb.ServiceOptions{}
	proto.SetExtension(svcOpts, grpcapiv1.E_Service, &grpcapiv1.ServiceSpec{
		DefaultPolicy: &grpcapiv1.Policy{Authenticated: true},
		Label:         "svc",
	})
	methodOpts := &descriptorpb.MethodOptions{}
	proto.SetExtension(methodOpts, grpcapiv1.E_Method, &grpcapiv1.MethodSpec{
		Policy: &grpcapiv1.Policy{
			Roles: []string{"admin"},
			AnyOf: []*grpcapiv1.Alternative{
				{Scopes: []string{"notes:admin"}},
			},
		},
		Exposure:    grpcapiv1.Exposure_EXPOSURE_HIDDEN,
		Label:       "admin",
		StreamAuth:  grpcapiv1.StreamAuthMode_STREAM_AUTH_MODE_PER_MESSAGE,
		OperationId: "Custom_Op",
	})

	fd := buildFile(t, fileOpts, svcOpts, methodOpts)
	p := New(Options{})

	fs, ok, err := p.File(fd)
	if err != nil || !ok {
		t.Fatalf("File = %+v, %v, %v", fs, ok, err)
	}
	if fs.API != "public" || fs.SchemaVersion != 1 || fs.DefaultExposure != policy.ExposurePublic {
		t.Fatalf("FileSpec = %+v", fs)
	}

	ss, ok, err := p.Service(fd.Services().Get(0))
	if err != nil || !ok {
		t.Fatalf("Service = %+v, %v, %v", ss, ok, err)
	}
	if ss.Label != "svc" || ss.DefaultPolicy == nil || len(ss.DefaultPolicy.Require) != 1 ||
		ss.DefaultPolicy.Require[0].Kind != "authenticated" {
		t.Fatalf("ServiceSpec = %+v", ss)
	}

	ms, ok, err := p.Method(fd.Services().Get(0).Methods().Get(0))
	if err != nil || !ok {
		t.Fatalf("Method = %+v, %v, %v", ms, ok, err)
	}
	if ms.Label != "admin" || ms.Exposure != policy.ExposureHidden || ms.OperationID != "Custom_Op" {
		t.Fatalf("MethodSpec = %+v", ms)
	}
	if ms.StreamAuth != policy.StreamAuthPerMessage {
		t.Fatalf("StreamAuth = %v", ms.StreamAuth)
	}
	if ms.Policy == nil || len(ms.Policy.Require) != 1 || ms.Policy.Require[0].Kind != "role" {
		t.Fatalf("sugar policy = %+v", ms.Policy)
	}
	if len(ms.Policy.AnyOf) != 1 || len(ms.Policy.AnyOf[0]) != 1 || ms.Policy.AnyOf[0][0].Kind != "scope" {
		t.Fatalf("any_of = %+v", ms.Policy.AnyOf)
	}
}

func TestProviderRejectsUnknownFields(t *testing.T) {
	spec := &grpcapiv1.MethodSpec{Policy: &grpcapiv1.Policy{Anonymous: true}}
	spec.ProtoReflect().SetUnknown([]byte{0x08, 0x01})

	methodOpts := &descriptorpb.MethodOptions{}
	proto.SetExtension(methodOpts, grpcapiv1.E_Method, spec)
	fd := buildFile(t, &descriptorpb.FileOptions{}, &descriptorpb.ServiceOptions{}, methodOpts)

	_, _, err := New(Options{}).Method(fd.Services().Get(0).Methods().Get(0))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("error = %v, want unknown field rejection", err)
	}

	_, _, err = New(Options{AllowUnknownFields: true}).Method(fd.Services().Get(0).Methods().Get(0))
	if err != nil {
		t.Fatalf("AllowUnknownFields should pass: %v", err)
	}
}

func TestProviderRejectsNestedUnknownFields(t *testing.T) {
	inner := &grpcapiv1.Policy{Require: []*grpcapiv1.Requirement{{Kind: "role", Values: []string{"admin"}}}}
	inner.ProtoReflect().SetUnknown([]byte{0x10, 0x01})
	spec := &grpcapiv1.MethodSpec{Policy: inner}

	methodOpts := &descriptorpb.MethodOptions{}
	proto.SetExtension(methodOpts, grpcapiv1.E_Method, spec)
	fd := buildFile(t, &descriptorpb.FileOptions{}, &descriptorpb.ServiceOptions{}, methodOpts)

	_, _, err := New(Options{}).Method(fd.Services().Get(0).Methods().Get(0))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("error = %v, want nested unknown field rejection", err)
	}
}

func buildFile(t *testing.T, fileOpts *descriptorpb.FileOptions, svcOpts *descriptorpb.ServiceOptions, methodOpts *descriptorpb.MethodOptions) protoreflect.FileDescriptor {
	t.Helper()
	fdp := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("test/policy.proto"),
		Package: proto.String("test.policy.v1"),
		Syntax:  proto.String("proto3"),
		Options: fileOpts,
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("Req")},
			{Name: proto.String("Resp")},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name:    proto.String("PolicyService"),
			Options: svcOpts,
			Method: []*descriptorpb.MethodDescriptorProto{{
				Name:       proto.String("Do"),
				InputType:  proto.String(".test.policy.v1.Req"),
				OutputType: proto.String(".test.policy.v1.Resp"),
				Options:    methodOpts,
			}},
		}},
	}
	fd, err := protodesc.NewFile(fdp, nil)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	return fd
}
