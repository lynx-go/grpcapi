package guard

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/lynx-go/grpcapi/authz"
	grpcapiv1 "github.com/lynx-go/grpcapi/genproto/grpcapi/v1"
	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// fixtureFileDescriptor 用 protodesc 构造最小业务 proto 文件描述符（不依赖
// 磁盘 proto 源）：DemoService{Ping, AdminPing}，服务默认档 PUBLIC，两方法均
// 显式 method_auth PUBLIC。extraBindings>0 时给 Ping 追加 N 个 additional_bindings
// （驱动 operationId 数字后缀解析）。调用方保证 protoPath / package 全局唯一
// （protoregistry 冲突即失败）。
func fixtureFileDescriptor(t *testing.T, protoPath, pkg string, extraBindings int) protoreflect.FileDescriptor {
	t.Helper()

	methodOpts := func(method string) *descriptorpb.MethodOptions {
		opts := &descriptorpb.MethodOptions{}
		proto.SetExtension(opts, grpcapiv1.E_MethodAuth, &grpcapiv1.MethodAuth{
			Access: grpcapiv1.AccessLevel_ACCESS_LEVEL_PUBLIC,
		})
		proto.SetExtension(opts, annotations.E_Http, &annotations.HttpRule{
			Pattern: &annotations.HttpRule_Get{Get: "/v1/" + method},
		})
		return opts
	}

	pingOpts := methodOpts("ping")
	if extraBindings > 0 {
		rule, ok := proto.GetExtension(pingOpts, annotations.E_Http).(*annotations.HttpRule)
		if !ok || rule == nil {
			t.Fatal("fixture: http rule 扩展取回失败")
		}
		for i := 0; i < extraBindings; i++ {
			rule.AdditionalBindings = append(rule.AdditionalBindings, &annotations.HttpRule{
				Pattern: &annotations.HttpRule_Post{Post: "/v1/ping:extra" + strconv.Itoa(i+2)},
			})
		}
	}

	svcOpts := &descriptorpb.ServiceOptions{}
	proto.SetExtension(svcOpts, grpcapiv1.E_ServiceAuth, &grpcapiv1.ServiceAuth{
		DefaultAccess: grpcapiv1.AccessLevel_ACCESS_LEVEL_PUBLIC,
	})

	fdp := &descriptorpb.FileDescriptorProto{
		Name:    proto.String(protoPath),
		Package: proto.String(pkg),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("PingRequest")},
			{Name: proto.String("PingResponse")},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name:    proto.String("DemoService"),
			Options: svcOpts,
			Method: []*descriptorpb.MethodDescriptorProto{
				{
					Name:       proto.String("Ping"),
					InputType:  proto.String(pkg + ".PingRequest"),
					OutputType: proto.String(pkg + ".PingResponse"),
					Options:    pingOpts,
				},
				{
					Name:       proto.String("AdminPing"),
					InputType:  proto.String(pkg + ".PingRequest"),
					OutputType: proto.String(pkg + ".PingResponse"),
					Options:    methodOpts("admin-ping"),
				},
			},
		}},
	}
	fd, err := protodesc.NewFile(fdp, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatalf("构造 fixture descriptor 失败: %v", err)
	}
	return fd
}

// fixturePolicies 用 fixture descriptor 驱动 authz.Build 构造策略注册表
// （guard 各断言 helper 的 Policies 输入与真实项目同源）。
func fixturePolicies(t *testing.T, fd protoreflect.FileDescriptor) *authz.PolicySet {
	t.Helper()
	set, err := authz.Build([]protoreflect.FileDescriptor{fd}, authz.Options{})
	if err != nil {
		t.Fatalf("authz.Build(fixture) 失败: %v", err)
	}
	return set
}

// guardFatal 是替身 TB 触发 Fatal 时的控制流信号（不依赖 Goexit）。
type guardFatal struct{}

// guardTB 是 testing.TB 的记录式替身：Fatal/Fatalf/FailNow 不再 Goexit，而是
// 标记 failed 并 panic(guardFatal{})，使“守卫必须 Fatal”可以被断言；其余方法
// （Log/Logf 等）委托给真实 *testing.T。
type guardTB struct {
	testing.TB
	failed bool
	msg    string
}

func (g *guardTB) Fail()    { g.failed = true }
func (g *guardTB) FailNow() { g.failed = true; panic(guardFatal{}) }
func (g *guardTB) Fatal(args ...any) {
	g.failed = true
	g.msg = fmt.Sprint(args...)
	panic(guardFatal{})
}
func (g *guardTB) Fatalf(format string, args ...any) {
	g.failed = true
	g.msg = fmt.Sprintf(format, args...)
	panic(guardFatal{})
}
func (g *guardTB) Error(args ...any) { g.failed = true; g.msg = fmt.Sprint(args...) }
func (g *guardTB) Errorf(format string, args ...any) {
	g.failed = true
	g.msg = fmt.Sprintf(format, args...)
}
func (g *guardTB) Helper() {}

// expectGuardFatal 在子测试中运行 fn，断言守卫 helper（经替身 TB 调用）触发了
// Fatal：真实 *testing.T 供 fixture 准备使用（此阶段的失败是真失败），替身 TB
// 供被测 helper 使用。
func expectGuardFatal(t *testing.T, name string, fn func(t *testing.T, tb testing.TB)) {
	t.Helper()
	t.Run(name, func(st *testing.T) {
		st.Helper()
		g := &guardTB{TB: st}
		func() {
			defer func() {
				if r := recover(); r != nil {
					if _, ok := r.(guardFatal); !ok {
						panic(r)
					}
				}
			}()
			fn(st, g)
		}()
		if !g.failed {
			st.Errorf("期望守卫断言触发 Fatal，但未失败（防空转负例失效）: %s", g.msg)
		}
	})
}
