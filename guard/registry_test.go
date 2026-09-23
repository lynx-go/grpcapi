package guard

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoregistry"
)

const (
	registryCountPkg    = "guardtest.registry.count.v1"
	registryCoveragePkg = "guardtest.registry.coverage.v1"
)

func TestAssertMethodCount(t *testing.T) {
	fd := fixtureFileDescriptor(t, "guardtest/registry/count/v1/demo.proto", registryCountPkg, 0)
	if err := protoregistry.GlobalFiles.RegisterFile(fd); err != nil {
		t.Fatalf("注册 fixture 失败: %v", err)
	}

	AssertMethodCount(t, registryCountPkg, 2)

	// 点分边界：截断的段前缀 "…count.v" 不得误中 "…count.v1"（防 v1/v10 混淆）。
	expectGuardFatal(t, "点分边界（v 前缀不误中 v1）", func(_ *testing.T, tb testing.TB) {
		assertMethodCount(tb, "guardtest.registry.count.v", 2)
	})
	expectGuardFatal(t, "快照不符", func(_ *testing.T, tb testing.TB) {
		assertMethodCount(tb, registryCountPkg, 3)
	})
	expectGuardFatal(t, "空前缀", func(_ *testing.T, tb testing.TB) {
		assertMethodCount(tb, "", 2)
	})
	expectGuardFatal(t, "未知前缀（零命中）", func(_ *testing.T, tb testing.TB) {
		assertMethodCount(tb, "guardtest.registry.nope.v1", 0)
	})
}

// coverageWrapper 模拟 SDK wrapper：方法名与 proto RPC 同名（值接收者）。
type coverageWrapper struct{}

func (coverageWrapper) Ping()      {}
func (coverageWrapper) AdminPing() {}

// coveragePartialWrapper 负例 fixture：故意缺 AdminPing。
type coveragePartialWrapper struct{}

func (coveragePartialWrapper) Ping() {}

// coverageIface 模拟接口型 wrapper 字段。
type coverageIface interface {
	Ping()
	AdminPing()
}

func TestAssertServiceCoverage(t *testing.T) {
	fd := fixtureFileDescriptor(t, "guardtest/registry/coverage/v1/demo.proto", registryCoveragePkg, 0)
	if err := protoregistry.GlobalFiles.RegisterFile(fd); err != nil {
		t.Fatalf("注册 fixture 失败: %v", err)
	}

	t.Run("值型 wrapper 正例（DemoService → demo）", func(st *testing.T) {
		type client struct{ demo coverageWrapper }
		AssertServiceCoverage(st, registryCoveragePkg, &client{})
	})

	t.Run("接口型 wrapper 正例", func(st *testing.T) {
		type client struct{ demo coverageIface }
		AssertServiceCoverage(st, registryCoveragePkg, client{})
	})

	expectGuardFatal(t, "缺 RPC 方法", func(_ *testing.T, tb testing.TB) {
		type client struct{ demo coveragePartialWrapper }
		assertServiceCoverage(tb, registryCoveragePkg, &client{})
	})

	expectGuardFatal(t, "缺 wrapper 字段", func(_ *testing.T, tb testing.TB) {
		type client struct{ other coverageWrapper }
		assertServiceCoverage(tb, registryCoveragePkg, &client{})
	})

	expectGuardFatal(t, "字段名未去 Service 后缀", func(_ *testing.T, tb testing.TB) {
		type client struct{ demoService coverageWrapper }
		assertServiceCoverage(tb, registryCoveragePkg, &client{})
	})

	expectGuardFatal(t, "client 非结构体", func(_ *testing.T, tb testing.TB) {
		assertServiceCoverage(tb, registryCoveragePkg, 42)
	})

	expectGuardFatal(t, "client nil", func(_ *testing.T, tb testing.TB) {
		assertServiceCoverage(tb, registryCoveragePkg, nil)
	})

	expectGuardFatal(t, "空前缀", func(_ *testing.T, tb testing.TB) {
		type client struct{ demo coverageWrapper }
		assertServiceCoverage(tb, "", &client{})
	})

	expectGuardFatal(t, "前缀零命中", func(_ *testing.T, tb testing.TB) {
		type client struct{ demo coverageWrapper }
		assertServiceCoverage(tb, "guardtest.registry.nope.v1", &client{})
	})
}
