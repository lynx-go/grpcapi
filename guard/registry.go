package guard

import (
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// AssertMethodCount 遍历 protoregistry.GlobalFiles，统计 packagePrefix 下全部
// service 的方法总数并断言等于 want（快照锁：防静默增删 RPC；不等时 Fatal 并
// 给出实际数与快照更新提示）。前缀按点分边界匹配（"pkg.v1" 命中 "pkg.v1.Svc"
// 而不误中 "pkg.v10.Svc"）。前缀下扫不到任何 service 时 Fatal（防前缀写错空转）。
func AssertMethodCount(t *testing.T, packagePrefix string, want int) {
	t.Helper()
	assertMethodCount(t, packagePrefix, want)
}

func assertMethodCount(tb testing.TB, packagePrefix string, want int) {
	if packagePrefix == "" {
		tb.Fatal("AssertMethodCount: packagePrefix 为空：拒绝空转")
	}
	count := 0
	services := 0
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		svcs := fd.Services()
		for i := 0; i < svcs.Len(); i++ {
			svc := svcs.Get(i)
			if !nameUnderPrefix(string(svc.FullName()), packagePrefix) {
				continue
			}
			services++
			count += svc.Methods().Len()
		}
		return true
	})
	if services == 0 {
		tb.Fatalf("%s 下未发现任何 service（前缀写错或文件未注册进 protoregistry？拒绝快照空转）", packagePrefix)
	}
	if count != want {
		tb.Fatalf("%s 下 service 方法总数 = %d，与快照 %d 不符：新增/删除 RPC 请同步更新调用方快照常量",
			packagePrefix, count, want)
	}
}

// nameUnderPrefix 按点分边界判定全名是否落在前缀下。
func nameUnderPrefix(full, prefix string) bool {
	if !strings.HasPrefix(full, prefix) {
		return false
	}
	if len(full) == len(prefix) || full[len(prefix)] == '.' {
		return true
	}
	return strings.HasSuffix(prefix, ".")
}

// AssertServiceCoverage 反射断言：registry 中 packagePrefix 下每个 proto service
// 在 client 结构体上都有同名 wrapper 字段（服务名去 "Service" 后缀、首字母小写，
// 如 ProjectsService → projects），且每个 service 的每个 RPC 在该字段类型上都有
// 同名导出方法——拦住类型化封装面静默滞后于 proto 演进。前缀下扫不到任何
// service 时 Fatal（防前缀写错空转）。
func AssertServiceCoverage(t *testing.T, packagePrefix string, client any) {
	t.Helper()
	assertServiceCoverage(t, packagePrefix, client)
}

func assertServiceCoverage(tb testing.TB, packagePrefix string, client any) {
	switch {
	case packagePrefix == "":
		tb.Fatal("AssertServiceCoverage: packagePrefix 为空：拒绝空转")
	case client == nil:
		tb.Fatal("AssertServiceCoverage: client 为 nil：拒绝空转")
	}
	cv := reflect.ValueOf(client)
	for cv.Kind() == reflect.Pointer {
		cv = cv.Elem()
	}
	if cv.Kind() != reflect.Struct {
		tb.Fatalf("AssertServiceCoverage: client 必须是结构体（或其指针），得到 %s", cv.Kind())
	}
	ct := cv.Type()

	found := 0
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		svcs := fd.Services()
		for i := 0; i < svcs.Len(); i++ {
			svc := svcs.Get(i)
			if !nameUnderPrefix(string(svc.FullName()), packagePrefix) {
				continue
			}
			found++
			fieldName := lowerFirst(strings.TrimSuffix(string(svc.Name()), "Service"))
			field, ok := ct.FieldByName(fieldName)
			if !ok {
				tb.Fatalf("client 缺少 %s 的 wrapper 字段 %q", svc.FullName(), fieldName)
			}

			ms := svc.Methods()
			methodSet := methodSetType(field.Type)
			for j := 0; j < ms.Len(); j++ {
				name := string(ms.Get(j).Name())
				m, ok := methodSet.MethodByName(name)
				if !ok {
					tb.Fatalf("%s.%s 缺少同名词导出方法（新增 RPC 未补 wrapper？）",
						svc.FullName(), name)
				}
				if m.PkgPath != "" {
					tb.Fatalf("%s.%s 必须是导出方法", svc.FullName(), name)
				}
			}
		}
		return true
	})
	if found == 0 {
		tb.Fatalf("packagePrefix %q 下未发现任何 service（前缀写错或文件未注册进 protoregistry？）", packagePrefix)
	}
}

// methodSetType 归一到可查方法集的反射类型：接口取本身（接口方法集即全部
// 方法），结构体取其指针（指针方法集含值与指针接收者方法），其余原样。
func methodSetType(typ reflect.Type) reflect.Type {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	switch typ.Kind() {
	case reflect.Interface:
		return typ
	case reflect.Struct:
		return reflect.PointerTo(typ)
	default:
		return typ
	}
}

// lowerFirst 首字母小写（ASCII；非 ASCII 首字母原样返回——proto 服务名约定为
// ASCII 标识符）。
func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	if b[0] >= 'A' && b[0] <= 'Z' {
		b[0] += 'a' - 'A'
	}
	return string(b)
}
