package guard

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/lynx-go/grpcapi/authz"
	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// AccessExtensionKey 是 swagger access 扩展的库默认键名。项目沿用自有键名
// （如 x-torchwood-access）时经 SwaggerOptions.AccessExtension 覆盖；
// 提供常量只为消除手写拼错。
const AccessExtensionKey = "x-grpcapi-access"

// SwaggerOptions 是 SwaggerAccessMatches 的输入。
type SwaggerOptions struct {
	// GenprotoSubdirs 相对项目 genproto 根的子目录清单（如 {"server/v1"}），
	// 逐目录扫描 *.swagger.json。
	GenprotoSubdirs []string

	// GenprotoRoot 项目 genproto 目录路径。
	GenprotoRoot string

	// Files 业务 proto 文件描述符清单（与 genproto 生成物一一对应的单一事实源，
	// 通常与启动期 authz.Build 的输入同源）。
	Files []protoreflect.FileDescriptor

	// Policies 策略注册表（authz.Build 的产物）。
	Policies *authz.PolicySet

	// AccessExtension swagger access 扩展键名（空 = AccessExtensionKey）。
	AccessExtension string

	// ErrorResponseRef 期望的 default 响应 $ref（如 "#/definitions/v1ErrorResponse"）。
	// 空则在各 swagger 的 definitions 中动态查找（“小写包名前缀 + ErrorResponse
	// 消息名”形态且唯一命中；找不到或有歧义即 Fatal）。
	ErrorResponseRef string

	// MinFiles / MinOps 是防空转下限门禁：断言至少检查到多少个 swagger 文件 /
	// operation（项目按自身规模设定；MinOps<=0 直接 Fatal）。
	MinFiles, MinOps int

	// ServiceAccess 解析服务默认 access 档（method_auth 缺省回落源，
	// 通常包装 service_auth 收集逻辑）。任一业务服务解析失败即 Fatal。
	ServiceAccess func(service string) (string, bool)
}

// swaggerOperation 是 swagger.json 中单个 HTTP operation 的最小解析结构。
// 注意 default 响应位于 operation.responses.default（非 operation 顶层）。
type swaggerOperation struct {
	OperationID string `json:"operationId"`
	Responses   struct {
		Default struct {
			Schema struct {
				Ref string `json:"$ref"`
			} `json:"schema"`
		} `json:"default"`
	} `json:"responses"`
}

// SwaggerAccessMatches 断言 genproto/**/*.swagger.json 的 access 扩展与
// authz.PolicySet 完全一致（平移自 torchwood
// TestSwaggerAccessExtensionMatchesCollectMethodsByAccess）：
//
//  1. 每个 swagger 顶层扩展 == ServiceAccess(service)（服务默认档）；
//  2. 每个 operation 的有效扩展（显式否则继承顶层）== 策略 access 字符串；
//  3. operationId 按 LastIndex("_") 解析 RPC；"{N}" 数字后缀（additional_bindings
//     生成，从 2 起编号）必须落在该 RPC 真实声明的绑定数内；
//  4. 每个 operation 的 default 响应 $ref 必须命中（ErrorResponseRef 或动态查找）；
//  5. 反向覆盖：策略表登记的每个方法都必须在 swagger 中出现 ≥1 次
//     （缺失通常意味着漏配 google.api.http 注解，会从机器可读面静默消失）；
//  6. MinFiles/MinOps 下限门禁。
//
// 空参防御：Files 空、Policies nil、ServiceAccess nil、GenprotoRoot/Subdirs 空、
// MinOps<=0 一律 Fatal（拒绝空转的假绿灯）。
func SwaggerAccessMatches(t *testing.T, o SwaggerOptions) {
	t.Helper()
	swaggerAccessMatches(t, o)
}

func swaggerAccessMatches(tb testing.TB, o SwaggerOptions) {
	switch {
	case len(o.Files) == 0:
		tb.Fatal("SwaggerOptions.Files 为空：拒绝空转（请传入业务 proto 文件描述符清单）")
	case o.Policies == nil:
		tb.Fatal("SwaggerOptions.Policies 为 nil：拒绝空转")
	case o.ServiceAccess == nil:
		tb.Fatal("SwaggerOptions.ServiceAccess 为 nil：拒绝空转（服务默认档解析必须显式注入）")
	case o.GenprotoRoot == "" || len(o.GenprotoSubdirs) == 0:
		tb.Fatal("SwaggerOptions.GenprotoRoot/GenprotoSubdirs 为空：拒绝空转")
	case o.MinOps <= 0:
		tb.Fatal("SwaggerOptions.MinOps <= 0：拒绝空转（operation 下限门禁必须为正数）")
	}
	accessExt := o.AccessExtension
	if accessExt == "" {
		accessExt = AccessExtensionKey
	}

	accessOf := make(map[string]string)  // 全方法名 → access 字符串（来自 PolicySet）
	defaultOf := make(map[string]string) // 服务全名 → 服务默认 access（来自 ServiceAccess）
	byProtoPath := make(map[string]protoreflect.FileDescriptor, len(o.Files))
	for _, fd := range o.Files {
		byProtoPath[fd.Path()] = fd
		for i := 0; i < fd.Services().Len(); i++ {
			s := fd.Services().Get(i)
			svc := string(s.FullName())
			def, ok := o.ServiceAccess(svc)
			if !ok {
				tb.Fatalf("service %s 无法解析服务默认 access（ServiceAccess 返回 false）", svc)
			}
			defaultOf[svc] = def
		}
	}
	for _, p := range o.Policies.Methods() {
		as, ok := accessString(p.Access)
		if !ok {
			tb.Fatalf("method %s access 非法（%d）：策略表不应包含 UNSPECIFIED/未知档位", p.Method, int(p.Access))
		}
		accessOf[p.Method] = as
	}

	seenMethods := make(map[string]int) // 全方法名 → 在 swagger 中出现的次数
	badDefaultRef := make([]string, 0, 4)
	defaultRefOK := 0
	checkedOps := 0
	checkedFiles := 0

	for _, sub := range o.GenprotoSubdirs {
		dir := filepath.Join(o.GenprotoRoot, sub)
		entries, err := os.ReadDir(dir)
		if err != nil {
			tb.Fatalf("读取 swagger 目录 %s 失败: %v", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".swagger.json") {
				continue
			}
			protoPath := sub + "/" + strings.TrimSuffix(name, ".swagger.json") + ".proto"
			fd, ok := byProtoPath[protoPath]
			if !ok {
				// 纯消息文件 / 框架产物无业务服务，跳过（与 torchwood 同语义）。
				tb.Logf("跳过无对应业务 proto 的 swagger 文件: %s", protoPath)
				continue
			}
			services := fd.Services()
			if services.Len() != 1 {
				tb.Fatalf("%s 应恰好包含一个业务服务（实际 %d 个）", protoPath, services.Len())
			}
			service := services.Get(0)
			serviceName := string(service.FullName())

			raw, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- 测试输入路径来自项目 genproto
			if err != nil {
				tb.Fatalf("读取 %s 失败: %v", name, err)
			}
			var doc struct {
				Paths       map[string]map[string]json.RawMessage `json:"paths"`
				Definitions map[string]json.RawMessage            `json:"definitions"`
			}
			if err := json.Unmarshal(raw, &doc); err != nil {
				tb.Fatalf("解析 %s 失败: %v", name, err)
			}
			var topLevel map[string]json.RawMessage
			if err := json.Unmarshal(raw, &topLevel); err != nil {
				tb.Fatalf("解析 %s 失败: %v", name, err)
			}
			topAccess := jsonString(tb, topLevel[accessExt], "%s 顶层扩展 %s", name, accessExt)
			checkedFiles++

			wantDefault := defaultOf[serviceName]
			if topAccess != wantDefault {
				tb.Fatalf("%s 顶层 %s=%q 与服务默认 access 不一致（%s 期望 %q）",
					name, accessExt, topAccess, serviceName, wantDefault)
			}

			defaultRef := o.ErrorResponseRef
			if defaultRef == "" {
				defaultRef = "#" + lookupErrorDefinition(tb, name, doc.Definitions)
			}

			for _, ops := range doc.Paths {
				for method, rawOp := range ops {
					var op swaggerOperation
					if err := json.Unmarshal(rawOp, &op); err != nil {
						tb.Fatalf("%s %s %s 解析失败: %v", name, method, rawOp, err)
					}
					if op.OperationID == "" {
						continue
					}
					var opLevel map[string]json.RawMessage
					if err := json.Unmarshal(rawOp, &opLevel); err != nil {
						tb.Fatalf("%s %s 解析失败: %v", name, method, err)
					}
					opAccess := jsonString(tb, opLevel[accessExt], "%s %s 扩展 %s", name, op.OperationID, accessExt)

					// default 响应必须引用运行时真实错误体（如 ErrorResponse），
					// rpcStatus 属生成器默认值失真，回归即红。
					if op.Responses.Default.Schema.Ref == defaultRef {
						defaultRefOK++
					} else {
						badDefaultRef = append(badDefaultRef,
							name+"/"+op.OperationID+" → "+op.Responses.Default.Schema.Ref)
					}

					// operationId 格式为 "{Service}_{RPC}"；additional_bindings
					// 生成 "{Service}_{RPC}{N}" 后缀（如 Check2，N 从 2 起）。
					sep := strings.LastIndex(op.OperationID, "_")
					if sep <= 0 {
						tb.Fatalf("%s operationId %q 格式非法（应为 {Service}_{RPC}）", name, op.OperationID)
					}
					rpc := op.OperationID[sep+1:]
					md := findMethodByOperationID(service, rpc)
					if md == nil {
						tb.Fatalf("%s operationId %q 找不到对应 RPC（数字后缀越界或 RPC 不存在）", name, op.OperationID)
					}

					fullMethod := "/" + serviceName + "/" + string(md.Name())
					want, ok := accessOf[fullMethod]
					if !ok {
						tb.Fatalf("%s %q 不在策略注册表中（Policies 未覆盖该文件？）", name, fullMethod)
					}

					effective := opAccess
					if effective == "" {
						effective = topAccess
					}
					if effective != want {
						tb.Fatalf("%s %s 有效 %s=%q 与策略 access %q 不一致",
							name, op.OperationID, accessExt, effective, want)
					}
					seenMethods[fullMethod]++
					checkedOps++
				}
			}
		}
	}

	if checkedFiles < o.MinFiles {
		tb.Fatalf("swagger 文件检查数量 %d 低于下限 %d（GenprotoRoot/Subdirs 配错？）", checkedFiles, o.MinFiles)
	}
	if checkedOps < o.MinOps {
		tb.Fatalf("swagger operation 检查数量 %d 低于下限 %d", checkedOps, o.MinOps)
	}
	if len(badDefaultRef) > 0 {
		tb.Fatalf("以下 operation 的 default 响应未命中期望引用（应重跑 proto 生成）：\n%s",
			strings.Join(badDefaultRef, "\n"))
	}
	if defaultRefOK < checkedOps {
		tb.Fatalf("default 响应引用计数异常：ok=%d ops=%d", defaultRefOK, checkedOps)
	}

	// 反向覆盖率：策略表登记的每个方法都必须在 swagger 出现 ≥1 次。
	missing := make([]string, 0, 4)
	for fm := range accessOf {
		if seenMethods[fm] == 0 {
			missing = append(missing, fm)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		tb.Fatalf("以下方法未出现在任何 swagger paths 中（漏配 google.api.http 注解？）：\n%s",
			strings.Join(missing, "\n"))
	}
}

// jsonString 从 RawMessage 解析 JSON 字符串；缺失（nil）返回空串，非字符串 Fatal。
func jsonString(tb testing.TB, raw json.RawMessage, context string, args ...any) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		tb.Fatalf("%s：扩展值不是字符串: %v", fmt.Sprintf(context, args...), err)
	}
	return s
}

// lookupErrorDefinition 在 definitions 中动态查找 ErrorResponse 定义键
// （“小写包名前缀 + 消息名”形态且唯一命中，如 v1ErrorResponse）。
// 命中返回 "/definitions/<key>"（带前导 #）；否则 Fatal。
func lookupErrorDefinition(tb testing.TB, file string, definitions map[string]json.RawMessage) string {
	const suffix = "ErrorResponse"
	var candidates []string
	for name := range definitions {
		idx := strings.LastIndex(name, suffix)
		if idx <= 0 || idx+len(suffix) != len(name) {
			continue
		}
		if !lowerPackagePrefix(name[:idx]) {
			continue
		}
		candidates = append(candidates, name)
	}
	switch len(candidates) {
	case 1:
		return "/definitions/" + candidates[0]
	case 0:
		tb.Fatalf("%s definitions 中找不到 ErrorResponse 定义（SwaggerOptions.ErrorResponseRef 为空时的动态查找失败；生成器命名规则变更需重验）", file)
	default:
		sort.Strings(candidates)
		tb.Fatalf("%s definitions 中 ErrorResponse 定义有歧义：%s（请显式指定 SwaggerOptions.ErrorResponseRef）",
			file, strings.Join(candidates, ", "))
	}
	return ""
}

// lowerPackagePrefix 判定前缀是否为“小写包名段”形态（字母小写/数字/点）。
func lowerPackagePrefix(s string) bool {
	if s == "" {
		return false
	}
	for _, ch := range s {
		switch {
		case ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9', ch == '.':
		default:
			return false
		}
	}
	return true
}

// accessString 映射 authz.AccessLevel → swagger access 字符串。固定小写映射，
// 不提供项目覆盖——项目扩展名不同只需改 AccessExtension。
func accessString(l authz.AccessLevel) (string, bool) {
	switch l {
	case authz.AccessPublic:
		return "public", true
	case authz.AccessEndUser:
		return "end_user", true
	case authz.AccessServer:
		return "server", true
	case authz.AccessPermission:
		return "permission", true
	case authz.AccessSystem:
		return "system", true
	}
	return "", false
}

// findMethodByOperationID 先按原名精确查找；未命中时按 additional_bindings 的
// "{N}" 数字后缀解析（如 Check2），并校验 N 落在该方法真实声明过的 HTTP 绑定
// 索引范围内（防数字截断把未知 RPC 误配到形似方法）。
// 平移自 torchwood findMethodByOperationID。
func findMethodByOperationID(service protoreflect.ServiceDescriptor, rpc string) protoreflect.MethodDescriptor {
	methods := service.Methods()
	for i := 0; i < methods.Len(); i++ {
		if string(methods.Get(i).Name()) == rpc {
			return methods.Get(i)
		}
	}
	// 仅当尾部是纯数字后缀时尝试绑定索引匹配：openapiv2 对 additional_bindings
	// 从 2 起编号（主规则走精确匹配），因此要求 2 <= N <= 该方法声明的绑定总数，
	// 基名必须真实存在。
	if idx := strings.LastIndexAny(rpc, "0123456789"); idx >= 0 && idx == len(rpc)-1 {
		base, numStr := rpc[:idx], rpc[idx:]
		if n, err := strconv.Atoi(numStr); err == nil && n >= 2 {
			for i := 0; i < methods.Len(); i++ {
				m := methods.Get(i)
				if string(m.Name()) == base && n <= methodHTTPBindingCount(m) {
					return m
				}
			}
		}
	}
	return nil
}

// methodHTTPBindingCount 返回方法声明的 google.api.http 绑定总数
// （主规则 1 + additional_bindings）。未声明 http 规则返回 0。
func methodHTTPBindingCount(m protoreflect.MethodDescriptor) int {
	if m.Options() == nil {
		return 0
	}
	rule, ok := proto.GetExtension(m.Options(), annotations.E_Http).(*annotations.HttpRule)
	if !ok || rule == nil {
		return 0
	}
	return 1 + len(rule.GetAdditionalBindings())
}

// SwaggerSnakeCaseProperties 抽检各 swagger 文件 definitions 的属性名必须为
// snake_case（要求 openapiv2 生成器 json_names_for_fields=false 的回归门禁；
// "@type" 为 protojson Any 魔法键，豁免）。任一目录扫不到 swagger 文件即 Fatal
// （防空转）。
func SwaggerSnakeCaseProperties(t *testing.T, root string, subdirs []string) {
	t.Helper()
	swaggerSnakeCaseProperties(t, root, subdirs)
}

func swaggerSnakeCaseProperties(tb testing.TB, root string, subdirs []string) {
	if root == "" || len(subdirs) == 0 {
		tb.Fatal("SwaggerSnakeCaseProperties: root/subdirs 为空：拒绝空转")
	}
	snake := func(s string) bool {
		if s == "" {
			return true
		}
		for i, ch := range s {
			if ch >= 'A' && ch <= 'Z' {
				return false
			}
			if i == 0 && ch >= '0' && ch <= '9' {
				return false
			}
			if ch != '_' && (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') {
				return false
			}
		}
		return true
	}
	var bad []string
	files := 0
	for _, sub := range subdirs {
		dir := filepath.Join(root, sub)
		entries, err := os.ReadDir(dir)
		if err != nil {
			tb.Fatalf("读取 swagger 目录 %s 失败: %v", dir, err)
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".swagger.json") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- 测试输入路径来自项目 genproto
			if err != nil {
				tb.Fatalf("读取 %s 失败: %v", e.Name(), err)
			}
			files++
			var doc struct {
				Definitions map[string]struct {
					Properties map[string]json.RawMessage `json:"properties"`
				} `json:"definitions"`
			}
			if err := json.Unmarshal(raw, &doc); err != nil {
				tb.Fatalf("解析 %s 失败: %v", e.Name(), err)
			}
			for defName, def := range doc.Definitions {
				for prop := range def.Properties {
					if prop == "@type" {
						continue
					}
					if !snake(prop) {
						bad = append(bad, e.Name()+"/"+defName+"."+prop)
					}
				}
			}
		}
	}
	if files == 0 {
		tb.Fatal("SwaggerSnakeCaseProperties: 未扫描到任何 swagger 文件（拒绝空转）")
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		tb.Fatalf("以下 swagger 属性名非 snake_case（检查生成器 json_names_for_fields 配置）：\n%s",
			strings.Join(bad, "\n"))
	}
}

// SwaggerNoDefinition 断言各 swagger 文件（含引用点）不含被禁定义名
// （如 "rpcStatus"：生成器默认注入的错误体与运行时错误体不符，buf
// disable_default_errors 配置回退即红）。逐文件做原文包含检查——引用与定义
// 一网打尽。任一目录扫不到 swagger 文件即 Fatal（防空转）。
func SwaggerNoDefinition(t *testing.T, root string, subdirs []string, banned string) {
	t.Helper()
	swaggerNoDefinition(t, root, subdirs, banned)
}

func swaggerNoDefinition(tb testing.TB, root string, subdirs []string, banned string) {
	switch {
	case root == "" || len(subdirs) == 0:
		tb.Fatal("SwaggerNoDefinition: root/subdirs 为空：拒绝空转")
	case banned == "":
		tb.Fatal("SwaggerNoDefinition: banned 为空：拒绝空转")
	}
	files := 0
	var offenders []string
	for _, sub := range subdirs {
		dir := filepath.Join(root, sub)
		err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(d.Name(), ".swagger.json") {
				return nil
			}
			raw, err := os.ReadFile(path) // #nosec G304 -- 测试输入路径来自项目 genproto
			if err != nil {
				return err
			}
			files++
			if strings.Contains(string(raw), banned) {
				offenders = append(offenders, filepath.ToSlash(path))
			}
			return nil
		})
		if err != nil {
			tb.Fatalf("扫描 %s 失败: %v", dir, err)
		}
	}
	if files == 0 {
		tb.Fatal("SwaggerNoDefinition: 未扫描到任何 swagger 文件（拒绝空转）")
	}
	if len(offenders) > 0 {
		tb.Fatalf("以下 swagger 仍含被禁定义 %q（生成器 disable_default_errors 配置被回退？）：\n%s",
			banned, strings.Join(offenders, "\n"))
	}
}
