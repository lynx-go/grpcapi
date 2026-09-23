package guard

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/lynx-go/grpcapi/authz"
)

// MatrixOptions 是 RenderMatrix 的渲染选项：列头与每方法行回调由项目定义
// （列投影是项目文案主权，库只保证结构合法与输出确定性）。
type MatrixOptions struct {
	// Header 列头（不含首尾管道符）。
	Header []string

	// Row 把单个方法策略渲染为一行单元格；输出长度必须与 Header 一致。
	Row func(p authz.MethodPolicy) []string

	// Preamble 渲染在矩阵表前的文档头（生成来源、再生成方式等项目文案）。
	Preamble string

	// Appendix 渲染在矩阵表后的附录（如威胁模型已知取舍等静态文本）。
	Appendix string
}

// RenderMatrix 从 PolicySet 渲染 Markdown 授权矩阵。输出确定性：行按方法全名
// 排序（PolicySet.Methods() 的顺序契约不在此假设），列值全部来自 MethodPolicy
// 与 Row 回调。set/Row/Header 任一为空、或行宽与列头不一致时返回错误
// （防空转与静默生成残表）。
func RenderMatrix(set *authz.PolicySet, o MatrixOptions) ([]byte, error) {
	switch {
	case set == nil:
		return nil, fmt.Errorf("guard.RenderMatrix: PolicySet 为 nil")
	case o.Row == nil:
		return nil, fmt.Errorf("guard.RenderMatrix: Row 回调必填")
	case len(o.Header) == 0:
		return nil, fmt.Errorf("guard.RenderMatrix: Header 必填")
	}
	methods := set.Methods()
	if len(methods) == 0 {
		return nil, fmt.Errorf("guard.RenderMatrix: PolicySet 为空（拒绝渲染空文档覆盖磁盘）")
	}

	type rowPair struct {
		method string
		cells  []string
	}
	rows := make([]rowPair, 0, len(methods))
	for _, p := range methods {
		cells := o.Row(p)
		if len(cells) != len(o.Header) {
			return nil, fmt.Errorf("guard.RenderMatrix: 方法 %s 的行宽 %d 与列头 %d 不一致",
				p.Method, len(cells), len(o.Header))
		}
		rows = append(rows, rowPair{method: p.Method, cells: cells})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].method < rows[j].method })

	var buf bytes.Buffer
	if o.Preamble != "" {
		buf.WriteString(o.Preamble)
		buf.WriteString("\n")
	}
	buf.WriteString("| " + strings.Join(o.Header, " | ") + " |\n")
	seps := make([]string, len(o.Header))
	for i := range seps {
		seps[i] = "---"
	}
	buf.WriteString("| " + strings.Join(seps, " | ") + " |\n")
	for _, r := range rows {
		buf.WriteString("| " + strings.Join(r.cells, " | ") + " |\n")
	}
	if o.Appendix != "" {
		buf.WriteString(o.Appendix)
		if !strings.HasSuffix(o.Appendix, "\n") {
			buf.WriteString("\n")
		}
	}
	return buf.Bytes(), nil
}

// AssertDocUnchanged 与磁盘文档做字节级比对（CI 锁：渲染结果 ≠ 磁盘即红）。
// 不一致时把渲染结果写到 path+".actual" 供人工比对，并 Fatal 提示首个差异行。
// 文件缺失同样 Fatal（文档尚未生成初版）。
func AssertDocUnchanged(t *testing.T, rendered []byte, path string) {
	t.Helper()
	assertDocUnchanged(t, rendered, path)
}

func assertDocUnchanged(tb testing.TB, rendered []byte, path string) {
	disk, err := os.ReadFile(path) // #nosec G304 -- 测试输入路径由调用方（项目守卫测试）给定
	if err != nil {
		tb.Fatalf("读取 %s 失败（文档尚未生成初版？）: %v", path, err)
	}
	if bytes.Equal(disk, rendered) {
		return
	}
	actual := path + ".actual"
	if werr := os.WriteFile(actual, rendered, 0o644); werr != nil {
		tb.Logf("写出 %s 失败: %v", actual, werr)
	}
	tb.Fatalf("文档与渲染结果漂移（首个差异在第 %d 行；磁盘 %d 字节 vs 渲染 %d 字节）：已写出 %s 供比对，确认后请覆盖磁盘文件并随策略变更一起提交",
		firstDiffLine(disk, rendered), len(disk), len(rendered), actual)
}

// firstDiffLine 返回两份内容首个差异的 1 基行号（完全相同返回 0）。
func firstDiffLine(a, b []byte) int {
	line := 1
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var ca, cb byte
		if i < len(a) {
			ca = a[i]
		}
		if i < len(b) {
			cb = b[i]
		}
		if ca != cb {
			return line
		}
		if ca == '\n' {
			line++
		}
	}
	return 0
}
