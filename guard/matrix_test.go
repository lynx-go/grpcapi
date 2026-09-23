package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lynx-go/grpcapi/authz"
)

const (
	matrixFixturePkg  = "guardtest.matrix.v1"
	matrixFixturePath = "guardtest/matrix/v1/demo.proto"
)

func TestRenderMatrixSnapshot(t *testing.T) {
	fd := fixtureFileDescriptor(t, matrixFixturePath, matrixFixturePkg, 0)
	set := fixturePolicies(t, fd)

	rendered, err := RenderMatrix(set, MatrixOptions{
		Header: []string{"Method", "Access"},
		Row: func(p authz.MethodPolicy) []string {
			acc, ok := accessString(p.Access)
			if !ok {
				t.Fatalf("method %s access 非法", p.Method)
			}
			return []string{p.Method, acc}
		},
		Preamble: "# 授权矩阵",
		Appendix: "## 附录",
	})
	if err != nil {
		t.Fatalf("RenderMatrix: %v", err)
	}

	// 快照断言：行按方法全名排序（AdminPing < Ping），Preamble/Appendix 原样。
	want := strings.Join([]string{
		"# 授权矩阵",
		"| Method | Access |",
		"| --- | --- |",
		"| /" + matrixFixturePkg + ".DemoService/AdminPing | public |",
		"| /" + matrixFixturePkg + ".DemoService/Ping | public |",
		"## 附录",
		"",
	}, "\n")
	if string(rendered) != want {
		t.Fatalf("矩阵快照不一致：\n--- want ---\n%s\n--- got ---\n%s", want, rendered)
	}
}

func TestRenderMatrixRejectsBadInput(t *testing.T) {
	fd := fixtureFileDescriptor(t, "guardtest/matrix/bad/v1/demo.proto", "guardtest.matrix.bad.v1", 0)
	set := fixturePolicies(t, fd)
	okOpts := MatrixOptions{
		Header: []string{"Method", "Access"},
		Row: func(p authz.MethodPolicy) []string {
			return []string{p.Method, "public"}
		},
	}

	if _, err := RenderMatrix(nil, okOpts); err == nil {
		t.Error("期望 nil PolicySet 报错")
	}
	if _, err := RenderMatrix(set, MatrixOptions{Header: okOpts.Header}); err == nil {
		t.Error("期望缺 Row 回调报错")
	}
	if _, err := RenderMatrix(set, MatrixOptions{Row: okOpts.Row}); err == nil {
		t.Error("期望缺 Header 报错")
	}
	badWidth := MatrixOptions{
		Header: []string{"Method", "Access", "Extra"},
		Row:    okOpts.Row,
	}
	if _, err := RenderMatrix(set, badWidth); err == nil {
		t.Error("期望行宽不一致报错")
	}
}

func TestAssertDocUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authz-matrix.md")
	if err := os.WriteFile(path, []byte("# 矩阵\n\n| a |\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 一致：通过。
	AssertDocUnchanged(t, []byte("# 矩阵\n\n| a |\n"), path)

	// 漂移：Fatal 且落盘 .actual。
	expectGuardFatal(t, "内容漂移", func(_ *testing.T, tb testing.TB) {
		assertDocUnchanged(tb, []byte("# 矩阵\n\n| b |\n"), path)
	})
	actual, err := os.ReadFile(path + ".actual") // #nosec G304 -- 测试自身写出的对比文件
	if err != nil {
		t.Fatalf(".actual 未落盘: %v", err)
	}
	if string(actual) != "# 矩阵\n\n| b |\n" {
		t.Fatalf(".actual 内容不符: %q", actual)
	}

	// 文件缺失：Fatal。
	expectGuardFatal(t, "文件缺失", func(_ *testing.T, tb testing.TB) {
		assertDocUnchanged(tb, []byte("x"), filepath.Join(t.TempDir(), "missing.md"))
	})
}
