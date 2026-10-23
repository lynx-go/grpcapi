package guard

import (
	"context"
	"testing"

	"github.com/lynx-go/grpcapi/surface"
)

// ManifestConfig 是策略 manifest 快照配置。
type ManifestConfig struct {
	Path string
}

// MatrixConfig 是授权矩阵快照配置。
type MatrixConfig struct {
	Path    string
	Options MatrixOptions
}

// SuiteConfig 是 guard.Run 的输入；零值字段跳过对应检查。
type SuiteConfig struct {
	Surface *surface.Surface
	Docs    Loader

	Policy MatchOptions
	Naming NamingRule
	Banned []string

	Matrix   *MatrixConfig
	Manifest *ManifestConfig
	SDK      *SDKConfig

	MinDocuments  int
	MinOperations int
}

// SDKConfig 是 Surface SDK 覆盖检查配置。
type SDKConfig struct {
	API     string
	Prefix  string
	Client  any
	Options SDKOptions
	// WantMethods > 0 时同时锁定方法总数。
	WantMethods int
}

type staticLoader []Document

func (s staticLoader) Load(context.Context) ([]Document, error) { return s, nil }

// Run 一次跑完配置的守卫；每个检查是独立子测试。tb 收宽为 testing.TB
// 与 guard 其余断言一致：传 *testing.T 时仍是子测试形态，传替身 TB
// （测试里断言 Fatal）时顺序执行、失败经 TB 上报。
func Run(tb testing.TB, cfg SuiteConfig) {
	tb.Helper()
	if cfg.Surface == nil {
		tb.Fatal("guard.Run: Surface 为 nil：拒绝空转")
	}
	var docs []Document
	if cfg.Docs != nil {
		loaded, err := cfg.Docs.Load(context.Background())
		if err != nil {
			tb.Fatalf("guard.Run: load docs: %v", err)
		}
		docs = loaded
	}
	if cfg.Docs == nil && (cfg.Naming != nil || len(cfg.Banned) > 0) {
		tb.Fatal("guard.Run: Naming/Banned 检查需要 Docs")
	}

	sub := func(name string, fn func(testing.TB)) {
		tb.Helper()
		if t, ok := tb.(*testing.T); ok {
			t.Run(name, func(st *testing.T) {
				st.Helper()
				fn(st)
			})
			return
		}
		fn(tb)
	}

	if cfg.Docs != nil {
		sub("openapi/policy", func(tb testing.TB) {
			opts := cfg.Policy
			if opts.MinDocuments == 0 {
				opts.MinDocuments = cfg.MinDocuments
			}
			if opts.MinOperations == 0 {
				opts.MinOperations = cfg.MinOperations
			}
			AssertDocuments(tb, staticLoader(docs), cfg.Surface, opts)
		})
	}
	if cfg.Naming != nil {
		sub("openapi/naming", func(tb testing.TB) {
			AssertJSONNaming(tb, docs, cfg.Naming)
		})
	}
	if len(cfg.Banned) > 0 {
		sub("openapi/banned", func(tb testing.TB) {
			for _, banned := range cfg.Banned {
				AssertNoSchema(tb, docs, banned)
			}
		})
	}
	if cfg.SDK != nil {
		sub("sdk/coverage", func(tb testing.TB) {
			AssertSurfaceCoverage(tb, cfg.Surface, cfg.SDK.API, cfg.SDK.Prefix, cfg.SDK.Client, cfg.SDK.Options)
			if cfg.SDK.WantMethods > 0 {
				AssertSurfaceMethodCount(tb, cfg.Surface, cfg.SDK.API, cfg.SDK.Prefix, cfg.SDK.WantMethods)
			}
		})
	}
	if cfg.Manifest != nil {
		sub("manifest/snapshot", func(tb testing.TB) {
			data, err := cfg.Surface.Policy().Manifest().JSON()
			if err != nil {
				tb.Fatalf("manifest JSON: %v", err)
			}
			assertDocUnchanged(tb, data, cfg.Manifest.Path)
		})
	}
	if cfg.Matrix != nil {
		sub("matrix/snapshot", func(tb testing.TB) {
			rendered, err := RenderMatrix(cfg.Surface.Policy(), cfg.Matrix.Options)
			if err != nil {
				tb.Fatalf("RenderMatrix: %v", err)
			}
			assertDocUnchanged(tb, rendered, cfg.Matrix.Path)
		})
	}
}
