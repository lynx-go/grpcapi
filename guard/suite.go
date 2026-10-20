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

// Run 一次跑完配置的守卫；每个检查是独立子测试。
func Run(t *testing.T, cfg SuiteConfig) {
	t.Helper()
	if cfg.Surface == nil {
		t.Fatal("guard.Run: Surface 为 nil：拒绝空转")
	}
	var docs []Document
	if cfg.Docs != nil {
		loaded, err := cfg.Docs.Load(context.Background())
		if err != nil {
			t.Fatalf("guard.Run: load docs: %v", err)
		}
		docs = loaded
	}
	if cfg.Docs == nil && (cfg.Naming != nil || len(cfg.Banned) > 0) {
		t.Fatal("guard.Run: Naming/Banned 检查需要 Docs")
	}

	if cfg.Docs != nil {
		t.Run("openapi/policy", func(t *testing.T) {
			opts := cfg.Policy
			if opts.MinDocuments == 0 {
				opts.MinDocuments = cfg.MinDocuments
			}
			if opts.MinOperations == 0 {
				opts.MinOperations = cfg.MinOperations
			}
			AssertDocuments(t, staticLoader(docs), cfg.Surface, opts)
		})
	}
	if cfg.Naming != nil {
		t.Run("openapi/naming", func(t *testing.T) {
			AssertJSONNaming(t, docs, cfg.Naming)
		})
	}
	if len(cfg.Banned) > 0 {
		t.Run("openapi/banned", func(t *testing.T) {
			for _, banned := range cfg.Banned {
				AssertNoSchema(t, docs, banned)
			}
		})
	}
	if cfg.SDK != nil {
		t.Run("sdk/coverage", func(t *testing.T) {
			AssertSurfaceCoverage(t, cfg.Surface, cfg.SDK.API, cfg.SDK.Prefix, cfg.SDK.Client, cfg.SDK.Options)
			if cfg.SDK.WantMethods > 0 {
				AssertSurfaceMethodCount(t, cfg.Surface, cfg.SDK.API, cfg.SDK.Prefix, cfg.SDK.WantMethods)
			}
		})
	}
	if cfg.Manifest != nil {
		t.Run("manifest/snapshot", func(t *testing.T) {
			data, err := cfg.Surface.Policy().Manifest().JSON()
			if err != nil {
				t.Fatalf("manifest JSON: %v", err)
			}
			AssertDocUnchanged(t, data, cfg.Manifest.Path)
		})
	}
	if cfg.Matrix != nil {
		t.Run("matrix/snapshot", func(t *testing.T) {
			rendered, err := RenderMatrix(cfg.Surface.Policy(), cfg.Matrix.Options)
			if err != nil {
				t.Fatalf("RenderMatrix: %v", err)
			}
			AssertDocUnchanged(t, rendered, cfg.Matrix.Path)
		})
	}
}
