// Package guard 是测试期断言族：把 proto 派生的 Surface、外部生成的
// OpenAPI 文档与 policy.Set 三方对齐，防止「代码、文档、策略」漂移。
//
// 只应在 _test.go 中 import 本包；它依赖 testing.TB，不属于运行时。
//
// # 推荐入口
//
//	guard.Run(t, guard.SuiteConfig{...})
//
// SuiteConfig 零值字段跳过对应检查；Manifest 与 Matrix 是快照锁——
// 权限矩阵发生变化时测试失败，必须显式更新快照文件，使授权面变更
// 在 code review 中可见。启动装配结果用 AssertRouteTable 比对
// server.Routes() 与策略集。
//
// # 单条断言
//
// AssertDocuments（文档 ↔ Surface 的 label/覆盖/命名）、
// AssertJSONNaming / AssertNoSchema、AssertSurfaceMethodCount /
// AssertSurfaceCoverage（SDK 客户端覆盖）可单独使用；
// OpenAPIv2 / OpenAPIv3 / Swagger 构造 Document Loader。
//
// # 兼容层
//
// SwaggerAccessMatches / SwaggerSnakeCaseProperties / SwaggerNoDefinition
// 与全局 registry 形态的 AssertMethodCount / AssertServiceCoverage 是
// v2 遗留断言，保留至下游迁移完成，新项目不要使用（见 MIGRATION.md）。
package guard
