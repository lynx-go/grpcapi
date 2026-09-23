package interceptor

import (
	"fmt"
	"sort"
	"strings"

	"github.com/lynx-go/grpcapi/authz"
	"google.golang.org/grpc"
)

// frameworkServicePrefixes 是不参与业务 authz 断言的 gRPC 框架内置服务
// 白名单：grpc.health.v1.Health 由运行时注册用于健康检查，
// grpc.reflection.* 用于 server reflection。它们不是业务 API、不携带
// 业务 authz 注解，由部署层网络策略保护。validate 拦截器复用同一白名单。
var frameworkServicePrefixes = []string{
	"grpc.health.v1.",
	"grpc.reflection.",
}

// FrameworkExempt 判断 fullMethod（"/pkg.Svc/Method" 形态）是否属于
// 框架内置服务，此类方法不要求 authz 注解与请求校验。
func FrameworkExempt(fullMethod string) bool {
	for _, prefix := range frameworkServicePrefixes {
		if strings.HasPrefix(fullMethod, "/"+prefix) {
			return true
		}
	}
	return false
}

// AssertAllRegisteredHavePolicy 断言每个已注册的 gRPC 方法都在策略集
// 中（框架豁免除外）。漏配的方法会被 auth 拦截器 fail-closed 拒绝，
// 但在启动期直接报错以尽早暴露 proto 注解与注册实现之间的漂移。
// 所有缺失方法聚合在一个 error 里，按字典序列出。
func AssertAllRegisteredHavePolicy(srv *grpc.Server, set *authz.PolicySet) error {
	var missing []string
	for serviceName, info := range srv.GetServiceInfo() {
		// 服务粒度豁免：框架服务整体不参与断言。
		if FrameworkExempt("/" + serviceName + "/") {
			continue
		}
		for _, m := range info.Methods {
			fullMethod := "/" + serviceName + "/" + m.Name
			if _, ok := set.Get(fullMethod); !ok {
				missing = append(missing, fullMethod)
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("registered grpc methods missing authz policy: %s", strings.Join(missing, ", "))
	}
	return nil
}
