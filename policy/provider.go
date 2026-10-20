package policy

import "google.golang.org/protobuf/reflect/protoreflect"

// FileSpec 是文件级策略声明。
type FileSpec struct {
	API             string
	SchemaVersion   uint32
	DefaultPolicy   *Policy
	DefaultExposure Exposure
}

// ServiceSpec 是服务级缺省声明。
type ServiceSpec struct {
	DefaultPolicy   *Policy
	DefaultExposure Exposure
	Label           string
}

// MethodSpec 是方法级声明。
type MethodSpec struct {
	Policy         *Policy
	Exposure       Exposure
	Label          string
	OperationID    string
	InheritDefault bool
	StreamAuth     StreamAuthMode
}

// Provider 抽象策略来源：默认实现读 grpcapi.v1 扩展；项目可以实现
// legacyProvider 读旧注解，或从配置中心/数据库读取。
type Provider interface {
	File(protoreflect.FileDescriptor) (FileSpec, bool, error)
	Service(protoreflect.ServiceDescriptor) (ServiceSpec, bool, error)
	Method(protoreflect.MethodDescriptor) (MethodSpec, bool, error)
}
