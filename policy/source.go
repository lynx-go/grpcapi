package policy

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// Source 提供策略收集所需的 proto 文件描述符。
type Source interface {
	Files(ctx context.Context) ([]protoreflect.FileDescriptor, error)
}

type filesSource []protoreflect.FileDescriptor

func (s filesSource) Files(context.Context) ([]protoreflect.FileDescriptor, error) {
	return s, nil
}

// FromFiles 使用显式文件描述符列表。
func FromFiles(files ...protoreflect.FileDescriptor) Source {
	return filesSource(files)
}

type registrySource struct {
	prefixes []string
}

func (s registrySource) Files(context.Context) ([]protoreflect.FileDescriptor, error) {
	var out []protoreflect.FileDescriptor
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if len(s.prefixes) == 0 {
			out = append(out, fd)
			return true
		}
		for _, prefix := range s.prefixes {
			if nameUnderPrefix(string(fd.Package()), prefix) {
				out = append(out, fd)
				return true
			}
		}
		return true
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Path() < out[j].Path() })
	return out, nil
}

// FromRegistry 从 protoregistry.GlobalFiles 按包前缀收集描述符。
// prefixes 为空表示全部文件。前缀按点分边界匹配。
func FromRegistry(prefixes ...string) Source {
	return registrySource{prefixes: prefixes}
}

type descriptorSetSource struct {
	set *descriptorpb.FileDescriptorSet
}

func (s descriptorSetSource) Files(context.Context) ([]protoreflect.FileDescriptor, error) {
	files, err := protodesc.NewFiles(s.set)
	if err != nil {
		return nil, fmt.Errorf("policy: build descriptor set: %w", err)
	}
	var out []protoreflect.FileDescriptor
	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		out = append(out, fd)
		return true
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Path() < out[j].Path() })
	return out, nil
}

// FromDescriptorSet 使用 buf build 产出的 FileDescriptorSet。
func FromDescriptorSet(set *descriptorpb.FileDescriptorSet) Source {
	return descriptorSetSource{set: set}
}

// FromFileDescriptorSet 读取磁盘上的 FileDescriptorSet。
func FromFileDescriptorSet(path string) Source {
	return fileDescriptorSetSource(path)
}

type fileDescriptorSetSource string

func (s fileDescriptorSetSource) Files(context.Context) ([]protoreflect.FileDescriptor, error) {
	raw, err := os.ReadFile(string(s)) // #nosec G304 -- 调用方显式提供镜像路径
	if err != nil {
		return nil, fmt.Errorf("policy: read descriptor set %s: %w", s, err)
	}
	var set descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("policy: unmarshal descriptor set %s: %w", s, err)
	}
	return descriptorSetSource{set: &set}.Files(context.Background())
}

func nameUnderPrefix(full, prefix string) bool {
	if prefix == "" {
		return true
	}
	if !strings.HasPrefix(full, prefix) {
		return false
	}
	if len(full) == len(prefix) || full[len(prefix)] == '.' {
		return true
	}
	return strings.HasSuffix(prefix, ".")
}
