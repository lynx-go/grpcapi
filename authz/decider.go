package authz

import (
	"context"
	"fmt"

	"github.com/lynx-go/grpcapi/policy"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Request 是一次授权决策的输入。
type Request struct {
	policy.EvalContext
	Stream bool
}

// Decision 是一次授权决策的结果。
type Decision struct {
	Allow bool
	// Code 可选；零值（codes.OK）表示由拦截器按场景推导。
	Code codes.Code
	// Reason 只进日志/审计，不下发客户端。
	Reason string
	// Failed 是第一个失败的 requirement（用于审计/调试）。
	Failed *policy.Requirement
	// Obligations 是外部引擎的附加建议（如 mask/log），由项目消费。
	Obligations map[string]string
}

// Decider 是授权决策 SPI。默认实现是 RequirementDecider；项目可以替换成
// OPA/Cerbos/Casbin/SpiceDB/自研引擎。
type Decider interface {
	Decide(ctx context.Context, req Request) (Decision, error)
}

// RequirementDecider 按 policy.Policy 树与 registry 求值。
type RequirementDecider struct {
	registry *policy.Registry
}

// NewRequirementDecider 从 Set 取 registry，并校验所有引用的 kind 都可求值。
func NewRequirementDecider(set *policy.Set) (*RequirementDecider, error) {
	if set == nil {
		return nil, fmt.Errorf("authz: policy.Set is nil")
	}
	reg := set.Registry()
	if reg == nil {
		reg = policy.DefaultRegistry()
	}
	for _, op := range set.Operations() {
		for _, req := range requirementsOf(op.Policy) {
			kind, ok := reg.Get(req.Kind)
			if !ok {
				return nil, fmt.Errorf("authz: operation %s references unknown kind %q", op.ID, req.Kind)
			}
			if kind.Evaluate == nil {
				return nil, fmt.Errorf("authz: kind %q used by %s has no Evaluate implementation; provide a custom Decider", req.Kind, op.ID)
			}
		}
	}
	return &RequirementDecider{registry: reg}, nil
}

// Decide 实现 Decider。
func (d *RequirementDecider) Decide(ctx context.Context, req Request) (Decision, error) {
	return decidePolicy(ctx, req, d.registry)
}

func decidePolicy(ctx context.Context, req Request, reg *policy.Registry) (Decision, error) {
	p := req.Operation.Policy

	// fail-closed：空策略/未展开 preset 属于配置错误，不能静默放行。
	if p.Preset != "" || (!p.Anonymous && len(p.Require) == 0 && len(p.AnyOf) == 0) {
		return Decision{Allow: false, Code: codes.Internal, Reason: "empty or unexpanded policy"}, nil
	}

	if p.Anonymous {
		if failed, err := matchAny(ctx, req, p.Forbid, reg); err != nil {
			return Decision{}, err
		} else if failed != nil {
			return Decision{Allow: false, Code: codes.PermissionDenied, Reason: "forbidden", Failed: failed}, nil
		}
		return Decision{Allow: true}, nil
	}

	if req.Principal == nil {
		return Decision{Allow: false, Code: codes.Unauthenticated, Reason: "missing principal"}, nil
	}

	if failed, err := matchAny(ctx, req, p.Forbid, reg); err != nil {
		return Decision{}, err
	} else if failed != nil {
		return Decision{Allow: false, Code: codes.PermissionDenied, Reason: "forbidden", Failed: failed}, nil
	}

	for i := range p.Require {
		ok, err := matchRequirement(ctx, req, p.Require[i], reg)
		if err != nil {
			return Decision{}, err
		}
		if !ok {
			return Decision{Allow: false, Code: codes.PermissionDenied, Reason: "requirement not satisfied", Failed: &p.Require[i]}, nil
		}
	}

	if len(p.AnyOf) > 0 {
		for _, group := range p.AnyOf {
			ok := true
			for i := range group {
				matched, err := matchRequirement(ctx, req, group[i], reg)
				if err != nil {
					return Decision{}, err
				}
				if !matched {
					ok = false
					break
				}
			}
			if ok {
				return Decision{Allow: true}, nil
			}
		}
		return Decision{Allow: false, Code: codes.PermissionDenied, Reason: "no any_of alternative satisfied"}, nil
	}

	return Decision{Allow: true}, nil
}

func requirementsOf(p policy.Policy) []policy.Requirement {
	out := make([]policy.Requirement, 0, len(p.Require)+len(p.Forbid))
	out = append(out, p.Require...)
	out = append(out, p.Forbid...)
	for _, group := range p.AnyOf {
		out = append(out, group...)
	}
	return out
}

func matchAny(ctx context.Context, req Request, reqs []policy.Requirement, reg *policy.Registry) (*policy.Requirement, error) {
	for i := range reqs {
		ok, err := matchRequirement(ctx, req, reqs[i], reg)
		if err != nil {
			return nil, err
		}
		if ok {
			r := reqs[i]
			return &r, nil
		}
	}
	return nil, nil
}

func matchRequirement(ctx context.Context, req Request, r policy.Requirement, reg *policy.Registry) (bool, error) {
	kind, ok := reg.Get(r.Kind)
	if !ok {
		return false, status.Errorf(codes.Internal, "authz: unknown requirement kind %q", r.Kind)
	}
	if kind.Evaluate == nil {
		return false, status.Errorf(codes.Internal, "authz: kind %q has no Evaluate implementation", r.Kind)
	}
	matched, err := kind.Evaluate(ctx, req.EvalContext, r)
	if err != nil {
		if st, ok := status.FromError(err); ok {
			return false, st.Err()
		}
		return false, status.Errorf(codes.Internal, "authz: evaluate %s: %v", r.Kind, err)
	}
	return matched, nil
}

var _ Decider = (*RequirementDecider)(nil)
