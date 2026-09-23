package interceptor_test

import (
	"context"
	"strings"
	"testing"

	"github.com/lynx-go/grpcapi/interceptor"
	"google.golang.org/grpc"
)

// markInterceptor 返回一个记录自身经过顺序的空拦截器。
func markInterceptor(order *[]string, name string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		*order = append(*order, name)
		return handler(ctx, req)
	}
}

func chainItems(order *[]string, slots ...interceptor.Slot) []interceptor.ChainItem {
	prefix := map[interceptor.Slot]string{
		interceptor.SlotClientInfo: "clientinfo",
		interceptor.SlotAuth:       "auth",
		interceptor.SlotRateLimit:  "ratelimit",
		interceptor.SlotAudit:      "audit",
		interceptor.SlotUsage:      "usage",
		interceptor.SlotValidate:   "validate",
	}
	items := make([]interceptor.ChainItem, 0, len(slots))
	for _, s := range slots {
		items = append(items, interceptor.ChainItem{Slot: s, Interceptor: markInterceptor(order, prefix[s])})
	}
	return items
}

func TestAssembleValidChains(t *testing.T) {
	cases := []struct {
		name  string
		slots []interceptor.Slot
	}{
		{"minimal", []interceptor.Slot{interceptor.SlotClientInfo, interceptor.SlotValidate}},
		{"full chain", []interceptor.Slot{
			interceptor.SlotClientInfo, interceptor.SlotAuth, interceptor.SlotRateLimit,
			interceptor.SlotAudit, interceptor.SlotUsage, interceptor.SlotValidate,
		}},
		{"subset in order", []interceptor.Slot{
			interceptor.SlotClientInfo, interceptor.SlotAudit, interceptor.SlotValidate,
		}},
		{"duplicate middle slots", []interceptor.Slot{
			interceptor.SlotClientInfo, interceptor.SlotAuth, interceptor.SlotAuth,
			interceptor.SlotRateLimit, interceptor.SlotRateLimit, interceptor.SlotValidate,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var order []string
			chain, err := interceptor.Assemble(chainItems(&order, tc.slots...)...)
			if err != nil {
				t.Fatalf("Assemble failed: %v", err)
			}
			if len(chain) != len(tc.slots) {
				t.Fatalf("chain length = %d, want %d", len(chain), len(tc.slots))
			}
			// 产出顺序与输入一致：逐条执行后 marks 应等于 slot 名序列。
			handler := grpc.UnaryHandler(func(ctx context.Context, req any) (any, error) { return nil, nil })
			for _, ic := range chain {
				_, _ = ic(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/t.S/Get"}, handler)
			}
			want := make([]string, 0, len(tc.slots))
			for _, s := range tc.slots {
				want = append(want, s.String())
			}
			if strings.Join(order, ",") != strings.Join(want, ",") {
				t.Fatalf("execution order = %v, want %v", order, want)
			}
		})
	}
}

func TestAssembleRejects(t *testing.T) {
	var sink []string
	ok := func(s interceptor.Slot) interceptor.ChainItem {
		return interceptor.ChainItem{Slot: s, Interceptor: markInterceptor(&sink, s.String())}
	}

	cases := []struct {
		name    string
		items   []interceptor.ChainItem
		wantSub string
	}{
		{
			name:    "empty",
			items:   nil,
			wantSub: "no items",
		},
		{
			name:    "missing head",
			items:   []interceptor.ChainItem{ok(interceptor.SlotAuth), ok(interceptor.SlotValidate)},
			wantSub: "first item must be clientinfo",
		},
		{
			name:    "missing tail",
			items:   []interceptor.ChainItem{ok(interceptor.SlotClientInfo), ok(interceptor.SlotAuth)},
			wantSub: "last item must be validate",
		},
		{
			name:    "head not clientinfo",
			items:   []interceptor.ChainItem{ok(interceptor.SlotAudit), ok(interceptor.SlotValidate)},
			wantSub: "first item must be clientinfo",
		},
		{
			name: "backwards order",
			items: []interceptor.ChainItem{
				ok(interceptor.SlotClientInfo), ok(interceptor.SlotAudit),
				ok(interceptor.SlotAuth), ok(interceptor.SlotValidate),
			},
			wantSub: "goes backwards",
		},
		{
			name:    "validate in middle",
			items:   []interceptor.ChainItem{ok(interceptor.SlotClientInfo), ok(interceptor.SlotValidate), ok(interceptor.SlotAudit)},
			wantSub: "goes backwards",
		},
		{
			name:    "out of range slot",
			items:   []interceptor.ChainItem{ok(interceptor.SlotClientInfo), {Slot: interceptor.SlotCount, Interceptor: markInterceptor(&sink, "x")}},
			wantSub: "invalid slot",
		},
		{
			name:    "negative slot",
			items:   []interceptor.ChainItem{ok(interceptor.SlotClientInfo), {Slot: interceptor.Slot(-1), Interceptor: markInterceptor(&sink, "x")}},
			wantSub: "invalid slot",
		},
		{
			name:    "nil interceptor",
			items:   []interceptor.ChainItem{ok(interceptor.SlotClientInfo), {Slot: interceptor.SlotAuth}},
			wantSub: "nil interceptor",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := interceptor.Assemble(tc.items...)
			if err == nil {
				t.Fatal("Assemble should fail")
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not mention %q", err, tc.wantSub)
			}
		})
	}
}
