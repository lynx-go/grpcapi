package interceptor_test

import (
	"context"
	"strings"
	"testing"

	"github.com/lynx-go/grpcapi/interceptor"
	"google.golang.org/grpc"
)

func markUnary(order *[]string, name string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		*order = append(*order, name)
		return handler(ctx, req)
	}
}

func markStream(order *[]string, name string) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		*order = append(*order, name)
		return handler(srv, ss)
	}
}

func stage(order *[]string, name string, n int) interceptor.Stage {
	return interceptor.Stage{
		Name:   name,
		Order:  n,
		Unary:  markUnary(order, name),
		Stream: markStream(order, name),
	}
}

func TestAssembleValidChain(t *testing.T) {
	var order []string
	chain, err := interceptor.AssembleWith(interceptor.DefaultChainOptions(),
		stage(&order, interceptor.StageClientInfo, interceptor.OrderClientInfo),
		stage(&order, interceptor.StageAuthn, interceptor.OrderAuthn),
		stage(&order, interceptor.StageAuthz, interceptor.OrderAuthz),
		stage(&order, interceptor.StageValidate, interceptor.OrderValidate),
	)
	if err != nil {
		t.Fatalf("AssembleWith: %v", err)
	}
	if got := len(chain.Unary()); got != 4 {
		t.Fatalf("unary len = %d, want 4", got)
	}
	if got := len(chain.Stream()); got != 4 {
		t.Fatalf("stream len = %d, want 4", got)
	}
	if !chain.Has(interceptor.StageAuthz) || !chain.HasStream(interceptor.StageAuthz) {
		t.Fatal("authz stage should have unary+stream")
	}
	if chain.HasStage("nope") {
		t.Fatal("unknown stage should not exist")
	}
	if got := chain.String(); got != "clientinfo -> authn -> authz -> validate" {
		t.Fatalf("String = %q", got)
	}

	handler := func(context.Context, any) (any, error) { return nil, nil }
	for _, ic := range chain.Unary() {
		_, _ = ic(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/t.S/Get"}, handler)
	}
	want := []string{"clientinfo", "authn", "authz", "validate"}
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Fatalf("order = %v, want %v", order, want)
	}
	if len(chain.ServerOptions()) != 2 {
		t.Fatalf("ServerOptions len = %d, want 2", len(chain.ServerOptions()))
	}
}

func TestAssembleAllowsUnaryOnlyAndStreamOnly(t *testing.T) {
	unaryOnly := interceptor.Stage{Name: "u", Order: 1, Unary: markUnary(new([]string), "u")}
	streamOnly := interceptor.Stage{Name: "s", Order: 2, Stream: markStream(new([]string), "s")}
	chain, err := interceptor.Assemble(unaryOnly, streamOnly)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if chain.Has("s") || !chain.Has("u") {
		t.Fatal("unary presence mismatch")
	}
	if chain.HasStream("u") || !chain.HasStream("s") {
		t.Fatal("stream presence mismatch")
	}
}

func TestAssembleRejects(t *testing.T) {
	var sink []string
	ok := func(name string, order int) interceptor.Stage {
		return stage(&sink, name, order)
	}

	cases := []struct {
		name    string
		stages  []interceptor.Stage
		opts    interceptor.ChainOptions
		wantSub string
	}{
		{name: "empty", wantSub: "no stages"},
		{name: "empty name", stages: []interceptor.Stage{{Order: 1, Unary: markUnary(&sink, "x")}}, wantSub: "empty name"},
		{name: "duplicate", stages: []interceptor.Stage{ok("x", 1), ok("x", 2)}, wantSub: "duplicate stage"},
		{name: "nil interceptors", stages: []interceptor.Stage{{Name: "x", Order: 1}}, wantSub: "no interceptor"},
		{name: "backwards", stages: []interceptor.Stage{ok("x", 2), ok("y", 1)}, wantSub: "goes backwards"},
		{
			name:    "first mismatch",
			stages:  []interceptor.Stage{ok("x", 1), ok("y", 2)},
			opts:    interceptor.ChainOptions{First: "y"},
			wantSub: "first stage must be",
		},
		{
			name:    "last mismatch",
			stages:  []interceptor.Stage{ok("x", 1), ok("y", 2)},
			opts:    interceptor.ChainOptions{Last: "x"},
			wantSub: "last stage must be",
		},
		{
			name:    "required missing",
			stages:  []interceptor.Stage{ok("x", 1)},
			opts:    interceptor.ChainOptions{Required: []string{"y"}},
			wantSub: "required stage",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := interceptor.AssembleWith(tc.opts, tc.stages...)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error = %v, want %q", err, tc.wantSub)
			}
		})
	}
}

func TestChainStagesCopy(t *testing.T) {
	var sink []string
	chain, err := interceptor.Assemble(stage(&sink, "x", 1))
	if err != nil {
		t.Fatal(err)
	}
	stages := chain.Stages()
	stages[0].Name = "mutated"
	if chain.Stages()[0].Name != "x" {
		t.Fatal("Stages exposed internal slice")
	}
}
