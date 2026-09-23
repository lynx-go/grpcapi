package contextx_test

import (
	"context"
	"strconv"
	"sync"
	"testing"

	"github.com/lynx-go/grpcapi/contextx"
)

func TestClientInfoRoundTrip(t *testing.T) {
	ctx := context.Background()
	if _, ok := contextx.ClientInfoFrom(ctx); ok {
		t.Fatal("empty ctx should not carry ClientInfo")
	}
	want := contextx.ClientInfo{IP: "203.0.113.7", UserAgent: "torchwood-cli/1.0"}
	ctx = contextx.WithClientInfo(ctx, want)
	got, ok := contextx.ClientInfoFrom(ctx)
	if !ok {
		t.Fatal("ClientInfo lost after WithClientInfo")
	}
	if got != want {
		t.Fatalf("ClientInfo mismatch: got %+v, want %+v", got, want)
	}
}

func TestAuditTrailRoundTrip(t *testing.T) {
	ctx := context.Background()
	if trail := contextx.AuditTrailFrom(ctx); trail != nil {
		t.Fatal("empty ctx should not carry AuditTrail")
	}

	trail := contextx.NewAuditTrail()
	ctx = contextx.WithAuditTrail(ctx, trail)

	// handler 内原地回填（ctx 不派生新值）。
	contextx.SetAuditResource(ctx, "proj_01h9")
	contextx.SetAuditMetadata(ctx, "changes.before", "name=old")
	contextx.SetAuditMetadata(ctx, "changes.after", "name=new")

	if got := trail.Resource(); got != "proj_01h9" {
		t.Fatalf("resource = %q, want %q", got, "proj_01h9")
	}
	md := trail.Metadata()
	if md["changes.before"] != "name=old" || md["changes.after"] != "name=new" {
		t.Fatalf("metadata = %+v", md)
	}

	// 通过 ctx 取回的指针与写入方一致。
	if got := contextx.AuditTrailFrom(ctx); got != trail {
		t.Fatal("AuditTrailFrom returned a different trail")
	}
}

func TestAuditTrailNoopWithoutTrail(t *testing.T) {
	ctx := context.Background()
	// 无槽位时 setter 必须 no-op（不 panic、不派生 ctx），供直调场景使用。
	contextx.SetAuditResource(ctx, "whatever")
	contextx.SetAuditMetadata(ctx, "k", "v")
	if trail := contextx.AuditTrailFrom(ctx); trail != nil {
		t.Fatalf("expected nil trail, got %+v", trail)
	}
}

func TestAuditTrailMetadataReturnsCopy(t *testing.T) {
	trail := contextx.NewAuditTrail()
	contextx.SetAuditMetadata(context.Background(), "unused", "") // no-op path
	ctx := contextx.WithAuditTrail(context.Background(), trail)
	contextx.SetAuditMetadata(ctx, "k", "v1")

	md := trail.Metadata()
	md["k"] = "mutated"
	md["extra"] = "injected"

	if got := trail.Metadata(); got["k"] != "v1" || len(got) != 1 {
		t.Fatalf("Metadata not isolated from caller mutation: %+v", got)
	}
}

func TestAuditTrailConcurrentWrites(t *testing.T) {
	trail := contextx.NewAuditTrail()
	ctx := contextx.WithAuditTrail(context.Background(), trail)

	const goroutines, perG = 32, 25
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				contextx.SetAuditMetadata(ctx, "key-"+strconv.Itoa(g*perG+i), "v")
			}
			if g == 0 {
				contextx.SetAuditResource(ctx, "res")
			}
		}(g)
	}
	wg.Wait()

	if got := trail.Resource(); got != "res" {
		t.Fatalf("resource = %q, want %q", got, "res")
	}
	if md := trail.Metadata(); len(md) != goroutines*perG {
		t.Fatalf("metadata has %d entries, want %d (concurrent writes lost)", len(md), goroutines*perG)
	}
}

func TestAuditTrailNilReceiver(t *testing.T) {
	var trail *contextx.AuditTrail
	if got := trail.Resource(); got != "" {
		t.Fatalf("nil trail Resource = %q", got)
	}
	if md := trail.Metadata(); md != nil {
		t.Fatalf("nil trail Metadata = %+v", md)
	}
}
