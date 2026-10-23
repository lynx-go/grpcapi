package ratelimit_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/lynx-go/grpcapi/principal"
	"github.com/lynx-go/grpcapi/ratelimit"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newUnaryInfo() *grpc.UnaryServerInfo {
	return &grpc.UnaryServerInfo{FullMethod: "/svc.Echo/Get"}
}

func TestRatelimitRejectsInvalidConfig(t *testing.T) {
	if _, err := ratelimit.New(ratelimit.Options{Limit: 0}); err == nil {
		t.Fatal("want error for Limit <= 0")
	}
	if _, err := ratelimit.New(ratelimit.Options{Limit: -1}); err == nil {
		t.Fatal("want error for negative Limit")
	}
}

func TestRatelimitFixedWindow(t *testing.T) {
	l, err := ratelimit.New(ratelimit.Options{Limit: 2, Window: 80 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if ok, retry := l.Allow(ctx, "k"); !ok {
			t.Fatalf("request %d limited, want allowed", i)
		} else if retry != 0 {
			t.Fatalf("allowed request returned retryAfter %v", retry)
		}
	}
	ok, retry := l.Allow(ctx, "k")
	if ok {
		t.Fatal("third request allowed, want limited")
	}
	if retry <= 0 || retry > 80*time.Millisecond {
		t.Fatalf("retryAfter = %v, want within window", retry)
	}
	// 窗口滚动后重新放行。
	time.Sleep(90 * time.Millisecond)
	if ok, _ := l.Allow(ctx, "k"); !ok {
		t.Fatal("request after window rollover limited")
	}
	// 不同键互不影响。
	if ok, _ := l.Allow(ctx, "other"); !ok {
		t.Fatal("other key limited by k's window")
	}
}

func TestRatelimitUnaryResourceExhaustedWithRetryInfo(t *testing.T) {
	l, err := ratelimit.New(ratelimit.Options{Limit: 1, Window: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	handler := func(context.Context, any) (any, error) { return "ok", nil }
	if _, err := l.Unary()(context.Background(), "req", newUnaryInfo(), handler); err != nil {
		t.Fatalf("first request: %v", err)
	}
	_, err = l.Unary()(context.Background(), "req", newUnaryInfo(), handler)
	if err == nil {
		t.Fatal("second request passed, want ResourceExhausted")
	}
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("code = %v, want ResourceExhausted", status.Code(err))
	}
	st := status.Convert(err)
	found := false
	for _, d := range st.Details() {
		if ri, ok := d.(*errdetails.RetryInfo); ok {
			found = true
			if ri.GetRetryDelay().AsDuration() < time.Second {
				t.Fatalf("retry delay = %v, want >= 1s", ri.GetRetryDelay().AsDuration())
			}
		}
	}
	if !found {
		t.Fatal("RetryInfo detail missing")
	}
}

func TestRatelimitDefaultKeyPrefersPrincipal(t *testing.T) {
	l, err := ratelimit.New(ratelimit.Options{Limit: 1, Window: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	alice := principal.With(context.Background(), &principal.Principal{ID: "alice"})
	handler := func(context.Context, any) (any, error) { return "ok", nil }
	if _, err := l.Unary()(alice, "req", newUnaryInfo(), handler); err != nil {
		t.Fatalf("alice first: %v", err)
	}
	// 同主体第二次被限。
	if _, err := l.Unary()(alice, "req", newUnaryInfo(), handler); err == nil {
		t.Fatal("alice second passed, want limited")
	}
	// 不同主体不受影响。
	bob := principal.With(context.Background(), &principal.Principal{ID: "bob"})
	if _, err := l.Unary()(bob, "req", newUnaryInfo(), handler); err != nil {
		t.Fatalf("bob first: %v", err)
	}
}

func TestRatelimitConcurrent(t *testing.T) {
	l, err := ratelimit.New(ratelimit.Options{Limit: 100, Window: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	handler := func(context.Context, any) (any, error) { return "ok", nil }
	var wg sync.WaitGroup
	var limited int64
	var mu sync.Mutex
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := l.Unary()(context.Background(), "req", newUnaryInfo(), handler)
			if err != nil {
				mu.Lock()
				limited++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	mu.Lock()
	got := limited
	mu.Unlock()
	if got != 100 {
		t.Fatalf("limited = %d, want exactly 100 (Limit)", got)
	}
}

func TestRatelimitOnLimitedHook(t *testing.T) {
	var called bool
	l, err := ratelimit.New(ratelimit.Options{
		Limit: 1, Window: time.Minute,
		OnLimited: func(context.Context, string, time.Duration) { called = true },
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := func(context.Context, any) (any, error) { return "ok", nil }
	_, _ = l.Unary()(context.Background(), "req", newUnaryInfo(), handler)
	_, _ = l.Unary()(context.Background(), "req", newUnaryInfo(), handler)
	if !called {
		t.Fatal("OnLimited not called")
	}
	_ = errors.New // 保持 errors 引用用于未来断言扩展
}
