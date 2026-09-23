package interceptor_test

import (
	"context"
	"strings"
	"testing"

	"github.com/lynx-go/grpcapi/interceptor"
	testvalidatev1 "github.com/lynx-go/grpcapi/interceptor/testdata/gen/testvalidate/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// invokeValidate 以给定 FullMethod/req 调用校验拦截器，返回 handler 是否
// 被执行及其错误。
func invokeValidate(t *testing.T, ic grpc.UnaryServerInterceptor, fullMethod string, req any) (handled bool, err error) {
	t.Helper()
	handler := func(ctx context.Context, _ any) (any, error) {
		handled = true
		return nil, nil
	}
	_, err = ic(context.Background(), req, &grpc.UnaryServerInfo{FullMethod: fullMethod}, handler)
	return handled, err
}

func TestValidatePassesValidRequest(t *testing.T) {
	ic := interceptor.NewValidate().Unary()
	handled, err := invokeValidate(t, ic, "/testvalidate.v1.Echo/Get", &testvalidatev1.EchoRequest{
		Id:    "abc",
		Name:  "hello",
		Count: 3,
	})
	if err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	if !handled {
		t.Fatal("handler not invoked for valid request")
	}
}

func TestValidateRejectsInvalidRequest(t *testing.T) {
	ic := interceptor.NewValidate().Unary()
	// id 为空（min_len）、name 大写（pattern）、count 越界（gte/lte）：
	// 三条违规一次触发，验证聚合格式。
	handled, err := invokeValidate(t, ic, "/testvalidate.v1.Echo/Get", &testvalidatev1.EchoRequest{
		Name:  "ABC",
		Count: -1,
	})
	if handled {
		t.Fatal("handler must not run for invalid request")
	}
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %s, want InvalidArgument (err = %v)", status.Code(err), err)
	}
	msg := status.Convert(err).Message()
	for _, field := range []string{"id", "name", "count"} {
		if !strings.Contains(msg, field) {
			t.Fatalf("violation message %q does not mention field %q", msg, field)
		}
	}
	if !strings.Contains(msg, "; ") {
		t.Fatalf("violation message %q should join multiple violations with \"; \"", msg)
	}
	if got := strings.Count(msg, "; ") + 1; got != 3 {
		t.Fatalf("violation message has %d parts, want 3: %q", got, msg)
	}
}

func TestValidateCELFailureFailsClosed(t *testing.T) {
	ic := interceptor.NewValidate().Unary()
	handled, err := invokeValidate(t, ic, "/testvalidate.v1.Echo/Get", &testvalidatev1.BadCelRequest{
		Note: "anything",
	})
	if handled {
		t.Fatal("handler must not run when rules fail to evaluate")
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %s, want Internal (fail-closed), err = %v", status.Code(err), err)
	}
}

func TestValidateFrameworkExempt(t *testing.T) {
	ic := interceptor.NewValidate().Unary()
	// 框架服务豁免：即使请求是带坏 CEL 规则的消息也直接放行。
	handled, err := invokeValidate(t, ic, "/grpc.health.v1.Health/Check", &testvalidatev1.BadCelRequest{})
	if err != nil {
		t.Fatalf("framework method should bypass validation: %v", err)
	}
	if !handled {
		t.Fatal("handler not invoked for exempt method")
	}
}

func TestValidateNonProtoRequestPassesThrough(t *testing.T) {
	ic := interceptor.NewValidate().Unary()
	// 非 proto 消息（理论不可达）不校验。
	handled, err := invokeValidate(t, ic, "/testvalidate.v1.Echo/Get", &struct{}{})
	if err != nil {
		t.Fatalf("non-proto request should pass through: %v", err)
	}
	if !handled {
		t.Fatal("handler not invoked for non-proto request")
	}
}

func TestValidateEmptyProtoPasses(t *testing.T) {
	ic := interceptor.NewValidate().Unary()
	handled, err := invokeValidate(t, ic, "/testvalidate.v1.Echo/Get", &emptypb.Empty{})
	if err != nil || !handled {
		t.Fatalf("message without rules should pass, err = %v", err)
	}
}
