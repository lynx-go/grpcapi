package guard

import (
	"testing"

	echov1 "github.com/lynx-go/grpcapi/example/echo/v1"
)

type echoSDK struct{}

func (echoSDK) Shout(*echov1.ShoutRequest) {}
func (echoSDK) Hear(*echov1.HearRequest)   {}
func (echoSDK) Ping(*echov1.PingRequest)   {}

type echoClient struct{ echo echoSDK }

type echoClientMissingPing struct{ echo echoSDKPingMissing }

type echoSDKPingMissing struct{}

func (echoSDKPingMissing) Shout(*echov1.ShoutRequest) {}
func (echoSDKPingMissing) Hear(*echov1.HearRequest)   {}

func TestAssertSurfaceCoverage(t *testing.T) {
	s := testSurface(t)
	AssertSurfaceCoverage(t, s, "public", "example.echo.v1", echoClient{}, SDKOptions{})
	AssertSurfaceMethodCount(t, s, "public", "example.echo.v1", 3)

	expectGuardFatal(t, "missing RPC", func(_ *testing.T, tb testing.TB) {
		AssertSurfaceCoverage(tb, s, "public", "example.echo.v1", echoClientMissingPing{}, SDKOptions{})
	})
	expectGuardFatal(t, "missing field", func(_ *testing.T, tb testing.TB) {
		type wrong struct{ other echoSDK }
		AssertSurfaceCoverage(tb, s, "public", "example.echo.v1", wrong{}, SDKOptions{})
	})
	expectGuardFatal(t, "method count", func(_ *testing.T, tb testing.TB) {
		AssertSurfaceMethodCount(tb, s, "public", "example.echo.v1", 4)
	})
	expectGuardFatal(t, "unknown api", func(_ *testing.T, tb testing.TB) {
		AssertSurfaceCoverage(tb, s, "internal", "", echoClient{}, SDKOptions{})
	})
}
