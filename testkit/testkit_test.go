package testkit_test

import (
	"io"
	"net/http"
	"testing"

	"github.com/lynx-go/grpcapi/server"
	"github.com/lynx-go/grpcapi/testkit"
)

func TestNewServerExtraRoute(t *testing.T) {
	s := testkit.NewServer(t, server.Config{
		DisableGRPC: true,
		ExtraRoutes: []server.ExtraRoute{
			server.GET("/ping", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("pong"))
			})).Public(),
		},
	})
	resp, err := s.HTTP().Get(s.URL() + "/ping")
	if err != nil {
		t.Fatalf("GET /ping: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "pong" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
}

func TestPrincipalHelpers(t *testing.T) {
	p := testkit.Principal("", map[string][]string{"roles": {"admin"}})
	if p.Kind != "user" || p.ID == "" || len(p.Claim("roles")) != 1 {
		t.Fatalf("principal = %+v", p)
	}
}
