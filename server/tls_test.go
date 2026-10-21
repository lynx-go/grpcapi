package server_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	echov1 "github.com/lynx-go/grpcapi/example/echo/v1"
	"github.com/lynx-go/grpcapi/gateway"
	"github.com/lynx-go/grpcapi/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("append cert")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   "localhost",
		MinVersion:   tls.VersionTLS12,
	}
}

func TestInProcessGatewayIgnoresGRPCOptionsCredentials(t *testing.T) {
	tlsCfg := testTLSConfig(t)
	s, err := server.New(context.Background(), server.Config{
		Policy:               testSet(t),
		Services:             []server.Registration{testRegistration(t)},
		GRPCAddr:             "127.0.0.1:0",
		HTTPAddr:             "127.0.0.1:0",
		GRPCOptions:          []grpc.ServerOption{grpc.Creds(credentials.NewTLS(tlsCfg))},
		DisableHealth:        true,
		AllowNoAuthenticator: true,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-errCh:
		case <-time.After(5 * time.Second):
			t.Error("server did not shut down")
		}
	}()

	var httpAddr string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, httpAddr = s.Addrs()
		if httpAddr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if httpAddr == "" {
		t.Fatal("server did not start")
	}
	var resp *http.Response
	for time.Now().Before(deadline) {
		resp, err = http.Get("http://" + httpAddr + "/v1/echo:ping")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("HTTP GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "pong") {
		t.Fatalf("ping status=%d body=%s", resp.StatusCode, body)
	}
}

func TestNetworkDialTLSGatewayUsesExplicitClientConfig(t *testing.T) {
	tlsCfg := testTLSConfig(t)
	serverTLS := &tls.Config{Certificates: tlsCfg.Certificates, MinVersion: tls.VersionTLS12}
	clientTLS := &tls.Config{RootCAs: tlsCfg.RootCAs, ServerName: "localhost", MinVersion: tls.VersionTLS12}

	extLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ext := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	echov1.RegisterEchoServiceServer(ext, echoImpl{})
	go func() { _ = ext.Serve(extLis) }()
	defer ext.Stop()

	s, err := server.New(context.Background(), server.Config{
		Policy:               testSet(t),
		Services:             []server.Registration{testRegistration(t)},
		HTTPAddr:             "127.0.0.1:0",
		GRPCAddr:             extLis.Addr().String(),
		TLS:                  serverTLS,
		NetworkDial:          true,
		Dial:                 gateway.DialConfig{TLS: clientTLS},
		DisableGRPC:          true,
		DisableHealth:        true,
		AllowNoAuthenticator: true,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case <-errCh:
		case <-time.After(5 * time.Second):
			t.Error("server did not shut down")
		}
	}()

	var httpAddr string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, httpAddr = s.Addrs()
		if httpAddr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if httpAddr == "" {
		t.Fatal("server did not start")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}
	var resp *http.Response
	for time.Now().Before(deadline) {
		resp, err = client.Get("https://" + httpAddr + "/v1/echo:ping")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("HTTPS gateway GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "pong") {
		t.Fatalf("ping status=%d body=%s", resp.StatusCode, body)
	}
}

func TestServerTLSAndInProcessGateway(t *testing.T) {
	tlsCfg := testTLSConfig(t)
	s, err := server.New(context.Background(), server.Config{
		Policy:               testSet(t),
		Services:             []server.Registration{testRegistration(t)},
		GRPCAddr:             "127.0.0.1:0",
		HTTPAddr:             "127.0.0.1:0",
		TLS:                  tlsCfg,
		DisableHealth:        true,
		AllowNoAuthenticator: true,
	})
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx) }()

	var grpcAddr, httpAddr string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		grpcAddr, httpAddr = s.Addrs()
		if grpcAddr != "" && httpAddr != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if grpcAddr == "" || httpAddr == "" {
		cancel()
		t.Fatalf("server did not start: grpc=%q http=%q", grpcAddr, httpAddr)
	}

	clientTLS := &tls.Config{RootCAs: tlsCfg.RootCAs, ServerName: "localhost", MinVersion: tls.VersionTLS12}
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}}
	var resp *http.Response
	for time.Now().Before(deadline) {
		resp, err = httpClient.Get("https://" + httpAddr + "/v1/echo:ping")
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		cancel()
		t.Fatalf("HTTPS GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "pong") {
		cancel()
		t.Fatalf("HTTPS ping status=%d body=%s", resp.StatusCode, body)
	}

	conn, err := grpc.NewClient(grpcAddr, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		cancel()
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer conn.Close()
	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()
	if _, err := echov1.NewEchoServiceClient(conn).Ping(callCtx, &echov1.PingRequest{}); err != nil {
		cancel()
		t.Fatalf("gRPC ping over TLS: %v", err)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down")
	}
}
