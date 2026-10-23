# grpcapi

**English** | [简体中文](./README_ZH.md)

grpcapi turns the "declare your API in proto, serve it over gRPC and HTTP"
pattern into a reusable library: policy collection with fail-closed startup
assertions, authentication and authorization, a standard interceptor chain,
a gateway assembly kit, and guard test helpers. It belongs to the
[lynx](https://github.com/lynx-go/lynx) ecosystem but does not depend on it —
the only direct dependencies are the gRPC ecosystem itself (grpc,
grpc-gateway, protobuf, jwt, protovalidate).

## Why grpcapi?

- **Proto is the single source of truth.** HTTP routes come from
  `google.api.http`, access policies from `grpcapi.v1` options on the same
  proto file. No second route table to maintain in Go.
- **Fail-closed startup.** Missing policies, unregistered operations,
  protected routes without an authenticator, missing CSRF, route conflicts —
  all fail at startup, never at request time.
- **Secure by default.** Session cookies default to `Secure`; CSRF with no
  configured origins falls back to same-origin; the HTTP body limit follows
  the gRPC receive limit.
- **One-step assembly.** `server.New` wires the in-process gateway, the
  default interceptor chain, health checks, the route table, startup
  assertions, and graceful shutdown.
- **Guard tests.** Align the proto surface, generated OpenAPI documents, and
  the policy set; snapshot the authorization matrix so every change to it is
  visible in code review.

## Core concepts

| Concept | Meaning |
|---|---|
| **Service** | A gRPC service plus the HTTP routes generated from its proto annotations |
| **Route** | An HTTP endpoint; usually declared in proto, with a few handwritten health/webhook extras |
| **Policy** | Who may call: public / authenticated / role / permission / scope / custom |
| **Principal** | Who is calling: the identity and claims produced by an authenticator |

## Installation

```
go get github.com/lynx-go/grpcapi
```

Go 1.26 or newer is required. The proto annotations ship as a separate Buf
module — see [Proto distribution](#proto-distribution).

## Quick start

### 1. Declare routes and policies in proto

```protobuf
import "google/api/annotations.proto";
import "grpcapi/v1/policy.proto";

option (grpcapi.v1.api) = {
  api: "public"
  schema_version: 1
  default_exposure: EXPOSURE_PUBLIC
};

service NoteService {
  option (grpcapi.v1.service) = {
    default_policy: { authenticated: true }
    default_exposure: EXPOSURE_PUBLIC
  };

  rpc ListNotes(ListNotesRequest) returns (ListNotesResponse) {
    option (google.api.http) = { get: "/v1/notes" };
  }

  rpc DeleteNote(DeleteNoteRequest) returns (DeleteNoteResponse) {
    option (google.api.http) = { delete: "/v1/notes/{id}" };
    option (grpcapi.v1.method) = {
      policy: { permissions: ["notes.read", "notes.delete"] }
      label: "permission"
    };
  }

  rpc PurgeNotes(PurgeNotesRequest) returns (PurgeNotesResponse) {
    option (google.api.http) = { post: "/v1/notes:purge" body: "*" };
    option (grpcapi.v1.method) = {
      policy: {
        any_of: [
          { roles: ["admin"] },
          { scopes: ["notes:admin"] }
        ]
      }
      label: "server"
    };
  }
}
```

The proto Service plus `google.api.http` is the single source of truth for
routing; do not maintain a second route table in Go.

### 2. Build the policy set

```go
import (
    "github.com/lynx-go/grpcapi/policy"
    "github.com/lynx-go/grpcapi/policy/protopolicy"
)

set, err := policy.Build(ctx,
    policy.FromRegistry("notes.api.v1"), // or policy.FromFiles / FromFileDescriptorSet
    policy.Options{
        Provider: protopolicy.New(protopolicy.Options{}),
        Registry: policy.DefaultRegistry(),
        // Vocabulary: policy.NewVocabulary(map[string][]string{"scope": {"notes"}}),
    })
```

### 3. Assemble the server in one step (recommended)

```go
srv, err := server.New(ctx, server.Config{
    Policy: set,
    Services: []server.Registration{{
        API:        "public",
        Descriptor: notesv1.File_notes_proto.Services().ByName("NoteService"),
        RegisterGRPC: func(s *grpc.Server) {
            notesv1.RegisterNoteServiceServer(s, impl)
        },
        RegisterHTTP: func(ctx context.Context, mux *runtime.ServeMux, conn grpc.ClientConnInterface) error {
            return notesv1.RegisterNoteServiceHandlerClient(ctx, mux, notesv1.NewNoteServiceClient(conn))
        },
    }},
    GRPCAddr: ":9060",
    HTTPAddr: ":8080",
    // This example configures no Authenticators, yet the proto in step 1
    // declares protected policies; fail-closed semantics require you to
    // acknowledge that explicitly, or server.New fails at startup.
    // Remove this switch once JWT/session/API-key auth is wired in.
    AllowNoAuthenticator: true,
})
if err != nil {
    log.Fatal(err)
}
log.Fatal(srv.Run(ctx))
```

`server.New` takes care of the in-process gateway connection,
mux/dial/register/mount, the default interceptor chain, health checks, the
route table, startup assertions, and graceful shutdown.

The registration closures can be generated instead of handwritten:

```bash
go build -o bin/protoc-gen-grpcapi ./cmd/protoc-gen-grpcapi
```

```yaml
# buf.gen.yaml
plugins:
  - local: bin/protoc-gen-grpcapi
    out: .
    opt: module=github.com/lynx-go/grpcapi
```

This generates `NewNoteServiceRegistration(impl) server.Registration`.
Tier 1 users can still assemble `gateway.NewMux` / `gateway.Dial` /
`gateway.Register` piece by piece.

### 4. Manual assembly

```go
decider, err := authz.NewRequirementDecider(set)
authorizer, err := authz.NewInterceptor(set, decider, authz.InterceptorOptions{})

chain, err := interceptor.Assemble(
    interceptor.RecoveryStage(interceptor.RecoveryOptions{}),
    interceptor.RequestIDStage(interceptor.RequestIDOptions{}),
    interceptor.ClientInfoStage(interceptor.NewClientInfo(interceptor.ClientInfoConfig{})),
    interceptor.AuthnStage(authnUnary, authnStream),
    interceptor.AuthzStage(authorizer.Unary(), authorizer.Stream()),
    interceptor.ValidateStage(interceptor.NewValidate()),
)
srv := grpc.NewServer(chain.ServerOptions()...)
```

Reference authenticator implementations live in `authn/jwt`,
`authn/session`, `authn/apikey`, and `authn/admin`; the CSRF middleware is
in `csrf`.

When assembling by hand, also assert at startup that every registered
method has a policy (`server.New` has this built in):

```go
if err := interceptor.AssertAllRegisteredHavePolicy(srv, set); err != nil {
    log.Fatal(err)
}
```

## Testing guards

```go
surf, err := surface.Build([]protoreflect.FileDescriptor{notesv1.File_notes_proto}, set)
if err != nil {
    t.Fatal(err)
}
docs, err := guard.OpenAPIv2(os.DirFS("gen"), guard.OpenAPIv2Options{})
if err != nil {
    t.Fatal(err)
}

guard.Run(t, guard.SuiteConfig{
    Surface: surf,
    Docs:    docs,
    Policy: guard.MatchOptions{
        MetadataKey:   "x-grpcapi-policy",
        MinOperations: 3,
    },
    Naming:   guard.SnakeCase,
    Manifest: &guard.ManifestConfig{Path: "docs/policy.manifest.json"},
    Matrix: &guard.MatrixConfig{
        Path: "docs/authz-matrix.md",
        Options: guard.MatrixOptions{
            Header: []string{"Method", "Label"},
            Row: func(op policy.Operation) []string {
                return []string{op.ID, op.EffectiveLabel()}
            },
        },
    },
})

// Guard the assembled server's route table against the policy set.
guard.AssertRouteTable(t, srv.Routes(), guard.RouteTableOptions{Policies: set})
```

The legacy `SwaggerAccessMatches` / `SwaggerSnakeCaseProperties` /
`SwaggerNoDefinition` assertions remain available; new projects should
combine `guard.Run(SuiteConfig{...})` with the `Document` assertions.

## Policy quick reference

```protobuf
policy: { anonymous: true }                 // public
policy: { authenticated: true }             // any authenticated caller
policy: { roles: ["admin"] }                // any of these roles
policy: { permissions: ["notes.read"] }     // all of these permissions
policy: { scopes: ["notes:write"] }         // any of these scopes
policy: { any_of: [ { roles: ["admin"] }, { scopes: ["notes:admin"] } ] }
policy: { preset: "tw.server" preset_args: { scope: "echoes:write" } }
policy: { require: [ { kind: "tenant" values: ["acme"] } ] }
```

- The default registry provides `authenticated` / `claim` / `principal_kind`
  / `role` / `permission` / `scope`.
- The default `scope` requirement matches the claim exactly; `resource:op`
  semantics are available through the `policy/scope` registry entry
  (compatible with v2's `resource.op`).
- `forbid` is deny-overrides.
- With `inherit_default: true`, the method policy merges with the
  service/file defaults: `require`/`forbid` combine with AND across layers
  (`forbid` is always deny-overrides); each `any_of` group is folded
  directly into the alternatives — groups are always OR, and inheritance
  never turns them into a cross-layer Cartesian AND. To intersect on top of
  the defaults, put several conditions into the same `any_of` group (AND
  within a group).

## Packages

| Package | Purpose |
|---|---|
| [`policy`](./policy) | Collect and evaluate policies; [`policy/protopolicy`](./policy/protopolicy) reads the proto annotations |
| [`authz`](./authz) | Authorization decisions; gRPC interceptors and HTTP middleware sharing one Decider |
| [`authn`](./authn) | Authenticator interface plus reference implementations: `jwt`, `session`, `apikey`, `admin` |
| [`interceptor`](./interceptor) | Standard interceptor chain: recovery, request ID, client info, authn/authz hooks, validation |
| [`gateway`](./gateway) | grpc-gateway assembly: mux, dial, register, header policy, error encoding |
| [`server`](./server) | Composition root: one-step assembly with built-in startup assertions |
| [`guard`](./guard) | Test-time assertions aligning the proto surface, OpenAPI docs, and policy |
| [`surface`](./surface) | Unified API-surface IR derived from proto + policy |
| [`csrf`](./csrf) | Double-submit cookie CSRF middleware |
| [`principal`](./principal) | Request identity and claims, with context accessors |
| [`contextx`](./contextx) | Request ID / client info / audit helpers on context |
| [`testkit`](./testkit) | Test fixtures for `server.New`; test-only |

## Proto distribution

The proto module is published to the Buf Schema Registry:
`buf.build/lynx-go/grpcapi`. Register it in your project's `buf.yaml`:

```yaml
version: v2
deps:
  - buf.build/lynx-go/grpcapi
```

Then `import "grpcapi/v1/policy.proto"` in your protos. v3 removed
`authz.proto`: the legacy annotations are vendored per
[MIGRATION.md](./MIGRATION.md) (path A) and consumed through a legacy
Provider; they are not for new projects.

## Documentation

- [example/](./example) — a runnable Tier-0 example: proto declares the
  routes and policies, `server.New` does the rest.
- [MIGRATION.md](./MIGRATION.md) — upgrading from v2, including where the
  legacy `authz` annotations went.
- [GENERALIZATION.md](./GENERALIZATION.md) — full design rationale and
  decisions. A design document; the authoritative API reference is the
  godoc.
- [docs/history/DESIGN.md](./docs/history/DESIGN.md) — the archived v2
  design.
- [CHANGELOG.md](./CHANGELOG.md) — release notes.

## Versioning

- 0.x: minor releases may carry breaking changes. Read
  [CHANGELOG.md](./CHANGELOG.md) and the migration guide before upgrading.
- **API freeze scope (from v0.3.0):** the public API surface consumers
  have already adopted is frozen until v1 — the `gateway` package (all
  public symbols), `interceptor.Stage` and its name/order constants,
  `policy.Build` / `policy.Set`, and `authn.Options` / `authn.Chain`.
  Breaking changes may only arrive as new types, new functions, or new
  fields (additive-only); no renames or removals of existing symbols.
  v0.2.1 gateway symbols removed during the v3 convergence are restored
  as deprecated shims (`gateway/compat.go`: `IncomingMatcher`,
  `OutgoingMatcher`, `NewErrorHandler`, `BuilderEncoder`), so upgrading
  consumers compile again; the shims are scheduled for removal in v1.0.
- **Minimum usable version: v0.2.0.** v0.1.0's go.mod requires an
  unpublished zero pseudo-version of `genproto` and cannot be resolved
  externally; do not reference it.
- `genproto` is a separate Go module, and the main repo's `replace` only
  applies within this repo. When upgrading, **tag genproto first, then bump
  the main repo's require version** — a missing tag surfaces downstream as
  an obscure module-resolution compile error.

## License

[Apache-2.0](./LICENSE)
