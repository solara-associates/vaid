# Gateway configuration examples — VAID JWT bridge

**Status: draft, documentation only.** These snippets point a gateway's
*existing* JWT-authentication feature at this bridge's issuer and JWKS
(`docs/jwt/v1/profile.md` §8). Neither gateway's JWT support is specific to
VAID; the bridge's whole point is that a gateway needs no VAID-aware code at
all, only ordinary JWT/JWKS configuration.

**Verification status of each snippet is stated explicitly below.** Every
field name here was checked against that project's current, published
documentation (linked). "Verified" means the field names and config shape
are confirmed against the docs; it does **not** mean this snippet was run
against a live gateway — none of these were. Labeled `UNTESTED AGAINST A
LIVE GATEWAY` throughout.

---

## agentgateway (Kubernetes CRD: `AgentgatewayPolicy`)

Verified against: https://agentgateway.dev/docs/kubernetes/latest/security/jwt/setup/
(accessed 2026-10). Field names quoted exactly as documented there:
`issuer`, `audiences`, `jwks.remote.url`, `jwks.remote.cacheDuration`, under
`traffic.jwtAuthentication.providers[]`.

```yaml
apiVersion: gateway.agentgateway.dev/v1alpha1  # group per the agentgateway docs; CONFIRM against your installed CRD version
kind: AgentgatewayPolicy
metadata:
  name: vaid-jwt-bridge-auth
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: your-protected-route
  traffic:
    jwtAuthentication:
      mode: Strict
      providers:
        - issuer: "https://bridge.acme.example"          # must equal the bridge's `iss`
          audiences: ["https://reports.acme.example"]      # must match what callers request as `aud`
          jwks:
            remote:
              url: "https://bridge.acme.example/.well-known/jwks.json"
              cacheDuration: "5m"
```

**`apiVersion` note:** the docs page confirms the `jwks.remote.url` shape but
was not the source for the exact `apiVersion` group/version of
`AgentgatewayPolicy` in your installed CRD set — confirm that field against
`kubectl explain agentgatewaypolicy` in your cluster before applying.

A non-Kubernetes (standalone) agentgateway deployment also supports JWT auth
(`gateways.<name>.jwtAuth`, confirmed field names: `mode`, `issuer`,
`audiences`, `jwks.file`:
https://agentgateway.dev/docs/standalone/latest/documentation/configuration/security/jwt-authn/),
but that page's examples showed only the **file-based** JWKS variant, not a
remote-URL one — do not assume `jwks.remote.url` carries over verbatim to
standalone config without checking the standalone schema directly; it is
not reproduced here because it was not verified against that specific path.

**UNTESTED AGAINST A LIVE GATEWAY.**

---

## Envoy Gateway / Envoy AI Gateway (`SecurityPolicy`)

Verified against: https://gateway.envoyproxy.io/docs/tasks/security/jwt-authentication/
(Envoy Gateway v1.9.2, accessed 2026-10). Envoy AI Gateway's LLM-traffic
routing builds on Envoy Gateway's `Gateway`/`HTTPRoute`/`SecurityPolicy` CRDs
rather than defining its own JWT mechanism, so the same `SecurityPolicy`
shape applies whether the protected route carries ordinary or
LLM/agent traffic. `issuer` and `audiences` field names confirmed against
the underlying Envoy `jwt_authn` filter proto
(https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/filters/http/jwt_authn/v3/config.proto),
which `JWTProvider` mirrors; `remoteJWKS.uri` confirmed against the Envoy
Gateway task doc itself.

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: vaid-jwt-bridge-auth
spec:
  targetRef:
    group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: your-protected-route
  jwt:
    providers:
      - name: vaid-jwt-bridge
        issuer: "https://bridge.acme.example"
        audiences:
          - "https://reports.acme.example"
        remoteJWKS:
          uri: "https://bridge.acme.example/.well-known/jwks.json"
```

**UNTESTED AGAINST A LIVE GATEWAY.**

---

## What is NOT covered here

- Key rotation timing (how long a gateway's JWKS cache may lag a bridge key
  rotation) — set `cacheDuration` / an equivalent TTL short enough that a
  retired key is evicted before the last JWT it signed could still be
  presented, given this profile's short `exp` (profile §3.1, §7).
- mTLS or network-level trust between the gateway and the bridge's
  `/.well-known/jwks.json` endpoint — both examples assume the gateway can
  reach that URL; securing that path is a deployment decision outside this
  profile.
- Rate limiting or further authorization (scope/capability checks beyond
  signature and `aud`/`iss`) on the issued JWT — profile §7 is explicit that
  `act` is informational only; any additional authorization a gateway wants
  to layer on `vaid.scope_boundary`/`vaid.capability_set` is its own policy,
  not specified here.
