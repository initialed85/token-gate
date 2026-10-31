# token-gate

Traefik `forwardAuth` responder for the agent-facing APIs: it answers **204** when a
bearer token matches and **401** when it does not, and tells Traefik which token matched.

The Google gate (`oauth2-proxy`, see `home-ops/clusters/*/applications/auth/`) is right for a
browser and useless to a curl. An IP allowlist is useless to an agent on a network you forgot to
list. This is the third shape: a URL, a token, and a log line naming the owner.

## Contract

`GET|HEAD|POST … /check` is the target Traefik calls; `/healthz` is the kubelet probe; anything
else is 404.

| credential | result |
| --- | --- |
| `authorization: Bearer <token>` | 204 + `X-Auth-Request-User: <NAME>` |
| `x-api-key: <token>` | 204 + `X-Auth-Request-User: <NAME>` |
| `?token=<token>` on the **forwarded** URI | 204 + `X-Auth-Request-User: <NAME>` |
| nothing, a wrong token, `Basic …` | 401 + `WWW-Authenticate` + a one-line hint |

The query form exists for clients that cannot set a header. It is the fallback, not the
preference: a token in a URL lands in access logs, so the gate **redacts it from its own logs**
(`redactURI`) and leaves a 6-character preview on the deny side.

`trustForwardHeader: true` on the Middleware is what makes `X-Forwarded-Uri` arrive; without it
the query fallback silently never fires and every diagnosis starts from the wrong premise.

## Tokens

One environment variable per consumer, from a Secret mounted with `envFrom`:

```
API_TOKEN_EDWARD=<32+ chars>   → owner EDWARD
API_TOKEN_BENCH=<32+ chars>    → owner BENCH
```

Rules, all enforced at startup:

- a token shorter than 32 characters is **ignored**, not accepted;
- a value containing anything outside `[A-Za-z0-9._-]` is **ignored** — this is what stops a k8s
  service-linked variable (`TOKEN_GATE_PORT=tcp://10.43.5.243:8080`) from becoming a credential
  that accepts requests, and it is why `enableServiceLinks: false` is set on the pod;
- with zero usable tokens the process **refuses to start**, so a half-applied Secret surfaces as
  a pod that is visibly not Ready rather than a gate that 401s everything for a week.

Compare is constant-time over **every** entry. Revoking a consumer is deleting one key and
`kubectl -n auth rollout restart deployment/token-gate`; the gate has no cache to expire.

## Deployed shape

`home-ops/clusters/dev/applications/auth/` (namespace `auth` on home-dev, Argo app `auth-dev`):

- `token-gate.yaml` — Deployment (2 replicas, `enableServiceLinks: false`) + Service `token-gate`
  on `:8080`, image `initialed85/token-gate:latest` with `imagePullPolicy: Always`.
- `middleware-api-tokens.yaml` — `Middleware api-tokens` in namespace `auth`. Reference it from
  any namespace as `auth-api-tokens@kubernetescrd` (Traefik v3 splits the reference on the **first**
  hyphen; the oauth2 middleware in the same namespace proves the rule).
- `___secret/api-tokens.yaml` — **gitignored**. Out of band, applied by hand, like
  `___secret/oauth2-proxy.yaml`:

  ```sh
  kubectl --context home-dev -n auth apply -f \
    clusters/dev/applications/auth/___secret/api-tokens.yaml
  kubectl --context home-dev -n auth rollout restart deployment/token-gate
  ```

Order matters twice over: Traefik builds **no router** for an Ingress naming a Middleware that
does not exist (measured: the host answers 404, fail closed), so the gate and Middleware deploy
before any Ingress references them; and the gate fatals without tokens, so the Secret applies
before the Deployment rolls.

## Adopt

```yaml
metadata:
  annotations:
    traefik.ingress.kubernetes.io/router.middlewares: auth-api-tokens@kubernetescrd
```

`Middleware lan-tailscale-only` in namespace `traefik-common` is the same shape with an IP list
(`traefik-common-lan-tailscale-only@kubernetescrd`). Traefik applies **all** listed middlewares,
so listing both means LAN-only **and** token. Decide per host; do not leave both on an API an
agent must reach from a hotel.

## Probes

```sh
./validate.sh              # image build + container contract test, local
./build.sh                 # build + push :latest on the x86 daemon (this machine is arm64)
cd ../chromium && ./validate.sh   # chromium -> screenshot -> OCR, token-bearing
```

Against a live host:

```sh
TOKEN=$(kubectl -n auth get secret api-tokens -o jsonpath='{.data.API_TOKEN_EDWARD}' | base64 -d)
curl -sI https://chromium.dev.initialed85.cc/healthz | head -1                        # 401
curl -sI -H "authorization: Bearer $TOKEN" https://chromium.dev.initialed85.cc/healthz | head -1  # 204/200
kubectl -n auth logs deployment/token-gate | tail    # allow name=EDWARD ... / deny ... presented=none
```

Websocket handshakes carry the same header, so the CDP proxy is gated by the same rule; confirm
with the `websocat`-style probe in `home-ops/investigations/ingress-auth.md` before trusting it.

## Gotchas

- **401 body is a hint, not a joke.** It says what to send, because a 401 from a machine API reads
  like an outage and the person debugging it is usually an agent with a curl.
- Deny logs are rate-limited to one line per client per 30 s, so a scanner cannot fill the disk.
- A client on a network outside the IP allowlist gets **403 from Traefik** and never reaches this
  gate at all. Do not waste time on the gate's logs when you see 403.
- The gate never sees the request body and adds no size limit: body caps belong to the app
  (chromium's `MAX_BODY_BYTES`, ocr's `-limit-request-body`) or to a Traefik `Buffering`
  middleware, not to a forwardAuth responder that answers before the body is read.
