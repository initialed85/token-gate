# Traefik forwardAuth responder: bearer tokens for the agent-facing APIs.
#
# Static Go binary, no dependencies, listening on one port. Alpine (not scratch)
# on purpose: `kubectl exec` into a gate that answers 401 is a debugging
# session you will want at 2am.
FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /token-gate .

FROM alpine:latest

# Alpine ships `nobody` at 65534, so no user creation is needed (and `adduser -D -u 65534`
# fails on a uid that already exists).
COPY --from=build /token-gate /usr/local/bin/token-gate

ENV PORT=8080
EXPOSE 8080
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/token-gate"]
