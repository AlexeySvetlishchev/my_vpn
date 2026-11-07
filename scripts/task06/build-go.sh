#!/bin/bash
set -eu
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 GOTOOLCHAIN=local
export GOPROXY=off GOSUMDB=off GOMODCACHE=/go/pkg/mod
mkdir -p /work
tar -xf /input/go.tar -C /work
mkdir -p /work/tools
tar -xf /input/tools.tar -C /work/tools
cd /work
go build -mod=readonly -trimpath -buildvcs=false \
  -ldflags='-s -w -buildid= -X github.com/amnezia-vpn/amneziawg-go/v3/ipc.socketDirectory=/run/vpn-task06/amneziawg' \
  -o /out/amneziawg-go .
chmod 0755 /out/amneziawg-go
cd /work/tools/src
export CFLAGS='-O2 -ffile-prefix-map=/work=.'
make -j2 RUNSTATEDIR=/run/vpn-task06 WIREGUARD_TOOLS_VERSION=3.1.20260812 LDFLAGS='-static -Wl,--build-id=none'
cp wg /out/awg
chmod 0755 /out/awg
sha256sum /out/amneziawg-go /out/awg
