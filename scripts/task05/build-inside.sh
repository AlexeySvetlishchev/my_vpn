#!/bin/bash
set -euo pipefail
export LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=0
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 GOTOOLCHAIN=local
export GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
mkdir -p /build/go /build/tools
tar -xf /input/go.tar -C /build/go
tar -xf /input/tools.tar -C /build/tools
cd /build/go
go mod download
go mod verify
go build -mod=readonly -trimpath -buildvcs=false -ldflags='-s -w -buildid= -X github.com/amnezia-vpn/amneziawg-go/v3/ipc.socketDirectory=/run/vpn-task05/amneziawg' -o /out/amneziawg-go .
cd /build/tools/src
export CFLAGS='-O2 -ffile-prefix-map=/build=.'
make -j2 RUNSTATEDIR=/run/vpn-task05 WIREGUARD_TOOLS_VERSION=3.1.20260812 LDFLAGS='-static -Wl,--build-id=none'
cp wg /out/awg
/out/amneziawg-go --version
/out/awg --version
sha256sum /out/amneziawg-go /out/awg
