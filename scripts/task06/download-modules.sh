#!/bin/bash
set -euo pipefail
export LC_ALL=C TZ=UTC SOURCE_DATE_EPOCH=0
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 GOTOOLCHAIN=local
mkdir -p /work
tar -xf /input/go.tar -C /work
cd /work
go mod download
go mod verify
