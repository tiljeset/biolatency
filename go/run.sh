#!/usr/bin/env bash
set -xeuo pipefail 
go generate && go build && sudo ./biolatency
