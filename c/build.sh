#!/usr/bin/env bash
set -xeuo pipefail

CFLAGS="-g -O2 -Wall -Werror=undef"

# bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clang $CFLAGS -target bpf -D__TARGET_ARCH_x86 \
	-c -o biolatency.bpf.o biolatency.bpf.c

bpftool gen skeleton biolatency.bpf.o name biolatency > biolatency.skel.h

# both gcc and clang works here; requires libbpf to link against
cc $CFLAGS -Werror -o biolatency biolatency.c -lbpf
