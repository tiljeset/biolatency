#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "maps.bpf.h"

char LICENSE[] SEC("license") = "GPL";

// Will be put in rodata. Can be used to inject configs from userspace.
const volatile int my_dummy_value = 0;

#define MAX_DISKS 255
#define MAX_REQ_OPS 14
#define MAX_LATENCY_SLOT 27

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u64);
} counts SEC(".maps");

struct request_queue___x {
    struct gendisk *disk;
} __attribute__((preserve_access_index));

struct request___x {
    struct request_queue___x *q;
    struct gendisk *rq_disk;
} __attribute__((preserve_access_index));

static __always_inline struct gendisk *get_disk(void *request)
{
    struct request___x *r = request;
    if (bpf_core_field_exists(r->rq_disk))
        return BPF_CORE_READ(r, rq_disk);
    return BPF_CORE_READ(r, q, disk);
}

#define MKDEV(ma, mi) ((mi & 0xff) | (ma << 8) | ((mi & ~0xff) << 12))

SEC("raw_tp/block_rq_complete")
int block_rq_complete(struct bpf_raw_tracepoint_args *ctx) {
	//bpf_printk("block_rq_complete event\n");
	struct request *rq = (struct request *) ctx->args[0];

	if (my_dummy_value != 0) {
		static u64 value = 0;
		u32 key = my_dummy_value;
		value++;
		bpf_printk("Setting counts[%u] = %lu", key, value);
		bpf_map_update_elem(&counts, &key, &value, 0);
		return 0;
	}

	struct gendisk *disk = get_disk(rq);
	u32 key = disk ? MKDEV(BPF_CORE_READ(disk, major), BPF_CORE_READ(disk, first_minor)) : 0;

	return 0;
}
