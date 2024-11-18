#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/bpf.h>

#include "biolatency.skel.h"

// This should really go in a header file
struct disk_latency_key_t {
    uint32_t dev;
    uint8_t op;
    uint64_t bucket;
};

static int libbpf_print_callback(enum libbpf_print_level level, const char *format, va_list args) {
	const char *level_str;
	switch (level) {
		case LIBBPF_WARN: level_str = "WARN";
		case LIBBPF_INFO: level_str = "INFO";
		case LIBBPF_DEBUG: level_str = "DEBUG";
	}
	
	int ret = 0;
	ret += fprintf(stderr, "[%s] ", level_str);
	ret += vfprintf(stderr, format, args);
	return ret;
}

bool probe_tp_btf(const char *name)
{
	LIBBPF_OPTS(bpf_prog_load_opts, opts, .expected_attach_type = BPF_TRACE_RAW_TP);
	struct bpf_insn insns[] = {
		{ .code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0 },
		{ .code = BPF_JMP | BPF_EXIT },
	};
	int fd, insn_cnt = sizeof(insns) / sizeof(struct bpf_insn);

	opts.attach_btf_id = libbpf_find_vmlinux_btf_id(name, BPF_TRACE_RAW_TP);
	fd = bpf_prog_load(BPF_PROG_TYPE_TRACING, NULL, "GPL", insns, insn_cnt, &opts);
	if (fd >= 0)
		close(fd);
	return fd >= 0;
}

static void sig_handler(int sig) {}

int main() {
	int rc;
	libbpf_set_print(libbpf_print_callback);

	signal(SIGINT, sig_handler);

	// load and verify bpf _application_
	printf("===== OPEN ======\n");
	struct biolatency *skel = biolatency__open();
	assert(skel);

	// set configuration data through skel->rodata->...
	// no data to set ....
	
	// Load and verify bpf _programs_
	printf("===== LOAD ======\n");
	rc = biolatency__load(skel);
	assert (!rc);

	assert(probe_tp_btf("block_rq_complete"));

	// attach tracepoints
	printf("===== ATTACH ======\n");
	rc = biolatency__attach(skel);
	assert(!rc);

	printf("Waiting for events, press Ctrl-C to stop...");
	while (1) {
		sleep(-1);
		break;
	}
	printf("\n");

	// read the map
	{
		struct disk_latency_key_t key = { 66304, 1, 4 };
		struct disk_latency_key_t next_key;
		uint64_t value;
		int fd = bpf_map__fd(skel->maps.bio_latency_seconds);
		assert(fd > 0);


		int err;
		while (!bpf_map_get_next_key(fd, &key, &next_key)) {
			key = next_key;
			err = bpf_map_lookup_elem(fd, &key, &value);
			assert (err >= 0);
			printf("counts[%u:%u] (%lu): %lu\n", key.dev,key.op, key.bucket, value);
		}
	}
	
	biolatency__destroy(skel);
	return 0;
}
