#include "span_context.h"

#define MAX_DISTANCE 10

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, u64);
	__type(value, s64);
	__uint(max_entries, MAX_CONCURRENT_SPANS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} goroutines_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, s64);
	__type(value, struct span_context);
	__uint(max_entries, MAX_CONCURRENT_SPANS);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} goroutines_to_w3c_context SEC(".maps");

static __always_inline void* find_context_in_map(void *ctx, void *context_map) {
    void *data = ctx;
    for (int i = 0; i < MAX_DISTANCE; i++) {
        void* found_in_map = bpf_map_lookup_elem(context_map, &data);
        if (found_in_map != NULL) {
            return data;
        }

        // We assume context.Context implementation containens Parent context.Context member
        // Since the parent is also an interface, we need to read the data part of it
        bpf_probe_read(&data, sizeof(data), data+8);
    }

    bpf_printk("context %lx not found in context map", ctx);
    return NULL;
}

static __always_inline s64 get_goroutine_id() {
    u64 thread_id = bpf_get_current_pid_tgid();
    s64* goId_ptr = bpf_map_lookup_elem(&goroutines_map, &thread_id);

    if(goId_ptr == NULL) {
        return 0;
    }

    s64 go_id;
    bpf_probe_read(&go_id, sizeof(go_id), goId_ptr);
    return go_id;

}