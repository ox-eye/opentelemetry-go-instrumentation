#include "arguments.h"
#include "go_context.h"
#include "go_types.h"
#include "bpf_helpers.h"

char __license[]
SEC("license") = "Dual MIT/GPL";

#define RUNNING_STATE 2

// Injected in init
volatile const u64 goid_pos;


SEC("uprobe/runtime_newproc1")
int uprobe_runtime_newproc1_Returns(struct pt_regs *ctx) {

    s64 parent_go_id = get_goroutine_id();

    if (parent_go_id == 0) {
        return 0;
    }
    struct span_context *span_ctx_ptr = bpf_map_lookup_elem(&goroutines_to_w3c_context, &parent_go_id);

    // No span context exists for parent goroutine id, returning
    if (span_ctx_ptr == NULL) {
        return 0;
    }
    void *g_ptr;
    if (is_registers_abi) {
        u64 gp_pos = 1;
        g_ptr = get_argument(ctx, gp_pos);
    } else {
        void *g_ptr_ptr = (void *) ctx->rsp + 48;
        bpf_probe_read(&g_ptr, sizeof(g_ptr), g_ptr_ptr);
    }
    s64 child_go_id = 0;
    bpf_probe_read(&child_go_id, sizeof(child_go_id), g_ptr + goid_pos);

    struct span_context span_ctx;
    bpf_probe_read(&span_ctx, sizeof(span_ctx), span_ctx_ptr);
    bpf_printk(
            "uprobe/runtime_newproc1: Copying existing w3c context from parent goroutine id %u to new goroutine id %u",
            parent_go_id, child_go_id);

    bpf_map_update_elem(&goroutines_to_w3c_context, &child_go_id, &span_ctx, 0);

    return 0;
}

SEC("uprobe/runtime_casgstatus")
int uprobe_runtime_casgstatus(struct pt_regs *ctx) {
    u32 newval;
    if (is_registers_abi) {
        u64 newval_pos = 3;
        newval = get_argument(ctx, newval_pos);
    } else {
        bpf_probe_read(&newval, sizeof(newval), (void *) (ctx->rsp + 20));
    }

    if (newval != RUNNING_STATE) {
        return 0;
    }

    void *g_ptr;
    if (is_registers_abi) {
        u64 g_ptr_pos = 1;
        g_ptr = get_argument(ctx, g_ptr_pos);
    } else {
        void *g_ptr_ptr = (void *) (ctx->rsp + 8);
        bpf_probe_read(&g_ptr, sizeof(g_ptr), g_ptr_ptr);
    }

    s64 goid = 0;
    bpf_probe_read(&goid, sizeof(goid), g_ptr + goid_pos);
    u64 thread_id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&goroutines_map, &thread_id, &goid, 0);
    bpf_printk("uprobe_runtime_casgstatus: Caught runtime_casgstatus event with thread_id: %u and go_id: %d", thread_id,
               goid);

    return 0;
}