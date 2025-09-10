// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 CHANGEME-Authors */

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/mntns.h>
#include <gadget/types.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct event {
  struct gadget_process proc;
  char op[8];
  int  fd;
  long retval;
  char path[256];
  char argv[256];
};

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(file_io_tracer, events, event);
/*
 * Correlate paths with file descriptors and in-flight syscalls
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u64); /* pid_tgid */
  __type(value, __u8[256]); /* path */
  __uint(max_entries, 8192);
} inprog_open SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u64); /* pid_tgid */
  __type(value, __s32); /* fd */
  __uint(max_entries, 8192);
} inprog_close SEC(".maps");

struct fd_key {
  __u32 tgid;
  __s32 fd;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct fd_key);
  __type(value, __u8[256]);
  __uint(max_entries, 16384);
} fd_path SEC(".maps");

/* per-cpu scratch buffer to avoid large on-stack arrays */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u8[256]);
} scratch_path SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u8[512]);
} scratch_argv SEC(".maps");

static __always_inline void emit_event(void *ctx, const char *op, int fd, long retval, const char *path) {
  struct event *e = gadget_reserve_buf(&events, sizeof(*e));
  if (!e)
    return;
  gadget_process_populate(&e->proc);
  __builtin_memset(e->op, 0, sizeof(e->op));
  __builtin_memcpy(e->op, op, 7);
  e->fd = fd;
  e->retval = retval;
  if (path)
    __builtin_memcpy(e->path, path, sizeof(e->path));
  else
    e->path[0] = '\0';
  e->argv[0] = '\0';
  gadget_submit_buf(ctx, &events, e, sizeof(*e));
}

/* no in-kernel path filter; emit all events */

/* openat(openat2) enter: capture filename */
SEC("tracepoint/syscalls/sys_enter_openat")
int tp_sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
  if (gadget_should_discard_data_current())
    return 0;
  __u64 id = bpf_get_current_pid_tgid();
  const char *filename = (const char *)ctx->args[1];
  __u32 zero = 0;
  __u8 *p = bpf_map_lookup_elem(&scratch_path, &zero);
  if (!p)
    return 0;
  long n = bpf_probe_read_user_str(p, 256, filename);
  if (n > 0)
    bpf_map_update_elem(&inprog_open, &id, p, BPF_ANY);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int tp_sys_enter_openat2(struct trace_event_raw_sys_enter *ctx) {
  if (gadget_should_discard_data_current())
    return 0;
  __u64 id = bpf_get_current_pid_tgid();
  const char *filename = (const char *)ctx->args[1];
  __u32 zero = 0;
  __u8 *p = bpf_map_lookup_elem(&scratch_path, &zero);
  if (!p)
    return 0;
  long n = bpf_probe_read_user_str(p, 256, filename);
  if (n > 0)
    bpf_map_update_elem(&inprog_open, &id, p, BPF_ANY);
  return 0;
}

/* openat(openat2) exit: emit event and remember fd->path */
SEC("tracepoint/syscalls/sys_exit_openat")
int tp_sys_exit_openat(struct trace_event_raw_sys_exit *ctx) {
  if (gadget_should_discard_data_current())
    return 0;
  __u64 id = bpf_get_current_pid_tgid();
  __s64 ret = ctx->ret;
  __u8 *pathp = bpf_map_lookup_elem(&inprog_open, &id);
  if (pathp) {
    emit_event((void *)ctx, "open", (__s32)ret, ret, (const char *)pathp);
    if (ret >= 0) {
      struct fd_key key = { .tgid = id >> 32, .fd = (__s32)ret };
      bpf_map_update_elem(&fd_path, &key, pathp, BPF_ANY);
    }
    bpf_map_delete_elem(&inprog_open, &id);
  }
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat2")
int tp_sys_exit_openat2(struct trace_event_raw_sys_exit *ctx) {
  if (gadget_should_discard_data_current())
    return 0;
  __u64 id = bpf_get_current_pid_tgid();
  __s64 ret = ctx->ret;
  __u8 *pathp = bpf_map_lookup_elem(&inprog_open, &id);
  if (pathp) {
    emit_event((void *)ctx, "open", (__s32)ret, ret, (const char *)pathp);
    if (ret >= 0) {
      struct fd_key key = { .tgid = id >> 32, .fd = (__s32)ret };
      bpf_map_update_elem(&fd_path, &key, pathp, BPF_ANY);
    }
    bpf_map_delete_elem(&inprog_open, &id);
  }
  return 0;
}

/* close enter/exit: correlate fd with path and emit */
SEC("tracepoint/syscalls/sys_enter_close")
int tp_sys_enter_close(struct trace_event_raw_sys_enter *ctx) {
  if (gadget_should_discard_data_current())
    return 0;
  __u64 id = bpf_get_current_pid_tgid();
  __s32 fd = (__s32)ctx->args[0];
  bpf_map_update_elem(&inprog_close, &id, &fd, BPF_ANY);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int tp_sys_exit_close(struct trace_event_raw_sys_exit *ctx) {
  if (gadget_should_discard_data_current())
    return 0;
  __u64 id = bpf_get_current_pid_tgid();
  __s32 *fdp = bpf_map_lookup_elem(&inprog_close, &id);
  if (!fdp)
    return 0;
  struct fd_key key = { .tgid = id >> 32, .fd = *fdp };
  __u8 *pathp = bpf_map_lookup_elem(&fd_path, &key);
  if (pathp) {
    emit_event((void *)ctx, "close", *fdp, ctx->ret, (const char *)pathp);
  }
  if (pathp)
    bpf_map_delete_elem(&fd_path, &key);
  bpf_map_delete_elem(&inprog_close, &id);
  return 0;
}

/* process exit */
SEC("tracepoint/sched/sched_process_exit")
int tp_sched_process_exit(struct trace_event_raw_sched_process_template *ctx) {
  if (gadget_should_discard_data_current())
    return 0;
  /* capture real exit_code from current task */
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  int code = 0;
  bpf_core_read(&code, sizeof(code), &task->exit_code);
  emit_event((void *)ctx, "exit", -1, code, 0);
  return 0;
}

/* process start via execve/execveat (emit filename) */
SEC("tracepoint/syscalls/sys_enter_execve")
int tp_sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
  if (gadget_should_discard_data_current())
    return 0;
  const char *filename = (const char *)ctx->args[0];
  const char *const *argv = (const char *const *)ctx->args[1];
  __u32 zero = 0;
  __u8 *argv_buf = bpf_map_lookup_elem(&scratch_argv, &zero);
  if (!argv_buf)
    return 0;
  __u8 *path_buf = bpf_map_lookup_elem(&scratch_path, &zero);
  if (!path_buf)
    return 0;
  /* stage strings in per-cpu buffers first */
  if (bpf_probe_read_user_str(path_buf, 256, filename) > 0)
    ;
  /* Best-effort argv capture: only argv[0] to satisfy verifier */
  const char *arg0p = 0;
  if (bpf_core_read(&arg0p, sizeof(arg0p), &argv[0]) == 0 && arg0p)
    bpf_probe_read_user_str(argv_buf, 512, arg0p);
  struct event *event = gadget_reserve_buf(&events, sizeof(struct event));
  if (!event)
    return 0;
  gadget_process_populate(&event->proc);
  __builtin_memset(event->op, 0, sizeof(event->op));
  __builtin_memcpy(event->op, "exec", 5);
  event->fd = -1;
  event->retval = 0;
  __builtin_memcpy(event->path, path_buf, sizeof(event->path));
  __builtin_memcpy(event->argv, argv_buf, sizeof(event->argv));
  gadget_submit_buf((void *)ctx, &events, event, sizeof(*event));
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int tp_sys_enter_execveat(struct trace_event_raw_sys_enter *ctx) {
  if (gadget_should_discard_data_current())
    return 0;
  const char *filename = (const char *)ctx->args[1];
  const char *const *argv = (const char *const *)ctx->args[2];
  __u32 zero = 0;
  __u8 *argv_buf = bpf_map_lookup_elem(&scratch_argv, &zero);
  if (!argv_buf)
    return 0;
  __u8 *path_buf = bpf_map_lookup_elem(&scratch_path, &zero);
  if (!path_buf)
    return 0;
  /* stage strings in per-cpu buffers first */
  if (bpf_probe_read_user_str(path_buf, 256, filename) > 0)
    ;
  const char *arg0p = 0;
  if (bpf_core_read(&arg0p, sizeof(arg0p), &argv[0]) == 0 && arg0p)
    bpf_probe_read_user_str(argv_buf, 512, arg0p);
  struct event *event = gadget_reserve_buf(&events, sizeof(struct event));
  if (!event)
    return 0;
  gadget_process_populate(&event->proc);
  __builtin_memset(event->op, 0, sizeof(event->op));
  __builtin_memcpy(event->op, "exec", 5);
  event->fd = -1;
  event->retval = 0;
  __builtin_memcpy(event->path, path_buf, sizeof(event->path));
  __builtin_memcpy(event->argv, argv_buf, sizeof(event->argv));
  gadget_submit_buf((void *)ctx, &events, event, sizeof(*event));
  return 0;
}

char LICENSE[] SEC("license") = "GPL";