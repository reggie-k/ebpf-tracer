// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
/* Copyright (c) 2024 CHANGEME-Authors */

#include <vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns.h>
#include <gadget/types.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct event {
  gadget_timestamp timestamp;
  gadget_mntns_id mntns_id;
  __u32 pid;
  __u32 ppid;
  __u8 comm[TASK_COMM_LEN];
  __u8 op[8];
  __s32 fd;
  __s64 retval;
  __u8 path[256];
  __u8 argv[512];
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

static __always_inline void emit_event(void *ctx, const char *op, __s32 fd, __s64 retval, const __u8 *path) {
  struct event *event = gadget_reserve_buf(&events, sizeof(*event));
  if (!event)
    return;
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  event->timestamp = bpf_ktime_get_boot_ns();
  event->mntns_id = gadget_get_current_mntns_id();
  event->pid = pid_tgid >> 32;
  /* parent pid via task->real_parent->tgid */
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct task_struct *parent = 0;
  __u32 ppid = 0;
  bpf_core_read(&parent, sizeof(parent), &task->real_parent);
  if (parent)
    bpf_core_read(&ppid, sizeof(ppid), &parent->tgid);
  event->ppid = ppid;
  bpf_get_current_comm(&event->comm, sizeof(event->comm));
  __builtin_memset(event->op, 0, sizeof(event->op));
  __builtin_memcpy(event->op, op, 7);
  event->fd = fd;
  event->retval = retval;
  if (path)
    __builtin_memcpy(event->path, path, sizeof(event->path));
  else
    event->path[0] = '\0';
  event->argv[0] = '\0';
  gadget_submit_buf(ctx, &events, event, sizeof(*event));
}

/* openat(openat2) enter: capture filename */
SEC("tracepoint/syscalls/sys_enter_openat")
int tp_sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
  __u64 id = bpf_get_current_pid_tgid();
  const char *filename = (const char *)ctx->args[1];
  __u8 path[256] = {};
  long n = bpf_probe_read_user_str(path, sizeof(path), filename);
  if (n > 0)
    bpf_map_update_elem(&inprog_open, &id, &path, BPF_ANY);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int tp_sys_enter_openat2(struct trace_event_raw_sys_enter *ctx) {
  __u64 id = bpf_get_current_pid_tgid();
  const char *filename = (const char *)ctx->args[1];
  __u8 path[256] = {};
  long n = bpf_probe_read_user_str(path, sizeof(path), filename);
  if (n > 0)
    bpf_map_update_elem(&inprog_open, &id, &path, BPF_ANY);
  return 0;
}

/* openat(openat2) exit: emit event and remember fd->path */
SEC("tracepoint/syscalls/sys_exit_openat")
int tp_sys_exit_openat(struct trace_event_raw_sys_exit *ctx) {
  __u64 id = bpf_get_current_pid_tgid();
  __s64 ret = ctx->ret;
  __u8 *pathp = bpf_map_lookup_elem(&inprog_open, &id);
  if (pathp) {
    emit_event((void *)ctx, "open", (__s32)ret, ret, pathp);
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
  __u64 id = bpf_get_current_pid_tgid();
  __s64 ret = ctx->ret;
  __u8 *pathp = bpf_map_lookup_elem(&inprog_open, &id);
  if (pathp) {
    emit_event((void *)ctx, "open", (__s32)ret, ret, pathp);
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
  __u64 id = bpf_get_current_pid_tgid();
  __s32 fd = (__s32)ctx->args[0];
  bpf_map_update_elem(&inprog_close, &id, &fd, BPF_ANY);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int tp_sys_exit_close(struct trace_event_raw_sys_exit *ctx) {
  __u64 id = bpf_get_current_pid_tgid();
  __s32 *fdp = bpf_map_lookup_elem(&inprog_close, &id);
  if (!fdp)
    return 0;
  struct fd_key key = { .tgid = id >> 32, .fd = *fdp };
  __u8 *pathp = bpf_map_lookup_elem(&fd_path, &key);
  emit_event((void *)ctx, "close", *fdp, ctx->ret, pathp);
  if (pathp)
    bpf_map_delete_elem(&fd_path, &key);
  bpf_map_delete_elem(&inprog_close, &id);
  return 0;
}

/* process exit */
SEC("tracepoint/sched/sched_process_exit")
int tp_sched_process_exit(struct trace_event_raw_sched_process_template *ctx) {
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
  const char *filename = (const char *)ctx->args[0];
  __u8 path[256] = {};
  const char *const *argv = (const char *const *)ctx->args[1];
  __u8 argbuf[512] = {};
  int off = 0;
  long n = bpf_probe_read_user_str(path, sizeof(path), filename);
  /* Best-effort argv copy: read up to 6 args */
  #pragma unroll
  for (int i = 0; i < 6; i++) {
    const char *argp = 0;
    if (bpf_core_read(&argp, sizeof(argp), &argv[i]) < 0)
      break;
    if (!argp)
      break;
    int rem = (int)sizeof(argbuf) - off - 1;
    if (rem <= 0)
      break;
    int w = bpf_probe_read_user_str(&argbuf[off], rem, argp);
    if (w <= 0)
      break;
    off += w - 1;
    if (off < (int)sizeof(argbuf) - 1) {
      argbuf[off++] = ' ';
    }
  }
  struct event *event = gadget_reserve_buf(&events, sizeof(struct event));
  if (event) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->timestamp = bpf_ktime_get_boot_ns();
    event->mntns_id = gadget_get_current_mntns_id();
    event->pid = pid_tgid >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = 0; __u32 ppid = 0;
    bpf_core_read(&parent, sizeof(parent), &task->real_parent);
    if (parent) bpf_core_read(&ppid, sizeof(ppid), &parent->tgid);
    event->ppid = ppid;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __builtin_memset(event->op, 0, sizeof(event->op));
    __builtin_memcpy(event->op, "exec", 5);
    event->fd = -1;
    event->retval = 0;
    if (n > 0) __builtin_memcpy(event->path, path, sizeof(event->path)); else event->path[0] = '\0';
    if (off > 0) __builtin_memcpy(event->argv, argbuf, sizeof(event->argv)); else event->argv[0] = '\0';
    gadget_submit_buf((void *)ctx, &events, event, sizeof(*event));
  }
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int tp_sys_enter_execveat(struct trace_event_raw_sys_enter *ctx) {
  const char *filename = (const char *)ctx->args[1];
  __u8 path[256] = {};
  const char *const *argv = (const char *const *)ctx->args[2];
  __u8 argbuf[512] = {};
  int off = 0;
  long n = bpf_probe_read_user_str(path, sizeof(path), filename);
  #pragma unroll
  for (int i = 0; i < 6; i++) {
    const char *argp = 0;
    if (bpf_core_read(&argp, sizeof(argp), &argv[i]) < 0)
      break;
    if (!argp)
      break;
    int rem = (int)sizeof(argbuf) - off - 1;
    if (rem <= 0)
      break;
    int w = bpf_probe_read_user_str(&argbuf[off], rem, argp);
    if (w <= 0)
      break;
    off += w - 1;
    if (off < (int)sizeof(argbuf) - 1) {
      argbuf[off++] = ' ';
    }
  }
  struct event *event = gadget_reserve_buf(&events, sizeof(struct event));
  if (event) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    event->timestamp = bpf_ktime_get_boot_ns();
    event->mntns_id = gadget_get_current_mntns_id();
    event->pid = pid_tgid >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = 0; __u32 ppid = 0;
    bpf_core_read(&parent, sizeof(parent), &task->real_parent);
    if (parent) bpf_core_read(&ppid, sizeof(ppid), &parent->tgid);
    event->ppid = ppid;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    __builtin_memset(event->op, 0, sizeof(event->op));
    __builtin_memcpy(event->op, "exec", 5);
    event->fd = -1;
    event->retval = 0;
    if (n > 0) __builtin_memcpy(event->path, path, sizeof(event->path)); else event->path[0] = '\0';
    if (off > 0) __builtin_memcpy(event->argv, argbuf, sizeof(event->argv)); else event->argv[0] = '\0';
    gadget_submit_buf((void *)ctx, &events, event, sizeof(*event));
  }
  return 0;
}

char LICENSE[] SEC("license") = "GPL";