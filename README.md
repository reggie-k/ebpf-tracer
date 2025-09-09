# file-io-tracer

file-io-tracer is an Inspektor Gadget that traces open/close/exit syscalls and correlates file descriptors to file paths. It helps debug leftover git lock files in Argo CD repo-server.

## How to use

```
sudo ig run ghcr.io/CHANGEME-ORG/CHANGEME-GADGET-NAME:latest
```

## Requirements

- ig v0.26.0+
- Linux v5.8+ (ringbuf). For older kernels, add a perf buffer fallback.

Notes for k3d and vcluster:
- Deploy on the host cluster nodes (where containers run). Ensure IG has required privileges and mounts.
- Works across architectures via tracepoints; BTF with CO-RE recommended. Consider btfgen for portability.

## License (CHANGEME)

The user space components are licensed under the [Apache License, Version
2.0](LICENSE). The BPF code templates are licensed under the [General Public
License, Version 2.0, with the Linux-syscall-note](LICENSE-bpf.txt).