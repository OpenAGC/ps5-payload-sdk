# Host process-memory and bootstrap regressions

Run the production `crt/kernel_procio.c` against a simulated four-level page
table and guarded local/remote memory:

```sh
make -C tests test
```

The test defaults to AddressSanitizer and UndefinedBehaviorSanitizer. On macOS,
the verified compiler command is `make -C tests test HOST_CC=/usr/bin/clang`.
`HOST_CC` and `HOST_CFLAGS` can be overridden for other host toolchains.

The 18 cases cover both copy directions, noncontiguous physical pages, two- and
three-page unaligned copies, aligned full pages, an exact page ending, a
single-page copy, zero length, successful mdbg bypass, an unmapped following
page, and a transfer failure after partial progress. Guards check the entire
source and destination, including bytes outside the requested range.

Before the remaining-length correction, a 16-byte request starting eight bytes
before a page boundary attempted chunks of 8 and 16 bytes. The guarded backend
rejected the second chunk with `offset=8 length=16 requested=16`, and the test
failed. Correct chunks are 8 and 8 bytes. These are host algorithm tests, not
PS5 kernel or whole-console shutdown qualification.

The same target tests `crt/boot_trace.h` with tracing enabled and disabled.
The enabled test checks PID/value formatting, long-event bounds and ignored
debug-output errors. The disabled test proves arguments are not evaluated and
no syscall dependency is introduced.

## Opt-in early bootstrap tracing

`CRT_TRACE=1` on a clean CRT build enables `PS5_PAYLOAD_CRT_TRACE=1`. Changing
the flag requires rebuilding the CRT objects. By default the trace compiles
out. Diagnostic messages begin with `[PS5SDK_BOOT]` and contain the PID, event
and hexadecimal value. They use only the established raw syscall path after
`__crt_syscall_init`, including before `__klog_init`; no libc formatting or
kernel-memory lookup is needed to emit a marker.

Markers cover kernel arguments, prison/direct-map discovery, IOMMU scan start,
visited-slot count and completion, errno resolution, normal logging, patching,
dynamic linking, constructors and main. They cannot observe code before syscall
initialization, and logging can change timing. Preserve production artifacts
and use an isolated diagnostic CRT for comparisons.
