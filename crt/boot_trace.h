/* SPDX-License-Identifier: GPL-3.0-or-later */
#pragma once

/* Diagnostic-only: call after __crt_syscall_init succeeds. This must not use
 * libc, dynamic symbol lookup, kernel-memory access, or initialized klog state.
 * Disabled builds do not evaluate either argument. */
#if defined(PS5_PAYLOAD_CRT_TRACE) && PS5_PAYLOAD_CRT_TRACE
#include "syscall.h"

static inline char*
crt_boot_text(char *out, char *end, const char *text) {
  while(*text && out < end) {
    *out++ = *text++;
  }
  return out;
}

static inline char*
crt_boot_number(char *out, unsigned long value, unsigned int base) {
  static const char digits[] = "0123456789abcdef";
  char reverse[20];
  unsigned int count = 0;
  do {
    reverse[count++] = digits[value % base];
    value /= base;
  } while(value);
  while(count) {
    *out++ = reverse[--count];
  }
  return out;
}

static inline void
crt_boot_trace(const char *event, unsigned long value) {
  char buffer[192];
  char *out = buffer;
  long pid = __crt_syscall(SYS_getpid, 0L, 0L, 0L, 0L, 0L, 0L);

  out = crt_boot_text(out, buffer + 32, "<118>[PS5SDK_BOOT] pid=");
  out = crt_boot_number(out, (unsigned long)pid, 10);
  out = crt_boot_text(out, buffer + 64, " event=");
  out = crt_boot_text(out, buffer + 144, event);
  out = crt_boot_text(out, buffer + 160, " value=0x");
  out = crt_boot_number(out, value, 16);
  *out++ = '\n';
  *out = 0;
  /* Same raw debug-output syscall used by klog.c; no formatter is needed. */
  (void)__crt_syscall(0x259, 7L, buffer, 0L, 0L, 0L, 0L);
}

#define CRT_BOOT_TRACE(event, value) crt_boot_trace((event), (unsigned long)(value))
#else
#define CRT_BOOT_TRACE(event, value) ((void)0)
#endif
