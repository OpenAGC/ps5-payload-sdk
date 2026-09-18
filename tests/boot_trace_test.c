/* SPDX-License-Identifier: GPL-3.0-or-later */
#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "../crt/boot_trace.h"

#if defined(PS5_PAYLOAD_CRT_TRACE) && PS5_PAYLOAD_CRT_TRACE
static char captured[192];
static long test_pid = 478;
static unsigned int calls;

long
__crt_syscall(long sysno, ...) {
  va_list args;
  va_start(args, sysno);
  calls++;
  if(sysno == SYS_getpid) {
    for(int i = 0; i < 6; i++) assert(va_arg(args, long) == 0);
    va_end(args);
    return test_pid;
  }
  assert(sysno == 0x259 && va_arg(args, long) == 7);
  const char *text = va_arg(args, const char *);
  assert(strlen(text) < sizeof(captured));
  strcpy(captured, text);
  for(int i = 0; i < 4; i++) assert(va_arg(args, long) == 0);
  va_end(args);
  /* A diagnostic-output failure must not become a bootstrap failure. */
  return -1;
}
#endif

int
main(void) {
  unsigned long evaluated = 0;
  CRT_BOOT_TRACE("phase", evaluated++);
#if defined(PS5_PAYLOAD_CRT_TRACE) && PS5_PAYLOAD_CRT_TRACE
  assert(evaluated == 1 && calls == 2);
  assert(!strcmp(captured, "<118>[PS5SDK_BOOT] pid=478 event=phase value=0x0\n"));
  CRT_BOOT_TRACE("kernel.error", ULONG_MAX);
  assert(!strcmp(captured,
      "<118>[PS5SDK_BOOT] pid=478 event=kernel.error value=0xffffffffffffffff\n"));
  char long_event[256];
  memset(long_event, 'a', sizeof(long_event));
  long_event[sizeof(long_event) - 1] = 0;
  test_pid = -1;
  CRT_BOOT_TRACE(long_event, ULONG_MAX);
  assert(calls == 6 && strlen(captured) < sizeof(captured));
  assert(strstr(captured, " value=0xffffffffffffffff\n"));
  puts("boot_trace: enabled formatting, bounds and ignored-output-error passed");
#else
  assert(evaluated == 0);
  /* Even undeclared expressions must disappear in a disabled build. */
  CRT_BOOT_TRACE(missing_event, missing_value);
  puts("boot_trace: disabled arguments and syscall dependency eliminated");
#endif
  return 0;
}
