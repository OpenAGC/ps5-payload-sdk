/* Copyright (C) 2024 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include "boot_trace.h"
#include "kernel.h"
#include "klog.h"
#include "patch.h"
#include "payload.h"
#include "rtld.h"
#include "rtld_dlfcn.h"
#include "rtld_payload.h"
#include "syscall.h"


/**
 * Dependencies provided by the ELF linker.
 **/
extern unsigned char __bss_start[] __attribute__((weak));
extern unsigned char __bss_end[] __attribute__((weak));


/**
 * Entry point to the main program.
 **/
extern int main(int argc, char* argv[], char *envp[]);


/**
 * Remember the args passed to _start and the cpu state.
 **/
static payload_args_t* payload_args = 0;
static void* jmpbuf[32];


/**
 * Initialize payload runtime.
 **/
static int
payload_init(payload_args_t *args) {
  int *__isthreaded = 0;
  int error = 0;

  if((error=__crt_syscall_init(args))) {
    return error;
  }
  CRT_BOOT_TRACE("syscall.ready", args);
  CRT_BOOT_TRACE("kernel.begin", 0);
  if((error=__kernel_init(args))) {
    CRT_BOOT_TRACE("kernel.error", error);
    return error;
  }
  CRT_BOOT_TRACE("kernel.end", 0);
  CRT_BOOT_TRACE("klog.begin", 0);
  if((error=__klog_init())) {
    CRT_BOOT_TRACE("klog.error", error);
    return error;
  }
  CRT_BOOT_TRACE("klog.end", 0);

  if(!KERNEL_DLSYM(0x2, __isthreaded)) {
    klog_puts("Unable to resolve the symbol '__isthreaded'");
    return -1;
  }
  *__isthreaded = 1;

  CRT_BOOT_TRACE("patch.begin", 0);
  if((error=__patch_init())) {
    CRT_BOOT_TRACE("patch.error", error);
    klog_puts("Unable to initialize patches");
    return error;
  }
  CRT_BOOT_TRACE("patch.end", 0);
  CRT_BOOT_TRACE("rtld.begin", 0);
  if((error=__rtld_init())) {
    CRT_BOOT_TRACE("rtld.error", error);
    klog_puts("Unable to initialize rtld");
    return error;
  }

  CRT_BOOT_TRACE("rtld.end", 0);
  return 0;
}


/**
 * Run the payload.
 **/
static int
payload_run(void) {
  const char* __progname = 0;
  char** (*getargv)(void) = 0;
  int (*getargc)(void) = 0;
  rtld_lib_t* lib = 0;
  char** environ = 0;
  char** argv = 0;
  int argc = 0;
  int err = 0;

  if((KERNEL_DLSYM(0x1, getargc) || KERNEL_DLSYM(0x2001, getargc)) &&
     (KERNEL_DLSYM(0x1, getargv) || KERNEL_DLSYM(0x2001, getargv))) {
    argc = getargc();
    argv = getargv();
  }

  if(!(KERNEL_DLSYM(0x1, environ))) {
    if(!(KERNEL_DLSYM(0x2001, environ))) {
      environ = 0;
    }
  }

  if(!(KERNEL_DLSYM(0x1, __progname))) {
    if(!(KERNEL_DLSYM(0x2001, __progname))) {
      __progname = "";
    }
  }

  CRT_BOOT_TRACE("payload.new.begin", 0);
  if(!(lib=__rtld_payload_new(__progname))) {
    CRT_BOOT_TRACE("payload.new.error", 0);
    return -1;
  }
  CRT_BOOT_TRACE("payload.new.end", lib);

  __rtld_dlfcn_setroot(lib);
  CRT_BOOT_TRACE("payload.open.begin", 0);
  if((err=__rtld_lib_open(lib))) {
    CRT_BOOT_TRACE("payload.open.error", err);
    __rtld_lib_destroy(lib);
    return err;
  }

  CRT_BOOT_TRACE("payload.open.end", 0);

  // run .init constructors
  CRT_BOOT_TRACE("constructors.begin", 0);
  if((err=__rtld_lib_init(lib, argc, argv, environ))) {
    CRT_BOOT_TRACE("constructors.error", err);
    __rtld_lib_close(lib);
    __rtld_lib_destroy(lib);
    return err;
  }

  CRT_BOOT_TRACE("constructors.end", 0);

  // run the actual payload
  CRT_BOOT_TRACE("main.begin", 0);
  err = main(argc, argv, environ);
  CRT_BOOT_TRACE("main.end", err);
  if(payload_args->payloadout) {
    *payload_args->payloadout = err;
  }

  // run .fini destructors
  if((err=__rtld_lib_fini(lib))) {
    __rtld_lib_close(lib);
    __rtld_lib_destroy(lib);
    return err;
  }

  err = __rtld_lib_close(lib);
  __rtld_lib_destroy(lib);

  return err;
}


/**
 * Terminate the payload.
 **/
static int
payload_terminate(void) {
  void (*exit)(int) = 0;
  int exit_code = 0;

  // we are running inside a hijacked process, just return
  if(kernel_dynlib_dlsym(-1, 0x2001, "sceKernelDlsym")) {
    return exit_code;
  }

  if(payload_args->payloadout) {
    exit_code = *payload_args->payloadout;
  }

  // resolve and run exit
  if(KERNEL_DLSYM(0x2, exit)) {
    exit(exit_code);
  }

  // should not happend
  __builtin_trap();

  return -1;
}


/**
 * Exit the payload by transfering the flow of control back to _start().
 **/
void
payload_exit(int exit_code) {
  if(payload_args->payloadout) {
    *payload_args->payloadout = exit_code;
  }
  __builtin_longjmp(jmpbuf, 1);
}


/**
 * Provide a convenience function for accessing the payload args.
 **/
payload_args_t*
payload_get_args(void) {
  return payload_args;
}


/**
 * Entry-point invoked by the ELF loader.
 **/
int
__crt_start(payload_args_t *args) {
  int err;

  // clear .bss section
  for(unsigned char* bss=__bss_start; bss<__bss_end; bss++) {
    *bss = 0;
  }

  payload_args = args;

  // init payload runtime
  if((err=payload_init(args))) {
    if(args->payloadout) {
      *args->payloadout = err;
    }
    return payload_terminate();
  }

  // run payload
  if(!__builtin_setjmp(jmpbuf)) {
    if((err=payload_run())) {
      if(args->payloadout) {
	*args->payloadout = err;
      }
    }
  }

  // terminate payload
  return payload_terminate();
}
