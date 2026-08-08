/* Copyright (C) 2025 John Törnblom

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

#include <errno.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/syscall.h>

#define VM_PAGE_SIZE 0x4000UL

/**
 * shared objects do not link with crt1.o, declare deps as weak.
 **/
__attribute__((weak)) int kernel_mprotect(pid_t, intptr_t, size_t, int);
__attribute__((weak)) int kernel_mprotect_exact_with_vm_lock_held(
    pid_t, intptr_t, size_t, int);
__attribute__((weak)) void kernel_vm_operation_lock(void);
__attribute__((weak)) void kernel_vm_operation_unlock(void);


static long
__syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
  unsigned long ret;
  char iserror;

  register long r10 __asm__("r10") = a4;
  register long r8 __asm__("r8") = a5;
  register long r9 __asm__("r9") = a6;

  __asm__ __volatile__(
     "syscall" : "=a"(ret), "=@ccc"(iserror), "+r"(r10), "+r"(r8), "+r"(r9) :
     "a"(n), "D"(a1), "S"(a2), "d"(a3) :
     "rcx", "r11", "memory"
     );

  return iserror ? -ret : ret;
}


static void*
sys_mmap(void* addr, size_t size, int prot, int flags, int fd, off_t offset) {
  long ret;

  if((ret=__syscall6(SYS_mmap, (long)addr, size, prot, flags, fd, offset)) < 0) {
    errno = -ret;
    return (void*)-1;
  }

  return (void*)ret;
}


static int
sys_mprotect(const void* addr, size_t size, int prot) {
  long ret;

  if((ret=__syscall6(SYS_mprotect, (long)addr, size, prot, 0, 0, 0)) < 0) {
    errno = -ret;
    return -1;
  }

  return (int)ret;
}


static int
sys_munmap(void* addr, size_t size) {
  long ret;

  if((ret=__syscall6(SYS_munmap, (long)addr, size, 0, 0, 0, 0)) < 0) {
    errno = -ret;
    return -1;
  }

  return (int)ret;
}


static int
vm_operation_lock_available(void) {
  return kernel_vm_operation_lock && kernel_vm_operation_unlock;
}


int
mprotect(const void* addr, size_t size, int prot) {
  if(!(prot & PROT_EXEC)) {
    int ret;
    int locked = vm_operation_lock_available();
    if(locked) {
      kernel_vm_operation_lock();
    }
    ret = sys_mprotect(addr, size, prot);
    if(locked) {
      kernel_vm_operation_unlock();
    }
    return ret;
  }

  errno = 0;
  if(kernel_mprotect && !kernel_mprotect(-1, (intptr_t)addr, size, prot)) {
    return 0;
  }

  /* kernel_mprotect sets errno for its checked failures.  Keep that detail
   * for callers; old payloads may still return an error without setting it. */
  if(!errno) {
    errno = EPERM;
  }
  return -1;
}


void*
mmap(void* addr, size_t size, int prot, int flags, int fd, off_t offset) {
  void *map_addr;
  int locked = vm_operation_lock_available();
  size_t exec_protect_size = size;

  if(locked) {
    kernel_vm_operation_lock();
  }
  if(!(prot & PROT_EXEC)) {
    map_addr = sys_mmap(addr, size, prot, flags, fd, offset);
    if(locked) {
      kernel_vm_operation_unlock();
    }
    return map_addr;
  }

  if(size > (size_t)-1-(VM_PAGE_SIZE-1)) {
    if(locked) {
      kernel_vm_operation_unlock();
    }
    errno = EOVERFLOW;
    return MAP_FAILED;
  }
  exec_protect_size = (size + VM_PAGE_SIZE - 1) & ~(VM_PAGE_SIZE - 1);

  prot &= ~PROT_EXEC;
  if((map_addr=sys_mmap(addr, size, prot, flags, fd, offset)) == MAP_FAILED) {
    if(locked) {
      kernel_vm_operation_unlock();
    }
    return map_addr;
  }

  prot |= PROT_EXEC;
  errno = 0;
  int protect_result;
  if(locked && kernel_mprotect_exact_with_vm_lock_held) {
    protect_result = kernel_mprotect_exact_with_vm_lock_held(
        -1, (intptr_t)map_addr, exec_protect_size, prot);
  } else {
    if(locked) {
      kernel_vm_operation_unlock();
      locked = 0;
    }
    protect_result = kernel_mprotect
        ? kernel_mprotect(-1, (intptr_t)map_addr, size, prot) : -1;
  }
  if(protect_result) {
    int error = errno;
    if(!locked && vm_operation_lock_available()) {
      kernel_vm_operation_lock();
      locked = 1;
    }
    sys_munmap(map_addr, size);
    if(locked) {
      kernel_vm_operation_unlock();
    }
    errno = error ? error : EPERM;
    return MAP_FAILED;
  }

  if(locked) {
    kernel_vm_operation_unlock();
  }
  return map_addr;
}


int
munmap(void* addr, size_t size) {
  int ret;
  int locked = vm_operation_lock_available();

  if(locked) {
    kernel_vm_operation_lock();
  }
  ret = sys_munmap(addr, size);
  if(locked) {
    kernel_vm_operation_unlock();
  }
  return ret;
}
