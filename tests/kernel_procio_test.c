/* Host-only regression tests for the actual process-memory copy fallback.
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../crt/kernel.h"
#include "../crt/mdbg.h"

int kernel_proc_copyin(int, const void *, unsigned long, unsigned long);
int kernel_proc_copyout(int, unsigned long, void *, unsigned long);

enum { PAGE_SIZE = 4096, PAGE_COUNT = 4, GUARD = 16, TEST_PID = 42 };
static const unsigned long proc_addr = 0x1000, vmspace_addr = 0x2000;
const unsigned long KERNEL_OFFSET_PROC_P_VMSPACE = 0x200;
unsigned long KERNEL_OFFSET_VMSPACE_VM_PMAP = 0x2e0;
unsigned long KERNEL_ADDRESS_DMAP_BASE = 0xffff800000000000UL;

static unsigned char remote[PAGE_COUNT][PAGE_SIZE];
static unsigned char local[PAGE_COUNT * PAGE_SIZE + 2 * GUARD];
static unsigned long requested, start_addr, copied, chunks[PAGE_COUNT];
static unsigned int transfers, range_errors, page_reads, mdbg_calls;
static int mdbg_success, missing_page, fail_transfer;

unsigned long
kernel_get_proc(int pid) {
  assert(pid == TEST_PID);
  return proc_addr;
}

int
mdbg_copyin(int pid, const void *buf, unsigned long addr, unsigned long len) {
  assert(pid == TEST_PID && buf == local + GUARD);
  assert(addr == start_addr && len == requested);
  mdbg_calls++;
  return mdbg_success ? 0 : -1;
}

int
mdbg_copyout(int pid, unsigned long addr, void *buf, unsigned long len) {
  return mdbg_copyin(pid, buf, addr, len);
}

/* Distinct physical pages expose accidental cross-page copying. */
static unsigned long
physical_page(unsigned long page) {
  return 0xa0000 + page * 0x2000;
}

static int
transfer(unsigned long kaddr, void *buf, unsigned long len, int write_remote) {
  uintptr_t offset = (uintptr_t)buf - (uintptr_t)(local + GUARD);
  unsigned long physical = kaddr - KERNEL_ADDRESS_DMAP_BASE;
  unsigned long page = (physical - physical_page(0)) / 0x2000;
  unsigned long within = physical - physical_page(page);

  assert(transfers < PAGE_COUNT);
  chunks[transfers++] = len;
  if(offset > requested || len > requested - offset) {
    range_errors++;
    fprintf(stderr, "out-of-range %s: offset=%lu length=%lu requested=%lu\n",
            write_remote ? "copyin" : "copyout", (unsigned long)offset,
            len, requested);
    return -1;
  }
  assert(page < PAGE_COUNT && within < PAGE_SIZE);
  assert(len <= PAGE_SIZE - within);
  if(fail_transfer == (int)transfers) {
    return -1;
  }
  if(write_remote) {
    memcpy(remote[page] + within, buf, len);
  } else {
    memcpy(buf, remote[page] + within, len);
  }
  copied += len;
  return 0;
}

int
kernel_copyin(const void *buf, unsigned long kaddr, unsigned long len) {
  return transfer(kaddr, (void *)buf, len, 1);
}

int
kernel_copyout(unsigned long kaddr, void *buf, unsigned long len) {
  unsigned long value;
  if(kaddr == proc_addr + KERNEL_OFFSET_PROC_P_VMSPACE) {
    value = vmspace_addr;
  } else if(kaddr == vmspace_addr + KERNEL_OFFSET_VMSPACE_VM_PMAP + 0x20) {
    value = KERNEL_ADDRESS_DMAP_BASE + 0x10000;
  } else if(kaddr == vmspace_addr + KERNEL_OFFSET_VMSPACE_VM_PMAP + 0x28) {
    value = 0x10000;
  } else if(kaddr == KERNEL_ADDRESS_DMAP_BASE + 0x10000) {
    value = 0x11001;
  } else if(kaddr == KERNEL_ADDRESS_DMAP_BASE + 0x11000) {
    value = 0x12001;
  } else if(kaddr == KERNEL_ADDRESS_DMAP_BASE + 0x12000) {
    value = 0x13001;
  } else if(kaddr >= KERNEL_ADDRESS_DMAP_BASE + 0x13000 &&
            kaddr < KERNEL_ADDRESS_DMAP_BASE + 0x13000 + PAGE_COUNT * 8) {
    unsigned long page = (kaddr - KERNEL_ADDRESS_DMAP_BASE - 0x13000) / 8;
    page_reads++;
    value = (int)page == missing_page ? 0 : physical_page(page) | 1;
  } else {
    return transfer(kaddr, buf, len, 0);
  }
  assert(len == sizeof(value));
  memcpy(buf, &value, sizeof(value));
  return 0;
}

static unsigned char
pattern(unsigned long index) {
  return (unsigned char)(index * 37 + 11);
}

static void
reset(unsigned long addr, unsigned long len, int write_remote) {
  assert(addr + len <= PAGE_COUNT * PAGE_SIZE);
  start_addr = addr;
  requested = len;
  copied = transfers = range_errors = page_reads = mdbg_calls = 0;
  mdbg_success = fail_transfer = 0;
  missing_page = -1;
  memset(chunks, 0, sizeof(chunks));
  memset(local, 0xa5, sizeof(local));
  memset(remote, 0xa5, sizeof(remote));
  for(unsigned long i = 0; i < len; i++) {
    if(write_remote) {
      local[GUARD + i] = pattern(i);
    } else {
      remote[(addr + i) / PAGE_SIZE][(addr + i) % PAGE_SIZE] = pattern(i);
    }
  }
}

static int
copy(int write_remote) {
  return write_remote ? kernel_proc_copyin(TEST_PID, local + GUARD, start_addr, requested)
                      : kernel_proc_copyout(TEST_PID, start_addr, local + GUARD, requested);
}

static void
check_bytes(int write_remote, unsigned long completed) {
  for(unsigned long i = 0; i < sizeof(local); i++) {
    unsigned long offset = i - GUARD;
    unsigned long used = write_remote ? requested : completed;
    unsigned char expected = i >= GUARD && offset < used ? pattern(offset) : 0xa5;
    assert(local[i] == expected);
  }
  for(unsigned long i = 0; i < sizeof(remote); i++) {
    unsigned long offset = i - start_addr;
    unsigned long used = write_remote ? completed : requested;
    unsigned char expected = i >= start_addr && offset < used ? pattern(offset) : 0xa5;
    assert(remote[i / PAGE_SIZE][i % PAGE_SIZE] == expected);
  }
}

int
main(void) {
  static const struct { unsigned long start, length; } cases[] = {
    {PAGE_SIZE - 8, 16},
    {PAGE_SIZE - 8, PAGE_SIZE + 104},
    {PAGE_SIZE, PAGE_SIZE * 2},
    {PAGE_SIZE - 8, 8},
    {123, 37},
    {0, 0},
  };
  for(int write_remote = 0; write_remote <= 1; write_remote++) {
    for(unsigned int i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
      reset(cases[i].start, cases[i].length, write_remote);
      int result = copy(write_remote);
      assert(result == 0 && range_errors == 0);
      assert(copied == requested && mdbg_calls == 1);
      if(i == 0) assert(transfers == 2 && chunks[0] == 8 && chunks[1] == 8);
      if(i == 1) assert(transfers == 3 && chunks[0] == 8 &&
                        chunks[1] == PAGE_SIZE && chunks[2] == 96);
      check_bytes(write_remote, requested);
    }

    reset(PAGE_SIZE - 8, 16, write_remote);
    mdbg_success = 1;
    assert(copy(write_remote) == 0);
    assert(mdbg_calls == 1 && transfers == 0 && page_reads == 0);
    check_bytes(write_remote, 0);

    reset(PAGE_SIZE - 8, 16, write_remote);
    missing_page = 1;
    assert(copy(write_remote) == -1);
    assert(copied == 8 && transfers == 1 && range_errors == 0);
    check_bytes(write_remote, 8);

    reset(PAGE_SIZE - 8, 16, write_remote);
    fail_transfer = 2;
    assert(copy(write_remote) == -1);
    assert(copied == 8 && transfers == 2 && range_errors == 0);
    check_bytes(write_remote, 8);
  }
  puts("kernel_procio: 18 guarded fallback/fast-path/error cases passed");
  return 0;
}
