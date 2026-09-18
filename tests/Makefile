HOST_CC ?= cc
HOST_CFLAGS ?= -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined -fno-omit-frame-pointer
BUILD ?= .build

.PHONY: test
test: $(BUILD)/kernel_procio_test $(BUILD)/boot_trace_on $(BUILD)/boot_trace_off
	./$(BUILD)/kernel_procio_test
	./$(BUILD)/boot_trace_on
	./$(BUILD)/boot_trace_off

$(BUILD)/kernel_procio_test: kernel_procio_test.c ../crt/kernel_procio.c ../crt/kernel.h ../crt/mdbg.h ../crt/payload.h
	mkdir -p $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) kernel_procio_test.c ../crt/kernel_procio.c -o $@

$(BUILD)/boot_trace_on: boot_trace_test.c ../crt/boot_trace.h ../crt/syscall.h
	mkdir -p $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) -DPS5_PAYLOAD_CRT_TRACE=1 boot_trace_test.c -o $@

$(BUILD)/boot_trace_off: boot_trace_test.c ../crt/boot_trace.h
	mkdir -p $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) boot_trace_test.c -o $@
