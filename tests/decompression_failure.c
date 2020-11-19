#include <darwintest.h>
#include <mach/mach.h>
#include <sys/sysctl.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <pthread.h>
#include "excserver.h"
#include "exc_helpers.h"

extern int pid_hibernate(int pid);

static vm_address_t page_size;

T_GLOBAL_META(
	T_META_REQUIRES_SYSCTL_EQ("hw.optional.wkdm_popcount", 1)
	);

static void
page_out(void)
{
	T_ASSERT_POSIX_SUCCESS(pid_hibernate(-2), NULL);
	T_ASSERT_POSIX_SUCCESS(pid_hibernate(-2), NULL);
}

static void
dirty_page(const vm_address_t address)
{
	assert((address & (page_size - 1)) == 0UL);
	uint32_t *const page_as_u32 = (uint32_t *)address;
	for (uint32_t i = 0; i < page_size / sizeof(uint32_t); i += 2) {
		page_as_u32[i + 0] = i % 4;
		page_as_u32[i + 1] = 0xcdcdcdcd;
	}
}

static bool
try_to_corrupt_page(vm_address_t page_va)
{
	int val;
	size_t size = sizeof(val);
	int result = sysctlbyname("vm.compressor_inject_error", &val, &size,
	    &page_va, sizeof(page_va));
	return result == 0;
}

static vm_address_t
create_corrupted_region(const vm_address_t buffer_length)
{
	void *const bufferp = malloc(buffer_length);
	T_ASSERT_NOTNULL(bufferp, "allocated test buffer");
	const vm_address_t buffer = (vm_address_t)bufferp;

	T_LOG("buffer address: %lx\n", (unsigned long)buffer);

	for (size_t buffer_offset = 0; buffer_offset < buffer_length;
	    buffer_offset += page_size) {
		dirty_page(buffer + buffer_offset);
	}

	page_out();

	uint32_t corrupt = 0;
	for (size_t buffer_offset = 0; buffer_offset < buffer_length;
	    buffer_offset += page_size) {
		if (try_to_corrupt_page(buffer + buffer_offset)) {
			corrupt++;
		}
	}

	T_LOG("corrupted %u/%lu pages. accessing...\n", corrupt,
	    (unsigned long)(buffer_length / page_size));
	if (corrupt == 0) {
		T_SKIP("no pages corrupted");
	}

	return buffer;
}

static bool
try_write(volatile uint32_t *word __unused)
{
#ifdef __arm64__
	uint64_t val = 1;
	__asm__ volatile (
             "str		%w0, %1\n"
             "mov		%0, 0\n"
             : "+r"(val) : "m"(*word));
	// The exception handler skips over the instruction that zeroes val when a
	// decompression failure is detected.
	return val == 0;
#else
	return false;
#endif
}

static void *
run_test(vm_address_t buffer_start, vm_address_t buffer_length)
{
	bool fault = false;
	for (size_t buffer_offset = 0; buffer_offset < buffer_length;
	    buffer_offset += page_size) {
		// Access pages until the fault is detected.
		if (!try_write((volatile uint32_t *)(buffer_start +
		    buffer_offset))) {
			T_LOG("test_thread breaking");
			fault = true;
			break;
		}
	}

	if (!fault) {
		T_SKIP("no faults");
	}
	T_LOG("test thread completing");
	return NULL;
}

static size_t
kern_memory_failure_handler(
	exception_type_t exception,
	mach_exception_data_t code)
{
	T_EXPECT_EQ(exception, EXC_BAD_ACCESS,
	    "Verified bad address exception");
	T_EXPECT_EQ((int)code[0], KERN_MEMORY_FAILURE, "caught KERN_MEMORY_FAILURE");
	T_PASS("received KERN_MEMORY_FAILURE from test thread");
	// Skip the next instruction as well so that the faulting code can detect
	// the exception.
	return 8;
}

static void
run_test_expect_fault()
{
	mach_port_t exc_port = create_exception_port(EXC_MASK_BAD_ACCESS);
	vm_address_t buffer_length = 10 * 1024ULL * 1024ULL;
	vm_address_t buffer_start = create_corrupted_region(buffer_length);

	run_exception_handler(exc_port, kern_memory_failure_handler);
	run_test(buffer_start, buffer_length);
	free((void *)buffer_start);
}



T_DECL(decompression_failure,
    "Confirm that exception is raised on decompression failure",
    // Disable software checks in development builds, as these would result in
    // panics.
    T_META_BOOTARGS_SET("vm_compressor_validation=0"))
{
	if (pid_hibernate(-2) != 0) {
		T_SKIP("compressor not active");
	}

	int value;
	size_t size = sizeof(value);
	if (sysctlbyname("vm.compressor_inject_error", &value, &size, NULL, 0)
	    != 0) {
		T_SKIP("vm.compressor_inject_error not present");
	}

	T_ASSERT_POSIX_SUCCESS(sysctlbyname("vm.pagesize", &value, &size, NULL, 0),
	    NULL);
	T_ASSERT_EQ_ULONG(size, sizeof(value), NULL);
	page_size = (vm_address_t)value;

	run_test_expect_fault();
}
