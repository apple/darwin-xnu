/*
 *  commpage_tests.c
 *  xnu_quick_test
 *
 *  Copyright 2009 Apple Inc. All rights reserved.
 *
 */

#include "tests.h"
#include <unistd.h>
#include <stdint.h>
#include <err.h>
#include <sys/param.h>
#include <System/machine/cpu_capabilities.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/bootstrap.h>


#ifdef _COMM_PAGE_ACTIVE_CPUS
int active_cpu_test(void);
#endif

int get_sys_uint64(const char *sel, uint64_t *val);
int get_sys_int32(const char *sel, int32_t *val);

#define getcommptr(var, commpageaddr) do { \
		var = (typeof(var))(uintptr_t)(commpageaddr); \
	} while(0)

/*
 * Check some of the data in the commpage
 * against manual sysctls
 */
int commpage_data_tests( void * the_argp )
{
	int ret;
	uint64_t sys_u64;
	int32_t sys_i32;

	volatile uint64_t *comm_u64;
	volatile uint32_t *comm_u32;
	volatile uint16_t *comm_u16;
	volatile uint8_t *comm_u8;


	/* _COMM_PAGE_CPU_CAPABILITIES */
	getcommptr(comm_u32, _COMM_PAGE_CPU_CAPABILITIES);

	ret = get_sys_int32("hw.ncpu", &sys_i32);
	if (ret) goto fail;

	if (sys_i32 != ((*comm_u32 & kNumCPUs) >> kNumCPUsShift)) {
		warnx("kNumCPUs does not match hw.ncpu");
		ret = -1;
		goto fail;
	}

	getcommptr(comm_u8, _COMM_PAGE_NCPUS);
	if (sys_i32 != (*comm_u8)) {
		warnx("_COMM_PAGE_NCPUS does not match hw.ncpu");
		ret = -1;
		goto fail;
	}

	ret = get_sys_int32("hw.logicalcpu", &sys_i32);
	if (ret) goto fail;

	if (sys_i32 != ((*comm_u32 & kNumCPUs) >> kNumCPUsShift)) {
		warnx("kNumCPUs does not match hw.logicalcpu");
		ret = -1;
		goto fail;
	}

	/* Intel only capabilities */
#if defined(__i386__) || defined(__x86_64__)
	ret = get_sys_int32("hw.optional.mmx", &sys_i32);
	if (ret) goto fail;

	if (!(sys_i32) ^ !(*comm_u32 & kHasMMX)) {
		warnx("kHasMMX does not match hw.optional.mmx");
		ret = -1;
		goto fail;
	}

	ret = get_sys_int32("hw.optional.sse", &sys_i32);
	if (ret) goto fail;

	if (!(sys_i32) ^ !(*comm_u32 & kHasSSE)) {
		warnx("kHasSSE does not match hw.optional.sse");
		ret = -1;
		goto fail;
	}
	ret = get_sys_int32("hw.optional.sse2", &sys_i32);
	if (ret) goto fail;

	if (!(sys_i32) ^ !(*comm_u32 & kHasSSE2)) {
		warnx("kHasSSE2 does not match hw.optional.sse2");
		ret = -1;
		goto fail;
	}

	ret = get_sys_int32("hw.optional.sse3", &sys_i32);
	if (ret) goto fail;

	if (!(sys_i32) ^ !(*comm_u32 & kHasSSE3)) {
		warnx("kHasSSE3 does not match hw.optional.sse3");
		ret = -1;
		goto fail;
	}

	ret = get_sys_int32("hw.optional.supplementalsse3", &sys_i32);
	if (ret) goto fail;

	if (!(sys_i32) ^ !(*comm_u32 & kHasSupplementalSSE3)) {
		warnx("kHasSupplementalSSE3 does not match hw.optional.supplementalsse3");
		ret = -1;
		goto fail;
	}

	ret = get_sys_int32("hw.optional.sse4_1", &sys_i32);
	if (ret) goto fail;

	if (!(sys_i32) ^ !(*comm_u32 & kHasSSE4_1)) {
		warnx("kHasSSE4_1 does not match hw.optional.sse4_1");
		ret = -1;
		goto fail;
	}

	ret = get_sys_int32("hw.optional.sse4_2", &sys_i32);
	if (ret) goto fail;

	if (!(sys_i32) ^ !(*comm_u32 & kHasSSE4_2)) {
		warnx("kHasSSE4_2 does not match hw.optional.sse4_2");
		ret = -1;
		goto fail;
	}

	ret = get_sys_int32("hw.optional.aes", &sys_i32);
	if (ret) goto fail;

	if (!(sys_i32) ^ !(*comm_u32 & kHasAES)) {
		warnx("kHasAES does not match hw.optional.aes");
		ret = -1;
		goto fail;
	}

	ret = get_sys_int32("hw.optional.x86_64", &sys_i32);
	if (ret) goto fail;

	if (!(sys_i32) ^ !(*comm_u32 & k64Bit)) {
		warnx("k64Bit does not match hw.optional.x86_64");
		ret = -1;
		goto fail;
	}
#endif /* __i386__ || __x86_64__ */
	 
	/* These fields are not implemented for all architectures */
#if defined(_COMM_PAGE_SCHED_GEN) && !TARGET_OS_EMBEDDED
	uint32_t preempt_count1, preempt_count2;
	uint64_t count;

	ret = get_sys_uint64("hw.cpufrequency_max", &sys_u64);
	if (ret) goto fail;
	
    getcommptr(comm_u32, _COMM_PAGE_SCHED_GEN);
	preempt_count1 = *comm_u32;
	/* execute for around 1 quantum (10ms) */
	for(count = MAX(10000000ULL, sys_u64/64); count > 0; count--) {
		asm volatile("");
	}
	preempt_count2 = *comm_u32;
	if (preempt_count1 >= preempt_count2) {
		warnx("_COMM_PAGE_SCHED_GEN not incrementing (%u => %u)",
			  preempt_count1, preempt_count2);
		ret = -1;
		goto fail;
	}
#endif /* _COMM_PAGE_SCHED_GEN */

#ifdef _COMM_PAGE_ACTIVE_CPUS
	ret = get_sys_int32("hw.activecpu", &sys_i32);
	if (ret) goto fail;

	getcommptr(comm_u8, _COMM_PAGE_ACTIVE_CPUS);
	if (sys_i32 != (*comm_u8)) {
		warnx("_COMM_PAGE_ACTIVE_CPUS does not match hw.activecpu");
		ret = -1;
		goto fail;
	}

	/* We shouldn't be supporting userspace processor_start/processor_exit on embedded */
#if !TARGET_OS_EMBEDDED
	ret = active_cpu_test();
	if (ret) goto fail;
#endif /* !TARGET_OS_EMBEDDED */
#endif /* _COMM_PAGE_ACTIVE_CPUS */

#ifdef _COMM_PAGE_PHYSICAL_CPUS
	ret = get_sys_int32("hw.physicalcpu_max", &sys_i32);
	if (ret) goto fail;

	getcommptr(comm_u8, _COMM_PAGE_PHYSICAL_CPUS);
	if (sys_i32 != (*comm_u8)) {
		warnx("_COMM_PAGE_PHYSICAL_CPUS does not match hw.physicalcpu_max");
		ret = -1;
		goto fail;
	}
#endif /* _COMM_PAGE_PHYSICAL_CPUS */

#ifdef _COMM_PAGE_LOGICAL_CPUS
	ret = get_sys_int32("hw.logicalcpu_max", &sys_i32);
	if (ret) goto fail;

	getcommptr(comm_u8, _COMM_PAGE_LOGICAL_CPUS);
	if (sys_i32 != (*comm_u8)) {
		warnx("_COMM_PAGE_LOGICAL_CPUS does not match hw.logicalcpu_max");
		ret = -1;
		goto fail;
	}
#endif /* _COMM_PAGE_LOGICAL_CPUS */

#if 0
#ifdef _COMM_PAGE_MEMORY_SIZE
	ret = get_sys_uint64("hw.memsize", &sys_u64);
	if (ret) goto fail;

	getcommptr(comm_u64, _COMM_PAGE_MEMORY_SIZE);
	if (sys_u64 != (*comm_u64)) {
		warnx("_COMM_PAGE_MEMORY_SIZE does not match hw.memsize");
		ret = -1;
		goto fail;
	}
#endif /* _COMM_PAGE_MEMORY_SIZE */
#endif

	ret = 0;

fail:
	
	return ret;
}


int get_sys_uint64(const char *sel, uint64_t *val)
{
	size_t size = sizeof(*val);
	int ret;

	ret = sysctlbyname(sel, val, &size, NULL, 0);
	if (ret == -1) {
		warn("sysctlbyname(%s)", sel);
		return ret;
	}

//	warnx("sysctlbyname(%s) => %llx", sel, *val);

	return 0;
}

int get_sys_int32(const char *sel, int32_t *val)
{
	size_t size = sizeof(*val);
	int ret;

	ret = sysctlbyname(sel, val, &size, NULL, 0);
	if (ret == -1) {
		warn("sysctlbyname(%s)", sel);
		return ret;
	}

//	warnx("sysctlbyname(%s) => %x", sel, *val);

	return 0;
}

#ifdef _COMM_PAGE_ACTIVE_CPUS
/*
 * Try to find a secondary processor that we can disable,
 * and make sure the commpage reflects that. This test
 * will pass on UP systems, and if all secondary processors
 * have been manually disabled
 */
int active_cpu_test(void)
{
	volatile uint8_t *activeaddr;
	uint8_t original_activecpu;
	boolean_t test_failed = FALSE;

	/* Code stolen from hostinfo.c */
	kern_return_t           ret;
	processor_t             *processor_list;                
	host_name_port_t        host;
	struct processor_basic_info     processor_basic_info;
	mach_msg_type_number_t  cpu_count;
	mach_msg_type_number_t  data_count;
	int                     i;


	getcommptr(activeaddr, _COMM_PAGE_ACTIVE_CPUS);
	original_activecpu = *activeaddr;

	host = mach_host_self();
	ret = host_processors(host,
						  (processor_array_t *) &processor_list, &cpu_count);
	if (ret != KERN_SUCCESS) {
		mach_error("host_processors()", ret);
		return ret;
	}

	/* skip master processor */
	for (i = 1; i < cpu_count; i++) {
		data_count = PROCESSOR_BASIC_INFO_COUNT;
		ret = processor_info(processor_list[i], PROCESSOR_BASIC_INFO,
							 &host,
							 (processor_info_t) &processor_basic_info,
							 &data_count);
		if (ret != KERN_SUCCESS) {
			if (ret == MACH_SEND_INVALID_DEST) {
				continue;
			}
			mach_error("processor_info", ret);
			return ret;
		}
	
		if (processor_basic_info.running) {
			/* found victim */
			ret = processor_exit(processor_list[i]);
			if (ret != KERN_SUCCESS) {
				mach_error("processor_exit()", ret);
				return ret;
			}

			sleep(1);

			if (*activeaddr != (original_activecpu - 1)) {
				test_failed = TRUE;
			}

			ret = processor_start(processor_list[i]);
			if (ret != KERN_SUCCESS) {
				mach_error("processor_exit()", ret);
				return ret;
			}

			sleep(1);

			break;
		}
	}

	if (test_failed) {
		warnx("_COMM_PAGE_ACTIVE_CPUS not updated after disabling a CPU");
		return -1;
	}

	if (*activeaddr != original_activecpu) {
		warnx("_COMM_PAGE_ACTIVE_CPUS not restored to original value");
		return -1;
	}

	return 0;
}
#endif
