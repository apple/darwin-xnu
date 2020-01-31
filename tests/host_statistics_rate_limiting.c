#include <unistd.h>
#include <stdint.h>
#include <sys/time.h>
#include <System/sys/codesign.h>
#include <mach/mach_time.h>
#include <mach/mach.h>
#include <darwintest.h>
#include <stdlib.h>

#if !defined(CS_OPS_CLEARPLATFORM)
#define CS_OPS_CLEARPLATFORM 13
#endif

#define WINDOW 1 /* seconds */
#define MAX_ATTEMP_PER_SEC 10
#define ITER 30
#define RETRY 5

static int
remove_platform_binary(void)
{
	int ret;
	uint32_t my_csflags;

	T_QUIET; T_ASSERT_POSIX_ZERO(csops(getpid(), CS_OPS_STATUS, &my_csflags, sizeof(my_csflags)), NULL);

	if (!(my_csflags & CS_PLATFORM_BINARY)) {
		return 0;
	}

	ret = csops(getpid(), CS_OPS_CLEARPLATFORM, NULL, 0);
	if (ret) {
		switch (errno) {
		case ENOTSUP:
			T_LOG("clearing platform binary not supported, skipping test");
			return -1;
		default:
			T_LOG("csops failed with flag CS_OPS_CLEARPLATFORM");
			return -1;
		}
	}

	my_csflags = 0;
	T_QUIET; T_ASSERT_POSIX_ZERO(csops(getpid(), CS_OPS_STATUS, &my_csflags, sizeof(my_csflags)), NULL);

	if (my_csflags & CS_PLATFORM_BINARY) {
		T_LOG("platform binary flag still set");
		return -1;
	}

	return 0;
}

struct all_host_info {
	vm_statistics64_data_t host_vm_info64_rev0;
	vm_statistics64_data_t host_vm_info64_rev1;
	vm_extmod_statistics_data_t host_extmod_info64;
	host_load_info_data_t host_load_info;
	vm_statistics_data_t host_vm_info_rev0;
	vm_statistics_data_t host_vm_info_rev1;
	vm_statistics_data_t host_vm_info_rev2;
	host_cpu_load_info_data_t host_cpu_load_info;
	task_power_info_v2_data_t host_expired_task_info;
	task_power_info_v2_data_t host_expired_task_info2;
};

static void
check_host_info(struct all_host_info* data, unsigned long iter, char lett)
{
	char* datap;
	unsigned long i, j;

	/* check that for the shorter revisions no data is copied on the bytes of diff with the longer */
	for (j = 0; j < iter; j++) {
		datap = (char*) &data[j].host_vm_info64_rev0;
		for (i = (HOST_VM_INFO64_REV0_COUNT * sizeof(int)); i < (HOST_VM_INFO64_REV1_COUNT * sizeof(int)); i++) {
			T_QUIET; T_ASSERT_EQ(datap[i], lett, "HOST_VM_INFO64_REV0 byte %lu iter %lu", i, j);
		}

		datap = (char*) &data[j].host_vm_info_rev0;
		for (i = (HOST_VM_INFO_REV0_COUNT * sizeof(int)); i < (HOST_VM_INFO_REV2_COUNT * sizeof(int)); i++) {
			T_QUIET; T_ASSERT_EQ(datap[i], lett, "HOST_VM_INFO_REV0 byte %lu iter %lu", i, j);
		}

		datap = (char*) &data[j].host_vm_info_rev1;
		for (i = (HOST_VM_INFO_REV1_COUNT * sizeof(int)); i < (HOST_VM_INFO_REV2_COUNT * sizeof(int)); i++) {
			T_QUIET; T_ASSERT_EQ(datap[i], lett, "HOST_VM_INFO_REV1 byte %lu iter %lu", i, j);
		}

		datap = (char*) &data[j].host_expired_task_info;
		for (i = (TASK_POWER_INFO_COUNT * sizeof(int)); i < (TASK_POWER_INFO_V2_COUNT * sizeof(int)); i++) {
			T_QUIET; T_ASSERT_EQ(datap[i], lett, "TASK_POWER_INFO_COUNT byte %lu iter %lu", i, j);
		}
	}
	T_LOG("No data overflow");

	datap = (char*) data;

	/* check that after MAX_ATTEMP_PER_SEC data are all the same */
	for (i = 0; i < sizeof(struct all_host_info); i++) {
		for (j = MAX_ATTEMP_PER_SEC - 1; j < iter - 1; j++) {
			T_QUIET; T_ASSERT_EQ(datap[i + (j * sizeof(struct all_host_info))], datap[i + ((j + 1) * sizeof(struct all_host_info))], "all_host_info iter %lu does not match iter %lu", j, j + 1);
		}
	}

	T_LOG("Data was cached");
}

static void
get_host_info(struct all_host_info* data, host_t self, int iter)
{
	int i;
	unsigned int count;
	for (i = 0; i < iter; i++) {
		count = HOST_VM_INFO64_REV0_COUNT;
		T_QUIET; T_ASSERT_POSIX_ZERO(host_statistics64(self, HOST_VM_INFO64, (host_info64_t)&data[i].host_vm_info64_rev0, &count), NULL);
		count = HOST_VM_INFO64_REV1_COUNT;
		T_QUIET; T_ASSERT_POSIX_ZERO(host_statistics64(self, HOST_VM_INFO64, (host_info64_t)&data[i].host_vm_info64_rev1, &count), NULL);
		count = HOST_EXTMOD_INFO64_COUNT;
		T_QUIET; T_ASSERT_POSIX_ZERO(host_statistics64(self, HOST_EXTMOD_INFO64, (host_info64_t)&data[i].host_extmod_info64, &count), NULL);
		count = HOST_LOAD_INFO_COUNT;
		T_QUIET; T_ASSERT_POSIX_ZERO(host_statistics(self, HOST_LOAD_INFO, (host_info_t)&data[i].host_load_info, &count), NULL);
		count = HOST_VM_INFO_REV0_COUNT;
		T_QUIET; T_ASSERT_POSIX_ZERO(host_statistics(self, HOST_VM_INFO, (host_info_t)&data[i].host_vm_info_rev0, &count), NULL);
		count = HOST_VM_INFO_REV1_COUNT;
		T_QUIET; T_ASSERT_POSIX_ZERO(host_statistics(self, HOST_VM_INFO, (host_info_t)&data[i].host_vm_info_rev1, &count), NULL);
		count = HOST_VM_INFO_REV2_COUNT;
		T_QUIET; T_ASSERT_POSIX_ZERO(host_statistics(self, HOST_VM_INFO, (host_info_t)&data[i].host_vm_info_rev2, &count), NULL);
		count = HOST_CPU_LOAD_INFO_COUNT;
		T_QUIET; T_ASSERT_POSIX_ZERO(host_statistics(self, HOST_CPU_LOAD_INFO, (host_info_t)&data[i].host_cpu_load_info, &count), NULL);
		count = TASK_POWER_INFO_COUNT;
		T_QUIET; T_ASSERT_POSIX_ZERO(host_statistics(self, HOST_EXPIRED_TASK_INFO, (host_info_t)&data[i].host_expired_task_info, &count), NULL);
		count = TASK_POWER_INFO_V2_COUNT;
		T_QUIET; T_ASSERT_POSIX_ZERO(host_statistics(self, HOST_EXPIRED_TASK_INFO, (host_info_t)&data[i].host_expired_task_info2, &count), NULL);
	}
}

T_DECL(test_host_statistics, "testing rate limit for host_statistics",
    T_META_CHECK_LEAKS(false), T_META_ALL_VALID_ARCHS(true))
{
	unsigned long long start, end, window;
	int retry = 0;
	host_t self;
	char lett = 'a';
	struct all_host_info* data;
	mach_timebase_info_data_t timebaseInfo = { 0, 0 };

	if (remove_platform_binary()) {
		T_SKIP("Failed to remove platform binary");
	}

	data = malloc(ITER * sizeof(struct all_host_info));
	T_QUIET; T_ASSERT_NE(data, NULL, "malloc");

	/* check the size of the data structure against the bytes in COUNT*/
	T_QUIET; T_ASSERT_EQ(sizeof(data[0].host_vm_info64_rev0), HOST_VM_INFO64_COUNT * sizeof(int), "HOST_VM_INFO64_COUNT");
	T_QUIET; T_ASSERT_EQ(sizeof(data[0].host_extmod_info64), HOST_EXTMOD_INFO64_COUNT * sizeof(int), "HOST_EXTMOD_INFO64_COUNT");
	T_QUIET; T_ASSERT_EQ(sizeof(data[0].host_load_info), HOST_LOAD_INFO_COUNT * sizeof(int), "HOST_LOAD_INFO_COUNT");
	T_QUIET; T_ASSERT_EQ(sizeof(data[0].host_vm_info_rev0), HOST_VM_INFO_COUNT * sizeof(int), "HOST_VM_INFO_COUNT");
	T_QUIET; T_ASSERT_EQ(sizeof(data[0].host_cpu_load_info), HOST_CPU_LOAD_INFO_COUNT * sizeof(int), "HOST_CPU_LOAD_INFO_COUNT");
	T_QUIET; T_ASSERT_EQ(sizeof(data[0].host_expired_task_info2), TASK_POWER_INFO_V2_COUNT * sizeof(int), "TASK_POWER_INFO_V2_COUNT");

	/* check that the latest revision is the COUNT */
	T_QUIET; T_ASSERT_EQ(HOST_VM_INFO64_REV1_COUNT, HOST_VM_INFO64_COUNT, "HOST_VM_INFO64_REV1_COUNT");
	T_QUIET; T_ASSERT_EQ(HOST_VM_INFO_REV2_COUNT, HOST_VM_INFO_COUNT, "HOST_VM_INFO_REV2_COUNT");

	/* check that the previous revision are smaller than the latest */
	T_QUIET; T_ASSERT_LE(HOST_VM_INFO64_REV0_COUNT, HOST_VM_INFO64_REV1_COUNT, "HOST_VM_INFO64_REV0");
	T_QUIET; T_ASSERT_LE(HOST_VM_INFO_REV0_COUNT, HOST_VM_INFO_REV2_COUNT, "HOST_VM_INFO_REV0_COUNT");
	T_QUIET; T_ASSERT_LE(HOST_VM_INFO_REV1_COUNT, HOST_VM_INFO_REV2_COUNT, "HOST_VM_INFO_REV1_COUNT");
	T_QUIET; T_ASSERT_LE(TASK_POWER_INFO_COUNT, TASK_POWER_INFO_V2_COUNT, "TASK_POWER_INFO_COUNT");

	memset(data, lett, ITER * sizeof(struct all_host_info));
	self = mach_host_self();

	T_QUIET; T_ASSERT_EQ(mach_timebase_info(&timebaseInfo), KERN_SUCCESS, NULL);
	window = (WINDOW * NSEC_PER_SEC * timebaseInfo.denom) / timebaseInfo.numer;
	retry = 0;

	/* try to get ITER copies of host_info within window time, in such a way we should hit for sure a cached copy */
	do {
		start = mach_continuous_time();
		get_host_info(data, self, ITER);
		end = mach_continuous_time();
		retry++;
	} while ((end - start > window) && retry <= RETRY);

	if (retry <= RETRY) {
		check_host_info(data, ITER, lett);
	} else {
		T_SKIP("Failed to find window for test");
	}
}
