#include <darwintest.h>
#include <darwintest_utils.h>
#include <kern/debug.h>
#include <kern/kern_cdata.h>
#include <kdd.h>
#include <libproc.h>
#include <sys/syscall.h>
#include <sys/stackshot.h>

T_GLOBAL_META(
		T_META_NAMESPACE("xnu.stackshot"),
		T_META_CHECK_LEAKS(false),
		T_META_ASROOT(true)
		);

static const char *current_process_name(void);
static void parse_stackshot(bool delta, void *ssbuf, size_t sslen);
static void parse_thread_group_stackshot(void **sbuf, size_t sslen);
static uint64_t stackshot_timestamp(void *ssbuf, size_t sslen);
static void initialize_thread(void);

#define DEFAULT_STACKSHOT_BUFFER_SIZE (1024 * 1024)
#define MAX_STACKSHOT_BUFFER_SIZE     (6 * 1024 * 1024)

T_DECL(microstackshots, "test the microstackshot syscall")
{
	void *buf = NULL;
	unsigned int size = DEFAULT_STACKSHOT_BUFFER_SIZE;

	while (1) {
		buf = malloc(size);
		T_QUIET; T_ASSERT_NOTNULL(buf, "allocated stackshot buffer");

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
		int len = syscall(SYS_microstackshot, buf, size,
				STACKSHOT_GET_MICROSTACKSHOT);
#pragma clang diagnostic pop
		if (len == ENOSYS) {
			T_SKIP("microstackshot syscall failed, likely not compiled with CONFIG_TELEMETRY");
		}
		if (len == -1 && errno == ENOSPC) {
			/* syscall failed because buffer wasn't large enough, try again */
			free(buf);
			buf = NULL;
			size *= 2;
			T_ASSERT_LE(size, (unsigned int)MAX_STACKSHOT_BUFFER_SIZE,
					"growing stackshot buffer to sane size");
			continue;
		}
		T_ASSERT_POSIX_SUCCESS(len, "called microstackshot syscall");
		break;
    }

	T_EXPECT_EQ(*(uint32_t *)buf,
			(uint32_t)STACKSHOT_MICRO_SNAPSHOT_MAGIC,
			"magic value for microstackshot matches");

	free(buf);
}

struct scenario {
	uint32_t flags;
	bool should_fail;
	pid_t target_pid;
	uint64_t since_timestamp;
	uint32_t size_hint;
	dt_stat_time_t timer;
};

static void
quiet(struct scenario *scenario)
{
	if (scenario->timer) {
		T_QUIET;
	}
}

static void
take_stackshot(struct scenario *scenario, void (^cb)(void *buf, size_t size))
{
	void *config = stackshot_config_create();
	quiet(scenario);
	T_ASSERT_NOTNULL(config, "created stackshot config");

	int ret = stackshot_config_set_flags(config, scenario->flags);
	quiet(scenario);
	T_ASSERT_POSIX_ZERO(ret, "set flags %#x on stackshot config", scenario->flags);

	if (scenario->size_hint > 0) {
		ret = stackshot_config_set_size_hint(config, scenario->size_hint);
		quiet(scenario);
		T_ASSERT_POSIX_ZERO(ret, "set size hint %" PRIu32 " on stackshot config",
				scenario->size_hint);
	}

	if (scenario->target_pid > 0) {
		ret = stackshot_config_set_pid(config, scenario->target_pid);
		quiet(scenario);
		T_ASSERT_POSIX_ZERO(ret, "set target pid %d on stackshot config",
				scenario->target_pid);
	}

	if (scenario->since_timestamp > 0) {
		ret = stackshot_config_set_delta_timestamp(config, scenario->since_timestamp);
		quiet(scenario);
		T_ASSERT_POSIX_ZERO(ret, "set since timestamp %" PRIu64 " on stackshot config",
				scenario->since_timestamp);
	}

	int retries_remaining = 5;

retry: ;
	uint64_t start_time = mach_absolute_time();
	ret = stackshot_capture_with_config(config);
	uint64_t end_time = mach_absolute_time();

	if (scenario->should_fail) {
		T_EXPECTFAIL;
		T_ASSERT_POSIX_ZERO(ret, "called stackshot_capture_with_config");
		return;
	}

	if (ret == EBUSY || ret == ETIMEDOUT) {
		if (retries_remaining > 0) {
			if (!scenario->timer) {
				T_LOG("stackshot_capture_with_config failed with %s (%d), retrying",
						strerror(ret), ret);
			}

			retries_remaining--;
			goto retry;
		} else {
			T_ASSERT_POSIX_ZERO(ret,
					"called stackshot_capture_with_config (no retries remaining)");
		}
	} else {
		quiet(scenario);
		T_ASSERT_POSIX_ZERO(ret, "called stackshot_capture_with_config");
	}

	if (scenario->timer) {
		dt_stat_mach_time_add(scenario->timer, end_time - start_time);
	}
	cb(stackshot_config_get_stackshot_buffer(config), stackshot_config_get_stackshot_size(config));

	ret = stackshot_config_dealloc(config);
	T_QUIET; T_EXPECT_POSIX_ZERO(ret, "deallocated stackshot config");
}

T_DECL(kcdata, "test that kcdata stackshots can be taken and parsed")
{
	struct scenario scenario = {
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS |
				STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT)
	};

	initialize_thread();
	T_LOG("taking kcdata stackshot");
	take_stackshot(&scenario, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(false, ssbuf, sslen);
	});
}

T_DECL(kcdata_faulting, "test that kcdata stackshots while faulting can be taken and parsed")
{
	struct scenario scenario = {
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS
				| STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT
				| STACKSHOT_ENABLE_BT_FAULTING | STACKSHOT_ENABLE_UUID_FAULTING),
	};

	initialize_thread();
	T_LOG("taking faulting stackshot");
	take_stackshot(&scenario, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(false, ssbuf, sslen);
	});
}

T_DECL(bad_flags, "test a poorly-formed stackshot syscall")
{
	struct scenario scenario = {
		.flags = STACKSHOT_SAVE_IN_KERNEL_BUFFER /* not allowed from user space */,
		.should_fail = true
	};

	T_LOG("attempting to take stackshot with kernel-only flag");
	take_stackshot(&scenario, ^(__unused void *ssbuf, __unused size_t sslen) {
		T_ASSERT_FAIL("stackshot data callback called");
	});
}

T_DECL(delta, "test delta stackshots")
{
	struct scenario scenario = {
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS
				| STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT)
	};

	initialize_thread();
	T_LOG("taking full stackshot");
	take_stackshot(&scenario, ^(void *ssbuf, size_t sslen) {
		uint64_t stackshot_time = stackshot_timestamp(ssbuf, sslen);

		T_LOG("taking delta stackshot since time %" PRIu64, stackshot_time);

		parse_stackshot(false, ssbuf, sslen);

		struct scenario delta_scenario = {
			.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS
					| STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT
					| STACKSHOT_COLLECT_DELTA_SNAPSHOT),
			.since_timestamp = stackshot_time
		};

		take_stackshot(&delta_scenario, ^(void *dssbuf, size_t dsslen) {
			parse_stackshot(true, dssbuf, dsslen);
		});
	});
}

static void
expect_instrs_cycles_in_stackshot(void *ssbuf, size_t sslen)
{
	kcdata_iter_t iter = kcdata_iter(ssbuf, sslen);

	bool in_task = false;
	bool in_thread = false;
	bool saw_instrs_cycles = false;
	iter = kcdata_iter_next(iter);

	KCDATA_ITER_FOREACH(iter) {
		switch (kcdata_iter_type(iter)) {
		case KCDATA_TYPE_CONTAINER_BEGIN:
			switch (kcdata_iter_container_type(iter)) {
			case STACKSHOT_KCCONTAINER_TASK:
				in_task = true;
				saw_instrs_cycles = false;
				break;

			case STACKSHOT_KCCONTAINER_THREAD:
				in_thread = true;
				saw_instrs_cycles = false;
				break;

			default:
				break;
			}
			break;

		case STACKSHOT_KCTYPE_INSTRS_CYCLES:
			saw_instrs_cycles = true;
			break;

		case KCDATA_TYPE_CONTAINER_END:
			if (in_thread) {
				T_QUIET; T_EXPECT_TRUE(saw_instrs_cycles, "saw instructions and cycles in thread");
				in_thread = false;
			} else if (in_task) {
				T_QUIET; T_EXPECT_TRUE(saw_instrs_cycles, "saw instructions and cycles in task");
				in_task = false;
			}

		default:
			break;
		}
	}
}

static void
skip_if_monotonic_unsupported(void)
{
	int supported = 0;
	size_t supported_size = sizeof(supported);
	int ret = sysctlbyname("kern.monotonic.supported", &supported, &supported_size, 0, 0);
	if (ret < 0 || !supported) {
		T_SKIP("monotonic is unsupported");
	}
}

T_DECL(instrs_cycles, "test a getting instructions and cycles in stackshot")
{
	skip_if_monotonic_unsupported();

	struct scenario scenario = {
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_INSTRS_CYCLES
				| STACKSHOT_KCDATA_FORMAT)
	};

	T_LOG("attempting to take stackshot with instructions and cycles");
	take_stackshot(&scenario, ^(void *ssbuf, size_t sslen) {
		parse_stackshot(false, ssbuf, sslen);
		expect_instrs_cycles_in_stackshot(ssbuf, sslen);
	});
}

T_DECL(delta_instrs_cycles, "test delta stackshots with instructions and cycles")
{
	skip_if_monotonic_unsupported();

	struct scenario scenario = {
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_INSTRS_CYCLES
				| STACKSHOT_KCDATA_FORMAT)
	};

	initialize_thread();
	T_LOG("taking full stackshot");
	take_stackshot(&scenario, ^(void *ssbuf, size_t sslen) {
		uint64_t stackshot_time = stackshot_timestamp(ssbuf, sslen);

		T_LOG("taking delta stackshot since time %" PRIu64, stackshot_time);

		parse_stackshot(false, ssbuf, sslen);
		expect_instrs_cycles_in_stackshot(ssbuf, sslen);

		struct scenario delta_scenario = {
			.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_INSTRS_CYCLES
					| STACKSHOT_KCDATA_FORMAT
					| STACKSHOT_COLLECT_DELTA_SNAPSHOT),
			.since_timestamp = stackshot_time
		};

		take_stackshot(&delta_scenario, ^(void *dssbuf, size_t dsslen) {
			parse_stackshot(true, dssbuf, dsslen);
			expect_instrs_cycles_in_stackshot(dssbuf, dsslen);
		});
	});
}

static void
check_thread_groups_supported()
{
	int err;
	int supported = 0;
	size_t supported_size = sizeof(supported);
	err = sysctlbyname("kern.thread_groups_supported", &supported, &supported_size, NULL, 0);

	if (err || !supported)
		T_SKIP("thread groups not supported on this system");
}

T_DECL(thread_groups, "test getting thread groups in stackshot")
{
	check_thread_groups_supported();

	struct scenario scenario = {
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_THREAD_GROUP
				| STACKSHOT_KCDATA_FORMAT)
	};

	T_LOG("attempting to take stackshot with thread group flag");
	take_stackshot(&scenario, ^(void *ssbuf, size_t sslen) {
		parse_thread_group_stackshot(ssbuf, sslen);
	});

}

#pragma mark performance tests

#define SHOULD_REUSE_SIZE_HINT 0x01
#define SHOULD_USE_DELTA       0x02
#define SHOULD_TARGET_SELF     0x04

static void
stackshot_perf(unsigned int options)
{
	struct scenario scenario = {
		.flags = (STACKSHOT_SAVE_LOADINFO | STACKSHOT_GET_GLOBAL_MEM_STATS
			| STACKSHOT_SAVE_IMP_DONATION_PIDS | STACKSHOT_KCDATA_FORMAT),
	};

	dt_stat_t size = dt_stat_create("bytes", "size");
	dt_stat_time_t duration = dt_stat_time_create("duration");
	scenario.timer = duration;

	if (options & SHOULD_TARGET_SELF) {
		scenario.target_pid = getpid();
	}

	while (!dt_stat_stable(duration) || !dt_stat_stable(size)) {
		__block uint64_t last_time = 0;
		__block uint32_t size_hint = 0;
		take_stackshot(&scenario, ^(void *ssbuf, size_t sslen) {
			dt_stat_add(size, (double)sslen);
			last_time = stackshot_timestamp(ssbuf, sslen);
			size_hint = (uint32_t)sslen;
		});
		if (options & SHOULD_USE_DELTA) {
			scenario.since_timestamp = last_time;
			scenario.flags |= STACKSHOT_COLLECT_DELTA_SNAPSHOT;
		}
		if (options & SHOULD_REUSE_SIZE_HINT) {
			scenario.size_hint = size_hint;
		}
	}

	dt_stat_finalize(duration);
	dt_stat_finalize(size);
}

T_DECL(perf_no_size_hint, "test stackshot performance with no size hint")
{
	stackshot_perf(0);
}

T_DECL(perf_size_hint, "test stackshot performance with size hint")
{
	stackshot_perf(SHOULD_REUSE_SIZE_HINT);
}

T_DECL(perf_process, "test stackshot performance targeted at process")
{
	stackshot_perf(SHOULD_REUSE_SIZE_HINT | SHOULD_TARGET_SELF);
}

T_DECL(perf_delta, "test delta stackshot performance")
{
	stackshot_perf(SHOULD_REUSE_SIZE_HINT | SHOULD_USE_DELTA);
}

T_DECL(perf_delta_process, "test delta stackshot performance targeted at a process")
{
	stackshot_perf(SHOULD_REUSE_SIZE_HINT | SHOULD_USE_DELTA | SHOULD_TARGET_SELF);
}

static uint64_t
stackshot_timestamp(void *ssbuf, size_t sslen)
{
	kcdata_iter_t iter = kcdata_iter(ssbuf, sslen);

	uint32_t type = kcdata_iter_type(iter);
	if (type != KCDATA_BUFFER_BEGIN_STACKSHOT && type != KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT) {
		T_ASSERT_FAIL("invalid kcdata type %u", kcdata_iter_type(iter));
	}

	iter = kcdata_iter_find_type(iter, KCDATA_TYPE_MACH_ABSOLUTE_TIME);
	T_QUIET;
	T_ASSERT_TRUE(kcdata_iter_valid(iter), "timestamp found in stackshot");

	return *(uint64_t *)kcdata_iter_payload(iter);
}

#define TEST_THREAD_NAME "stackshot_test_thread"

static void
parse_thread_group_stackshot(void **ssbuf, size_t sslen)
{
	bool seen_thread_group_snapshot = false;
	kcdata_iter_t iter = kcdata_iter(ssbuf, sslen);
	T_ASSERT_EQ(kcdata_iter_type(iter), KCDATA_BUFFER_BEGIN_STACKSHOT,
			"buffer provided is a stackshot");

	NSMutableSet *thread_groups = [[NSMutableSet alloc] init];

	iter = kcdata_iter_next(iter);
	KCDATA_ITER_FOREACH(iter) {
		switch (kcdata_iter_type(iter)) {
		case KCDATA_TYPE_ARRAY: {
			T_QUIET;
			T_ASSERT_TRUE(kcdata_iter_array_valid(iter),
					"checked that array is valid");

			if (kcdata_iter_array_elem_type(iter) != STACKSHOT_KCTYPE_THREAD_GROUP_SNAPSHOT) {
				continue;
			}

			seen_thread_group_snapshot = true;

			if (kcdata_iter_array_elem_size(iter) >= sizeof(struct thread_group_snapshot_v2)) {
				struct thread_group_snapshot_v2 *tgs_array = kcdata_iter_payload(iter);
				for (uint32_t j = 0; j < kcdata_iter_array_elem_count(iter); j++) {
					struct thread_group_snapshot_v2 *tgs = tgs_array + j;
					[thread_groups addObject:@(tgs->tgs_id)];
				}

			}
			else {
				struct thread_group_snapshot *tgs_array = kcdata_iter_payload(iter);
				for (uint32_t j = 0; j < kcdata_iter_array_elem_count(iter); j++) {
					struct thread_group_snapshot *tgs = tgs_array + j;
					[thread_groups addObject:@(tgs->tgs_id)];
				}
			}
			break;
		}
		}
	}
	KCDATA_ITER_FOREACH(iter) {
		NSError *error = nil;

		switch (kcdata_iter_type(iter)) {

		case KCDATA_TYPE_CONTAINER_BEGIN: {
			T_QUIET;
			T_ASSERT_TRUE(kcdata_iter_container_valid(iter),
					"checked that container is valid");

			NSDictionary *container = parseKCDataContainer(&iter, &error);
			T_QUIET; T_ASSERT_NOTNULL(container, "parsed container from stackshot");
			T_QUIET; T_ASSERT_NULL(error, "error unset after parsing container");

			if (kcdata_iter_container_type(iter) != STACKSHOT_KCCONTAINER_THREAD) {
				break;
			}

			int tg = [container[@"thread_snapshots"][@"thread_group"] intValue];

			T_ASSERT_TRUE([thread_groups containsObject:@(tg)], "check that the thread group the thread is in exists");

			break;
		};

		}
	}
	T_ASSERT_TRUE(seen_thread_group_snapshot, "check that we have seen a thread group snapshot");
}

static void
parse_stackshot(bool delta, void *ssbuf, size_t sslen)
{
	kcdata_iter_t iter = kcdata_iter(ssbuf, sslen);
	if (delta) {
		T_ASSERT_EQ(kcdata_iter_type(iter), KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT,
				"buffer provided is a delta stackshot");
	} else {
		T_ASSERT_EQ(kcdata_iter_type(iter), KCDATA_BUFFER_BEGIN_STACKSHOT,
				"buffer provided is a stackshot");
	}

	iter = kcdata_iter_next(iter);
	KCDATA_ITER_FOREACH(iter) {
		NSError *error = nil;

		switch (kcdata_iter_type(iter)) {
		case KCDATA_TYPE_ARRAY: {
			T_QUIET;
			T_ASSERT_TRUE(kcdata_iter_array_valid(iter),
					"checked that array is valid");

			NSMutableDictionary *array = parseKCDataArray(iter, &error);
			T_QUIET; T_ASSERT_NOTNULL(array, "parsed array from stackshot");
			T_QUIET; T_ASSERT_NULL(error, "error unset after parsing array");
			break;
		}

		case KCDATA_TYPE_CONTAINER_BEGIN: {
			T_QUIET;
			T_ASSERT_TRUE(kcdata_iter_container_valid(iter),
					"checked that container is valid");

			NSDictionary *container = parseKCDataContainer(&iter, &error);
			T_QUIET; T_ASSERT_NOTNULL(container, "parsed container from stackshot");
			T_QUIET; T_ASSERT_NULL(error, "error unset after parsing container");

			if (kcdata_iter_container_type(iter) != STACKSHOT_KCCONTAINER_TASK) {
				break;
			}
			int pid = [container[@"task_snapshots"][@"task_snapshot"][@"ts_pid"] intValue];
			if (pid != getpid()) {
				break;
			}

			T_EXPECT_EQ_STR(current_process_name(),
					[container[@"task_snapshots"][@"task_snapshot"][@"ts_p_comm"] UTF8String],
					"current process name matches in stackshot");

			T_QUIET;
			T_EXPECT_LE(pid, [container[@"task_snapshots"][@"task_snapshot"][@"ts_unique_pid"] intValue],
					"unique pid is greater than pid");

			bool found_main_thread = 0;
			for (id thread_key in container[@"task_snapshots"][@"thread_snapshots"]) {
				NSMutableDictionary *thread = container[@"task_snapshots"][@"thread_snapshots"][thread_key];
				NSDictionary *thread_snap = thread[@"thread_snapshot"];

				T_QUIET; T_EXPECT_GT([thread_snap[@"ths_thread_id"] intValue], 0,
						"thread ID of thread in current task is valid");
				T_QUIET; T_EXPECT_GT([thread_snap[@"ths_total_syscalls"] intValue], 0,
						"total syscalls of thread in current task is valid");
				T_QUIET; T_EXPECT_GT([thread_snap[@"ths_base_priority"] intValue], 0,
						"base priority of thread in current task is valid");
				T_QUIET; T_EXPECT_GT([thread_snap[@"ths_sched_priority"] intValue], 0,
						"scheduling priority of thread in current task is valid");

				NSString *pth_name = thread_snap[@"pth_name"];
				if (pth_name != nil && [pth_name isEqualToString:@TEST_THREAD_NAME]) {
					found_main_thread = true;
				}
			}
			T_EXPECT_TRUE(found_main_thread, "found main thread for current task in stackshot");
			break;
		}
		}
	}

	T_ASSERT_FALSE(KCDATA_ITER_FOREACH_FAILED(iter), "successfully iterated kcdata");
}

static const char *
current_process_name(void)
{
	static char name[64];

	if (!name[0]) {
		int ret = proc_name(getpid(), name, sizeof(name));
		T_QUIET;
		T_ASSERT_POSIX_ZERO(ret, "proc_pidname failed for current process");
	}

	return name;
}

static void
initialize_thread(void)
{
	int ret = pthread_setname_np(TEST_THREAD_NAME);
	T_QUIET;
	T_ASSERT_POSIX_ZERO(ret, "set thread name to %s", TEST_THREAD_NAME);
}
