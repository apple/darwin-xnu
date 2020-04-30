/*
 * Must come before including darwintest.h
 */
#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif /* defined(T_NAMESPACE) */

#include <darwintest.h>
#include <fcntl.h>
#include <inttypes.h>
#ifndef PRIVATE
/*
 * Need new CPU families.
 */
#define PRIVATE
#include <mach/machine.h>
#undef PRIVATE
#else /* !defined(PRIVATE) */
#include <mach/machine.h>
#endif /* defined(PRIVATE) */
#include <stdint.h>
#include <System/sys/guarded.h>
#include <System/sys/monotonic.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.monotonic"),
	T_META_CHECK_LEAKS(false),
	T_META_ENABLED(false)
	);

static bool
device_supports_uncore(void)
{
	int r;
	int type, subtype;
	unsigned int family;
	size_t size = sizeof(type);

	/*
	 * Only arm64 Monsoon devices support uncore counters.
	 */

	r = sysctlbyname("hw.cputype", &type, &size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(r, "sysctlbyname(\"hw.cputype\")");
	r = sysctlbyname("hw.cpusubtype", &subtype, &size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(r, "sysctlbyname(\"hw.cpusubtype\")");
	r = sysctlbyname("hw.cpufamily", &family, &size, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(r, "sysctlbyname(\"hw.cpufamily\")");

	if (type == CPU_TYPE_ARM64 &&
	    subtype == CPU_SUBTYPE_ARM64_V8 &&
	    (family == CPUFAMILY_ARM_MONSOON_MISTRAL ||
	    family == CPUFAMILY_ARM_VORTEX_TEMPEST)) {
		return true;
	}

	return false;
}

#define UNCORE_DEV_PATH "/dev/monotonic/uncore"

static int
open_uncore_error(int *error)
{
	guardid_t guard;
	int fd;

	guard = 0xa5adcafe;

	T_SETUPBEGIN;

	fd = guarded_open_np(UNCORE_DEV_PATH, &guard,
	    GUARD_CLOSE | GUARD_DUP | GUARD_WRITE, O_CLOEXEC | O_EXCL);
	if (fd < 0 && errno == ENOENT) {
		T_ASSERT_FALSE(device_supports_uncore(),
		    "lack of dev node implies no uncore support");
		T_SKIP("uncore counters are unsupported");
		__builtin_unreachable();
	}

	if (error == NULL) {
		T_ASSERT_POSIX_SUCCESS(fd, "open '%s'", UNCORE_DEV_PATH);
	} else {
		*error = errno;
	}

	T_SETUPEND;

	return fd;
}

static void
uncore_counts(int fd, uint64_t ctr_mask, uint64_t *counts)
{
	int r;
	union monotonic_ctl_counts *cts_ctl;

	cts_ctl = (union monotonic_ctl_counts *)counts;
	cts_ctl->in.ctr_mask = ctr_mask;

	r = ioctl(fd, MT_IOC_COUNTS, cts_ctl);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(r, "MT_IOC_COUNTS got counter values");
}

#define REF_TIMEBASE_EVENT 0x3
#define CTRS_MAX 32

T_DECL(uncore_max_counters,
    "ensure that the maximum number of uncore countes is sane",
    T_META_ASROOT(true))
{
	int nctrs = 0;
	int fd;

	fd = open_uncore_error(NULL);

	do {
		union monotonic_ctl_add add_ctl;
		int r;

		add_ctl.in.config.event = REF_TIMEBASE_EVENT;
		add_ctl.in.config.allowed_ctr_mask = UINT64_MAX;

		r = ioctl(fd, MT_IOC_ADD, &add_ctl);
		if (r < 0 && errno == E2BIG) {
			break;
		}

		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(r, "added reference timebase event to counters");
		nctrs++;
	} while (nctrs < CTRS_MAX);

	T_EXPECT_LT(nctrs, CTRS_MAX,
	    "only able to allocate a reasonable number of counters");
}

static uint32_t
uncore_add(int fd, uint64_t event, uint64_t allowed_ctrs, int error)
{
	int save_errno;
	int r;
	uint32_t ctr;
	union monotonic_ctl_add add_ctl;

	add_ctl.in.config.event = event;
	add_ctl.in.config.allowed_ctr_mask = allowed_ctrs;
	r = ioctl(fd, MT_IOC_ADD, &add_ctl);
	if (error) {
		save_errno = errno;
		T_EXPECT_LT(r, 0, "adding event to counter should fail");
		T_EXPECT_EQ(save_errno, error,
		    "adding event to counter should fail with %d: %s",
		    error, strerror(error));
		return UINT32_MAX;
	} else {
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(r,
		    "added event %#" PRIx64 " to counters", event);
	}

	ctr = add_ctl.out.ctr;
	T_QUIET; T_ASSERT_LT(ctr, (uint32_t)CTRS_MAX, "counter returned should be sane");
	return ctr;
}

T_DECL(uncore_collision,
    "ensure that trying to add an event on the same counter fails",
    T_META_ASROOT(true))
{
	int fd;
	uint32_t ctr;

	fd = open_uncore_error(NULL);

	ctr = uncore_add(fd, REF_TIMEBASE_EVENT, UINT64_MAX, 0);
	T_LOG("added event to uncore counter %d\n", ctr);

	(void)uncore_add(fd, REF_TIMEBASE_EVENT, UINT64_C(1) << ctr, ENOSPC);
}

static void
uncore_enable(int fd)
{
	union monotonic_ctl_enable en_ctl = {
		.in = { .enable = true }
	};

	T_ASSERT_POSIX_SUCCESS(ioctl(fd, MT_IOC_ENABLE, &en_ctl),
	    "enabling counters");
}

T_DECL(uncore_enabled_busy,
    "ensure that trying to add an event while enabled fails",
    T_META_ASROOT(true))
{
	int fd;

	fd = open_uncore_error(NULL);

	(void)uncore_add(fd, REF_TIMEBASE_EVENT, UINT64_MAX, 0);

	uncore_enable(fd);
	(void)uncore_add(fd, REF_TIMEBASE_EVENT, UINT64_MAX, EBUSY);
}

T_DECL(uncore_reset,
    "ensure that resetting the counters works")
{
	int fd;
	int r;

	fd = open_uncore_error(NULL);

	(void)uncore_add(fd, REF_TIMEBASE_EVENT, UINT64_C(1), 0);
	(void)uncore_add(fd, REF_TIMEBASE_EVENT, UINT64_C(1), ENOSPC);

	r = ioctl(fd, MT_IOC_RESET);
	T_ASSERT_POSIX_SUCCESS(r, "resetting succeeds");

	T_LOG("adding event to same counter after reset");
	(void)uncore_add(fd, REF_TIMEBASE_EVENT, UINT64_C(1), 0);
}

#define SLEEP_USECS (500 * 1000)

static int
uncore_add_all(int fd, uint64_t event, int *nmonitors)
{
	int nctrs = 0;
	int r;

	do {
		union monotonic_ctl_add add_ctl;

		add_ctl.in.config.event = event;
		add_ctl.in.config.allowed_ctr_mask = UINT64_MAX;

		r = ioctl(fd, MT_IOC_ADD, &add_ctl);
		if (r < 0 && errno == E2BIG) {
			break;
		}

		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(r, "added event %#" PRIx64 " to counters",
		    event);
		nctrs++;
	} while (nctrs < CTRS_MAX);

	if (nmonitors) {
		union monotonic_ctl_info info_ctl;
		r = ioctl(fd, MT_IOC_GET_INFO, &info_ctl);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(r, "got info about uncore counters");

		*nmonitors = (int)info_ctl.out.nmonitors;
	}

	return nctrs;
}

T_DECL(uncore_accuracy,
    "ensure that the uncore counters count accurately",
    T_META_ASROOT(true))
{
	int fd;
	int nctrs = 0;
	int nmonitors = 0;
	uint64_t ctr_mask;
	uint64_t counts[2][CTRS_MAX];
	uint64_t times[2];

	fd = open_uncore_error(NULL);

	/*
	 * The reference timebase event counts the same as mach_continuous_time
	 * (on hardware supporting uncore counters).  Make sure that the counter
	 * is close to the values returned from the trap.
	 *
	 * Fill all the counters with this event.
	 */
	nctrs = uncore_add_all(fd, REF_TIMEBASE_EVENT, &nmonitors);
	ctr_mask = (UINT64_C(1) << nctrs) - 1;

	T_LOG("added %d counters to check", nctrs);

	uncore_enable(fd);

	/*
	 * First, make sure there's an upper bound on the counter -- take the
	 * time around getting the counter values.
	 */

	times[0] = mach_absolute_time();
	uncore_counts(fd, ctr_mask, counts[0]);

	usleep(SLEEP_USECS);

	uncore_counts(fd, ctr_mask, counts[1]);
	times[1] = mach_absolute_time();

	T_QUIET; T_EXPECT_GT(times[1], times[0],
	    "mach_continuous_time is monotonically increasing");
	for (int i = 0; i < nctrs; i++) {
		T_EXPECT_GT(counts[1][i], counts[0][i],
		    "uncore counter %d value is monotonically increasing", i);
		T_EXPECT_LT(counts[1][i] - counts[0][i], times[1] - times[0],
		    "reference timebase on uncore counter %d satisfies upper bound "
		    "from mach_absolute_time", i);
	}

	/*
	 * Next, the lower bound -- put mach_absolute_time inside getting the
	 * counter values.
	 */

	uncore_counts(fd, ctr_mask, counts[0]);
	times[0] = mach_absolute_time();

	volatile int iterations = 100000;
	while (iterations--) {
		;
	}

	times[1] = mach_absolute_time();
	uncore_counts(fd, ctr_mask, counts[1]);

	for (int mon = 0; mon < nmonitors; mon++) {
		for (int i = 0; i < nctrs; i++) {
			T_QUIET;
			T_EXPECT_GT(counts[1][i * mon], counts[0][i * mon],
			    "uncore %d counter %d value is monotonically increasing",
			    mon, i);
			T_EXPECT_GT(counts[1][i * mon] - counts[0][i * mon],
			    times[1] - times[0],
			    "reference timebase on uncore %d counter %d satisfies "
			    "lower bound from mach_absolute_time", mon, i);
		}
	}
}

T_DECL(uncore_ownership,
    "ensure the dev node cannot be open in two places",
    T_META_ASROOT(true))
{
	int fd;
	int other_fd;
	int error;

	fd = open_uncore_error(NULL);

	other_fd = open_uncore_error(&error);
	T_ASSERT_LT(other_fd, 0, "opening a second uncore fd should fail");
	T_ASSERT_EQ(error, EBUSY, "failure should be EBUSY");
}

T_DECL(uncore_root_required,
    "ensure the dev node cannot be opened by non-root users",
    T_META_ASROOT(false))
{
	int fd;
	int error = 0;

	T_SKIP("libdarwintest doesn't drop privileges properly");

	fd = open_uncore_error(&error);
	T_ASSERT_LT(fd, 0, "opening dev node should not return an fd");
	T_ASSERT_EQ(error, EPERM,
	    "opening dev node as non-root user should fail with EPERM");
}

T_DECL(perf_uncore,
    "measure the latency of accessing the counters",
    T_META_TAG_PERF)
{
	int fd;
	int nctrs;
	int nmonitors;
	int r;
	uint64_t ctr_mask;
	dt_stat_thread_instructions_t counts_instrs;
	dt_stat_t counter_deltas;

	counts_instrs = dt_stat_thread_instructions_create("ioctl_counts");
	counter_deltas = dt_stat_create("abs_time", "between_each_counter");

	fd = open_uncore_error(NULL);

	nctrs = uncore_add_all(fd, REF_TIMEBASE_EVENT, &nmonitors);
	ctr_mask = (UINT64_C(1) << nctrs) - 1;

	uncore_enable(fd);

	do {
		dt_stat_token token;
		uint64_t counts[nctrs * nmonitors];
		union monotonic_ctl_counts *cts_ctl;

		cts_ctl = (union monotonic_ctl_counts *)counts;
		cts_ctl->in.ctr_mask = ctr_mask;

		token = dt_stat_thread_instructions_begin(counts_instrs);
		r = ioctl(fd, MT_IOC_COUNTS, cts_ctl);
		dt_stat_thread_instructions_end(counts_instrs, token);
		T_QUIET;
		T_ASSERT_POSIX_SUCCESS(r,
		    "getting uncore counter values %#" PRIx64, ctr_mask);

		for (int i = 0; i < (nctrs - 1); i++) {
			dt_stat_add(counter_deltas, (double)(counts[i + 1] - counts[i]));
		}
	} while (!dt_stat_stable(counts_instrs) || !dt_stat_stable(counter_deltas));

	dt_stat_finalize(counts_instrs);
	dt_stat_finalize(counter_deltas);
}
