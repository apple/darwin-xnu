#ifndef KTRACE_HELPERS_H
#define KTRACE_HELPERS_H

#include <darwintest.h>
#include <ktrace/ktrace.h>
#include <libproc.h>
#include <sys/sysctl.h>
#include <sys/kdebug.h>

static inline void
reset_ktrace(void)
{
	(void)sysctl((int[]){ CTL_KERN, KERN_KDEBUG, KERN_KDREMOVE }, 3,
	    NULL, 0, NULL, 0);
	kperf_reset();
}

static inline void
start_controlling_ktrace(void)
{
	T_SETUPBEGIN;

	int state = 0;
	size_t statesz = sizeof(state);
	int ret = sysctlbyname("ktrace.state", &state, &statesz, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "getting ktrace state");

	if (state == 1) {
		int ownerpid = 0;
		size_t pidsz = sizeof(ownerpid);
		ret = sysctlbyname("ktrace.owning_pid", &ownerpid, &pidsz, NULL, 0);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "getting owning pid");

		if (ownerpid <= 0) {
			T_LOG("ktrace is in foreground, but no owner");
			goto out;
		}

		char ownername[1024];
		ret = proc_name(ownerpid, ownername, sizeof(ownername));
		if (ret == 0) {
			T_LOG("ktrace is in foreground, but owner (%d) has no name", ownerpid);
			goto out;
		}

		T_LOG("ktrace is in foreground, owned by %s, sending SIGKILL", ownername);
		kill(ownerpid, SIGKILL);
		usleep(500000);

		ret = proc_name(ownerpid, ownername, sizeof(ownername));
		T_QUIET; T_ASSERT_EQ(ret, 0, "should have killed ktrace owner");
	}

out:
	reset_ktrace();
	T_ATEND(reset_ktrace);
	T_SETUPEND;
}

static inline uint64_t
ns_from_abs(ktrace_session_t s, uint64_t abstime)
{
	uint64_t ns = 0;
	int error = ktrace_convert_timestamp_to_nanoseconds(s, abstime, &ns);
	T_QUIET; T_ASSERT_POSIX_ZERO(error, "convert abstime to nanoseconds");
	return ns;
}

static inline uint64_t
relns_from_abs(ktrace_session_t s, uint64_t abstime)
{
	return ns_from_abs(s, abstime - ktrace_get_earliest_timestamp(s));
}

#endif /* !defined(KTRACE_HELPERS_H) */
