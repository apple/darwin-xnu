#include <sys/sysctl.h>
#include <sys/kern_memorystatus.h>

#include <darwintest.h>

#include "memorystatus_assertion_helpers.h"

static void log_state(uint32_t state);

int
set_priority(pid_t pid, int32_t priority, uint64_t user_data, boolean_t is_assertion_driven)
{
	int err;
	uint32_t flag = 0;
	memorystatus_priority_properties_t mjp = { 0 };

	if (is_assertion_driven) {
		/*
		 * Control over an assertion driven priority will be
		 * relinquished when priority == JETSAM_PRIORITY_IDLE
		 */
		if (priority == JETSAM_PRIORITY_IDLE) {
			T_LOG("Relinquish ...assertion... priority(%d) for pid[%d]", priority, pid);
		} else {
			T_LOG("Setting ...assertion... priority(%d) for pid[%d]", priority, pid);
		}
		flag |= MEMORYSTATUS_SET_PRIORITY_ASSERTION;
	} else {
		T_LOG("Setting ...requested... priority(%d) for pid[%d]", priority, pid);
		flag = 0;
	}

	mjp.priority = priority;
	mjp.user_data = user_data;

	err = memorystatus_control(MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES, pid, flag, &mjp, sizeof(mjp));

	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(err, "MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES failed");
	return err;
}

boolean_t
check_properties(pid_t pid, int32_t expected_priority, int32_t expected_limit_mb, uint64_t expected_user_data, boolean_t expected_assertion_state, const char *test)
{
	const char *PROP_CHECK_ERROR_STRING = "property mismatch";
	boolean_t verbose = true;
	boolean_t ret;

	int32_t  actual_priority = 0;
	int32_t  actual_limit_mb = 0;
	uint64_t actual_user_data = 0;
	uint32_t actual_state = 0;

	verbose = false;
	(void)get_priority_props(pid, verbose, &actual_priority, &actual_limit_mb, &actual_user_data, &actual_state);

	if (test != NULL) {
		T_LOG("check_properties: %s", test);
	}

	ret = verify_assertion_state(actual_state, expected_assertion_state);
	T_QUIET;
	T_ASSERT_TRUE(ret, "verify_assertion_state failed");


	/*
	 * These tests use well defined limits, so we don't try to handle defaults like
	 * a limit of <= 0 which typically applies a system-wide per process limit.
	 */

	if ((actual_priority != expected_priority) || (actual_limit_mb != expected_limit_mb) || (actual_user_data != expected_user_data)) {
		/* we have a mismatch */
		T_LOG("%s test failed: %s\n", test, PROP_CHECK_ERROR_STRING);

		if (actual_priority != expected_priority) {
			T_LOG("priority mismatch [actual / expected] [%d / %d]", actual_priority, expected_priority);
		}

		if (actual_limit_mb != expected_limit_mb) {
			T_LOG("limit mismatch [actual / expected] [%d / %d]", actual_limit_mb, expected_limit_mb);
		}

		if (actual_user_data != expected_user_data) {
			T_LOG("user data mismatch [actual / expected] [0x%llx / 0x%llx]", actual_user_data, expected_user_data);
		}

		T_LOG("state is 0x%x\n", actual_state);
		log_state(actual_state);

		T_ASSERT_FAIL("check_properties: %s", test);
	} else {
		T_PASS("check_properties: %s ok", test);
		return true;
	}
	return false;
}

int
set_assertion_priority(pid_t pid, int32_t priority, uint64_t user_data)
{
	return set_priority(pid, priority, user_data, TRUE);
}

int
relinquish_assertion_priority(pid_t pid, uint64_t user_data)
{
	return set_assertion_priority(pid, JETSAM_PRIORITY_IDLE, user_data);
}

int
set_memlimits(
	pid_t pid,
	int32_t active_limit_mb, int32_t inactive_limit_mb,
	boolean_t active_is_fatal, boolean_t inactive_is_fatal)
{
	int err;
	memorystatus_memlimit_properties_t mmprops;

	memset(&mmprops, 0, sizeof(memorystatus_memlimit_properties_t));

	mmprops.memlimit_active = active_limit_mb;
	mmprops.memlimit_inactive = inactive_limit_mb;

	if (active_is_fatal) {
		mmprops.memlimit_active_attr |= MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;
	} else {
		mmprops.memlimit_active_attr &= ~(uint32_t)MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;
	}

	if (inactive_is_fatal) {
		mmprops.memlimit_inactive_attr |= MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;
	} else {
		mmprops.memlimit_inactive_attr &= ~(uint32_t)MEMORYSTATUS_MEMLIMIT_ATTR_FATAL;
	}

	T_LOG("Setting pid[%d] limits active [%d %s] inactive [%d %s]", pid,
	    mmprops.memlimit_active, (active_is_fatal ? "hard" : "soft"),
	    mmprops.memlimit_inactive, (inactive_is_fatal ? "hard" : "soft"));

	err =  memorystatus_control(MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES, pid, 0, &mmprops, sizeof(mmprops));

	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(err, "MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES failed");
	return err;
}

boolean_t
get_priority_props(pid_t pid, boolean_t verbose, int32_t *priority, int32_t *limit_mb, uint64_t *user_data, uint32_t *state)
{
	memorystatus_priority_entry_t entry = {0};

	int size = memorystatus_control(MEMORYSTATUS_CMD_GET_PRIORITY_LIST, pid, 0, &entry, sizeof(entry));

	/* validate size returned */
	if (size <= 0) {
		T_ASSERT_FAIL("get_priority: can't get list size: %d!\n", size);
	}

	if (size != sizeof(entry)) {
		T_ASSERT_FAIL("get_priority: returned unexpected entry size\n");
	}

	if (entry.pid != pid) {
		T_ASSERT_FAIL("get_priority: returned unexpected entry pid\n");
	}

	T_LOG("get_priority_props: pid[%d] limit %d, user_data 0x%llx, priority %d, state 0x%x",
	    entry.pid, entry.limit, entry.user_data, entry.priority, entry.state);


	if (verbose) {
		log_state(entry.state);
	}

	if (priority) {
		*priority = entry.priority;
	}
	if (limit_mb) {
		*limit_mb = entry.limit;
	}
	if (user_data) {
		*user_data = entry.user_data;
	}
	if (state) {
		*state = entry.state;
	}

	return true;
}

boolean_t
verify_assertion_state(uint32_t state, boolean_t expected_assertion_state)
{
	boolean_t actual_assertion_state;
	char *actual_string;
	char *expected_string;

	if (expected_assertion_state == ASSERTION_STATE_IS_SET) {
		expected_string = "ASSERTION_STATE_IS_SET";
	} else {
		expected_string = "ASSERTION_STATE_IS_RELINQUISHED";
	}

	if (state & kMemorystatusAssertion) {
		/*
		 * An assertion driven jetsam priority is at play.
		 */
		actual_assertion_state = ASSERTION_STATE_IS_SET;
		actual_string = "ASSERTION_STATE_IS_SET";
	} else {
		/*
		 * There is no assertion driven jetsam priority in place.
		 */
		actual_assertion_state = ASSERTION_STATE_IS_RELINQUISHED;
		actual_string = "ASSERTION_STATE_IS_RELINQUISHED";
	}

	if (actual_assertion_state == expected_assertion_state) {
		T_PASS("%s as expected", expected_string);
		return true;
	} else {
		T_FAIL("state 0x%x:  %s but expected %s", state, actual_string, expected_string);
		// log_state(state);
		return false;   /* failed */
	}
}

static void
log_state(uint32_t state)
{
	T_LOG("\t%s kMemorystatusSuspended", ((state & kMemorystatusSuspended)        ? "IS " : "NOT"));
	T_LOG("\t%s kMemorystatusFrozen", ((state & kMemorystatusFrozen)           ? "IS " : "NOT"));
	T_LOG("\t%s kMemorystatusWasThawed", ((state & kMemorystatusWasThawed)        ? "IS " : "NOT"));
	T_LOG("\t%s kMemorystatusTracked", ((state & kMemorystatusTracked)          ? "IS " : "NOT"));
	T_LOG("\t%s kMemorystatusSupportsIdleExit", ((state & kMemorystatusSupportsIdleExit) ? "IS " : "NOT"));
	T_LOG("\t%s kMemorystatusDirty", ((state & kMemorystatusDirty)            ? "IS " : "NOT"));
	T_LOG("\t%s kMemorystatusAssertion", ((state & kMemorystatusAssertion)        ? "IS " : "NOT"));
}
