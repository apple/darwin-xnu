#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <spawn.h>
#include <spawn_private.h>
#include <stdint.h>
#include <sys/sysctl.h>
#include <sys/spawn_internal.h>
#include <sys/kern_memorystatus.h>
#include <mach-o/dyld.h>

#include <darwintest.h>
#include <darwintest_utils.h>

#include "memorystatus_assertion_helpers.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.vm"),
	T_META_CHECK_LEAKS(false)
	);

extern char **environ;

/*
 * This test has multiple sub-tests that set and then verify jetsam priority transitions
 * as though they were driven by assertions. It uses the MEMORYSTATUS_CMD_SET_MEMLIMIT_PROPERTIES
 * version of the memorystatus_control() system call and specifically tests the use of the
 * MEMORYSTATUS_SET_PRIORITY_ASSERTION flag.
 *
 * The kernel will apply policy that chooses a maximum jetsam priority, resolving conflicts
 * between an assertion driven priority and clean/dirty transition policy.
 *
 * Processes that do not opt into dirty-tracking should behave as they always have.
 * This is the typical App transition behavior.
 *
 * Processes that do opt into dirty-tracking have more complex policy:
 * For example:
 * A MAX assertion priority will prevent a dirty process from transitioning to a clean
 * state if the process opts into idle-exit.
 *    See: memorystatus_schedule_idle_demotion_locked() where we note that
 *    the process isn't going to be making the trip to the lower bands.
 *
 * But a MAX assertion evaluation will not prevent a clean process from transition to dirty.
 * Assertion driven priorities should not change memory limits, they are expected to
 * just change a process's position in the jetsam priority bands.
 *
 * MEMORYSTATUS_CMD_xxx requires root (in the absence of entitlement).
 * Use T_META_ASROOT(true) to accomplish this.
 *
 * A note on test strategy.  It is not necessary to spawn a child to test these
 * assertion calls.   The test can act on itself, that is, it can make calls to
 * set and relinquish assertion state just like it can make calls to do dirty/clean
 * transitions.  Of course, in reality, we expect only runningboardd to manipulate
 * assertion based priorities.
 */

/*
 * New flag to tell kernel this is an assertion driven priority update.
 */
#ifndef MEMORYSTATUS_SET_PRIORITY_ASSERTION
#define MEMORYSTATUS_SET_PRIORITY_ASSERTION 0x1
#endif

static void
proc_will_set_clean(pid_t pid)
{
	proc_set_dirty(pid, false);
	T_LOG("pid[%d] --> now clean", pid);
	return;
}

static void
proc_will_set_dirty(pid_t pid)
{
	proc_set_dirty(pid, true);
	T_LOG("pid[%d] --> now dirty", pid);
	return;
}

#define kJetsamAgingPolicyNone                          (0)
#define kJetsamAgingPolicyLegacy                        (1)
#define kJetsamAgingPolicySysProcsReclaimedFirst        (2)
#define kJetsamAgingPolicyAppsReclaimedFirst            (3)
#define kJetsamAgingPolicyMax                           kJetsamAgingPolicyAppsReclaimedFirst

#ifndef kMemorystatusAssertion
#define kMemorystatusAssertion 0x40
#endif

/*
 * Make repetitive (eg: back-to-back) calls using MEMORYSTATUS_SET_PRIORITY_ASSERTION.
 * We know that runningboardd may try to relinquish its hold on an assertion priority
 * when it hasn't first set the assertion priority. The kernel must survive this
 * pattern even though it might be considered poor behavior on runningboardd's part.
 * When dirty tracking processes are involved, we are exercising the kernel's
 * idle-deferred paths. Only assertion state (whether or not assertion state is
 * set or relinquished) is verified in this round of tests.
 * Test is invoked three times:
 *	Scenario 1) as a non-dirty-tracking process  (like a typical app)
 *		relinquish assertion priority multiple times
 *		set same assertion priority multiple times.
 *	Scenario 2) setup a dirty-tracking process that is clean  (like a typical extension)
 *		relinquish assertion priority multiple times
 *		set same assertion priority multiple times.
 *	Scenario 3) setup dirty-tracking process that is dirty  (like a typical extension)
 *		relinquish assertion priority multiple times
 *		set same assertion priority multiple times.
 */

static void
memorystatus_assertion_test_repetitive(char *test, boolean_t turn_on_dirty_tracking, boolean_t start_clean)
{
	int count;
	int maxcount = 3;
	boolean_t verbose;
	uint32_t state;
	uint64_t user_data = 0;
	pid_t mypid = getpid();

	/* these values will remain fixed during testing */
	int             active_limit_mb = 15;   /* arbitrary */
	int             inactive_limit_mb = 7;  /* arbitrary */

	/* these values may vary during test */
	int             requestedpriority = 0;
	int             assertionpriority = 0;

	T_SETUPBEGIN;

	requestedpriority =  JETSAM_PRIORITY_UI_SUPPORT;
	assertionpriority =  JETSAM_PRIORITY_FOREGROUND;
	set_memlimits(mypid, active_limit_mb, inactive_limit_mb, true, true);
	set_priority(mypid, requestedpriority, 0, false);

	if (turn_on_dirty_tracking) {
		proc_track_dirty(mypid, (PROC_DIRTY_TRACK | PROC_DIRTY_ALLOW_IDLE_EXIT | PROC_DIRTY_DEFER));

		if (start_clean) {
			proc_will_set_clean(mypid);
		} else {
			proc_will_set_dirty(mypid);
		}
	} else {
		/*
		 * Do nothing.
		 * Acts like an app with no dirty tracking
		 * By default launches in the requested priority and is
		 * considered idle because it's below FG band.
		 */
	}


	verbose = false;
	(void)get_priority_props(mypid, verbose, NULL, NULL, NULL, NULL);

	/* log current setup state */
	T_LOG("SETUP STATE COMPLETE: Test %s", test);

	T_SETUPEND;

	int i;
	boolean_t ret;
	for (i = 0; i < 2; i++) {
		if (i == 1 && turn_on_dirty_tracking) {
			T_LOG("Avoid idle-deferred - sleeping for 20");
			sleep(20);

			if (start_clean) {
				proc_will_set_dirty(mypid);
			} else {
				proc_will_set_clean(mypid);
			}

			(void)get_priority_props(mypid, verbose, NULL, NULL, NULL, &state);
		}

		/*
		 * Relinquish assertion priority even though we don't
		 * currently hold an assertion priority.
		 */
		for (count = 0; count < maxcount; count++) {
			if (relinquish_assertion_priority(mypid, user_data)) {
				T_ASSERT_FAIL("relinquish_assertion_priority failed");
			}
		}

		/* Verify assertion state is relinquished */
		(void)get_priority_props(mypid, verbose, NULL, NULL, NULL, &state);

		ret = verify_assertion_state(state, ASSERTION_STATE_IS_RELINQUISHED);
		T_QUIET;
		T_ASSERT_TRUE(ret, "verify_assertion_state failed");



		/*
		 * Set an assertion priority multiple times in a row.
		 */
		for (count = 0; count < maxcount; count++) {
			if (set_assertion_priority(mypid, assertionpriority, user_data) != 0) {
				T_ASSERT_FAIL("set_assertion_priority failed");
			}
		}

		/* Verify state holds an assertion priority */
		(void)get_priority_props(mypid, verbose, NULL, NULL, NULL, &state);

		ret = verify_assertion_state(state, ASSERTION_STATE_IS_SET);
		T_QUIET;
		T_ASSERT_TRUE(ret, "verify_assertion_state failed");
	}
}

/*
 * Process is dirty tracking and opts into pressured exit.
 */
static void
memorystatus_assertion_test_allow_idle_exit()
{
	pid_t mypid = getpid();

	/* these values will remain fixed during testing */
	int active_limit_mb   = 15; /* arbitrary */
	int inactive_limit_mb = 7;  /* arbitrary */

	/* these values may vary during test */
	int requestedpriority = JETSAM_PRIORITY_UI_SUPPORT;

	T_SETUPBEGIN;

	set_memlimits(mypid, active_limit_mb, inactive_limit_mb, true, true);
	set_priority(mypid, requestedpriority, 0, false);

	proc_track_dirty(mypid, (PROC_DIRTY_TRACK | PROC_DIRTY_ALLOW_IDLE_EXIT | PROC_DIRTY_DEFER));

	proc_will_set_clean(mypid);

	(void)check_properties(mypid, JETSAM_PRIORITY_IDLE_DEFERRED, inactive_limit_mb, 0x0, ASSERTION_STATE_IS_RELINQUISHED, "Clean start");

	T_LOG("SETUP STATE COMPLETE");

	int g_jetsam_aging_policy = 0;
	/*
	 * Jetsam aging policy
	 * Failure to retrieve is not fatal.
	 */
	size_t size = sizeof(g_jetsam_aging_policy);
	if (sysctlbyname("kern.jetsam_aging_policy", &g_jetsam_aging_policy, &size, NULL, 0) != 0) {
		T_LOG(__func__, true, "Unable to retrieve jetsam aging policy (not fatal)");
	}

	T_SETUPEND;

	/*
	 * Relinquish assertion priority even though we don't hold it.  No change in state expected.
	 */
	T_LOG("********Test0 clean: no state change on relinquish");
	relinquish_assertion_priority(mypid, 0xF00D);
	(void)check_properties(mypid, JETSAM_PRIORITY_IDLE_DEFERRED, inactive_limit_mb, 0xF00D, ASSERTION_STATE_IS_RELINQUISHED, "Test0");

	T_LOG("********Test1 clean: deferred now assertion[10]");
	set_assertion_priority(mypid, JETSAM_PRIORITY_FOREGROUND, 0xFEED);
	(void)check_properties(mypid, JETSAM_PRIORITY_FOREGROUND, inactive_limit_mb, 0xFEED, ASSERTION_STATE_IS_SET, "Test1");

	/* Test2 */
	T_LOG("********Test2 clean:  assertion[10 -> 3]");
	set_assertion_priority(mypid, JETSAM_PRIORITY_BACKGROUND, 0xFACE);
	(void)check_properties(mypid, JETSAM_PRIORITY_BACKGROUND, inactive_limit_mb, 0xFACE, ASSERTION_STATE_IS_SET, "Test2");

	/* Test3 */
	T_LOG("********Test3 clean: assertion[3 -> 0], but now deferred");
	relinquish_assertion_priority(mypid, 0xBEEF);
	(void)check_properties(mypid, JETSAM_PRIORITY_IDLE_DEFERRED, inactive_limit_mb, 0xBEEF, ASSERTION_STATE_IS_RELINQUISHED, "Test3");

	/* Test4 */
	T_LOG("********Test4 clean: deferred now assertion[10]");
	set_assertion_priority(mypid, JETSAM_PRIORITY_FOREGROUND, 0xFEED);
	(void)check_properties(mypid, JETSAM_PRIORITY_FOREGROUND, inactive_limit_mb, 0xFEED, ASSERTION_STATE_IS_SET, "Test4");

	T_LOG("Avoid idle-deferred moving forward. Sleeping for 20");
	sleep(20);

	/* Test5 */
	T_LOG("********Test5 dirty: set dirty priority but assertion[10] prevails");
	proc_will_set_dirty(mypid);   /* active priority is less than FG*/
	(void)check_properties(mypid, JETSAM_PRIORITY_FOREGROUND, active_limit_mb, 0xFEED, ASSERTION_STATE_IS_SET, "Test5");

	/* Test6 */
	T_LOG("********Test6 dirty: assertion[10 -> 3] but dirty priority prevails");
	set_assertion_priority(mypid, JETSAM_PRIORITY_BACKGROUND, 0xFEEB);  /* active priority is > BG */
	(void)check_properties(mypid, JETSAM_PRIORITY_UI_SUPPORT, active_limit_mb, 0xFEEB, ASSERTION_STATE_IS_SET, "Test6");

	/* Test7 */
	T_LOG("********Test7 dirty: assertion[3 -> 0] but dirty prevails");
	relinquish_assertion_priority(mypid, 0xBEEF);
	(void)check_properties(mypid, JETSAM_PRIORITY_UI_SUPPORT, active_limit_mb, 0xBEEF, ASSERTION_STATE_IS_RELINQUISHED, "Test7");


	/* Test8 */
	T_LOG("********Test8 dirty: assertion[0 -> 10] overrides dirty");
	set_assertion_priority(mypid, JETSAM_PRIORITY_FOREGROUND, 0xFEED);
	(void)check_properties(mypid, JETSAM_PRIORITY_FOREGROUND, active_limit_mb, 0xFEED, ASSERTION_STATE_IS_SET, "Test8");

	/* Test9 */
	T_LOG("********Test9 dirty wants to go clean, but clean state is prevented as assertion[10] prevails");
	proc_will_set_clean(mypid);
	(void)check_properties(mypid, JETSAM_PRIORITY_FOREGROUND, active_limit_mb, 0xFEED, ASSERTION_STATE_IS_SET, "Test9");

	/* Test10 */
	T_LOG("********Test10 dirty goes dirty and stays dirty, and assertion[10] prevails again");
	proc_will_set_dirty(mypid);
	(void)check_properties(mypid, JETSAM_PRIORITY_FOREGROUND, active_limit_mb, 0xFEED, ASSERTION_STATE_IS_SET, "Test10");

	/* Test11 */
	T_LOG("********Test11 dirty: assertion[10 -> 3] but dirty prevails");
	set_assertion_priority(mypid, JETSAM_PRIORITY_BACKGROUND, 0xFACE);
	(void)check_properties(mypid, JETSAM_PRIORITY_UI_SUPPORT, active_limit_mb, 0xFACE, ASSERTION_STATE_IS_SET, "Test11");

	/* Test12 */
	T_LOG("********Test12 dirty: assertion[3 -> 0] but dirty prevails");
	relinquish_assertion_priority(mypid, 0xBEEF);
	(void)check_properties(mypid, JETSAM_PRIORITY_UI_SUPPORT, active_limit_mb, 0xBEEF, ASSERTION_STATE_IS_RELINQUISHED, "Test12");


	/* Test13 */
	T_LOG("********Test13 dirty goes clean: both assertion[0] and clean");
	proc_will_set_clean(mypid);
	if (g_jetsam_aging_policy == kJetsamAgingPolicySysProcsReclaimedFirst) {
		/* For sysproc aging policy the daemon should be at idle deferred and with an active memory limit */
		(void)check_properties(mypid, JETSAM_PRIORITY_IDLE_DEFERRED, active_limit_mb, 0xBEEF, ASSERTION_STATE_IS_RELINQUISHED, "Test13");
	} else {
		/* For the legacy aging policy, daemon should be at idle band with inactive memory limit */
		(void)check_properties(mypid, JETSAM_PRIORITY_IDLE, inactive_limit_mb, 0xBEEF, ASSERTION_STATE_IS_RELINQUISHED, "Test13");
	}
}

/*
 * Process is dirty tracking and does not opt into pressured exit.
 * This test lives above Foreground.  Assertions will have no affect
 * except where the assertion priority bumps it above the requested priority.
 */
static void
memorystatus_assertion_test_do_not_allow_idle_exit()
{
	pid_t mypid = getpid();

	/* these values will remain fixed during testing */
	int             active_limit_mb = 15;   /* arbitrary */
	int             inactive_limit_mb = 7;  /* arbitrary */
	int             requestedpriority = JETSAM_PRIORITY_AUDIO_AND_ACCESSORY;

	T_SETUPBEGIN;

	set_memlimits(mypid, active_limit_mb, inactive_limit_mb, true, true);
	set_priority(mypid, requestedpriority, 0, false);
	proc_track_dirty(mypid, (PROC_DIRTY_TRACK));

	proc_will_set_dirty(mypid);

	(void)check_properties(mypid, JETSAM_PRIORITY_AUDIO_AND_ACCESSORY, active_limit_mb, 0x0, ASSERTION_STATE_IS_RELINQUISHED, "Dirty start");

	proc_will_set_clean(mypid);

	(void)check_properties(mypid, JETSAM_PRIORITY_AUDIO_AND_ACCESSORY, inactive_limit_mb, 0x0, ASSERTION_STATE_IS_RELINQUISHED, "Clean transition");

	T_LOG("SETUP STATE COMPLETE");

	T_SETUPEND;

	/*
	 * Relinquish assertion priority even though we don't hold it.  No change in state expected.
	 */


	/* Test0 */
	T_LOG("********Test0 clean: no state change on relinquish");
	relinquish_assertion_priority(mypid, 0xF00D);
	(void)check_properties(mypid, JETSAM_PRIORITY_AUDIO_AND_ACCESSORY, inactive_limit_mb, 0xF00D, ASSERTION_STATE_IS_RELINQUISHED, "Test0");

	/* Test1 */
	T_LOG("********Test1 clean: assertion[0 -> 10] but inactive priority prevails");
	set_assertion_priority(mypid, JETSAM_PRIORITY_FOREGROUND, 0xFEED);
	(void)check_properties(mypid, JETSAM_PRIORITY_AUDIO_AND_ACCESSORY, inactive_limit_mb, 0xFEED, ASSERTION_STATE_IS_SET, "Test1");

	/* Test2 */
	T_LOG("********Test2 clean:  assertion[10 -> 3] but inactive priority prevails");
	set_assertion_priority(mypid, JETSAM_PRIORITY_BACKGROUND, 0xFACE);
	(void)check_properties(mypid, JETSAM_PRIORITY_AUDIO_AND_ACCESSORY, inactive_limit_mb, 0xFACE, ASSERTION_STATE_IS_SET, "Test2");

	/* Test3 */
	T_LOG("********Test3 clean: assertion[3 -> 0], but inactive priority prevails");
	relinquish_assertion_priority(mypid, 0xBEEF);
	(void)check_properties(mypid, JETSAM_PRIORITY_AUDIO_AND_ACCESSORY, inactive_limit_mb, 0xBEEF, ASSERTION_STATE_IS_RELINQUISHED, "Test3");

	/* Test4 */
	T_LOG("********Test4 go dirty: assertion[0] has no affect, active priority prevails");
	proc_will_set_dirty(mypid);
	(void)check_properties(mypid, JETSAM_PRIORITY_AUDIO_AND_ACCESSORY, active_limit_mb, 0xBEEF, ASSERTION_STATE_IS_RELINQUISHED, "Test4");

	/* Test5 */
	T_LOG("********Test5 dirty: assertion[0 -> 10] active priority prevails");
	set_assertion_priority(mypid, JETSAM_PRIORITY_FOREGROUND, 0xFEED);
	(void)check_properties(mypid, JETSAM_PRIORITY_AUDIO_AND_ACCESSORY, active_limit_mb, 0xFEED, ASSERTION_STATE_IS_SET, "Test5");

	/* Test6 */
	T_LOG("********Test6 dirty:  assertion[10 -> 3] active priority prevails");
	set_assertion_priority(mypid, JETSAM_PRIORITY_BACKGROUND, 0xFACE);
	(void)check_properties(mypid, JETSAM_PRIORITY_AUDIO_AND_ACCESSORY, active_limit_mb, 0xFACE, ASSERTION_STATE_IS_SET, "Test6");

	/* Test 7 */
	T_LOG("********Test7 dirty: assertion[3 -> 0], active priority prevails");
	relinquish_assertion_priority(mypid, 0xBEEF);
	(void)check_properties(mypid, JETSAM_PRIORITY_AUDIO_AND_ACCESSORY, active_limit_mb, 0xBEEF, ASSERTION_STATE_IS_RELINQUISHED, "Test7");

	/* Test8 */
	T_LOG("********Test8 dirty: assertion[0 -> 19], dirty but now assertion[19] prevails");
	set_assertion_priority(mypid, JETSAM_PRIORITY_CRITICAL, 0xFEED);
	(void)check_properties(mypid, JETSAM_PRIORITY_CRITICAL, active_limit_mb, 0xFEED, ASSERTION_STATE_IS_SET, "Test8");


	/* Test9 */
	T_LOG("********Test9 go clean: inactive priority but assertion[19] prevails");
	proc_will_set_clean(mypid);
	(void)check_properties(mypid, JETSAM_PRIORITY_CRITICAL, inactive_limit_mb, 0xFEED, ASSERTION_STATE_IS_SET, "Test9");

	/* Test10 */
	T_LOG("********Test10 clean:  assertion[19 -> 3] inactive limit prevails");
	set_assertion_priority(mypid, JETSAM_PRIORITY_BACKGROUND, 0xFACE);
	(void)check_properties(mypid, JETSAM_PRIORITY_AUDIO_AND_ACCESSORY, inactive_limit_mb, 0xFACE, ASSERTION_STATE_IS_SET, "Test10");


	/* Test11 */
	T_LOG("********Test11 clean:  assertion[3 -> 0] inactive priority still prevails");
	relinquish_assertion_priority(mypid, 0xBEEF);
	(void)check_properties(mypid, JETSAM_PRIORITY_AUDIO_AND_ACCESSORY, inactive_limit_mb, 0xBEEF, ASSERTION_STATE_IS_RELINQUISHED, "Test11");

	/* Test12 */
	T_LOG("********Test12 dirty goes clean: both assertion[0] and clean");
	proc_will_set_clean(mypid);
	(void)check_properties(mypid, JETSAM_PRIORITY_AUDIO_AND_ACCESSORY, inactive_limit_mb, 0xBEEF, ASSERTION_STATE_IS_RELINQUISHED, "Test12");
}

T_DECL(assertion_test_bad_flags, "verify bad flag returns an error", T_META_TIMEOUT(30), T_META_ASROOT(true)) {
	int err;
	uint32_t flag = 0;

	memorystatus_priority_properties_t mjp = { 0 };

	mjp.priority = JETSAM_PRIORITY_FOREGROUND;
	mjp.user_data = 0;

	/*
	 * init a bad flag
	 */

	flag = 0xf;

	err = memorystatus_control(MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES, getpid(), flag, &mjp, sizeof(mjp));

	T_QUIET;
	T_ASSERT_POSIX_FAILURE(err, EINVAL, "MEMORYSTATUS_CMD_SET_PRIORITY_PROPERTIES should fail with bad flags (err=%d)", err);
}


T_DECL(assertion_test_repetitive_non_dirty_tracking, "Scenario #1 - repetitive assertion priority on non-dirty-tracking process", T_META_TIMEOUT(60), T_META_ASROOT(true)) {
	/*
	 * Verify back-to-back assertion calls set assertion state as expected.
	 * false --> non-dirty-tracking process (like a typical app)
	 * false --> clean/dirty does not apply here
	 */

	memorystatus_assertion_test_repetitive("Scenario #1", false, false);
}

T_DECL(assertion_test_repetitive_dirty_tracking_clean, "Scenario #2 - repetitive assertion priority on clean dirty-tracking process", T_META_TIMEOUT(60), T_META_ASROOT(true)) {
	/*
	 * Verify back-to-back assertion calls set assertion state as expected.
	 * true --> dirty-tracking process (like a typical extension/widget)
	 * true --> start clean / inactive
	 * This will exercise idle-deferred paths.
	 */
	memorystatus_assertion_test_repetitive("Scenario #2", true, true);
}

T_DECL(assertion_test_repetitive_dirty_tracking_dirty, "Scenario #3 - repetitive assertion priority on dirty dirty-tracking processes", T_META_TIMEOUT(60), T_META_ASROOT(true)) {
	/*
	 * Verify back-to-back assertion calls set assertion state as expected.
	 * true --> dirty-tracking process (like a typical extension/widget)
	 * false --> start dirty / active state
	 * This will exercise idle-deferred paths.
	 */
	memorystatus_assertion_test_repetitive("Scenario #3", true, false);
}


T_DECL(assertion_test_allow_idle_exit, "set assertion priorities on process supporting idle exit", T_META_TIMEOUT(360), T_META_ASROOT(true)) {
	memorystatus_assertion_test_allow_idle_exit();
}

T_DECL(assertion_test_do_not_allow_idle_exit, "set assertion priorities on process no idle exit allowed", T_META_TIMEOUT(360), T_META_ASROOT(true)) {
	memorystatus_assertion_test_do_not_allow_idle_exit();
}
