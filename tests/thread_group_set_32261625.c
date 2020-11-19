#include <darwintest.h>
#include <ktrace.h>
#include <sys/kdebug.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

#define TEST_EVENTID (0xfedcbb00)

static void*
newthread(void *arg)
{
#pragma unused(arg)
	while (1) {
		kdebug_trace(TEST_EVENTID, 0, 0, 0, 0);
		sleep(1);
	}
}

#define TEST_TIMEOUT (15 * NSEC_PER_SEC)

T_DECL(thread_group_set, "Checks that new threads get a THREAD_GROUP_SET tracepoint with a non-zero tid",
    T_META_ASROOT(true)) {
	pthread_t thread;
	__block int seen_new_thread = 0, __block seen_thread_group_set = 0;

	ktrace_machine_t machine = ktrace_machine_create_current();
	T_WITH_ERRNO; T_ASSERT_NOTNULL(machine, "ktrace_get_machine");

	bool has_tg = false;
	if (ktrace_machine_has_thread_groups(machine, &has_tg) || !has_tg) {
		T_SKIP("thread groups not supported on this system");
	}
	ktrace_machine_destroy(machine);

	ktrace_session_t session = ktrace_session_create();
	T_WITH_ERRNO; T_ASSERT_NOTNULL(session, "ktrace_session_create");

	ktrace_set_interactive(session);

	ktrace_set_completion_handler(session, ^{
		ktrace_session_destroy(session);
		T_ASSERT_TRUE(seen_new_thread, "seen new thread tracepoint");
		T_END;
	});

	ktrace_events_single(session, TEST_EVENTID, ^(__unused ktrace_event_t e) {
		T_EXPECT_TRUE(seen_thread_group_set, "seen THREAD_GROUP_SET tracepoint");
		seen_new_thread = 1;
		ktrace_end(session, 1);
	});

	ktrace_events_single(session, MACHDBG_CODE(DBG_MACH_THREAD_GROUP, MACH_THREAD_GROUP_SET), ^(ktrace_event_t e) {
		T_EXPECT_GT(e->arg3, (uintptr_t)0, "tid on THREAD_GROUP_SET");
		seen_thread_group_set = 1;
	});

	dispatch_after(dispatch_time(DISPATCH_TIME_NOW, TEST_TIMEOUT), dispatch_get_main_queue(), ^{
		ktrace_end(session, 0);
	});

	T_ASSERT_POSIX_SUCCESS(ktrace_start(session, dispatch_get_main_queue()), "ktrace_start");

	T_EXPECT_POSIX_SUCCESS(pthread_create(&thread, NULL, newthread, NULL), "pthread_create");
	T_EXPECT_POSIX_SUCCESS(pthread_detach(thread), "pthread_detach");

	dispatch_main();
}
