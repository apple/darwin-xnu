/*
 * kevent_qos: Tests Synchronous IPC QOS override.
 */

#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif

#include <darwintest.h>
#include <darwintest_multiprocess.h>

#include <dispatch/dispatch.h>
#include <pthread.h>
#include <launch.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <mach/mach_voucher.h>
#include <pthread/workqueue_private.h>
#include <voucher/ipc_pthread_priority_types.h>
#include <servers/bootstrap.h>
#include <stdlib.h>
#include <sys/event.h>
#include <unistd.h>
#include <crt_externs.h>
#include <mach/mach_port.h>
#include <mach/mach_sync_ipc.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.kevent_qos"));

#define ARRAYLEN(arr) (sizeof(arr) / sizeof(arr[0]))

#define INTERMITTENT_TIMEOUT_SEC (3)
#define RECV_TIMEOUT_SECS   (4)
#define SEND_TIMEOUT_SECS   (6)
#define HELPER_TIMEOUT_SECS (15)

#define ENV_VAR_QOS (3)
static const char *qos_env[ENV_VAR_QOS] = {"XNU_TEST_QOS_BO", "XNU_TEST_QOS_QO", "XNU_TEST_QOS_AO"};
static const char *qos_name_env[ENV_VAR_QOS] = {"XNU_TEST_QOS_NAME_BO", "XNU_TEST_QOS_NAME_QO", "XNU_TEST_QOS_NAME_AO"};

#define ENV_VAR_FUNCTION (1)
static const char *wl_function_name = "XNU_TEST_WL_FUNCTION";

static qos_class_t g_expected_qos[ENV_VAR_QOS];
static const char *g_expected_qos_name[ENV_VAR_QOS];

#define ENV_QOS_BEFORE_OVERRIDE (0)
#define ENV_QOS_QUEUE_OVERRIDE  (1)
#define ENV_QOS_AFTER_OVERRIDE  (2)

struct test_msg {
	mach_msg_header_t header;
	mach_msg_body_t body;
	mach_msg_port_descriptor_t port_descriptor;
	mach_msg_option_t opts;
	mach_msg_priority_t qos;
};

#pragma mark pthread callbacks

static void
thread_create_at_qos(qos_class_t qos, void * (*function)(void *));
static void
send(mach_port_t send_port, mach_port_t reply_port, mach_port_t msg_port, mach_msg_priority_t qos, mach_msg_option_t options);
static void
enable_kevent(uint64_t *workloop_id, unsigned long long port);
static void
populate_kevent(struct kevent_qos_s *kev, unsigned long long port);

static void
worker_cb(pthread_priority_t __unused priority)
{
	T_FAIL("a worker thread was created");
}

static void
event_cb(void ** __unused events, int * __unused nevents)
{
	T_FAIL("a kevent routine was called instead of workloop");
}

static uint32_t
get_user_promotion_basepri(void)
{
	mach_msg_type_number_t count = THREAD_POLICY_STATE_COUNT;
	struct thread_policy_state thread_policy;
	boolean_t get_default = FALSE;
	mach_port_t thread_port = pthread_mach_thread_np(pthread_self());

	kern_return_t kr = thread_policy_get(thread_port, THREAD_POLICY_STATE,
	    (thread_policy_t)&thread_policy, &count, &get_default);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "thread_policy_get");
	return thread_policy.thps_user_promotion_basepri;
}

#define EXPECT_QOS_EQ(qos, ...) do { \
	        if ((qos) == QOS_CLASS_USER_INTERACTIVE) { \
	                T_EXPECT_EFFECTIVE_QOS_EQ(QOS_CLASS_USER_INITIATED, __VA_ARGS__); \
	                T_EXPECT_EQ(47u, get_user_promotion_basepri(), __VA_ARGS__); \
	        } else { \
	                T_EXPECT_EFFECTIVE_QOS_EQ(qos, __VA_ARGS__); \
	        } \
	} while (0)

#define EXPECT_TEST_MSG(_ke)  do { \
	        struct kevent_qos_s *ke = _ke; \
	        mach_msg_header_t *hdr = (mach_msg_header_t *)ke->ext[0]; \
	        T_ASSERT_NOTNULL(hdr, "has a message"); \
	        T_ASSERT_EQ(hdr->msgh_size, (uint32_t)sizeof(struct test_msg), "of the right size"); \
	        struct test_msg *tmsg = (struct test_msg *)hdr; \
	        if (tmsg->opts & MACH_SEND_PROPAGATE_QOS) { \
	                T_EXPECT_EQ(tmsg->qos, ((uint32_t)(ke->ext[2] >> 32)), \
	                                "propagation works"); \
	        } \
	} while (0)

/*
 * Basic WL handler callback, it sleeps for n seconds and then checks the
 * effective Qos of the servicer thread.
 */
static void
workloop_cb_test_intransit(uint64_t *workloop_id __unused, void **eventslist, int *events)
{
	T_LOG("Workloop handler workloop_cb_test_intransit called. "
	    "Will wait for %d seconds to make sure client enqueues the sync msg \n",
	    2 * RECV_TIMEOUT_SECS);

	EXPECT_TEST_MSG(*eventslist);

	/* Wait for the client to send the high priority message to override the qos */
	sleep(2 * RECV_TIMEOUT_SECS);

	/* Skip the test if we can't check Qos */
	if (geteuid() != 0) {
		T_SKIP("kevent_qos test requires root privileges to run.");
	}

	/* The effective Qos should be the one expected after override */
	EXPECT_QOS_EQ(g_expected_qos[ENV_QOS_AFTER_OVERRIDE],
	    "dispatch_source event handler QoS should be %s", g_expected_qos_name[ENV_QOS_AFTER_OVERRIDE]);

	*events = 0;
	T_END;
}

/*
 * WL handler which checks if the servicer thread has correct Qos.
 */
static void
workloop_cb_test_sync_send(uint64_t *workloop_id __unused, void **eventslist, int *events)
{
	T_LOG("Workloop handler workloop_cb_test_sync_send called");

	EXPECT_TEST_MSG(*eventslist);

	if (geteuid() != 0) {
		T_SKIP("kevent_qos test requires root privileges to run.");
	}

	/* The effective Qos should be the one expected after override */
	EXPECT_QOS_EQ(g_expected_qos[ENV_QOS_AFTER_OVERRIDE],
	    "dispatch_source event handler QoS should be %s", g_expected_qos_name[ENV_QOS_AFTER_OVERRIDE]);

	*events = 0;
	T_END;
}

/*
 * WL handler which checks the overridden Qos and then enables the knote and checks
 * for the Qos again if that dropped the sync ipc override.
 */
static void
workloop_cb_test_sync_send_and_enable(uint64_t *workloop_id, struct kevent_qos_s **eventslist, int *events)
{
	unsigned override_priority;
	unsigned reenable_priority;

	T_LOG("Workloop handler workloop_cb_test_sync_send_and_enable called");

	EXPECT_TEST_MSG(*eventslist);

	if (geteuid() != 0) {
		T_SKIP("kevent_qos test requires root privileges to run.");
	}

	/* The effective Qos should be the one expected after override */
	EXPECT_QOS_EQ(g_expected_qos[ENV_QOS_AFTER_OVERRIDE],
	    "dispatch_source event handler QoS should be %s", g_expected_qos_name[ENV_QOS_AFTER_OVERRIDE]);

	/* Snapshot the current override priority */
	override_priority = get_user_promotion_basepri();

	/* Enable the knote */
	struct kevent_qos_s *kev = *eventslist;
	enable_kevent(workloop_id, kev->ident);

	/*
	 * Check if the override has been dropped, check for priority instead of qos since
	 * there will be async qos push.
	 */
	reenable_priority = get_user_promotion_basepri();
	T_EXPECT_LT(reenable_priority, override_priority,
	    "thread's current override priority %d should be less than override priority prior to enabling knote %d",
	    reenable_priority, override_priority);

	*events = 0;
	T_END;
}

/*
 * WL handler receives the first message and checks sync ipc override, then enables the knote
 * and receives 2nd message and checks it sync ipc override.
 */
static int send_two_sync_handler_called = 0;
static void
workloop_cb_test_send_two_sync(uint64_t *workloop_id __unused, struct kevent_qos_s **eventslist, int *events)
{
	T_LOG("Workloop handler workloop_cb_test_send_two_sync called for %d time", send_two_sync_handler_called + 1);

	EXPECT_TEST_MSG(*eventslist);

	if (geteuid() != 0) {
		T_SKIP("kevent_qos test requires root privileges to run.");
	}

	T_LOG("Number of events received is %d\n", *events);

	if (send_two_sync_handler_called == 0) {
		/* The effective Qos should be the one expected after override */
		EXPECT_QOS_EQ(g_expected_qos[ENV_QOS_AFTER_OVERRIDE],
		    "dispatch_source event handler QoS should be %s", g_expected_qos_name[ENV_QOS_AFTER_OVERRIDE]);

		/* Enable the knote to get 2nd message */
		struct kevent_qos_s *kev = *eventslist;
		uint64_t port = kev->ident;
		populate_kevent(kev, port);
		*events = 1;
	} else {
		EXPECT_QOS_EQ(g_expected_qos[ENV_QOS_BEFORE_OVERRIDE],
		    "dispatch_source event handler QoS should be %s", g_expected_qos_name[ENV_QOS_BEFORE_OVERRIDE]);
		*events = 0;
		T_END;
	}
	send_two_sync_handler_called++;
}

/*
 * Checks the sync ipc override and then waits for client to destroy the
 * special reply port and checks if that removes the sync ipc override.
 */
static boolean_t two_send_and_destroy_test_passed = FALSE;
static int two_send_and_destroy_handler = 0;
static void
workloop_cb_test_two_send_and_destroy(uint64_t *workloop_id __unused, struct kevent_qos_s **eventslist __unused, int *events)
{
	T_LOG("Workloop handler workloop_cb_test_two_send_and_destroy called %d times", two_send_and_destroy_handler + 1);

	EXPECT_TEST_MSG(*eventslist);

	if (geteuid() != 0) {
		T_SKIP("kevent_qos test requires root privileges to run.");
	}

	if (two_send_and_destroy_handler == 0) {
		/* Sleep to make sure the mqueue gets full */
		sleep(RECV_TIMEOUT_SECS);

		/* The effective Qos should be the one expected after override */
		EXPECT_QOS_EQ(g_expected_qos[ENV_QOS_AFTER_OVERRIDE],
		    "dispatch_source event handler QoS should be %s", g_expected_qos_name[ENV_QOS_AFTER_OVERRIDE]);

		sleep(SEND_TIMEOUT_SECS);

		/* Special reply port should have been destroyed, check Qos again */
		EXPECT_QOS_EQ(g_expected_qos[ENV_QOS_BEFORE_OVERRIDE],
		    "dispatch_source event handler QoS should be %s", g_expected_qos_name[ENV_QOS_BEFORE_OVERRIDE]);

		two_send_and_destroy_test_passed = TRUE;
	} else {
		if (two_send_and_destroy_test_passed) {
			T_END;
		}
	}

	/* Enable the knote to get next message */
	struct kevent_qos_s *kev = *eventslist;
	uint64_t port = kev->ident;
	populate_kevent(kev, port);
	*events = 1;
	two_send_and_destroy_handler++;
	T_LOG("Handler returning \n");
}

static mach_port_type_t
get_reply_port(struct kevent_qos_s *kev)
{
	mach_msg_header_t *hdr;
	mach_port_t reply_port;
	mach_port_type_t type;
	kern_return_t kr;

	hdr = (void*)kev->ext[0];
	T_QUIET; T_ASSERT_NOTNULL(hdr, "msg hdr");

	reply_port = hdr->msgh_remote_port;
	T_QUIET; T_ASSERT_TRUE(MACH_PORT_VALID(reply_port), "reply port valid");
	kr = mach_port_type(mach_task_self(), reply_port, &type);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_type");
	T_QUIET; T_ASSERT_TRUE(type & MACH_PORT_TYPE_SEND_ONCE, "send once received");

	return reply_port;
}

static void
send_reply(mach_port_t reply_port)
{
	kern_return_t kr;

	struct {
		mach_msg_header_t header;
	} send_msg = {
		.header = {
			.msgh_remote_port = reply_port,
			.msgh_local_port  = MACH_PORT_NULL,
			.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0),
			.msgh_id          = 0x100,
			.msgh_size        = sizeof(send_msg),
		},
	};

	kr = mach_msg(&(send_msg.header),
	    MACH_SEND_MSG,
	    send_msg.header.msgh_size,
	    0,
	    MACH_PORT_NULL,
	    0,
	    0);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "server mach_msg");
}

static void
populate_kevent(struct kevent_qos_s *kev, unsigned long long port)
{
	memset(kev, 0, sizeof(struct kevent_qos_s));
	kev->ident = port;
	kev->filter = EVFILT_MACHPORT;
	kev->flags = EV_ADD | EV_ENABLE | EV_UDATA_SPECIFIC | EV_DISPATCH | EV_VANISHED;
	kev->fflags = (MACH_RCV_MSG | MACH_RCV_LARGE | MACH_RCV_LARGE_IDENTITY |
	    MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_CTX) |
	    MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0));
	kev->data = 1;
}

static void
enable_kevent(uint64_t *workloop_id, unsigned long long port)
{
	kern_return_t kr;
	struct kevent_qos_s kev;

	populate_kevent(&kev, port);
	struct kevent_qos_s kev_err[] = {{ 0 }};

	kr = kevent_id(*workloop_id, &kev, 1, kev_err, 1, NULL,
	    NULL, KEVENT_FLAG_WORKLOOP | KEVENT_FLAG_ERROR_EVENTS | KEVENT_FLAG_DYNAMIC_KQ_MUST_EXIST);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(kr, "kevent_id");
}

/*
 * WL handler which sends a msg to the client from handler.
 */
static void
workloop_cb_test_sync_send_reply(uint64_t *workloop_id __unused, struct kevent_qos_s **eventslist, int *events)
{
	T_LOG("Workloop handler workloop_cb_test_sync_send_reply called");

	if (geteuid() != 0) {
		T_SKIP("kevent_qos test requires root privileges to run.");
	}

	T_QUIET; T_ASSERT_EQ_INT(*events, 1, "events received");
	T_QUIET; T_ASSERT_EQ_INT((*eventslist)->filter, EVFILT_MACHPORT, "received EVFILT_MACHPORT");

	/* send reply */
	send_reply(get_reply_port(*eventslist));

	*events = 0;
}

/*
 * WL handler which deallocates reply port.
 */
static void
workloop_cb_test_sync_send_deallocate(uint64_t *workloop_id __unused, struct kevent_qos_s **eventslist, int *events)
{
	mach_port_t reply_port;
	kern_return_t kr;

	T_LOG("Workloop handler workloop_cb_test_sync_send_deallocate called");

	if (geteuid() != 0) {
		T_SKIP("kevent_qos test requires root privileges to run.");
	}

	T_QUIET; T_ASSERT_EQ_INT(*events, 1, "events received");
	T_QUIET; T_ASSERT_EQ_INT((*eventslist)->filter, EVFILT_MACHPORT, "received EVFILT_MACHPORT");

	reply_port = get_reply_port(*eventslist);

	/* deallocate port */
	kr = mach_port_deallocate(mach_task_self(), reply_port);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_deallocate");

	*events = 0;

	T_LOG("Handler returning \n");
}


/*
 * WL handler which sends a msg to the client before enabling the event from handler.
 */
static void
workloop_cb_test_sync_send_reply_kevent(uint64_t *workloop_id, struct kevent_qos_s **eventslist, int *events)
{
	T_LOG("Workloop handler workloop_cb_test_sync_send_reply_kevent called");

	if (geteuid() != 0) {
		T_SKIP("kevent_qos test requires root privileges to run.");
	}

	T_QUIET; T_ASSERT_EQ_INT(*events, 1, "events received");
	T_QUIET; T_ASSERT_EQ_INT(((*eventslist)->filter), EVFILT_MACHPORT, "received EVFILT_MACHPORT");

	struct kevent_qos_s *kev = *eventslist;

	/* send reply */
	send_reply(get_reply_port(kev));

	/* Enable the knote */
	enable_kevent(workloop_id, kev->ident);

	*events = 0;

	T_LOG("Handler returning \n");
}

/*
 * WL handler which sends a msg to the client before enabling the event from pthread.
 */
static void
workloop_cb_test_sync_send_reply_kevent_pthread(uint64_t *workloop_id __unused, struct kevent_qos_s **eventslist, int *events)
{
	T_LOG("Workloop handler workloop_cb_test_sync_send_reply_kevent_pthread called");

	if (geteuid() != 0) {
		T_SKIP("kevent_qos test requires root privileges to run.");
	}

	T_QUIET; T_ASSERT_EQ_INT(*events, 1, "events received");
	T_QUIET; T_ASSERT_EQ_INT((*eventslist)->filter, EVFILT_MACHPORT, "received EVFILT_MACHPORT");

	struct kevent_qos_s *kev = *eventslist;

	/* send reply */
	send_reply(get_reply_port(kev));

	populate_kevent(kev, kev->ident);

	*events = 1;

	T_LOG("Handler returning \n");
}

/*
 * WL handler which sends a msg to the client after reenabling the event.
 */
static void
workloop_cb_test_sync_send_kevent_reply(uint64_t *workloop_id, struct kevent_qos_s **eventslist, int *events)
{
	T_LOG("workloop handler workloop_cb_test_sync_send_kevent_reply called");

	if (geteuid() != 0) {
		T_SKIP("kevent_qos test requires root privileges to run.");
	}

	T_QUIET; T_ASSERT_EQ_INT(*events, 1, "events received");
	T_QUIET; T_ASSERT_EQ_INT((*eventslist)->filter, EVFILT_MACHPORT, "received EVFILT_MACHPORT");

	struct kevent_qos_s *kev = *eventslist;
	mach_port_t reply_port = get_reply_port(*eventslist);

	/* Enable the knote */
	enable_kevent(workloop_id, kev->ident);

	/* send reply */
	send_reply(reply_port);

	*events = 0;

	T_LOG("Handler returning \n");
}

/*
 * WL handler that does nothing.
 */
static void
workloop_cb_test_sync_send_do_nothing(uint64_t *workloop_id __unused, struct kevent_qos_s **eventslist, int *events)
{
	T_LOG("Workloop handler workloop_cb_test_sync_send_do_nothing called");

	if (geteuid() != 0) {
		T_SKIP("kevent_qos test requires root privileges to run.");
	}

	T_QUIET; T_ASSERT_EQ_INT(*events, 1, "events received");
	T_QUIET; T_ASSERT_EQ_INT((*eventslist)->filter, EVFILT_MACHPORT, "received EVFILT_MACHPORT");

	/* do nothing */

	*events = 0;

	T_LOG("Handler returning \n");
}

/*
 * WL handler that returns the event to reenable.
 */
static void
workloop_cb_test_sync_send_do_nothing_kevent_pthread(uint64_t *workloop_id __unused, struct kevent_qos_s **eventslist, int *events)
{
	T_LOG("Workloop handler workloop_cb_test_sync_send_do_nothing_kevent_pthread called");

	if (geteuid() != 0) {
		T_SKIP("kevent_qos test requires root privileges to run.");
	}

	T_QUIET; T_ASSERT_EQ_INT(*events, 1, "events received");
	T_QUIET; T_ASSERT_EQ_INT((*eventslist)->filter, EVFILT_MACHPORT, "received EVFILT_MACHPORT");

	struct kevent_qos_s *kev = *eventslist;
	populate_kevent(kev, kev->ident);

	*events = 1;

	T_LOG("handler returning \n");
}

/*
 * WL handler that exits.
 */
static void
workloop_cb_test_sync_send_do_nothing_exit(uint64_t *workloop_id __unused, struct kevent_qos_s **eventslist, __unused int *events)
{
	T_LOG("workloop handler workloop_cb_test_sync_send_do_nothing_exit called");

	if (geteuid() != 0) {
		T_SKIP("kevent_qos test requires root privileges to run.");
	}

	T_QUIET; T_ASSERT_EQ_INT(*events, 1, "events received");
	T_QUIET; T_ASSERT_EQ_INT((*eventslist)->filter, EVFILT_MACHPORT, "received EVFILT_MACHPORT");

	/* call exit */
	exit(0);
}

/*
 * WL handler which:
 * first sync sends a msg to the client and reenables kevent after
 * second sync sends a msg and reenables kevent after.
 */
static void
workloop_cb_test_sync_send_reply_kevent_reply_kevent(uint64_t *workloop_id __unused, struct kevent_qos_s **eventslist, int *events)
{
	T_LOG("Workloop handler workloop_cb_test_sync_send_reply_kevent_reply_kevent called");

	if (geteuid() != 0) {
		T_SKIP("kevent_qos test requires root privileges to run.");
	}

	T_QUIET; T_ASSERT_EQ_INT(*events, 1, "events received");
	T_QUIET; T_ASSERT_EQ_INT((*eventslist)->filter, EVFILT_MACHPORT, "received EVFILT_MACHPORT");

	struct kevent_qos_s *kev = *eventslist;

	/* send reply */
	send_reply(get_reply_port(kev));

	populate_kevent(kev, kev->ident);

	*events = 1;

	T_LOG("Handler returning \n");
}

/*
 * WL handler which:
 * first sync reenables kevent and after sends a msg
 * second sync sends a msg and reenables kevent after.
 */
static int workloop_cb_test_sync_send_kevent_reply_reply_kevent_handler_called = 0;
static void
workloop_cb_test_sync_send_kevent_reply_reply_kevent(uint64_t *workloop_id, struct kevent_qos_s **eventslist, int *events)
{
	T_LOG("workloop handler workloop_cb_test_sync_send_kevent_reply_reply_kevent called");

	if (geteuid() != 0) {
		T_SKIP("kevent_qos test requires root privileges to run.");
	}

	T_QUIET; T_ASSERT_EQ_INT(*events, 1, "events received");
	T_QUIET; T_ASSERT_EQ_INT((*eventslist)->filter, EVFILT_MACHPORT, "received EVFILT_MACHPORT");

	struct kevent_qos_s *kev = *eventslist;
	mach_port_t reply_port = get_reply_port(kev);

	if (workloop_cb_test_sync_send_kevent_reply_reply_kevent_handler_called == 0) {
		workloop_cb_test_sync_send_kevent_reply_reply_kevent_handler_called = 1;

		/* Enable the knote */
		enable_kevent(workloop_id, kev->ident);

		/* send reply */
		send_reply(reply_port);

		*events = 0;
	} else {
		/* send reply */
		send_reply(reply_port);

		/* Enable the knote */
		enable_kevent(workloop_id, kev->ident);

		*events = 0;
	}

	T_LOG("Handler returning \n");
}

/*
 * WL handler which:
 * first sync reenables kevent and after sends a msg
 * second sync reenables kevent and after sends a msg
 */
static void
workloop_cb_test_sync_send_kevent_reply_kevent_reply(uint64_t *workloop_id, struct kevent_qos_s **eventslist, int *events)
{
	T_LOG("workloop handler workloop_cb_test_sync_send_kevent_reply_kevent_reply called");

	if (geteuid() != 0) {
		T_SKIP("kevent_qos test requires root privileges to run.");
	}

	T_QUIET; T_ASSERT_EQ_INT(*events, 1, "events received");
	T_QUIET; T_ASSERT_EQ_INT((*eventslist)->filter, EVFILT_MACHPORT, "received EVFILT_MACHPORT");

	struct kevent_qos_s *kev = *eventslist;
	mach_port_t reply_port = get_reply_port(kev);

	/* Enable the knote */
	enable_kevent(workloop_id, kev->ident);

	/* send reply */
	send_reply(reply_port);

	*events = 0;
	T_LOG("Handler returning \n");
}

/*
 * WL handler which:
 * first sync ends a msg and reenables kevent after
 * second sync reenables kevent and sends a msg after
 */
static int workloop_cb_test_sync_send_reply_kevent_kevent_reply_handler_called = 0;
static void
workloop_cb_test_sync_send_reply_kevent_kevent_reply(uint64_t *workloop_id, struct kevent_qos_s **eventslist, int *events)
{
	T_LOG("workloop handler workloop_cb_test_sync_send_reply_kevent_kevent_reply called");

	if (geteuid() != 0) {
		T_SKIP("kevent_qos test requires root privileges to run.");
	}

	T_QUIET; T_ASSERT_EQ_INT(*events, 1, "events received");
	T_QUIET; T_ASSERT_EQ_INT((*eventslist)->filter, EVFILT_MACHPORT, "received EVFILT_MACHPORT");

	struct kevent_qos_s *kev = *eventslist;
	mach_port_t reply_port = get_reply_port(kev);

	if (workloop_cb_test_sync_send_reply_kevent_kevent_reply_handler_called == 0) {
		workloop_cb_test_sync_send_reply_kevent_kevent_reply_handler_called = 1;

		/* send reply */
		send_reply(reply_port);

		populate_kevent(kev, kev->ident);

		*events = 1;
	} else {
		/* Enable the knote */
		enable_kevent(workloop_id, kev->ident);
		/* send reply */
		send_reply(reply_port);

		*events = 0;
	}

	T_LOG("Handler returning \n");
}
#pragma mark Mach receive

#define KEVENT_QOS_SERVICE_NAME "com.apple.xnu.test.kevent_qos"

static mach_port_t
get_server_port(void)
{
	mach_port_t port;
	kern_return_t kr = bootstrap_check_in(bootstrap_port,
	    KEVENT_QOS_SERVICE_NAME, &port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "server bootstrap_check_in");
	return port;
}

static void
env_set_qos(char **env, qos_class_t qos[], const char *qos_name[], const char *wl_function)
{
	int i;
	char *qos_str, *qos_name_str;
	for (i = 0; i < ENV_VAR_QOS; i++) {
		T_QUIET; T_ASSERT_POSIX_SUCCESS(asprintf(&qos_str, "%s=%d", qos_env[i], qos[i]),
		    NULL);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(
			asprintf(&qos_name_str, "%s=%s", qos_name_env[i], qos_name[i]), NULL);
		env[2 * i] = qos_str;
		env[2 * i + 1] = qos_name_str;
	}
	T_QUIET; T_ASSERT_POSIX_SUCCESS(asprintf(&env[2 * i], "%s=%s", wl_function_name, wl_function),
	    NULL);
	env[2 * i + 1] = NULL;
}

static void
environ_get_qos(qos_class_t qos[], const char *qos_name[], const char **wl_function)
{
	char *qos_str;
	char *qos_end;
	int i;

	for (i = 0; i < ENV_VAR_QOS; i++) {
		qos_str = getenv(qos_env[i]);
		T_QUIET; T_ASSERT_NOTNULL(qos_str, "getenv(%s)", qos_env[i]);

		unsigned long qos_l = strtoul(qos_str, &qos_end, 10);
		T_QUIET; T_ASSERT_EQ(*qos_end, '\0', "getenv(%s) = '%s' should be an "
		    "integer", qos_env[i], qos_str);

		T_QUIET; T_ASSERT_LT(qos_l, (unsigned long)100, "getenv(%s) = '%s' should "
		    "be less than 100", qos_env[i], qos_str);

		qos[i] = (qos_class_t)qos_l;
		qos_name[i] = getenv(qos_name_env[i]);
		T_QUIET; T_ASSERT_NOTNULL(qos_name[i], "getenv(%s)", qos_name_env[i]);
	}
	*wl_function = getenv(wl_function_name);
	T_QUIET; T_ASSERT_NOTNULL(*wl_function, "getenv(%s)", wl_function_name);
}

static mach_voucher_t
create_pthpriority_voucher(mach_msg_priority_t qos)
{
	char voucher_buf[sizeof(mach_voucher_attr_recipe_data_t) + sizeof(ipc_pthread_priority_value_t)];

	mach_voucher_t voucher = MACH_PORT_NULL;
	kern_return_t ret;
	ipc_pthread_priority_value_t ipc_pthread_priority_value =
	    (ipc_pthread_priority_value_t)qos;

	mach_voucher_attr_raw_recipe_array_t recipes;
	mach_voucher_attr_raw_recipe_size_t recipe_size = 0;
	mach_voucher_attr_recipe_t recipe =
	    (mach_voucher_attr_recipe_t)&voucher_buf[recipe_size];

	recipe->key = MACH_VOUCHER_ATTR_KEY_PTHPRIORITY;
	recipe->command = MACH_VOUCHER_ATTR_PTHPRIORITY_CREATE;
	recipe->previous_voucher = MACH_VOUCHER_NULL;
	memcpy((char *)&recipe->content[0], &ipc_pthread_priority_value, sizeof(ipc_pthread_priority_value));
	recipe->content_size = sizeof(ipc_pthread_priority_value_t);
	recipe_size += sizeof(mach_voucher_attr_recipe_data_t) + recipe->content_size;

	recipes = (mach_voucher_attr_raw_recipe_array_t)&voucher_buf[0];

	ret = host_create_mach_voucher(mach_host_self(),
	    recipes,
	    recipe_size,
	    &voucher);

	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "client host_create_mach_voucher");
	return voucher;
}

static void
send(
	mach_port_t send_port,
	mach_port_t reply_port,
	mach_port_t msg_port,
	mach_msg_priority_t qos,
	mach_msg_option_t options)
{
	kern_return_t ret = 0;

	struct test_msg send_msg = {
		.header = {
			.msgh_remote_port = send_port,
			.msgh_local_port  = reply_port,
			.msgh_bits        = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND,
	    reply_port ? MACH_MSG_TYPE_MAKE_SEND_ONCE : 0,
	    MACH_MSG_TYPE_MOVE_SEND,
	    MACH_MSGH_BITS_COMPLEX),
			.msgh_id          = 0x100,
			.msgh_size        = sizeof(send_msg),
		},
		.body = {
			.msgh_descriptor_count = 1,
		},
		.port_descriptor = {
			.name        = msg_port,
			.disposition = MACH_MSG_TYPE_MOVE_RECEIVE,
			.type        = MACH_MSG_PORT_DESCRIPTOR,
		},
		.opts = options,
	};

	if (msg_port == MACH_PORT_NULL) {
		send_msg.body.msgh_descriptor_count = 0;
	}

	if ((options & MACH_SEND_PROPAGATE_QOS) == 0) {
		send_msg.header.msgh_voucher_port = create_pthpriority_voucher(qos);
		send_msg.qos = qos;
	} else {
		qos_class_t qc;
		int relpri;
		pthread_get_qos_class_np(pthread_self(), &qc, &relpri);
		send_msg.qos = (uint32_t)_pthread_qos_class_encode(qc, relpri, 0);
	}

	ret = mach_msg(&(send_msg.header),
	    MACH_SEND_MSG |
	    MACH_SEND_TIMEOUT |
	    MACH_SEND_OVERRIDE |
	    ((reply_port ? MACH_SEND_SYNC_OVERRIDE : 0) | options),
	    send_msg.header.msgh_size,
	    0,
	    MACH_PORT_NULL,
	    10000,
	    0);

	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "client mach_msg");
}

static kern_return_t
receive(
	mach_port_t rcv_port,
	mach_port_t notify_port)
{
	kern_return_t ret = 0;

	struct test_msg rcv_msg = {
		.header = {
			.msgh_remote_port = MACH_PORT_NULL,
			.msgh_local_port  = rcv_port,
			.msgh_size        = sizeof(rcv_msg),
		},
	};

	T_LOG("Client: Starting sync receive\n");

	ret = mach_msg(&(rcv_msg.header),
	    MACH_RCV_MSG |
	    MACH_RCV_TIMEOUT |
	    MACH_RCV_SYNC_WAIT,
	    0,
	    rcv_msg.header.msgh_size,
	    rcv_port,
	    SEND_TIMEOUT_SECS * 1000,
	    notify_port);

	return ret;
}

T_HELPER_DECL(qos_get_special_reply_port,
    "Test get_special_reply_port and it's corner cases.")
{
	mach_port_t special_reply_port;
	mach_port_t new_special_reply_port;

	special_reply_port = thread_get_special_reply_port();
	T_QUIET; T_ASSERT_TRUE(MACH_PORT_VALID(special_reply_port), "get_thread_special_reply_port");

	new_special_reply_port = thread_get_special_reply_port();
	T_QUIET; T_ASSERT_TRUE(MACH_PORT_VALID(new_special_reply_port), "get_thread_special_reply_port");

	mach_port_destroy(mach_task_self(), special_reply_port);
	mach_port_destroy(mach_task_self(), new_special_reply_port);

	new_special_reply_port = thread_get_special_reply_port();
	T_QUIET; T_ASSERT_TRUE(MACH_PORT_VALID(new_special_reply_port), "get_thread_special_reply_port");

	T_END;
}

static void *
qos_client_send_to_intransit(void *arg __unused)
{
	mach_port_t qos_send_port;
	mach_port_t msg_port;
	mach_port_t special_reply_port;

	kern_return_t kr = bootstrap_look_up(bootstrap_port,
	    KEVENT_QOS_SERVICE_NAME, &qos_send_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "client bootstrap_look_up");

	special_reply_port = thread_get_special_reply_port();
	T_QUIET; T_ASSERT_TRUE(MACH_PORT_VALID(special_reply_port), "get_thread_special_reply_port");

	/* Create a rcv right to send in a msg */
	kr = mach_port_allocate(mach_task_self(),
	    MACH_PORT_RIGHT_RECEIVE,
	    &msg_port);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "client mach_port_allocate");

	kr = mach_port_insert_right(mach_task_self(),
	    msg_port,
	    msg_port,
	    MACH_MSG_TYPE_MAKE_SEND);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "client mach_port_insert_right");

	/* Send an empty msg on the port to fire the WL thread */
	send(qos_send_port, MACH_PORT_NULL, MACH_PORT_NULL,
	    (uint32_t)_pthread_qos_class_encode(g_expected_qos[ENV_QOS_BEFORE_OVERRIDE], 0, 0), 0);

	/* Sleep 3 seconds for the server to start */
	sleep(3);

	/* Send the message with msg port as in-transit port, this msg will not be dequeued */
	send(qos_send_port, MACH_PORT_NULL, msg_port,
	    (uint32_t)_pthread_qos_class_encode(g_expected_qos[ENV_QOS_BEFORE_OVERRIDE], 0, 0), 0);

	/* Send 5 messages to msg port to make sure the port is full */
	for (int i = 0; i < 5; i++) {
		send(msg_port, MACH_PORT_NULL, MACH_PORT_NULL,
		    (uint32_t)_pthread_qos_class_encode(g_expected_qos[ENV_QOS_BEFORE_OVERRIDE], 0, 0), 0);
	}

	T_LOG("Sent 5 msgs, now trying to send sync ipc messgae, which will block with a timeout\n");
	/* Send the message to the in-transit port, it should block and override the rcv's workloop */
	send(msg_port, special_reply_port, MACH_PORT_NULL,
	    (uint32_t)_pthread_qos_class_encode(g_expected_qos[ENV_QOS_AFTER_OVERRIDE], 0, 0), 0);
	T_LOG("Client done sending messages, now waiting for server to end the test");

	T_ASSERT_FAIL("client timed out");
	return NULL;
}

T_HELPER_DECL(qos_client_send_to_intransit_with_thr_pri,
    "Send synchronous messages from a pri thread to an intransit port")
{
	thread_create_at_qos(g_expected_qos[ENV_QOS_AFTER_OVERRIDE], qos_client_send_to_intransit);
	sleep(HELPER_TIMEOUT_SECS);
}

static void
thread_create_at_qos(qos_class_t qos, void * (*function)(void *))
{
	qos_class_t qos_thread;
	pthread_t thread;
	pthread_attr_t attr;
	int ret;

	ret = setpriority(PRIO_DARWIN_ROLE, 0, PRIO_DARWIN_ROLE_UI_FOCAL);
	if (ret != 0) {
		T_LOG("set priority failed\n");
	}

	pthread_attr_init(&attr);
	pthread_attr_set_qos_class_np(&attr, qos, 0);
	pthread_create(&thread, &attr, function, NULL);

	T_LOG("pthread created\n");
	pthread_get_qos_class_np(thread, &qos_thread, NULL);
	T_EXPECT_EQ(qos_thread, (qos_class_t)qos, NULL);
}

static void *
qos_send_and_sync_rcv(void *arg __unused)
{
	mach_port_t qos_send_port;
	mach_port_t special_reply_port;

	T_LOG("Client: from created thread\n");
	T_EXPECT_EFFECTIVE_QOS_EQ(g_expected_qos[ENV_QOS_AFTER_OVERRIDE],
	    "pthread QoS should be %s", g_expected_qos_name[ENV_QOS_AFTER_OVERRIDE]);

	kern_return_t kr = bootstrap_look_up(bootstrap_port,
	    KEVENT_QOS_SERVICE_NAME, &qos_send_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "client bootstrap_look_up");

	special_reply_port = thread_get_special_reply_port();
	T_QUIET; T_ASSERT_TRUE(MACH_PORT_VALID(special_reply_port), "get_thread_special_reply_port");

	/* enqueue two messages to make sure that mqueue is not empty */
	send(qos_send_port, MACH_PORT_NULL, MACH_PORT_NULL,
	    (uint32_t)_pthread_qos_class_encode(g_expected_qos[ENV_QOS_QUEUE_OVERRIDE], 0, 0), 0);

	send(qos_send_port, MACH_PORT_NULL, MACH_PORT_NULL,
	    (uint32_t)_pthread_qos_class_encode(g_expected_qos[ENV_QOS_QUEUE_OVERRIDE], 0, 0), 0);

	sleep(SEND_TIMEOUT_SECS);

	/* sync wait on msg port */
	receive(special_reply_port, qos_send_port);

	T_LOG("Client done doing sync rcv, now waiting for server to end the test");
	sleep(SEND_TIMEOUT_SECS);

	T_ASSERT_FAIL("client timed out");
	return NULL;
}

T_HELPER_DECL(qos_client_send_sync_and_sync_rcv,
    "Send messages and syncronously wait for rcv")
{
	thread_create_at_qos(g_expected_qos[ENV_QOS_AFTER_OVERRIDE], qos_send_and_sync_rcv);
	sleep(HELPER_TIMEOUT_SECS);
}

static void *
qos_client_send_sync_msg_and_test_link(void *arg)
{
	mach_port_t qos_send_port;
	mach_port_t special_reply_port;
	boolean_t in_effect = FALSE;
	kern_return_t kr;
	unsigned long expected_result = (unsigned long) arg;

	kr = bootstrap_look_up(bootstrap_port,
	    KEVENT_QOS_SERVICE_NAME, &qos_send_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "client bootstrap_look_up");

	/* start monitoring sync ipc link */
	kr = mach_sync_ipc_link_monitoring_start(&special_reply_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_sync_ipc_link_monitoring_start");

	/* Send the message to msg port */
	send(qos_send_port, special_reply_port, MACH_PORT_NULL,
	    (uint32_t)_pthread_qos_class_encode(g_expected_qos[ENV_QOS_AFTER_OVERRIDE], 0, 0), 0);

	/*
	 * wait for the reply
	 * some tests do not send a msg back so the receive
	 * might fail
	 */
	receive(special_reply_port, qos_send_port);

	/* stop monitoring link */
	kr = mach_sync_ipc_link_monitoring_stop(special_reply_port, &in_effect);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_sync_ipc_link_monitoring_stop");

	if (!in_effect) {
		T_LOG("Link was broken");
	} else {
		T_LOG("Link correct");
	}

	if (expected_result == 1) {
		T_ASSERT_TRUE(in_effect, "special reply port link after rcv");
	} else {
		T_ASSERT_FALSE(in_effect, "special reply port link after rcv");
	}
	T_END;
}

static void *
qos_client_send_2sync_msg_and_test_link(void *arg)
{
	mach_port_t qos_send_port;
	mach_port_t special_reply_port;
	boolean_t in_effect = FALSE;
	kern_return_t kr;
	unsigned long expected_result = (unsigned long) arg;

	kr = bootstrap_look_up(bootstrap_port,
	    KEVENT_QOS_SERVICE_NAME, &qos_send_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "client bootstrap_look_up");

	/* start monitoring sync ipc link */
	kr = mach_sync_ipc_link_monitoring_start(&special_reply_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_sync_ipc_link_monitoring_start");

	/* Send the first message to msg port */
	send(qos_send_port, special_reply_port, MACH_PORT_NULL,
	    (uint32_t)_pthread_qos_class_encode(g_expected_qos[ENV_QOS_AFTER_OVERRIDE], 0, 0), 0);

	/* wait for the reply */
	kr = receive(special_reply_port, qos_send_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "receive");

	/* Send the second message to msg port */
	send(qos_send_port, special_reply_port, MACH_PORT_NULL,
	    (uint32_t)_pthread_qos_class_encode(g_expected_qos[ENV_QOS_AFTER_OVERRIDE], 0, 0), 0);

	/* wait for the reply */
	kr = receive(special_reply_port, qos_send_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "receive");

	/* stop monitoring link */
	kr = mach_sync_ipc_link_monitoring_stop(special_reply_port, &in_effect);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_sync_ipc_link_monitoring_stop");

	if (!in_effect) {
		T_LOG("Link was broken");
	} else {
		T_LOG("Link correct");
	}

	if (expected_result == 1) {
		T_ASSERT_TRUE(in_effect, "special reply port link after rcv");
	} else {
		T_ASSERT_FALSE(in_effect, "special reply port link after rcv");
	}
	T_END;
}
T_HELPER_DECL(qos_client_send_sync_msg_with_link_check_correct_server,
    "Send sync message, wait for reply and check sync ipc link")
{
	pthread_t thread;
	pthread_attr_t attr;
	unsigned long expected_result = 1;

	pthread_attr_init(&attr);
	pthread_create(&thread, &attr, qos_client_send_sync_msg_and_test_link, (void *)expected_result);

	sleep(HELPER_TIMEOUT_SECS);
}

T_HELPER_DECL(qos_client_send_sync_msg_with_link_check_incorrect_server,
    "Send sync message, wait for reply and check sync ipc link")
{
	pthread_t thread;
	pthread_attr_t attr;
	unsigned long expected_result = 0;

	pthread_attr_init(&attr);
	pthread_create(&thread, &attr, qos_client_send_sync_msg_and_test_link, (void *)expected_result);

	sleep(HELPER_TIMEOUT_SECS);
}

T_HELPER_DECL(qos_client_send_2sync_msg_with_link_check_correct_server,
    "Send sync message, wait for reply and check sync ipc link")
{
	pthread_t thread;
	pthread_attr_t attr;
	unsigned long expected_result = 1;

	pthread_attr_init(&attr);
	pthread_create(&thread, &attr, qos_client_send_2sync_msg_and_test_link, (void *)expected_result);

	sleep(HELPER_TIMEOUT_SECS);
}

T_HELPER_DECL(qos_client_send_2sync_msg_with_link_check_incorrect_server,
    "Send sync message, wait for reply and check sync ipc link")
{
	pthread_t thread;
	pthread_attr_t attr;
	unsigned long expected_result = 0;

	pthread_attr_init(&attr);
	pthread_create(&thread, &attr, qos_client_send_2sync_msg_and_test_link, (void *)expected_result);

	sleep(HELPER_TIMEOUT_SECS);
}

static void *
qos_client_send_sync_msg(void *arg __unused)
{
	mach_port_t qos_send_port;
	mach_port_t special_reply_port;

	kern_return_t kr = bootstrap_look_up(bootstrap_port,
	    KEVENT_QOS_SERVICE_NAME, &qos_send_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "client bootstrap_look_up");

	special_reply_port = thread_get_special_reply_port();
	T_QUIET; T_ASSERT_TRUE(MACH_PORT_VALID(special_reply_port), "get_thread_special_reply_port");

	/* Send the message to msg port */
	send(qos_send_port, special_reply_port, MACH_PORT_NULL,
	    (uint32_t)_pthread_qos_class_encode(g_expected_qos[ENV_QOS_AFTER_OVERRIDE], 0, 0), 0);

	/* wait for the reply */
	receive(special_reply_port, qos_send_port);

	T_LOG("Client done sending messages, now waiting for server to end the test");
	sleep(2 * SEND_TIMEOUT_SECS);

	T_ASSERT_FAIL("client timed out");
	return NULL;
}

T_HELPER_DECL(qos_client_send_sync_msg_with_pri,
    "Send sync message and wait for reply")
{
	thread_create_at_qos(g_expected_qos[ENV_QOS_AFTER_OVERRIDE], qos_client_send_sync_msg);
	sleep(HELPER_TIMEOUT_SECS);
}

static void *
qos_client_send_two_sync_msg_high_qos(void *arg __unused)
{
	mach_port_t qos_send_port;
	mach_port_t special_reply_port;

	kern_return_t kr = bootstrap_look_up(bootstrap_port,
	    KEVENT_QOS_SERVICE_NAME, &qos_send_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "client bootstrap_look_up");

	special_reply_port = thread_get_special_reply_port();
	T_QUIET; T_ASSERT_TRUE(MACH_PORT_VALID(special_reply_port), "get_thread_special_reply_port");

	/* Send the message to msg port */
	send(qos_send_port, special_reply_port, MACH_PORT_NULL,
	    (uint32_t)_pthread_qos_class_encode(g_expected_qos[ENV_QOS_AFTER_OVERRIDE], 0, 0), 0);

	/* wait for the reply */
	receive(special_reply_port, qos_send_port);

	T_LOG("Client done sending messages, now waiting for server to end the test");
	sleep(SEND_TIMEOUT_SECS);

	T_ASSERT_FAIL("client timed out");
	return NULL;
}

static void *
qos_client_send_two_sync_msg_low_qos(void *arg __unused)
{
	mach_port_t qos_send_port;
	mach_port_t special_reply_port;

	kern_return_t kr = bootstrap_look_up(bootstrap_port,
	    KEVENT_QOS_SERVICE_NAME, &qos_send_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "client bootstrap_look_up");

	special_reply_port = thread_get_special_reply_port();
	T_QUIET; T_ASSERT_TRUE(MACH_PORT_VALID(special_reply_port), "get_thread_special_reply_port");

	/* Send the message to msg port */
	send(qos_send_port, special_reply_port, MACH_PORT_NULL,
	    (uint32_t)_pthread_qos_class_encode(g_expected_qos[ENV_QOS_BEFORE_OVERRIDE], 0, 0), 0);

	/* wait for the reply */
	receive(special_reply_port, qos_send_port);

	T_LOG("Client done sending messages, now waiting for server to end the test");
	sleep(SEND_TIMEOUT_SECS);

	T_ASSERT_FAIL("client timed out");
	return NULL;
}

T_HELPER_DECL(qos_client_send_two_sync_msg_with_thr_pri,
    "Send messages sync msgs from 2 threads at given thread pri")
{
	thread_create_at_qos(g_expected_qos[ENV_QOS_AFTER_OVERRIDE], qos_client_send_two_sync_msg_high_qos);
	sleep(INTERMITTENT_TIMEOUT_SEC);
	thread_create_at_qos(g_expected_qos[ENV_QOS_BEFORE_OVERRIDE], qos_client_send_two_sync_msg_low_qos);
	sleep(HELPER_TIMEOUT_SECS);
}

static mach_port_t other_thread_reply_port = MACH_PORT_NULL;
static void *
qos_client_destroy_other_threads_port(void *arg __unused)
{
	T_LOG("Waiting 6 seconds before destroying other thread's reply port");
	sleep(SEND_TIMEOUT_SECS);

	T_LOG("Destroying other thread's special reply port ");
	mach_port_destroy(mach_task_self(), other_thread_reply_port);

	T_LOG("Other thread done destroying ");
	sleep(3 * SEND_TIMEOUT_SECS);

	T_ASSERT_FAIL("client timed out");
	return NULL;
}

static void *
qos_client_create_sepcial_reply_and_spawn_thread(void *arg __unused)
{
	mach_port_t qos_send_port;
	mach_port_t special_reply_port;

	kern_return_t kr = bootstrap_look_up(bootstrap_port,
	    KEVENT_QOS_SERVICE_NAME, &qos_send_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "client bootstrap_look_up");

	special_reply_port = thread_get_special_reply_port();
	T_QUIET; T_ASSERT_TRUE(MACH_PORT_VALID(special_reply_port), "get_thread_special_reply_port");

	other_thread_reply_port = special_reply_port;

	/* Send an async message */
	send(qos_send_port, MACH_PORT_NULL, MACH_PORT_NULL,
	    (uint32_t)_pthread_qos_class_encode(g_expected_qos[ENV_QOS_BEFORE_OVERRIDE], 0, 0), 0);

	/* Send the sync ipc message */
	send(qos_send_port, special_reply_port, MACH_PORT_NULL,
	    (uint32_t)_pthread_qos_class_encode(g_expected_qos[ENV_QOS_BEFORE_OVERRIDE], 0, 0), 0);

	/* Create a new thread to send the sync message on our special reply port */
	thread_create_at_qos(g_expected_qos[ENV_QOS_AFTER_OVERRIDE], qos_client_destroy_other_threads_port);

	/* Client starting to receive messgae */
	receive(special_reply_port, qos_send_port);

	sleep(3 * SEND_TIMEOUT_SECS);

	T_ASSERT_FAIL("client timed out");
	return NULL;
}

T_HELPER_DECL(qos_client_send_two_msg_and_destroy,
    "Send a message with another threads special reply port while that thread destroys the port")
{
	thread_create_at_qos(g_expected_qos[ENV_QOS_AFTER_OVERRIDE], qos_client_create_sepcial_reply_and_spawn_thread);
	sleep(HELPER_TIMEOUT_SECS);
}

static mach_port_t send_complex_connection_port = MACH_PORT_NULL;

static void *
qos_client_send_complex_msg_to_service_port(void *arg __unused)
{
	mach_port_t svc_port, tsr_port, conn_port;
	kern_return_t kr;

	kr = bootstrap_look_up(bootstrap_port, KEVENT_QOS_SERVICE_NAME, &svc_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "client bootstrap_look_up");

	tsr_port = thread_get_special_reply_port();
	T_QUIET; T_ASSERT_TRUE(MACH_PORT_VALID(tsr_port), "get_thread_special_reply_port");

	conn_port = send_complex_connection_port;

	T_LOG("Sending to the service port with a sync IPC");
	send(svc_port, tsr_port, conn_port,
	    (uint32_t)_pthread_qos_class_encode(g_expected_qos[ENV_QOS_BEFORE_OVERRIDE], 0, 0),
	    MACH_SEND_PROPAGATE_QOS);

	receive(tsr_port, svc_port);

	sleep(3 * SEND_TIMEOUT_SECS);

	T_ASSERT_FAIL("client timed out");
	return NULL;
}

static void *
qos_client_send_to_connection_then_service_port(void *arg __unused)
{
	mach_port_t tsr_port, conn_port;
	mach_port_options_t opts = {
		.flags = MPO_INSERT_SEND_RIGHT,
	};
	kern_return_t kr;

	kr = mach_port_construct(mach_task_self(), &opts, 0ull, &conn_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct");
	send_complex_connection_port = conn_port;

	tsr_port = thread_get_special_reply_port();
	T_QUIET; T_ASSERT_TRUE(MACH_PORT_VALID(tsr_port), "get_thread_special_reply_port");

	T_LOG("Sending to the connection port with a sync IPC");
	send(conn_port, tsr_port, MACH_PORT_NULL,
	    (uint32_t)_pthread_qos_class_encode(g_expected_qos[ENV_QOS_BEFORE_OVERRIDE], 0, 0),
	    MACH_SEND_PROPAGATE_QOS);

	thread_create_at_qos(g_expected_qos[ENV_QOS_AFTER_OVERRIDE],
	    qos_client_send_complex_msg_to_service_port);

	receive(tsr_port, conn_port);

	sleep(3 * SEND_TIMEOUT_SECS);

	T_ASSERT_FAIL("client timed out");
	return NULL;
}

T_HELPER_DECL(qos_client_send_complex_msg_with_pri,
    "Send a message with several ports causing links")
{
	thread_create_at_qos(g_expected_qos[ENV_QOS_BEFORE_OVERRIDE],
	    qos_client_send_to_connection_then_service_port);
	sleep(HELPER_TIMEOUT_SECS);
}

static void
run_client_server(const char *server_name, const char *client_name, qos_class_t qos[],
    const char *qos_name[], const char *wl_function)
{
	char *env[2 * ENV_VAR_QOS + ENV_VAR_FUNCTION + 1];
	env_set_qos(env, qos, qos_name, wl_function);

	for (int i = 0; i < ENV_VAR_QOS; i++) {
		g_expected_qos[i] = qos[i];
		g_expected_qos_name[i] = qos_name[i];
	}

	dt_helper_t helpers[] = {
		dt_launchd_helper_env("com.apple.xnu.test.kevent_qos.plist",
	    server_name, env),
		dt_fork_helper(client_name)
	};
	dt_run_helpers(helpers, 2, HELPER_TIMEOUT_SECS);
}

#pragma mark Mach receive - kevent_qos

static void
expect_kevent_id_recv(mach_port_t port, qos_class_t qos[], const char *qos_name[], const char *wl_function)
{
	int r;

	/* Qos expected by workloop thread */
	for (int i = 0; i < ENV_VAR_QOS; i++) {
		g_expected_qos[i] = qos[i];
		g_expected_qos_name[i] = qos_name[i];
	}

	if (strcmp(wl_function, "workloop_cb_test_intransit") == 0) {
		T_QUIET; T_ASSERT_POSIX_ZERO(_pthread_workqueue_init_with_workloop(
			    worker_cb, event_cb,
			    (pthread_workqueue_function_workloop_t)workloop_cb_test_intransit, 0, 0), NULL);
	} else if (strcmp(wl_function, "workloop_cb_test_sync_send") == 0) {
		T_QUIET; T_ASSERT_POSIX_ZERO(_pthread_workqueue_init_with_workloop(
			    worker_cb, event_cb,
			    (pthread_workqueue_function_workloop_t)workloop_cb_test_sync_send, 0, 0), NULL);
	} else if (strcmp(wl_function, "workloop_cb_test_sync_send_and_enable") == 0) {
		T_QUIET; T_ASSERT_POSIX_ZERO(_pthread_workqueue_init_with_workloop(
			    worker_cb, event_cb,
			    (pthread_workqueue_function_workloop_t)workloop_cb_test_sync_send_and_enable, 0, 0), NULL);
	} else if (strcmp(wl_function, "workloop_cb_test_send_two_sync") == 0) {
		T_QUIET; T_ASSERT_POSIX_ZERO(_pthread_workqueue_init_with_workloop(
			    worker_cb, event_cb,
			    (pthread_workqueue_function_workloop_t)workloop_cb_test_send_two_sync, 0, 0), NULL);
	} else if (strcmp(wl_function, "workloop_cb_test_two_send_and_destroy") == 0) {
		T_QUIET; T_ASSERT_POSIX_ZERO(_pthread_workqueue_init_with_workloop(
			    worker_cb, event_cb,
			    (pthread_workqueue_function_workloop_t)workloop_cb_test_two_send_and_destroy, 0, 0), NULL);
	} else if (strcmp(wl_function, "workloop_cb_test_sync_send_reply") == 0) {
		T_QUIET; T_ASSERT_POSIX_ZERO(_pthread_workqueue_init_with_workloop(
			    worker_cb, event_cb,
			    (pthread_workqueue_function_workloop_t)workloop_cb_test_sync_send_reply, 0, 0), NULL);
	} else if (strcmp(wl_function, "workloop_cb_test_sync_send_deallocate") == 0) {
		T_QUIET; T_ASSERT_POSIX_ZERO(_pthread_workqueue_init_with_workloop(
			    worker_cb, event_cb,
			    (pthread_workqueue_function_workloop_t)workloop_cb_test_sync_send_deallocate, 0, 0), NULL);
	} else if (strcmp(wl_function, "workloop_cb_test_sync_send_reply_kevent") == 0) {
		T_QUIET; T_ASSERT_POSIX_ZERO(_pthread_workqueue_init_with_workloop(
			    worker_cb, event_cb,
			    (pthread_workqueue_function_workloop_t)workloop_cb_test_sync_send_reply_kevent, 0, 0), NULL);
	} else if (strcmp(wl_function, "workloop_cb_test_sync_send_reply_kevent_pthread") == 0) {
		T_QUIET; T_ASSERT_POSIX_ZERO(_pthread_workqueue_init_with_workloop(
			    worker_cb, event_cb,
			    (pthread_workqueue_function_workloop_t)workloop_cb_test_sync_send_reply_kevent_pthread, 0, 0), NULL);
	} else if (strcmp(wl_function, "workloop_cb_test_sync_send_kevent_reply") == 0) {
		T_QUIET; T_ASSERT_POSIX_ZERO(_pthread_workqueue_init_with_workloop(
			    worker_cb, event_cb,
			    (pthread_workqueue_function_workloop_t)workloop_cb_test_sync_send_kevent_reply, 0, 0), NULL);
	} else if (strcmp(wl_function, "workloop_cb_test_sync_send_do_nothing") == 0) {
		T_QUIET; T_ASSERT_POSIX_ZERO(_pthread_workqueue_init_with_workloop(
			    worker_cb, event_cb,
			    (pthread_workqueue_function_workloop_t)workloop_cb_test_sync_send_do_nothing, 0, 0), NULL);
	} else if (strcmp(wl_function, "workloop_cb_test_sync_send_do_nothing_kevent_pthread") == 0) {
		T_QUIET; T_ASSERT_POSIX_ZERO(_pthread_workqueue_init_with_workloop(
			    worker_cb, event_cb,
			    (pthread_workqueue_function_workloop_t)workloop_cb_test_sync_send_do_nothing_kevent_pthread, 0, 0), NULL);
	} else if (strcmp(wl_function, "workloop_cb_test_sync_send_do_nothing_exit") == 0) {
		T_QUIET; T_ASSERT_POSIX_ZERO(_pthread_workqueue_init_with_workloop(
			    worker_cb, event_cb,
			    (pthread_workqueue_function_workloop_t)workloop_cb_test_sync_send_do_nothing_exit, 0, 0), NULL);
	} else if (strcmp(wl_function, "workloop_cb_test_sync_send_reply_kevent_reply_kevent") == 0) {
		T_QUIET; T_ASSERT_POSIX_ZERO(_pthread_workqueue_init_with_workloop(
			    worker_cb, event_cb,
			    (pthread_workqueue_function_workloop_t)workloop_cb_test_sync_send_reply_kevent_reply_kevent, 0, 0), NULL);
	} else if (strcmp(wl_function, "workloop_cb_test_sync_send_kevent_reply_reply_kevent") == 0) {
		T_QUIET; T_ASSERT_POSIX_ZERO(_pthread_workqueue_init_with_workloop(
			    worker_cb, event_cb,
			    (pthread_workqueue_function_workloop_t)workloop_cb_test_sync_send_kevent_reply_reply_kevent, 0, 0), NULL);
	} else if (strcmp(wl_function, "workloop_cb_test_sync_send_kevent_reply_kevent_reply") == 0) {
		T_QUIET; T_ASSERT_POSIX_ZERO(_pthread_workqueue_init_with_workloop(
			    worker_cb, event_cb,
			    (pthread_workqueue_function_workloop_t)workloop_cb_test_sync_send_kevent_reply_kevent_reply, 0, 0), NULL);
	} else if (strcmp(wl_function, "workloop_cb_test_sync_send_reply_kevent_kevent_reply") == 0) {
		T_QUIET; T_ASSERT_POSIX_ZERO(_pthread_workqueue_init_with_workloop(
			    worker_cb, event_cb,
			    (pthread_workqueue_function_workloop_t)workloop_cb_test_sync_send_reply_kevent_kevent_reply, 0, 0), NULL);
	} else {
		T_ASSERT_FAIL("no workloop function specified \n");
	}

	struct kevent_qos_s kev[] = {{
					     .ident = port,
					     .filter = EVFILT_MACHPORT,
					     .flags = EV_ADD | EV_UDATA_SPECIFIC | EV_DISPATCH | EV_VANISHED,
					     .fflags = (MACH_RCV_MSG | MACH_RCV_LARGE | MACH_RCV_LARGE_IDENTITY |
	    MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_CTX) |
	    MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0)),
					     .data = 1,
					     .qos = (int32_t)_pthread_qos_class_encode(qos[ENV_QOS_QUEUE_OVERRIDE], 0, 0)
				     }};

	struct kevent_qos_s kev_err[] = {{ 0 }};

	/* Setup workloop for mach msg rcv */
	r = kevent_id(25, kev, 1, kev_err, 1, NULL,
	    NULL, KEVENT_FLAG_WORKLOOP | KEVENT_FLAG_ERROR_EVENTS);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(r, "kevent_id");
	T_QUIET; T_ASSERT_EQ(r, 0, "no errors returned from kevent_id");
	sleep(HELPER_TIMEOUT_SECS);
}

T_HELPER_DECL(server_kevent_id,
    "Reply with the QoS that a dispatch source event handler ran with")
{
	qos_class_t qos[ENV_VAR_QOS];
	const char *qos_name[ENV_VAR_QOS];
	const char *wl_function;
	environ_get_qos(qos, qos_name, &wl_function);

	expect_kevent_id_recv(get_server_port(), qos, qos_name, wl_function);
	sleep(HELPER_TIMEOUT_SECS);
	T_ASSERT_FAIL("should receive a message within %d seconds",
	    RECV_TIMEOUT_SECS);
}

#define TEST_QOS(server_name, client_name, name, wl_function_name, qos_bo, qos_bo_name, qos_qo, qos_qo_name, qos_ao, qos_ao_name) \
	T_DECL(server_kevent_id_##name, \
	                "Event delivery at " qos_ao_name " QoS using a kevent_id", \
	                T_META_ASROOT(YES)) \
	{ \
	        qos_class_t qos_array[ENV_VAR_QOS] = {qos_bo, qos_qo, qos_ao};  \
	        const char *qos_name_array[ENV_VAR_QOS] = {qos_bo_name, qos_qo_name, qos_ao_name}; \
	        run_client_server(server_name, client_name, qos_array, qos_name_array, wl_function_name); \
	}
/*
 * Test 1: Test special reply port SPI
 *
 * Create thread special reply port and check any subsequent calls to
 * the same should return MACH_PORT_NULL, unless the reply port is destroyed.
 */
TEST_QOS("server_kevent_id", "qos_get_special_reply_port", special_reply_port, "workloop_cb_test_intransit",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default")

/*
 * Test 2: Test sync ipc send to an in-transit port
 *
 * Send a sync ipc message (at IN qos) to an in-transit port enqueued in a port
 * attached to a workloop. Test that the servicer of the workloop gets
 * sync ipc override.
 */
TEST_QOS("server_kevent_id", "qos_client_send_to_intransit_with_thr_pri", transit_IN, "workloop_cb_test_intransit",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_MAINTENANCE, "maintenance",
    QOS_CLASS_USER_INITIATED, "user initiated")

/*
 * Test 3: Test sync ipc send to an in-transit port
 *
 * Send a sync ipc message (at UI qos) to an in-transit port enqueued in a port
 * attached to a workloop. Test that the servicer of the workloop gets
 * sync ipc override.
 */
TEST_QOS("server_kevent_id", "qos_client_send_to_intransit_with_thr_pri", transit_UI, "workloop_cb_test_intransit",
    QOS_CLASS_USER_INITIATED, "user initiated",
    QOS_CLASS_MAINTENANCE, "maintenance",
    QOS_CLASS_USER_INTERACTIVE, "user initiated with 47 basepri promotion")

/*
 * Test 4: Test starting a sync rcv overrides the servicer
 *
 * Send an async message to a port and then start waiting on
 * the port in mach msg rcv (at IN qos) with sync wait and test if the
 * servicer of the workloop gets sync ipc override.
 */
TEST_QOS("server_kevent_id", "qos_client_send_sync_and_sync_rcv", rcv_IN, "workloop_cb_test_intransit",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_MAINTENANCE, "maintenance",
    QOS_CLASS_USER_INITIATED, "user initiated")

/*
 * Test 5: Test starting a sync rcv overrides the servicer
 *
 * Send an async message to a port and then start waiting on
 * the port in mach msg rcv (at UI qos) with sync wait and test if the
 * servicer of the workloop gets sync ipc override.
 */
TEST_QOS("server_kevent_id", "qos_client_send_sync_and_sync_rcv", rcv_UI, "workloop_cb_test_intransit",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_MAINTENANCE, "maintenance",
    QOS_CLASS_USER_INTERACTIVE, "user interactive with 47 basepri promotion")

/*
 * Test 6: test sending sync ipc message (at IN qos) to port will override the servicer
 *
 * Send a message with sync ipc override to a port and check if the servicer
 * of the workloop on other side gets sync ipc override.
 */
TEST_QOS("server_kevent_id", "qos_client_send_sync_msg_with_pri", send_sync_IN, "workloop_cb_test_sync_send",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_MAINTENANCE, "maintenance",
    QOS_CLASS_USER_INITIATED, "user initiated")

/*
 * Test 7: test sending sync ipc message (at UI qos) to port will override the servicer
 *
 * Send a message with sync ipc override to a port and check if the servicer
 * of the workloop on other side gets sync ipc override.
 */
TEST_QOS("server_kevent_id", "qos_client_send_sync_msg_with_pri", send_sync_UI, "workloop_cb_test_sync_send",
    QOS_CLASS_MAINTENANCE, "maintenance",
    QOS_CLASS_MAINTENANCE, "maintenance",
    QOS_CLASS_USER_INTERACTIVE, "user initiated with 47 basepri promotion")

/*
 * Test 8: test enabling a knote in workloop handler will drop the sync ipc override of delivered message
 *
 * Send a sync ipc message to port and check the servicer of the workloop
 * on other side gets sync ipc override and once the handler enables the knote,
 * that sync ipc override is dropped.
 */
TEST_QOS("server_kevent_id", "qos_client_send_sync_msg_with_pri", send_sync_UI_and_enable, "workloop_cb_test_sync_send_and_enable",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_USER_INTERACTIVE, "user initiated with 47 basepri promotion")

/*
 * Test 9: test returning to begin processing drops sync ipc override of delivered message
 *
 * Send a sync ipc message and check if enabling the knote clears the override of
 * the delivered message, but should still have the override of an enqueued message.
 */
TEST_QOS("server_kevent_id", "qos_client_send_two_sync_msg_with_thr_pri", send_two_sync_UI, "workloop_cb_test_send_two_sync",
    QOS_CLASS_BACKGROUND, "background",
    QOS_CLASS_MAINTENANCE, "maintenance",
    QOS_CLASS_USER_INTERACTIVE, "user initiated with 47 basepri promotion")

/*
 * Test 10: test destroying the special reply port drops the override
 *
 * Send an async messages and a sync ipc message, the workloop handler
 * should get a sync ipc override, now test if destroying the special
 * reply port drops the sync ipc override on the servicer.
 */
TEST_QOS("server_kevent_id", "qos_client_send_two_msg_and_destroy", send_two_UI_and_destroy, "workloop_cb_test_two_send_and_destroy",
    QOS_CLASS_BACKGROUND, "background",
    QOS_CLASS_MAINTENANCE, "maintenance",
    QOS_CLASS_USER_INTERACTIVE, "user initiated with 47 basepri promotion")
/*
 * Test 11: test sending two ports with chaining
 *
 * Send a sync IPC to a connection port, which itself is embedded in a message
 * sent as a sync IPC to a service port.
 */
TEST_QOS("server_kevent_id", "qos_client_send_complex_msg_with_pri", send_complex_sync_UI_and_enable, "workloop_cb_test_sync_send_and_enable",
    QOS_CLASS_USER_INITIATED, "user initiated",
    QOS_CLASS_USER_INITIATED, "user initiated",
    QOS_CLASS_USER_INTERACTIVE, "user initiated with 47 basepri promotion")

/*
 * Test 12 - 19
 *
 * Test single sync ipc link with server that breaks/preserves the link in different ways.
 */
TEST_QOS("server_kevent_id", "qos_client_send_sync_msg_with_link_check_correct_server", send_sync_link_correct_server_s, "workloop_cb_test_sync_send_reply",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default")

TEST_QOS("server_kevent_id", "qos_client_send_sync_msg_with_link_check_correct_server", send_sync_link_correct_server_d, "workloop_cb_test_sync_send_deallocate",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default")

TEST_QOS("server_kevent_id", "qos_client_send_sync_msg_with_link_check_correct_server", send_sync_link_correct_server_sk, "workloop_cb_test_sync_send_reply_kevent",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default")

TEST_QOS("server_kevent_id", "qos_client_send_sync_msg_with_link_check_correct_server", send_sync_link_correct_server_skp, "workloop_cb_test_sync_send_reply_kevent_pthread",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default")

TEST_QOS("server_kevent_id", "qos_client_send_sync_msg_with_link_check_incorrect_server", send_sync_link_incorrect_server_ks, "workloop_cb_test_sync_send_kevent_reply",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default")

TEST_QOS("server_kevent_id", "qos_client_send_sync_msg_with_link_check_correct_server", send_sync_link_correct_server_n, "workloop_cb_test_sync_send_do_nothing",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default")

TEST_QOS("server_kevent_id", "qos_client_send_sync_msg_with_link_check_incorrect_server", send_sync_link_incorrect_server_kp, "workloop_cb_test_sync_send_do_nothing_kevent_pthread",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default")

TEST_QOS("server_kevent_id", "qos_client_send_sync_msg_with_link_check_correct_server", send_sync_link_correct_server_e, "workloop_cb_test_sync_send_do_nothing_exit",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default")
/*
 * Test 20 - 23
 *
 * Test sequential sync ipc link with server that breaks/preserves the link.
 */
TEST_QOS("server_kevent_id", "qos_client_send_2sync_msg_with_link_check_correct_server", send_2sync_link_correct_server_sksk, "workloop_cb_test_sync_send_reply_kevent_reply_kevent",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default")

TEST_QOS("server_kevent_id", "qos_client_send_2sync_msg_with_link_check_incorrect_server", send_2sync_link_incorrect_server_kssk, "workloop_cb_test_sync_send_kevent_reply_reply_kevent",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default")

TEST_QOS("server_kevent_id", "qos_client_send_2sync_msg_with_link_check_incorrect_server", send_2sync_link_incorrect_server_ksks, "workloop_cb_test_sync_send_kevent_reply_kevent_reply",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default")

TEST_QOS("server_kevent_id", "qos_client_send_2sync_msg_with_link_check_incorrect_server", send_2sync_link_incorrect_server_skks, "workloop_cb_test_sync_send_reply_kevent_kevent_reply",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default",
    QOS_CLASS_DEFAULT, "default")
