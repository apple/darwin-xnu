/*
 * turnstile_multihop: Tests turnstile and multi hop priority propagation.
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
#include <signal.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <libkern/OSAtomic.h>
#include <sys/wait.h>

#include "turnstile_multihop_helper.h"

T_GLOBAL_META(T_META_NAMESPACE("xnu.turnstile_multihop"));

#define HELPER_TIMEOUT_SECS (3000)

struct test_msg {
	mach_msg_header_t header;
	mach_msg_body_t body;
	mach_msg_port_descriptor_t port_descriptor;
};

static boolean_t spin_for_ever = false;

static void
thread_create_at_qos(qos_class_t qos, void * (*function)(void *));
static uint64_t
nanoseconds_to_absolutetime(uint64_t nanoseconds);
static int
sched_create_load_at_qos(qos_class_t qos, void **load_token);
static int
sched_terminate_load(void *load_token) __unused;
static void do_work(int num);
static void
dispatch_sync_cancel(mach_port_t owner_thread, qos_class_t promote_qos);

static void *sched_load_thread(void *);

struct load_token_context {
	volatile int threads_should_exit;
	int thread_count;
	qos_class_t qos;
	pthread_t *threads;
};

static struct mach_timebase_info sched_mti;
static pthread_once_t sched_mti_once_control = PTHREAD_ONCE_INIT;

static void
sched_mti_init(void)
{
	mach_timebase_info(&sched_mti);
}
uint64_t
nanoseconds_to_absolutetime(uint64_t nanoseconds)
{
	pthread_once(&sched_mti_once_control, sched_mti_init);

	return (uint64_t)(nanoseconds * (((double)sched_mti.denom) / ((double)sched_mti.numer)));
}

static int
sched_create_load_at_qos(qos_class_t qos, void **load_token)
{
	struct load_token_context *context = NULL;
	int ret;
	int ncpu;
	size_t ncpu_size = sizeof(ncpu);
	int nthreads;
	int i;
	pthread_attr_t attr;

	ret = sysctlbyname("hw.ncpu", &ncpu, &ncpu_size, NULL, 0);
	if (ret == -1) {
		T_LOG("sysctlbyname(hw.ncpu)");
		return errno;
	}

	T_QUIET; T_LOG("%s: Detected %d CPUs\n", __FUNCTION__, ncpu);

	nthreads = ncpu;
	T_QUIET; T_LOG("%s: Will create %d threads\n", __FUNCTION__, nthreads);

	ret = pthread_attr_init(&attr);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "pthread_attr_init");

	if (&pthread_attr_set_qos_class_np) {
		ret = pthread_attr_set_qos_class_np(&attr, qos, 0);
		T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "pthread_attr_set_qos_class_np");
	}

	context = calloc(1, sizeof(*context));
	if (context == NULL) {
		T_QUIET; T_LOG("calloc returned error"); return ENOMEM;
	}

	context->threads_should_exit = 0;
	context->thread_count = nthreads;
	context->qos = qos;
	context->threads = calloc((unsigned int)nthreads, sizeof(pthread_t));

	OSMemoryBarrier();

	for (i = 0; i < nthreads; i++) {
		ret = pthread_create(&context->threads[i], &attr, sched_load_thread, context);
		T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "pthread_create");
		T_QUIET; T_LOG("%s: Created thread %d (%p)\n", __FUNCTION__, i, (void *)context->threads[i]);
	}

	ret = pthread_attr_destroy(&attr);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "pthread_attr_destroy");

	*load_token = context;

	return 0;
}

static void *
sched_load_thread(void *arg)
{
	struct load_token_context *context = (struct load_token_context *)arg;

	T_QUIET; T_LOG("%s: Thread started %p\n", __FUNCTION__, (void *)pthread_self());

	while (!context->threads_should_exit) {
		uint64_t start = mach_absolute_time();
		uint64_t end = start + nanoseconds_to_absolutetime(900ULL * NSEC_PER_MSEC);

		while ((mach_absolute_time() < end) && !context->threads_should_exit) {
			;
		}
	}

	T_QUIET; T_LOG("%s: Thread terminating %p\n", __FUNCTION__, (void *)pthread_self());

	return NULL;
}

static int
sched_terminate_load(void *load_token)
{
	int ret;
	int i;
	struct load_token_context *context = (struct load_token_context *)load_token;

	context->threads_should_exit = 1;
	OSMemoryBarrier();

	for (i = 0; i < context->thread_count; i++) {
		T_QUIET; T_LOG("%s: Joining thread %d (%p)\n", __FUNCTION__, i, (void *)context->threads[i]);
		ret = pthread_join(context->threads[i], NULL);
		T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "pthread_join");
	}

	free(context->threads);
	free(context);

	return 0;
}


// Find the first num primes, simply as a means of doing work
static void
do_work(int num)
{
	volatile int i = 3, count, c;

	for (count = 2; count <= num;) {
		for (c = 2; c <= i; c++) {
			if (i % c == 0) {
				break;
			}
		}
		if (c == i) {
			count++;
		}
		i++;
	}
}

#pragma mark pthread callbacks

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

#define LISTENER_WLID  0x100
#define CONN_WLID      0x200

static uint32_t
register_port_options(void)
{
	return MACH_RCV_MSG | MACH_RCV_LARGE | MACH_RCV_LARGE_IDENTITY |
	       MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_CTX) |
	       MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
	       MACH_RCV_VOUCHER;
}

static void
register_port(uint64_t wlid, mach_port_t port)
{
	int r;

	struct kevent_qos_s kev = {
		.ident  = port,
		.filter = EVFILT_MACHPORT,
		.flags  = EV_ADD | EV_UDATA_SPECIFIC | EV_DISPATCH | EV_VANISHED,
		.fflags = register_port_options(),
		.data   = 1,
		.qos    = (int32_t)_pthread_qos_class_encode(QOS_CLASS_MAINTENANCE, 0, 0)
	};

	struct kevent_qos_s kev_err = { 0 };

	/* Setup workloop for mach msg rcv */
	r = kevent_id(wlid, &kev, 1, &kev_err, 1, NULL,
	    NULL, KEVENT_FLAG_WORKLOOP | KEVENT_FLAG_ERROR_EVENTS);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(r, "kevent_id");
	T_QUIET; T_ASSERT_EQ(r, 0, "no errors returned from kevent_id");
}

/*
 * Basic WL handler callback, it checks the
 * effective Qos of the servicer thread.
 */
static void
workloop_cb_test_intransit(uint64_t *workloop_id, void **eventslist, int *events)
{
	static bool got_peer;

	struct kevent_qos_s *kev = eventslist[0];
	mach_msg_header_t *hdr;
	struct test_msg *tmsg;

	T_LOG("Workloop handler %s called. Received message on 0x%llx",
	    __func__, *workloop_id);

	/* Skip the test if we can't check Qos */
	if (geteuid() != 0) {
		T_SKIP("kevent_qos test requires root privileges to run.");
	}

	T_QUIET; T_ASSERT_EQ(*events, 1, "should have one event");

	hdr = (mach_msg_header_t *)kev->ext[0];
	T_ASSERT_NOTNULL(hdr, "has a message");
	T_ASSERT_EQ(hdr->msgh_size, (uint32_t)sizeof(struct test_msg), "of the right size");
	tmsg = (struct test_msg *)hdr;

	switch (*workloop_id) {
	case LISTENER_WLID:
		T_LOG("Registering peer connection");
		T_QUIET; T_ASSERT_FALSE(got_peer, "Should not have seen peer yet");
		got_peer = true;
		break;

	case CONN_WLID:
		T_LOG("Received message on peer");
		break;

	default:
		T_FAIL("???");
	}

	sleep(5);
	T_LOG("Do some CPU work.");
	do_work(5000);

	/* Check if the override now is IN + 60 boost */
	T_EXPECT_EFFECTIVE_QOS_EQ(QOS_CLASS_USER_INITIATED,
	    "dispatch_source event handler QoS should be QOS_CLASS_USER_INITIATED");
	T_EXPECT_EQ(get_user_promotion_basepri(), 60u,
	    "dispatch_source event handler should be overridden at 60");

	if (*workloop_id == LISTENER_WLID) {
		register_port(CONN_WLID, tmsg->port_descriptor.name);

		kev->flags = EV_ADD | EV_ENABLE | EV_UDATA_SPECIFIC | EV_DISPATCH | EV_VANISHED;
		kev->fflags = register_port_options();
		kev->ext[0] = kev->ext[1] = kev->ext[2] = kev->ext[3] = 0;
		*events = 1;
	} else {
		/* this will unblock the waiter */
		mach_msg_destroy(hdr);
		*events = 0;
	}
}

static void
run_client_server(const char *server_name, const char *client_name)
{
	dt_helper_t helpers[] = {
		dt_launchd_helper_domain("com.apple.xnu.test.turnstile_multihop.plist",
	    server_name, NULL, LAUNCH_SYSTEM_DOMAIN),
		dt_fork_helper(client_name)
	};
	dt_run_helpers(helpers, 2, HELPER_TIMEOUT_SECS);
}

#pragma mark Mach receive

#define TURNSTILE_MULTIHOP_SERVICE_NAME "com.apple.xnu.test.turnstile_multihop"

static mach_port_t
get_server_port(void)
{
	mach_port_t port;
	kern_return_t kr = bootstrap_check_in(bootstrap_port,
	    TURNSTILE_MULTIHOP_SERVICE_NAME, &port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "server bootstrap_check_in");
	return port;
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
	};

	if (options & MACH_SEND_SYNC_USE_THRPRI) {
		send_msg.header.msgh_voucher_port = create_pthpriority_voucher(qos);
	}

	if (msg_port == MACH_PORT_NULL) {
		send_msg.body.msgh_descriptor_count = 0;
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

static void
receive(
	mach_port_t rcv_port,
	mach_port_t notify_port)
{
	kern_return_t ret = 0;

	struct {
		mach_msg_header_t header;
		mach_msg_body_t body;
		mach_msg_port_descriptor_t port_descriptor;
	} rcv_msg = {
		.header =
		{
			.msgh_remote_port = MACH_PORT_NULL,
			.msgh_local_port  = rcv_port,
			.msgh_size        = sizeof(rcv_msg),
		},
	};

	T_LOG("Client: Starting sync receive\n");

	ret = mach_msg(&(rcv_msg.header),
	    MACH_RCV_MSG |
	    MACH_RCV_SYNC_WAIT,
	    0,
	    rcv_msg.header.msgh_size,
	    rcv_port,
	    0,
	    notify_port);
}

static lock_t lock_DEF;
static lock_t lock_IN;
static lock_t lock_UI;

static mach_port_t main_thread_port;
static mach_port_t def_thread_port;
static mach_port_t in_thread_port;
static mach_port_t ui_thread_port;
static mach_port_t sixty_thread_port;

static uint64_t dispatch_sync_owner;

static int
get_pri(thread_t thread_port)
{
	kern_return_t kr;

	thread_extended_info_data_t extended_info;
	mach_msg_type_number_t count = THREAD_EXTENDED_INFO_COUNT;
	kr = thread_info(thread_port, THREAD_EXTENDED_INFO,
	    (thread_info_t)&extended_info, &count);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "thread_info");

	return extended_info.pth_curpri;
}

static void
set_thread_name(const char *fn_name)
{
	char name[50] = "";

	thread_t thread_port = pthread_mach_thread_np(pthread_self());

	int pri = get_pri(thread_port);

	snprintf(name, sizeof(name), "%s at pri %2d", fn_name, pri);
	pthread_setname_np(name);
}

static void
thread_wait_to_block(mach_port_t thread_port)
{
	thread_extended_info_data_t extended_info;
	kern_return_t kr;

	while (1) {
		mach_msg_type_number_t count = THREAD_EXTENDED_INFO_COUNT;
		kr = thread_info(thread_port, THREAD_EXTENDED_INFO,
		    (thread_info_t)&extended_info, &count);

		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "thread_info");

		if (extended_info.pth_run_state == TH_STATE_WAITING) {
			T_LOG("Target thread blocked\n");
			break;
		}
		thread_switch(thread_port, SWITCH_OPTION_DEPRESS, 0);
	}
}

static void
thread_wait_to_boost(mach_port_t thread_port, mach_port_t yield_thread, int priority)
{
	thread_extended_info_data_t extended_info;
	kern_return_t kr;

	while (1) {
		mach_msg_type_number_t count = THREAD_EXTENDED_INFO_COUNT;
		kr = thread_info(thread_port, THREAD_EXTENDED_INFO,
		    (thread_info_t)&extended_info, &count);

		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "thread_info");

		if (extended_info.pth_priority >= priority) {
			T_LOG("Target thread boosted\n");
			break;
		}
		thread_switch(yield_thread, SWITCH_OPTION_DEPRESS, 0);
	}
}

static void
dispatch_sync_wait(mach_port_t owner_thread, qos_class_t promote_qos)
{
	struct kevent_qos_s kev_err[] = {{ 0 }};
	uint32_t fflags = 0;
	uint64_t mask = 0;
	uint16_t action = 0;
	int r;

	action = EV_ADD | EV_DISABLE;
	fflags = NOTE_WL_SYNC_WAIT | NOTE_WL_DISCOVER_OWNER;

	dispatch_sync_owner = owner_thread;

	struct kevent_qos_s kev[] =  {{
					      .ident = mach_thread_self(),
					      .filter = EVFILT_WORKLOOP,
					      .flags = action,
					      .fflags = fflags,
					      .udata = (uintptr_t) &def_thread_port,
					      .qos = (int32_t)_pthread_qos_class_encode(promote_qos, 0, 0),
					      .ext[EV_EXTIDX_WL_MASK] = mask,
					      .ext[EV_EXTIDX_WL_VALUE] = dispatch_sync_owner,
					      .ext[EV_EXTIDX_WL_ADDR] = (uint64_t)&dispatch_sync_owner,
				      }};

	/* Setup workloop to fake dispatch sync wait on a workloop */
	r = kevent_id(30, kev, 1, kev_err, 1, NULL,
	    NULL, KEVENT_FLAG_WORKLOOP | KEVENT_FLAG_ERROR_EVENTS);
	T_QUIET; T_LOG("dispatch_sync_wait returned\n");
}

static void
dispatch_sync_cancel(mach_port_t owner_thread, qos_class_t promote_qos)
{
	struct kevent_qos_s kev_err[] = {{ 0 }};
	uint32_t fflags = 0;
	uint64_t mask = 0;
	uint16_t action = 0;
	int r;

	action = EV_DELETE | EV_ENABLE;
	fflags = NOTE_WL_SYNC_WAKE | NOTE_WL_END_OWNERSHIP;

	dispatch_sync_owner = owner_thread;

	struct kevent_qos_s kev[] =  {{
					      .ident = def_thread_port,
					      .filter = EVFILT_WORKLOOP,
					      .flags = action,
					      .fflags = fflags,
					      .udata = (uintptr_t) &def_thread_port,
					      .qos = (int32_t)_pthread_qos_class_encode(promote_qos, 0, 0),
					      .ext[EV_EXTIDX_WL_MASK] = mask,
					      .ext[EV_EXTIDX_WL_VALUE] = dispatch_sync_owner,
					      .ext[EV_EXTIDX_WL_ADDR] = (uint64_t)&dispatch_sync_owner,
				      }};

	/* Setup workloop to fake dispatch sync wake on a workloop */
	r = kevent_id(30, kev, 1, kev_err, 1, NULL,
	    NULL, KEVENT_FLAG_WORKLOOP | KEVENT_FLAG_ERROR_EVENTS);
	T_QUIET; T_LOG("dispatch_sync_cancel returned\n");
}

static void *
thread_at_sixty(void *arg __unused)
{
	int policy;
	struct sched_param param;
	int ret;
	void *load_token;
	uint64_t before_lock_time, after_lock_time;

	sixty_thread_port = mach_thread_self();

	set_thread_name(__FUNCTION__);

	/* Change our priority to 60 */
	ret = pthread_getschedparam(pthread_self(), &policy, &param);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "pthread_getschedparam");

	param.sched_priority = 60;

	ret = pthread_setschedparam(pthread_self(), policy, &param);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "pthread_setschedparam");

	ret = pthread_getschedparam(pthread_self(), &policy, &param);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "pthread_getschedparam");

	T_LOG("My priority is %d", param.sched_priority);

	thread_wait_to_boost(in_thread_port, ui_thread_port, 46);

	if (spin_for_ever) {
		/* Schedule load at Default */
		sched_create_load_at_qos(QOS_CLASS_DEFAULT, &load_token);
	}

	T_LOG("Thread at priority 60 trying to acquire UI lock");

	before_lock_time = mach_absolute_time();
	ull_lock(&lock_UI, 3, UL_UNFAIR_LOCK, 0);
	after_lock_time = mach_absolute_time();

	T_QUIET; T_LOG("The time for priority 60 thread to acquire lock was %llu \n",
	    (after_lock_time - before_lock_time));
	T_END;
}

static void *
thread_at_ui(void *arg __unused)
{
	ui_thread_port = mach_thread_self();

	set_thread_name(__FUNCTION__);

	/* Grab the first ulock */
	ull_lock(&lock_UI, 2, UL_UNFAIR_LOCK, 0);

	thread_wait_to_boost(def_thread_port, in_thread_port, 37);
	thread_create_at_qos(QOS_CLASS_USER_INTERACTIVE, thread_at_sixty);

	T_LOG("Thread at UI priority trying to acquire IN lock");
	ull_lock(&lock_IN, 2, UL_UNFAIR_LOCK, 0);
	ull_unlock(&lock_UI, 2, UL_UNFAIR_LOCK, 0);
	return NULL;
}

static void *
thread_at_in(void *arg __unused)
{
	in_thread_port = mach_thread_self();

	set_thread_name(__FUNCTION__);

	/* Grab the first ulock */
	ull_lock(&lock_IN, 2, UL_UNFAIR_LOCK, 0);

	T_LOG("Thread at IN priority got first lock ");

	thread_wait_to_boost(main_thread_port, def_thread_port, 31);

	/* Create a new thread at QOS_CLASS_USER_INTERACTIVE qos */
	thread_create_at_qos(QOS_CLASS_USER_INTERACTIVE, thread_at_ui);

	T_LOG("Thread at IN priority trying to acquire default lock");
	ull_lock(&lock_DEF, 1, UL_UNFAIR_LOCK, 0);
	ull_unlock(&lock_IN, 2, UL_UNFAIR_LOCK, 0);
	return NULL;
}

static void *
thread_at_default(void *arg __unused)
{
	def_thread_port = mach_thread_self();

	set_thread_name(__FUNCTION__);

	/* Grab the first ulock */
	ull_lock(&lock_DEF, 1, UL_UNFAIR_LOCK, 0);

	T_LOG("Thread at DEFAULT priority got first lock ");

	thread_wait_to_block(main_thread_port);

	/* Create a new thread at QOS_CLASS_USER_INITIATED qos */
	thread_create_at_qos(QOS_CLASS_USER_INITIATED, thread_at_in);

	T_LOG("Thread at Default priority trying to wait on dispatch sync for maintenance thread");
	dispatch_sync_wait(main_thread_port, QOS_CLASS_DEFAULT);
	ull_unlock(&lock_DEF, 1, UL_UNFAIR_LOCK, 0);
	return NULL;
}

static void *
thread_at_maintenance(void *arg __unused)
{
	mach_port_t service_port;
	mach_port_t conn_port;
	mach_port_t special_reply_port;
	mach_port_options_t opts = {
		.flags = MPO_INSERT_SEND_RIGHT,
	};

	main_thread_port = mach_thread_self();

	set_thread_name(__FUNCTION__);

	kern_return_t kr = bootstrap_look_up(bootstrap_port,
	    TURNSTILE_MULTIHOP_SERVICE_NAME, &service_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "client bootstrap_look_up");

	kr = mach_port_construct(mach_task_self(), &opts, 0ull, &conn_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct");

	special_reply_port = thread_get_special_reply_port();
	T_QUIET; T_ASSERT_TRUE(MACH_PORT_VALID(special_reply_port), "get_thread_special_reply_port");

	/* Become the dispatch sync owner, dispatch_sync_owner will be set in dispatch_sync_wait function */

	/* Send a sync message */
	send(conn_port, special_reply_port, MACH_PORT_NULL,
	    (uint32_t)_pthread_qos_class_encode(QOS_CLASS_MAINTENANCE, 0, 0), 0);

	/* Send an async checkin message */
	send(service_port, MACH_PORT_NULL, conn_port,
	    (uint32_t)_pthread_qos_class_encode(QOS_CLASS_MAINTENANCE, 0, 0), 0);

	/* Create a new thread at QOS_CLASS_DEFAULT qos */
	thread_create_at_qos(QOS_CLASS_DEFAULT, thread_at_default);

	/* Block on Sync IPC */
	receive(special_reply_port, service_port);

	T_LOG("received reply");

	dispatch_sync_cancel(def_thread_port, QOS_CLASS_DEFAULT);
	return NULL;
}

T_HELPER_DECL(three_ulock_sync_ipc_hop,
    "Create chain of 4 threads with 3 ulocks and 1 sync IPC at different qos")
{
	thread_create_at_qos(QOS_CLASS_MAINTENANCE, thread_at_maintenance);
	sigsuspend(0);
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
}

#pragma mark Mach receive - kevent_qos

T_HELPER_DECL(server_kevent_id,
    "Reply with the QoS that a dispatch source event handler ran with")
{
	T_QUIET; T_ASSERT_POSIX_ZERO(_pthread_workqueue_init_with_workloop(
		    worker_cb, event_cb,
		    (pthread_workqueue_function_workloop_t)workloop_cb_test_intransit, 0, 0), NULL);

	register_port(LISTENER_WLID, get_server_port());
	sigsuspend(0);
	T_ASSERT_FAIL("should receive a message");
}

#define TEST_MULTIHOP(server_name, client_name, name) \
	T_DECL(server_kevent_id_##name, \
	                "Event delivery using a kevent_id", \
	                T_META_ASROOT(YES)) \
	{ \
	        run_client_server(server_name, client_name); \
	}

#define TEST_MULTIHOP_SPIN(server_name, client_name, name) \
	T_DECL(server_kevent_id_##name, \
	                "Event delivery using a kevent_id", \
	                T_META_ASROOT(YES), T_META_ENABLED(FALSE)) \
	{ \
	        spin_for_ever = true; \
	        run_client_server(server_name, client_name); \
	        spin_for_ever = false; \
	}

/*
 * Test 1: Test multihop priority boosting with ulocks, dispatch sync and sync IPC.
 *
 * Create thread's at different Qos and acquire a ulock and block on next ulock/dispatch sync
 * creating a sync chain. The last hop the chain is blocked on Sync IPC.
 */
TEST_MULTIHOP("server_kevent_id", "three_ulock_sync_ipc_hop", three_ulock_sync_ipc_hop)

/*
 * Test 2: Test multihop priority boosting with ulocks, dispatch sync and sync IPC.
 *
 * Create thread's at different Qos and acquire a ulock and block on next ulock/dispatch sync
 * creating a sync chain. The last hop the chain is blocked on Sync IPC.
 * Before the last priority 60 thread blocks on ulock, it also starts spinforeverd at priority 31.
 */
TEST_MULTIHOP_SPIN("server_kevent_id", "three_ulock_sync_ipc_hop", three_ulock_sync_ipc_hop_spin)
