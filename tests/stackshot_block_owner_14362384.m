#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif
#include <darwintest.h>

#include <kdd.h>
#include <kern/kcdata.h>
#include <kern/debug.h>
#include <kern/block_hint.h>
#include <mach/mach.h>
#include <mach/mach_init.h>
#include <mach/mach_traps.h>
#include <mach/message.h>
#include <mach/port.h>
#include <mach/semaphore.h>
#include <mach/task.h>
#include <os/lock.h>
#include <pthread.h>
#include <signal.h>
#include <sys/sysctl.h>
#include <sys/stackshot.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <TargetConditionals.h>

#if !TARGET_OS_EMBEDDED
#include <pcre.h>
#endif


T_GLOBAL_META(
        T_META_NAMESPACE("xnu.scheduler"),
        T_META_ASROOT(true)
);

#include <Foundation/Foundation.h>

#define SENDS_TO_BLOCK 6
#define NUMRETRIES 5
#define KRWLCK_STORES_EXCL_OWNER 0

#define KMUTEX_SYSCTL_CHECK_EXISTS   0
#define KMUTEX_SYSCTL_ACQUIRE_WAIT   1
#define KMUTEX_SYSCTL_ACQUIRE_NOWAIT 2
#define KMUTEX_SYSCTL_SIGNAL         3
#define KMUTEX_SYSCTL_TEARDOWN       4

#define KRWLCK_SYSCTL_CHECK_EXISTS    0
#define KRWLCK_SYSCTL_RACQUIRE_NOWAIT 1
#define KRWLCK_SYSCTL_RACQUIRE_WAIT   2
#define KRWLCK_SYSCTL_WACQUIRE_NOWAIT 3
#define KRWLCK_SYSCTL_WACQUIRE_WAIT   4
#define KRWLCK_SYSCTL_SIGNAL          5
#define KRWLCK_SYSCTL_TEARDOWN        6

static const char kmutex_ctl[] = "debug.test_MutexOwnerCtl";
static const char krwlck_ctl[] = "debug.test_RWLockOwnerCtl";

static mach_port_t send = MACH_PORT_NULL;
static mach_port_t recv = MACH_PORT_NULL;

static void *
take_stackshot(uint32_t extra_flags, uint64_t since_timestamp)
{
	void * stackshot = NULL;
	int ret = 0;
	uint32_t stackshot_flags = STACKSHOT_SAVE_LOADINFO |
					STACKSHOT_GET_GLOBAL_MEM_STATS |
					STACKSHOT_SAVE_IMP_DONATION_PIDS |
					STACKSHOT_KCDATA_FORMAT;

	if (since_timestamp != 0)
		stackshot_flags |= STACKSHOT_COLLECT_DELTA_SNAPSHOT;

	stackshot_flags |= extra_flags;

	stackshot = stackshot_config_create();
	T_QUIET; T_ASSERT_NOTNULL(stackshot, "Allocating stackshot config");

	ret = stackshot_config_set_flags(stackshot, stackshot_flags);
	T_ASSERT_POSIX_ZERO(ret, "Setting flags on stackshot config");

	ret = stackshot_config_set_pid(stackshot, getpid());
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "Setting target pid on stackshot config");

	if (since_timestamp != 0) {
		ret = stackshot_config_set_delta_timestamp(stackshot, since_timestamp);
		T_QUIET; T_ASSERT_POSIX_ZERO(ret, "Setting prev snapshot time on stackshot config");
	}

	for (int retries = NUMRETRIES; retries > 0; retries--) {
		ret = stackshot_capture_with_config(stackshot);
		T_QUIET; T_ASSERT_TRUE(ret == 0 || ret == EBUSY || ret == ETIMEDOUT,
				"Attempting to take stackshot (error %d)...", ret);
		if (retries == 0 && (ret == EBUSY || ret == ETIMEDOUT))
			T_ASSERT_FAIL("Failed to take stackshot after %d retries: got %d (%s)", NUMRETRIES, ret, strerror(ret));
		if (ret == 0)
			break;
	}
	return stackshot;
}

static void
save_stackshot(void *stackshot, const char *filename)
{
	void *buf = stackshot_config_get_stackshot_buffer(stackshot);
	T_QUIET; T_ASSERT_NOTNULL(buf, "buf");
	size_t size = stackshot_config_get_stackshot_size(stackshot);
	FILE *f = fopen(filename, "w");
	T_QUIET; T_ASSERT_NOTNULL(f, "f");
	fwrite(buf, size, 1, f);
	fclose(f);
}

static
void check_python(void *stackshot, const char *fmt, ...)
{
	save_stackshot(stackshot, "/tmp/ss");

#if !TARGET_OS_EMBEDDED
	va_list args;
	va_start(args, fmt);
	char *re_string = NULL;
	vasprintf(&re_string, fmt, args);
	va_end(args);
	T_QUIET; T_ASSERT_NOTNULL(re_string, "vasprintf");

	const char *pcreErrorStr;
	int pcreErrorOffset;
	pcre *re = pcre_compile(re_string, 0, &pcreErrorStr, &pcreErrorOffset, NULL);
	T_QUIET; T_ASSERT_NOTNULL(re, "pcre_compile");

	bool found = false;
	FILE *p = popen("/usr/local/bin/kcdata --pretty /tmp/ss", "r");
	T_QUIET; T_ASSERT_NOTNULL(p, "popen");
	while (1) {
		char *line = NULL;
		size_t linecap = 0;
		ssize_t linesize = getline(&line, &linecap, p);
		if (linesize < 0) {
			if (line)
				free(line);
			break;
		}
		int pcre_ret = pcre_exec(re, NULL, line, strlen(line), 0, 0, NULL, 0);
		if (pcre_ret == 0){
			T_LOG("line: %s", line);
			found = true;
		}
		free(line);
	}
	T_EXPECT_TRUE(found, "found the waitinfo in kcdata.py output");
	pclose(p);
	pcre_free(re);
	free(re_string);
#endif
}


// waitinfo can be NULL, but len must be non-null and point to the length of the waitinfo array.
// when the function returns, len will be set to the number of waitinfo structs found in the stackshot.
static void
find_blocking_info(void * stackshot, struct stackshot_thread_waitinfo *waitinfo, int *len)
{
	void *buf = NULL;
	uint32_t t = 0;
	uint32_t buflen = 0;
	NSError *error = nil;
	NSMutableDictionary *parsed_container = nil;
	NSArray *parsed_waitinfo = nil;

	T_QUIET; T_ASSERT_NOTNULL(len, "Length pointer shouldn't be NULL");
	int oldlen = *len;
	*len = 0;

	buf = stackshot_config_get_stackshot_buffer(stackshot);
	T_QUIET; T_ASSERT_NOTNULL(buf, "Getting stackshot buffer");
	buflen = stackshot_config_get_stackshot_size(stackshot);

	kcdata_iter_t iter = kcdata_iter(buf, buflen);

	T_QUIET; T_ASSERT_TRUE(kcdata_iter_type(iter) == KCDATA_BUFFER_BEGIN_STACKSHOT ||
			kcdata_iter_type(iter) == KCDATA_BUFFER_BEGIN_DELTA_STACKSHOT,
			"Checking start of stackshot buffer");

	iter = kcdata_iter_next(iter);
	KCDATA_ITER_FOREACH(iter)
	{
		t = kcdata_iter_type(iter);

		if (t != KCDATA_TYPE_CONTAINER_BEGIN) {
			continue;
		}

		if (kcdata_iter_container_type(iter) != STACKSHOT_KCCONTAINER_TASK) {
			continue;
		}

		parsed_container = parseKCDataContainer(&iter, &error);
		T_QUIET; T_ASSERT_TRUE(!error, "Error while parsing container: %d (%s)",
				(int)error.code, [error.domain UTF8String]);
		T_QUIET; T_ASSERT_TRUE(parsed_container && !error, "Parsing container");

		parsed_waitinfo = parsed_container[@"task_snapshots"][@"thread_waitinfo"];
		for (id elem in parsed_waitinfo) {
			/* check to see that tid matches expected idle status */
			uint8_t type = [elem[@"wait_type"] unsignedCharValue];
			if (type != kThreadWaitNone) {
				if (waitinfo && *len < oldlen) {
					struct stackshot_thread_waitinfo *curr = &waitinfo[*len];
					curr->wait_type = type;
					curr->owner     = [elem[@"owner"] unsignedLongLongValue];
					curr->waiter    = [elem[@"waiter"] unsignedLongLongValue];
					curr->context   = [elem[@"context"] unsignedLongLongValue];
				}
				(*len)++;
			}
		}
		[parsed_container release];
	}
}

/* perform various actions with a mutex in kernel memory. note that, since we aren't allowed
 * to go to user space while still holding a mutex, the lock-acquiring actions in this kernel
 * sysctl will either lock and immediately release the lock, or lock and wait until a semaphore
 * is signalled, then unlock. if called with CHECK_EXISTS, returns whether or not the sysctl
 * exist in the kernel (to determine if we're running with CONFIG_XNUPOST defined). Else,
 * returns 1. */
static int kmutex_action(int action)
{
	int ret = 0;
	if (action == KMUTEX_SYSCTL_CHECK_EXISTS) {
		ret = sysctlbyname(krwlck_ctl, NULL, NULL, NULL, 0);
		return !(ret == -1);
	}

	char * action_name = "";
	switch(action) {
		case KMUTEX_SYSCTL_ACQUIRE_WAIT:
			action_name = "lock (and wait)";
			break;
		case KMUTEX_SYSCTL_ACQUIRE_NOWAIT:
			action_name = "lock";
			break;
		case KMUTEX_SYSCTL_SIGNAL:
			action_name = "signal to holder of";
			break;
		case KMUTEX_SYSCTL_TEARDOWN:
			action_name = "tear down";
			break;
		default:
			T_ASSERT_FAIL("Somebody passed the wrong argument to kmutex_action: %d", action);
			break;
	}

	ret = sysctlbyname(kmutex_ctl, NULL, NULL, &action, sizeof(int));
	T_ASSERT_POSIX_SUCCESS(ret, "sysctl: %s kernel mutex", action_name);
	return 1;
}

static void
sysctl_kmutex_test_match(uint64_t context)
{
	int ret = 0;
	unsigned long long unslid_kmutex_address = 0;
	size_t addrsize = sizeof(unslid_kmutex_address);

	ret = sysctlbyname(kmutex_ctl, &unslid_kmutex_address, &addrsize, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "Getting unslid location of kernel mutex. Size is %llu",
			(unsigned long long)addrsize);
	T_EXPECT_EQ(context, unslid_kmutex_address,
			"Context should match unslid location of mutex in kernel memory");
}

/* We don't really care what goes into these messages, we're just sending something to a port. */
static void
msg_send_helper(mach_port_t remote_port)
{
	int ret;
        mach_msg_header_t * msg = NULL;

        ret = vm_allocate(mach_task_self(),
                            (vm_address_t *)&msg,
                            PAGE_SIZE,
                            VM_MAKE_TAG(VM_MEMORY_MACH_MSG) | TRUE);

	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "Allocating vm page %p", (void*)msg);
        msg->msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0, 0);
	msg->msgh_size = PAGE_SIZE;
        msg->msgh_remote_port = remote_port;
        msg->msgh_local_port = MACH_PORT_NULL;
        msg->msgh_voucher_port = MACH_PORT_NULL;
        ret = mach_msg(msg,
 			MACH_SEND_MSG | MACH_MSG_OPTION_NONE,
			PAGE_SIZE,
                        0,
                        MACH_PORT_NULL,
                        MACH_MSG_TIMEOUT_NONE,
                        MACH_PORT_NULL);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "Sending message to port %d", remote_port);

        vm_deallocate(mach_task_self(), (vm_address_t)msg, PAGE_SIZE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "Deallocating vm page %p", (void*)msg);
}

static void
msg_recv_helper(mach_port_t local_port)
{
	int ret = 0;
	mach_msg_size_t size = 2*PAGE_SIZE;
	mach_msg_header_t * msg = NULL;
        ret = vm_allocate(mach_task_self(),
                          (vm_address_t *)&msg,
			  size,
                          VM_MAKE_TAG(VM_MEMORY_MACH_MSG) | TRUE );
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "Allocating page %p for message", (void*)msg);

	ret = mach_msg(msg,
			MACH_RCV_MSG,
			0,
			size,
			local_port,
			MACH_MSG_TIMEOUT_NONE,
			MACH_PORT_NULL);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "Received message on port %d", local_port);
        ret = vm_deallocate(mach_task_self(), (vm_address_t)msg, PAGE_SIZE);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "Deallocating page %p", (void*)msg);
}

/* perform various actions with a rwlock in kernel memory. note that, since we aren't allowed
 * to go to user space while still holding a rwlock, the lock-acquiring actions in this kernel
 * sysctl will either lock and immediately release the lock, or lock and wait until a semaphore
 * is signalled, then unlock. if called with CHECK_EXISTS, returns whether or not the sysctl
 * exist in the kernel (to determine if we're running with CONFIG_XNUPOST defined). Else,
 * returns 1. */
static int
krwlck_action(int action)
{
	int ret = 0;
	if (action == KRWLCK_SYSCTL_CHECK_EXISTS) {
		ret = sysctlbyname(krwlck_ctl, NULL, NULL, NULL, 0);
		return !(ret == -1);
	}

	char * action_name = "";
	switch(action) {
		case KRWLCK_SYSCTL_RACQUIRE_NOWAIT:
			action_name = "shared lock";
			break;
		case KRWLCK_SYSCTL_RACQUIRE_WAIT:
			action_name = "shared lock (and wait)";
			break;
		case KRWLCK_SYSCTL_WACQUIRE_NOWAIT:
			action_name = "exclusive lock";
			break;
		case KRWLCK_SYSCTL_WACQUIRE_WAIT:
			action_name = "exclusive lock (and wait)";
			break;
		case KRWLCK_SYSCTL_SIGNAL:
			action_name = "signal to holder of";
			break;
		case KRWLCK_SYSCTL_TEARDOWN:
			action_name = "tear down";
			break;
		default:
			T_ASSERT_FAIL("Somebody passed the wrong argument to krwlck_action: %d", action);
			break;
	}

	ret = sysctlbyname(krwlck_ctl, NULL, NULL, &action, sizeof(int));
	T_ASSERT_POSIX_SUCCESS(ret, "sysctl: %s kernel rwlock", action_name);
	return 1;
}

static void
sysctl_krwlck_test_match(uint64_t context)
{
	int ret = 0;
	unsigned long long unslid_krwlck_address = 0;
	size_t addrsize = sizeof(unslid_krwlck_address);

	ret = sysctlbyname(krwlck_ctl, &unslid_krwlck_address, &addrsize, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "Getting unslid location of kernel rwlock");
	T_EXPECT_EQ(context, unslid_krwlck_address, "Context should match unslid location of rwlock in kernel memory");
}

/* "Grabbing" threads: only purpose is to grab a sync primitive and hang. */

static void *
kmutex_grabbing_thread(void * arg)
{
	(void)arg;
	kmutex_action(KMUTEX_SYSCTL_ACQUIRE_NOWAIT);
	return NULL;
}

static void *
kmutex_grab_and_wait_thread(void * arg)
{
	(void)arg;
	kmutex_action(KMUTEX_SYSCTL_ACQUIRE_WAIT);
	return NULL;
}

static void *
sem_grabbing_thread(void * arg)
{
	semaphore_t *sem = (semaphore_t *)arg;
	semaphore_wait(*sem);
	return NULL;
}

static void *
msg_blocking_thread(void * arg)
{
	(void)arg;
	msg_recv_helper(send);

	for (int i = 0; i < SENDS_TO_BLOCK; i++)
		msg_send_helper(recv); // will block on send until message is received
	return NULL;
}

static void *
ulock_blocking_thread(void * arg)
{
	os_unfair_lock_t oul = (os_unfair_lock_t)arg;
	os_unfair_lock_lock(oul);
	os_unfair_lock_unlock(oul);
	return NULL;
}

// acquires a kernel rwlock for writing, and then waits on a kernel semaphore.
static void *
krwlck_write_waiting_thread(void * arg)
{
	(void)arg;
	krwlck_action(KRWLCK_SYSCTL_WACQUIRE_WAIT);
	return NULL;
}

// attempts to acquire a kernel rwlock for reading, and doesn't wait on a semaphore afterwards.
static void *
krwlck_read_grabbing_thread(void * arg)
{
	(void)arg;
	krwlck_action(KRWLCK_SYSCTL_RACQUIRE_NOWAIT);
	return NULL;
}

static void *
pthread_mutex_blocking_thread(void * arg)
{
	pthread_mutex_t *mtx = (pthread_mutex_t *)arg;
	pthread_mutex_lock(mtx);
	pthread_mutex_unlock(mtx);
	return NULL;
}

static void *
pthread_rwlck_blocking_thread(void * arg)
{
	pthread_rwlock_t *rwlck = (pthread_rwlock_t *)arg;
	pthread_rwlock_rdlock(rwlck);
	pthread_rwlock_unlock(rwlck);
	return NULL;
}

static void *
pthread_cond_blocking_thread(void * arg)
{
	pthread_mutex_t mtx  = PTHREAD_MUTEX_INITIALIZER;
	pthread_cond_t *cond = (pthread_cond_t *)arg;
	pthread_cond_wait(cond, &mtx);
	pthread_mutex_unlock(&mtx);
	return NULL;
}

static void *
waitpid_blocking_thread(void * arg)
{
	pid_t pid = (pid_t)arg;

	int ret = waitpid(pid, NULL, 0);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "Reaping child.");
	return NULL;
}

/*
 * Uses a debug sysctl to initialize a kernel mutex.
 *
 * The 'waiting' thread grabs this kernel mutex, and immediately waits on a kernel semaphore.
 * The 'grabbing' thread just attempts to lock the kernel mutex.
 * When the semaphore is signalled, the 'waiting' thread will unlock the kernel mutex,
 * giving the opportunity for the 'grabbing' thread to lock it and then immediately unlock it.
 * This allows us to create a situation in the kernel where we know a thread to be blocked
 * on a kernel mutex.
 */
static void
test_kmutex_blocking(void)
{
	int ret = 0;
	int len = 2;
	struct stackshot_thread_waitinfo waitinfo[2] = { { 0 }, { 0 } };
	uint64_t thread_id = 0;
	pthread_t grabbing, waiting;

	T_LOG("Starting %s", __FUNCTION__);
	ret = pthread_create(&waiting, NULL, kmutex_grab_and_wait_thread, NULL); // thread will block until we signal it
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "Spawning grab and wait thread");
	sleep(1); // give time for thread to block
	ret = pthread_create(&grabbing, NULL, kmutex_grabbing_thread, NULL); // thread should immediately block
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "Spawning waiting thread");
	sleep(3); // give (lots of) time for thread to give up spinning on lock

	void * stackshot = take_stackshot(STACKSHOT_THREAD_WAITINFO, 0);

	ret = pthread_threadid_np(waiting, &thread_id); // this is the thread that currently holds the kernel mutex
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "Getting integer value of thread id");

	check_python(stackshot, "thread \\d+: semaphore port \\w+ with unknown owner");

	find_blocking_info(stackshot, (struct stackshot_thread_waitinfo *)&waitinfo, &len);

	T_EXPECT_EQ(len, 2, "There should only be two blocking threads");
	for (int i = 0; i < len; i++) {
		struct stackshot_thread_waitinfo *curr = &waitinfo[i];
		if (curr->wait_type == kThreadWaitSemaphore)
			continue;
		T_EXPECT_EQ(curr->wait_type, kThreadWaitKernelMutex, "Wait type should match expected KernelMutex value");
		T_EXPECT_EQ(curr->owner, thread_id, "Thread ID of blocking thread should match 'owner' field in stackshot");
		sysctl_kmutex_test_match(curr->context);

		check_python(stackshot, "thread \\d+: kernel mutex %llx owned by thread %lld", curr->context, thread_id);
	}

	kmutex_action(KMUTEX_SYSCTL_SIGNAL); // waiting thread should now unblock.
	ret = pthread_join(waiting, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "Joining on waiting thread");
	ret = pthread_join(grabbing, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "Joining on grabber thread");
	kmutex_action(KMUTEX_SYSCTL_TEARDOWN);
	stackshot_config_dealloc(stackshot);
}

/* Initialize a userspace semaphore, and spawn a thread to block on it. */
static void
test_semaphore_blocking(void)
{
	int ret = 0;
	semaphore_t sem;
	struct stackshot_thread_waitinfo waitinfo = { 0 };
	int len = 1;
	uint64_t pid = 0;

	T_LOG("Starting %s", __FUNCTION__);
	ret = semaphore_create(mach_task_self(), &sem, SYNC_POLICY_FIFO, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "Creating semaphore");
	pthread_t tid;
	ret = pthread_create(&tid, NULL, sem_grabbing_thread, (void*)&sem); // thread should immediately block
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "Creating semaphore grabbing thread");

	sleep(1); // give time for thread to block

	void * stackshot = take_stackshot(STACKSHOT_THREAD_WAITINFO, 0);
	find_blocking_info(stackshot, (struct stackshot_thread_waitinfo *)&waitinfo, &len);
	T_EXPECT_EQ(len, 1, "Only one blocking thread should exist");
	T_EXPECT_EQ(waitinfo.wait_type, kThreadWaitSemaphore, "Wait type should match expected Semaphore value");

	pid = (uint64_t)getpid();
	T_EXPECT_EQ(waitinfo.owner, pid, "Owner value should match process ID");

	check_python(stackshot, "thread \\d+: semaphore port \\w+ owned by pid %d", (int)pid);

	ret = semaphore_signal(sem);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "Signalling semaphore");
	ret = pthread_join(tid, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "Joining on grabber thread");
	ret = semaphore_destroy(mach_task_self(), sem);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "Destroying semaphore");
	stackshot_config_dealloc(stackshot);
}

/* Spawn a process to send a message to, and block while both sending and receiving in different contexts. */
static void
test_mach_msg_blocking(void)
{
	int ret = 0;
	pthread_t tid;
	void *stackshot = NULL;
	struct stackshot_thread_waitinfo waitinfo = { 0 };
	int len = 1;

	T_LOG("Starting %s", __FUNCTION__);
	ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &send);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "Allocating send port");
	ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &recv);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "Allocating recv port");
	ret = mach_port_insert_right(mach_task_self(), send, send, MACH_MSG_TYPE_MAKE_SEND);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "Getting send right to send port");
	ret = mach_port_insert_right(mach_task_self(), recv, recv, MACH_MSG_TYPE_MAKE_SEND);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "Getting send right to recv port");

	ret = pthread_create(&tid, NULL, msg_blocking_thread, (void*)&send); // thread should block on recv soon
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "Creating message blocking thread");

	sleep(1); // give time for thread to block
	stackshot = take_stackshot(STACKSHOT_THREAD_WAITINFO, 0);
	find_blocking_info(stackshot, (struct stackshot_thread_waitinfo *)&waitinfo, &len);

	T_EXPECT_EQ(len, 1, "Only one blocking thread should exist");
	T_EXPECT_EQ(waitinfo.wait_type, kThreadWaitPortReceive, "Wait type should match expected PortReceive value");

	check_python(stackshot, "thread \\d+: mach_msg receive on port \\w+ name %llx", (long long)send);

	stackshot_config_dealloc(stackshot);

	msg_send_helper(send); // ping! msg_blocking_thread will now try to send us stuff, and block until we receive.

	sleep(1); // give time for thread to block
	stackshot = take_stackshot(STACKSHOT_THREAD_WAITINFO, 0);
	find_blocking_info(stackshot, (struct stackshot_thread_waitinfo *)&waitinfo, &len);
	T_EXPECT_EQ(len, 1, "Only one blocking thread should exist");
	T_EXPECT_EQ(waitinfo.wait_type, kThreadWaitPortSend, "Wait type should match expected PortSend value");

	check_python(stackshot, "thread \\d+: mach_msg send on port \\w+ owned by pid %d", (int)getpid());

	stackshot_config_dealloc(stackshot);

	msg_recv_helper(recv); // thread should block until we receive one of its messages
	ret = pthread_join(tid, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "Joining on blocking thread");
}

static void
test_ulock_blocking(void)
{
	int ret = 0;
	void *stackshot = NULL;
	uint64_t thread_id = 0;
	pthread_t tid;
	struct os_unfair_lock_s ouls = OS_UNFAIR_LOCK_INIT;
	os_unfair_lock_t oul = &ouls;
	struct stackshot_thread_waitinfo waitinfo = { 0 };
	int len = 1;

	T_LOG("Starting %s", __FUNCTION__);
	os_unfair_lock_lock(oul);
	ret = pthread_create(&tid, NULL, ulock_blocking_thread, (void*)oul);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "Creating ulock blocking thread");
	sleep(3); // give time for thread to spawn, fall back to kernel for contention, and block

	stackshot = take_stackshot(STACKSHOT_THREAD_WAITINFO, 0);

	find_blocking_info(stackshot, (struct stackshot_thread_waitinfo *)&waitinfo, &len);
	T_EXPECT_EQ(len, 1, "Only one blocking thread should exist");
	T_EXPECT_EQ(waitinfo.wait_type, kThreadWaitUserLock, "Wait type should match expected UserLock value");

	os_unfair_lock_unlock(oul);
	ret = pthread_join(tid, NULL); // wait for thread to unblock and exit
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "Joining on blocking thread");

	ret = pthread_threadid_np(NULL, &thread_id); // this thread is the "owner" of the ulock
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "Getting integer value of thread id");
	T_EXPECT_EQ(waitinfo.owner, thread_id, "Thread ID of blocking thread should match 'owner' field in stackshot");

	check_python(stackshot, "thread \\d+: unfair lock \\w+ owned by thread %lld", thread_id);
	stackshot_config_dealloc(stackshot);
	return;
}

static void
test_krwlock_blocking(void)
{
	int ret = 0;
	void *stackshot = NULL;
	uint64_t thread_id = 0;
	pthread_t waiting, grabbing;
	int len = 2;
	struct stackshot_thread_waitinfo waitinfo[2] = { { 0 }, { 0 } };

	T_LOG("Starting %s", __FUNCTION__);
	// this thread should spawn, acquire a kernel rwlock for write, and then wait on a semaphore
	ret = pthread_create(&waiting, NULL, krwlck_write_waiting_thread, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "Creating krwlck write waiting thread");
	sleep(1); // give time for thread to block
	// this thread should spawn and try to acquire the same kernel rwlock for read, but block
	ret = pthread_create(&grabbing, NULL, krwlck_read_grabbing_thread, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "Creating krwlck read grabbing thread");
	sleep(1); // give time for thread to block

	stackshot = take_stackshot(STACKSHOT_THREAD_WAITINFO, 0);

	check_python(stackshot, "thread \\d+: semaphore port \\w+ with unknown owner");

	find_blocking_info(stackshot, (struct stackshot_thread_waitinfo *)&waitinfo, &len);

	T_EXPECT_EQ(len, 2, "There should only be two blocking threads");
	for (int i = 0; i < len; i++) {
		struct stackshot_thread_waitinfo *curr = &waitinfo[i];
		if (curr->wait_type == kThreadWaitSemaphore)
			continue;
		T_EXPECT_EQ(curr->wait_type, kThreadWaitKernelRWLockRead, "Wait type should match expected KRWLockRead value");
		sysctl_krwlck_test_match(curr->context);

		check_python(stackshot, "thread \\d+: krwlock %llx for reading", curr->context);

#if KRWLCK_STORES_EXCL_OWNER /* A future planned enhancement */
		ret = pthread_threadid_np(waiting, &thread_id); // this is the thread that currently holds the kernel mutex
		T_QUIET; T_ASSERT_POSIX_ZERO(ret, "Getting integer value of thread id");
		T_EXPECT_EQ(curr->owner, thread_id, "Thread ID of blocking thread should match 'owner' field in stackshot");
#else
		(void)thread_id; // suppress compiler warning about unused variable
#endif /* RWLCK_STORES_EXCL_OWNER */
	}

	krwlck_action(KRWLCK_SYSCTL_SIGNAL); // pthread should now unblock & finish
	ret = pthread_join(waiting, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "Joining on waiting thread");
	ret = pthread_join(grabbing, NULL);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "Joining on grabbing thread");
	krwlck_action(KRWLCK_SYSCTL_TEARDOWN);
	stackshot_config_dealloc(stackshot);
}


static void
test_pthread_mutex_blocking(void)
{
	int ret = 0;
	void *stackshot = NULL;
	uint64_t thread_id = 0;
	pthread_t tid;
	struct stackshot_thread_waitinfo waitinfo = { 0 };
	pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
	int len = 1;

	T_LOG("Starting %s", __FUNCTION__);

	ret = pthread_threadid_np(NULL, &thread_id); // this thread is the "owner" of the mutex
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "Getting integer value of thread id");

	pthread_mutex_lock(&mtx);
	ret = pthread_create(&tid, NULL, pthread_mutex_blocking_thread, (void*)&mtx);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "Creating pthread mutex blocking thread");
	sleep(2); // give time for thread to block

	stackshot = take_stackshot(STACKSHOT_THREAD_WAITINFO, 0);

	check_python(stackshot, "thread \\d+: pthread mutex %llx owned by thread %lld", &mtx, thread_id);

	find_blocking_info(stackshot, (struct stackshot_thread_waitinfo *)&waitinfo, &len);
	T_EXPECT_EQ(len, 1, "Only one blocking thread should exist");
	T_EXPECT_EQ(waitinfo.wait_type, kThreadWaitPThreadMutex,
			"Wait type should match expected PThreadMutex value");
	stackshot_config_dealloc(stackshot);

	pthread_mutex_unlock(&mtx);
	ret = pthread_join(tid, NULL); // wait for thread to unblock and exit


	T_EXPECT_EQ(waitinfo.owner, thread_id,
			"Thread ID of blocking thread should match 'owner' field in stackshot");
	T_EXPECT_EQ(waitinfo.context, (uint64_t)&mtx,
			"Userspace address of mutex should match 'context' field in stackshot");
}

static void
test_pthread_rwlck_blocking(void)
{
	int ret = 0;
	void *stackshot = NULL;
	pthread_t tid;
	struct stackshot_thread_waitinfo waitinfo = { 0 };
	pthread_rwlock_t rwlck = PTHREAD_RWLOCK_INITIALIZER;
	int len = 1;

	T_LOG("Starting %s", __FUNCTION__);
	pthread_rwlock_wrlock(&rwlck);
	ret = pthread_create(&tid, NULL, pthread_rwlck_blocking_thread, (void*)&rwlck);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "Creating pthread rwlck blocking thread");
	sleep(2);

	stackshot = take_stackshot(STACKSHOT_THREAD_WAITINFO, 0);

	check_python(stackshot, "thread \\d+: pthread rwlock %llx for reading", (long long)&rwlck);

	find_blocking_info(stackshot, (struct stackshot_thread_waitinfo *)&waitinfo, &len);
	T_EXPECT_EQ(len, 1, "Only one blocking thread should exist");
	T_EXPECT_EQ(waitinfo.wait_type, kThreadWaitPThreadRWLockRead,
			"Wait type should match expected PThreadRWLockRead value");
	stackshot_config_dealloc(stackshot);

	pthread_rwlock_unlock(&rwlck);
	ret = pthread_join(tid, NULL); // wait for thread to unblock and exit
	T_EXPECT_EQ(waitinfo.context, (uint64_t)&rwlck,
			"Userspace address of rwlck should match 'context' field in stackshot");
}



static void
test_pthread_cond_blocking(void)
{
	int ret = 0;
	void *stackshot = NULL;
	pthread_t tid;
	pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
	struct stackshot_thread_waitinfo waitinfo = { 0 };
	int len = 1;

	T_LOG("Starting %s", __FUNCTION__);
	ret = pthread_create(&tid, NULL, pthread_cond_blocking_thread, (void*)&cond);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, "Creating pthread condvar blocking thread");
	sleep(2);

	stackshot = take_stackshot(STACKSHOT_THREAD_WAITINFO, 0);

	check_python(stackshot, "thread \\d+: pthread condvar %llx", (long long)&cond);

	find_blocking_info(stackshot, (struct stackshot_thread_waitinfo *)&waitinfo, &len);
	T_EXPECT_EQ(len, 1, "Only one blocking thread should exist");
	T_EXPECT_EQ(waitinfo.wait_type, kThreadWaitPThreadCondVar,
			"Wait type should match expected PThreadCondVar value");
	stackshot_config_dealloc(stackshot);

	pthread_cond_signal(&cond);
	ret = pthread_join(tid, NULL); // wait for thread to unblock and exit
	T_EXPECT_EQ(waitinfo.context, (uint64_t)&cond,
			"Userspace address of condvar should match 'context' field in stackshot");
	pthread_cond_destroy(&cond);
}

static void
test_waitpid_blocking(void)
{
	int ret = 0;
	pid_t pid = 0;
	void *stackshot = NULL;
	struct stackshot_thread_waitinfo waitinfo = { 0 };
	int len = 1;
	pthread_t tid;

	T_LOG("Starting %s", __FUNCTION__);
	if ((pid = fork()) == 0) {
		pause();
	} else {
		T_ASSERT_POSIX_SUCCESS(ret, "Running in parent. Child pid is %d", pid);

		sleep(1); // allow enough time for child to run & sleep
		ret = pthread_create(&tid, NULL, waitpid_blocking_thread, (void*)pid);
		T_QUIET; T_ASSERT_POSIX_ZERO(ret, "Creating waitpid blocking thread");

		sleep(1); // allow enough time for reaping thread to waitpid & block
		stackshot = take_stackshot(STACKSHOT_THREAD_WAITINFO, 0);
		find_blocking_info(stackshot, (struct stackshot_thread_waitinfo *)&waitinfo, &len);
		T_EXPECT_EQ(len, 1, "Only one blocking thread should exist");
		T_EXPECT_EQ(waitinfo.wait_type, kThreadWaitOnProcess,
				"Wait type should match expected WaitOnProcess value");

		check_python(stackshot, "thread \\d+: waitpid, for pid %d", (int)pid);

		stackshot_config_dealloc(stackshot);
		T_EXPECT_EQ(waitinfo.owner, pid,
			"Process ID of blocking process should match 'owner' field in stackshot");

		ret = kill(pid, SIGUSR1); // wake up child so waitpid thread can reap it & exit
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "Send SIGUSR1 to child process");
		ret = pthread_join(tid, NULL);
		T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, "Join on waitpid thread");
	}
}

/*
 *
 * Test declarations
 *
 */

T_DECL(stackshot_block_owner_klocks, "tests stackshot block owner for kernel locks") {
	/* check to see if kmutex sysctl exists before running kmutex test */
	if (kmutex_action(KMUTEX_SYSCTL_CHECK_EXISTS))
		test_kmutex_blocking();
	/* check to see if krwlck sysctl exists before running krwlck test */
	if (krwlck_action(KRWLCK_SYSCTL_CHECK_EXISTS))
		test_krwlock_blocking();
	test_ulock_blocking();
}

T_DECL(stackshot_block_owner_pthread_mutex, "tests stackshot block owner: pthread mutex") {
	test_pthread_mutex_blocking();
}

T_DECL(stackshot_block_owner_pthread_rwlck, "tests stackshot block owner: pthread rw locks") {
	test_pthread_rwlck_blocking();
}

T_DECL(stackshot_block_owner_pthread_condvar, "tests stackshot block owner: pthread condvar") {
	test_pthread_cond_blocking();
}

T_DECL(stackshot_block_owner_semaphore, "tests stackshot block owner: semaphore") {
	test_semaphore_blocking();
}

T_DECL(stackshot_block_owner_mach_msg, "tests stackshot block owner: mach messaging") {
	test_mach_msg_blocking();
}

T_DECL(stackshot_block_owner_waitpid, "tests stackshot block owner: waitpid") {
	test_waitpid_blocking();
}
