/*
 * mach eventlink: Tests mach eventlink kernel synchronization primitive.
 */

#include <darwintest.h>
#include <darwintest_multiprocess.h>

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
#include <spawn.h>
#include <spawn_private.h>
#include <mach/mach_eventlink.h>

T_GLOBAL_META(T_META_NAMESPACE("xnu.mach_eventlink"),
    T_META_RUN_CONCURRENTLY(true));

static kern_return_t
test_eventlink_create(mach_port_t *port_pair)
{
	kern_return_t kr;

	kr = mach_eventlink_create(mach_task_self(), MELC_OPTION_NO_COPYIN, port_pair);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_create");

	return kr;
}

static pthread_t
thread_create_for_test(void * (*function)(void *), void *arg)
{
	pthread_t pthread;
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_create(&pthread, &attr, function, arg);

	T_LOG("pthread created\n");
	return pthread;
}

static void *
while1loop(void *arg)
{
	arg = NULL;
	while (1) {
		;
	}
	return NULL;
}

static void *
test_eventlink_wait_with_timeout(void *arg)
{
	kern_return_t kr;
	mach_port_t eventlink_port = (mach_port_t) (uintptr_t)arg;
	mach_port_t self = mach_thread_self();
	uint64_t ticks = mach_absolute_time();
	uint64_t count = 1;

	/* Associate thread with eventlink port */
	kr = mach_eventlink_associate(eventlink_port, self, 0, 0, 0, 0, MELA_OPTION_NONE);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_associate");

	/* Wait on the eventlink with timeout */
	kr = mach_eventlink_wait_until(eventlink_port, &count, MELSW_OPTION_NONE,
	    KERN_CLOCK_MACH_ABSOLUTE_TIME, ticks + 5000);

	T_EXPECT_MACH_ERROR(kr, KERN_OPERATION_TIMED_OUT, "mach_eventlink_wait_until returned expected error");
	T_EXPECT_EQ(count, (uint64_t)0, "mach_eventlink_wait_until returned correct count value");

	return NULL;
}

static void *
test_eventlink_wait_no_wait(void *arg)
{
	kern_return_t kr;
	mach_port_t eventlink_port = (mach_port_t) (uintptr_t)arg;
	mach_port_t self = mach_thread_self();
	uint64_t count = 1;

	/* Associate thread with eventlink port */
	kr = mach_eventlink_associate(eventlink_port, self, 0, 0, 0, 0, MELA_OPTION_NONE);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_associate");

	/* Wait on the eventlink */
	kr = mach_eventlink_wait_until(eventlink_port, &count, MELSW_OPTION_NO_WAIT,
	    KERN_CLOCK_MACH_ABSOLUTE_TIME, 0);

	T_EXPECT_MACH_ERROR(kr, KERN_OPERATION_TIMED_OUT, "mach_eventlink_wait_until returned expected error");
	T_EXPECT_EQ(count, (uint64_t)0, "mach_eventlink_wait_until returned correct count value");

	return NULL;
}

static void *
test_eventlink_wait_destroy(void *arg)
{
	kern_return_t kr;
	mach_port_t eventlink_port = (mach_port_t) (uintptr_t)arg;
	mach_port_t self = mach_thread_self();
	uint64_t count = 1;

	/* Associate thread with eventlink port */
	kr = mach_eventlink_associate(eventlink_port, self, 0, 0, 0, 0, MELA_OPTION_NONE);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_associate");

	/* Wait on the eventlink */
	kr = mach_eventlink_wait_until(eventlink_port, &count, MELSW_OPTION_NONE,
	    KERN_CLOCK_MACH_ABSOLUTE_TIME, 0);

	T_EXPECT_MACH_ERROR(kr, KERN_TERMINATED, "mach_eventlink_wait_until returned expected error");

	return NULL;
}

static void *
test_eventlink_wait_for_signal(void *arg)
{
	kern_return_t kr;
	mach_port_t eventlink_port = (mach_port_t) (uintptr_t)arg;
	mach_port_t self = mach_thread_self();
	uint64_t count = 0;

	/* Associate thread with eventlink port */
	kr = mach_eventlink_associate(eventlink_port, self, 0, 0, 0, 0, MELA_OPTION_NONE);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_associate");

	/* Wait on the eventlink */
	kr = mach_eventlink_wait_until(eventlink_port, &count, MELSW_OPTION_NONE,
	    KERN_CLOCK_MACH_ABSOLUTE_TIME, 0);

	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_wait_until");
	T_EXPECT_EQ(count, (uint64_t)1, "mach_eventlink_wait_until returned correct count value");

	return NULL;
}

static void *
test_eventlink_wait_then_signal(void *arg)
{
	kern_return_t kr;
	mach_port_t eventlink_port = (mach_port_t) (uintptr_t)arg;
	mach_port_t self = mach_thread_self();
	uint64_t count = 0;

	/* Associate thread with eventlink port */
	kr = mach_eventlink_associate(eventlink_port, self, 0, 0, 0, 0, MELA_OPTION_NONE);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_associate");

	/* Wait on the eventlink */
	kr = mach_eventlink_wait_until(eventlink_port, &count, MELSW_OPTION_NONE,
	    KERN_CLOCK_MACH_ABSOLUTE_TIME, 0);

	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_wait_until");
	T_EXPECT_EQ(count, (uint64_t)1, "mach_eventlink_wait_until returned correct count value");

	/* Signal the eventlink to wakeup other side */
	kr = mach_eventlink_signal(eventlink_port, 0);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_signal");

	return NULL;
}

static void *
test_eventlink_wait_then_wait_signal_with_no_wait(void *arg)
{
	kern_return_t kr;
	mach_port_t eventlink_port = (mach_port_t) (uintptr_t)arg;
	mach_port_t self = mach_thread_self();
	uint64_t count = 0;

	/* Associate thread with eventlink port */
	kr = mach_eventlink_associate(eventlink_port, self, 0, 0, 0, 0, MELA_OPTION_NONE);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_associate");

	/* Wait on the eventlink */
	kr = mach_eventlink_wait_until(eventlink_port, &count, MELSW_OPTION_NONE,
	    KERN_CLOCK_MACH_ABSOLUTE_TIME, 0);

	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_wait_until");
	T_EXPECT_EQ(count, (uint64_t)1, "mach_eventlink_wait_until returned correct count value");

	/* Signal wait the eventlink */
	kr = mach_eventlink_signal_wait_until(eventlink_port, &count, 0, MELSW_OPTION_NO_WAIT,
	    KERN_CLOCK_MACH_ABSOLUTE_TIME, 0);

	T_EXPECT_MACH_ERROR(kr, KERN_OPERATION_TIMED_OUT, "mach_eventlink_wait_until returned expected error");
	T_EXPECT_EQ(count, (uint64_t)1, "mach_eventlink_wait_until returned correct count value");

	return NULL;
}

static void *
test_eventlink_wait_then_wait_signal_with_prepost(void *arg)
{
	kern_return_t kr;
	mach_port_t eventlink_port = (mach_port_t) (uintptr_t)arg;
	mach_port_t self = mach_thread_self();
	uint64_t count = 0;

	/* Associate thread with eventlink port */
	kr = mach_eventlink_associate(eventlink_port, self, 0, 0, 0, 0, MELA_OPTION_NONE);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_associate");

	/* Wait on the eventlink */
	kr = mach_eventlink_wait_until(eventlink_port, &count, MELSW_OPTION_NONE,
	    KERN_CLOCK_MACH_ABSOLUTE_TIME, 0);

	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_wait_until");
	T_EXPECT_EQ(count, (uint64_t)1, "mach_eventlink_wait_until returned correct count value");

	/* Signal wait the eventlink with stale counter value */
	count = 0;
	kr = mach_eventlink_signal_wait_until(eventlink_port, &count, 0, MELSW_OPTION_NONE,
	    KERN_CLOCK_MACH_ABSOLUTE_TIME, 0);

	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_signal_wait_until");
	T_EXPECT_EQ(count, (uint64_t)1, "mach_eventlink_wait_until returned correct count value");

	return NULL;
}

static void *
test_eventlink_wait_then_signal_loop(void *arg)
{
	kern_return_t kr;
	mach_port_t eventlink_port = (mach_port_t) (uintptr_t)arg;
	mach_port_t self = mach_thread_self();
	uint64_t count = 0;
	int i;

	/* Associate thread with eventlink port */
	kr = mach_eventlink_associate(eventlink_port, self, 0, 0, 0, 0, MELA_OPTION_NONE);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_associate");

	/* Wait on the eventlink */
	kr = mach_eventlink_wait_until(eventlink_port, &count, MELSW_OPTION_NONE,
	    KERN_CLOCK_MACH_ABSOLUTE_TIME, 0);

	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_wait_until");
	T_EXPECT_EQ(count, (uint64_t)1, "mach_eventlink_wait_until returned correct count value");

	for (i = 1; i < 100; i++) {
		/* Signal wait the eventlink */
		kr = mach_eventlink_signal_wait_until(eventlink_port, &count, 0, MELSW_OPTION_NONE,
		    KERN_CLOCK_MACH_ABSOLUTE_TIME, 0);

		T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_signal_wait_until");
		T_EXPECT_EQ(count, (uint64_t)(i + 1), "mach_eventlink_wait_until returned correct count value");
	}

	/* Signal the eventlink to wakeup other side */
	kr = mach_eventlink_signal(eventlink_port, 0);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_signal");

	return NULL;
}

/*
 * Test 1: Create ipc eventlink kernel object.
 *
 * Calls eventlink creates which returns a pair of eventlink port objects.
 */
T_DECL(test_eventlink_create, "eventlink create test", T_META_ASROOT(YES))
{
	kern_return_t kr;
	mach_port_t port_pair[2];

	kr = test_eventlink_create(port_pair);
	if (kr != KERN_SUCCESS) {
		return;
	}

	mach_port_deallocate(mach_task_self(), port_pair[0]);
	mach_port_deallocate(mach_task_self(), port_pair[1]);
}

/*
 * Test 2: Create ipc eventlink kernel object and call eventlink destroy
 *
 * Calls eventlink creates which returns a pair of eventlink port objects.
 * Calls eventlink destroy on eventlink port pair.
 */
T_DECL(test_eventlink_destroy, "eventlink destroy test", T_META_ASROOT(YES))
{
	kern_return_t kr;
	mach_port_t port_pair[2];

	kr = test_eventlink_create(port_pair);
	if (kr != KERN_SUCCESS) {
		return;
	}

	kr = mach_eventlink_destroy(port_pair[0]);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_destroy");
	kr = mach_eventlink_destroy(port_pair[1]);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_destroy");
}

/*
 * Test 3: Associate threads to eventlink object.
 *
 * Create eventlink object pair and associate threads to each side and then
 * disassociate threads and check for error conditions.
 */
T_DECL(test_eventlink_associate, "eventlink associate test", T_META_ASROOT(YES))
{
	kern_return_t kr;
	mach_port_t port_pair[2];
	mach_port_t self = mach_thread_self();
	mach_port_t other_thread = MACH_PORT_NULL;
	pthread_t pthread;

	/* eventlink associate to NULL eventlink object */
	kr = mach_eventlink_associate(MACH_PORT_NULL, self, 0, 0, 0, 0, MELA_OPTION_NONE);
	T_EXPECT_MACH_ERROR(kr, MACH_SEND_INVALID_DEST, "mach_eventlink_associate with null eventlink returned expected error");

	/* eventlink disassociate to NULL eventlink object */
	kr = mach_eventlink_disassociate(MACH_PORT_NULL, MELD_OPTION_NONE);
	T_EXPECT_MACH_ERROR(kr, MACH_SEND_INVALID_DEST, "mach_eventlink_disassociate with null eventlink returned expected error");

	/* Create an eventlink and associate threads to it */
	kr = test_eventlink_create(port_pair);
	if (kr != KERN_SUCCESS) {
		return;
	}

	pthread = thread_create_for_test(while1loop, NULL);
	other_thread = pthread_mach_thread_np(pthread);

	for (int i = 0; i < 3; i++) {
		/* Associate thread to eventlink objects */
		kr = mach_eventlink_associate(port_pair[0], self, 0, 0, 0, 0, MELA_OPTION_NONE);
		T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_associate for object 1");

		kr = mach_eventlink_associate(port_pair[1], other_thread, 0, 0, 0, 0, MELA_OPTION_NONE);
		T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_associate for object 2");

		/* Try to associate again with diff threads, expect failure */
		kr = mach_eventlink_associate(port_pair[0], other_thread, 0, 0, 0, 0, MELA_OPTION_NONE);
		T_EXPECT_MACH_ERROR(kr, KERN_NAME_EXISTS, "mach_eventlink_associate for associated "
		    "objects returned expected error");

		kr = mach_eventlink_associate(port_pair[1], self, 0, 0, 0, 0, MELA_OPTION_NONE);
		T_EXPECT_MACH_ERROR(kr, KERN_NAME_EXISTS, "mach_eventlink_associate for associated "
		    "objects return expected error");

		/* Try to disassociate the threads */
		kr = mach_eventlink_disassociate(port_pair[0], MELD_OPTION_NONE);
		T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_disassociate for object 1");

		kr = mach_eventlink_disassociate(port_pair[1], MELD_OPTION_NONE);
		T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_disassociate for object 2");

		/* Try to disassociate the threads again, expect failure */
		kr = mach_eventlink_disassociate(port_pair[0], MELD_OPTION_NONE);
		T_EXPECT_MACH_ERROR(kr, KERN_INVALID_ARGUMENT, "mach_eventlink_disassociate for "
		    "disassociated objects returned expected error");

		kr = mach_eventlink_disassociate(port_pair[1], MELD_OPTION_NONE);
		T_EXPECT_MACH_ERROR(kr, KERN_INVALID_ARGUMENT, "mach_eventlink_disassociate for "
		    "disassociated objects returned expected error");
	}

	kr = mach_eventlink_destroy(port_pair[0]);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_destroy");

	/* Try disassociate on other end of destoryed eventlink pair */
	kr = mach_eventlink_disassociate(port_pair[1], MELD_OPTION_NONE);
	T_EXPECT_MACH_ERROR(kr, KERN_TERMINATED, "mach_eventlink_disassociate for "
	    "terminated object returned expected error");

	kr = mach_eventlink_destroy(port_pair[1]);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_destroy");
}

/*
 * Test 4: Test eventlink wait with timeout.
 *
 * Create an eventlink object, associate threads and test eventlink wait with timeout.
 */
T_DECL(test_eventlink_wait_timeout, "eventlink wait timeout test", T_META_ASROOT(YES))
{
	kern_return_t kr;
	mach_port_t port_pair[2];
	pthread_t pthread;

	/* Create an eventlink and associate threads to it */
	kr = test_eventlink_create(port_pair);
	if (kr != KERN_SUCCESS) {
		return;
	}

	pthread = thread_create_for_test(test_eventlink_wait_with_timeout, (void *)(uintptr_t)port_pair[0]);
	sleep(10);

	/* destroy the eventlink object, the wake status of thread will check if the test passsed or failed */
	mach_port_deallocate(mach_task_self(), port_pair[0]);
	mach_port_deallocate(mach_task_self(), port_pair[1]);

	pthread_join(pthread, NULL);
}

/*
 * Test 5: Test eventlink wait with no wait.
 *
 * Create an eventlink object, associate threads and test eventlink wait with no wait flag.
 */
T_DECL(test_eventlink_wait_no_wait, "eventlink wait no wait test", T_META_ASROOT(YES))
{
	kern_return_t kr;
	mach_port_t port_pair[2];
	pthread_t pthread;

	/* Create an eventlink and associate threads to it */
	kr = test_eventlink_create(port_pair);
	if (kr != KERN_SUCCESS) {
		return;
	}

	pthread = thread_create_for_test(test_eventlink_wait_no_wait, (void *)(uintptr_t)port_pair[0]);
	pthread_join(pthread, NULL);

	mach_port_deallocate(mach_task_self(), port_pair[0]);
	mach_port_deallocate(mach_task_self(), port_pair[1]);
}

/*
 * Test 6: Test eventlink wait and destroy.
 *
 * Create an eventlink object, associate threads and destroy the port.
 */
T_DECL(test_eventlink_wait_and_destroy, "eventlink wait and destroy", T_META_ASROOT(YES))
{
	kern_return_t kr;
	mach_port_t port_pair[2];
	pthread_t pthread;

	/* Create an eventlink and associate threads to it */
	kr = test_eventlink_create(port_pair);
	if (kr != KERN_SUCCESS) {
		return;
	}

	pthread = thread_create_for_test(test_eventlink_wait_destroy, (void *)(uintptr_t)port_pair[0]);

	sleep(5);

	/* Increase the send right count for port before destroy to make sure no sender does not fire on destroy */
	kr = mach_port_mod_refs(mach_task_self(), port_pair[0], MACH_PORT_RIGHT_SEND, 2);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_mod_refs");

	/* Destroy the port for thread to wakeup */
	kr = mach_eventlink_destroy(port_pair[0]);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_destroy");

	pthread_join(pthread, NULL);
	mach_port_deallocate(mach_task_self(), port_pair[1]);
}


/*
 * Test 7: Test eventlink wait and destroy remote side.
 *
 * Create an eventlink object, associate threads, wait and destroy the remote eventlink port.
 */
T_DECL(test_eventlink_wait_and_destroy_remote, "eventlink wait and remote destroy", T_META_ASROOT(YES))
{
	kern_return_t kr;
	mach_port_t port_pair[2];
	pthread_t pthread;

	/* Create an eventlink and associate threads to it */
	kr = test_eventlink_create(port_pair);
	if (kr != KERN_SUCCESS) {
		return;
	}

	pthread = thread_create_for_test(test_eventlink_wait_destroy, (void *)(uintptr_t)port_pair[0]);

	sleep(5);

	/* Increase the send right count for port before destroy to make sure no sender does not fire on destroy */
	kr = mach_port_mod_refs(mach_task_self(), port_pair[1], MACH_PORT_RIGHT_SEND, 2);
	T_ASSERT_MACH_SUCCESS(kr, "mach_port_mod_refs");

	/* Destroy the port for thread to wakeup */
	kr = mach_eventlink_destroy(port_pair[1]);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_destroy");

	pthread_join(pthread, NULL);
	mach_port_deallocate(mach_task_self(), port_pair[0]);
}

/*
 * Test 8: Test eventlink wait and deallocate port.
 *
 * Create an eventlink object, associate threads, wait and deallocate the eventlink port.
 */
T_DECL(test_eventlink_wait_and_deallocate, "eventlink wait and deallocate", T_META_ASROOT(YES))
{
	kern_return_t kr;
	mach_port_t port_pair[2];
	pthread_t pthread;

	/* Create an eventlink and associate threads to it */
	kr = test_eventlink_create(port_pair);
	if (kr != KERN_SUCCESS) {
		return;
	}

	pthread = thread_create_for_test(test_eventlink_wait_destroy, (void *)(uintptr_t)port_pair[0]);

	sleep(5);

	/* Destroy the port for thread to wakeup */
	mach_port_deallocate(mach_task_self(), port_pair[0]);

	pthread_join(pthread, NULL);
	mach_port_deallocate(mach_task_self(), port_pair[1]);
}

/*
 * Test 9: Test eventlink wait and disassociate.
 *
 * Create an eventlink object, associate threads, wait and disassociate thread from the eventlink port.
 */
T_DECL(test_eventlink_wait_and_disassociate, "eventlink wait and disassociate", T_META_ASROOT(YES))
{
	kern_return_t kr;
	mach_port_t port_pair[2];
	pthread_t pthread;

	/* Create an eventlink and associate threads to it */
	kr = test_eventlink_create(port_pair);
	if (kr != KERN_SUCCESS) {
		return;
	}

	pthread = thread_create_for_test(test_eventlink_wait_destroy, (void *)(uintptr_t)port_pair[0]);

	sleep(5);

	/* Disassociate thread from eventlink for thread to wakeup */
	kr = mach_eventlink_disassociate(port_pair[0], MELD_OPTION_NONE);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_disassociate");

	pthread_join(pthread, NULL);
	mach_port_deallocate(mach_task_self(), port_pair[1]);
	mach_port_deallocate(mach_task_self(), port_pair[0]);
}

/*
 * Test 10: Test eventlink wait and signal.
 *
 * Create an eventlink object, associate threads and test wait signal.
 */
T_DECL(test_eventlink_wait_and_signal, "eventlink wait and signal", T_META_ASROOT(YES))
{
	kern_return_t kr;
	mach_port_t port_pair[2];
	pthread_t pthread;
	mach_port_t self = mach_thread_self();

	/* Create an eventlink and associate threads to it */
	kr = test_eventlink_create(port_pair);
	if (kr != KERN_SUCCESS) {
		return;
	}

	pthread = thread_create_for_test(test_eventlink_wait_for_signal, (void *)(uintptr_t)port_pair[0]);

	sleep(5);

	/* Associate thread and signal the eventlink */
	kr = mach_eventlink_associate(port_pair[1], self, 0, 0, 0, 0, MELA_OPTION_NONE);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_associate for object 2");

	kr = mach_eventlink_signal(port_pair[1], 0);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_signal for object 2");

	pthread_join(pthread, NULL);

	mach_port_deallocate(mach_task_self(), port_pair[0]);
	mach_port_deallocate(mach_task_self(), port_pair[1]);
}

/*
 * Test 11: Test eventlink wait_signal.
 *
 * Create an eventlink object, associate threads and test wait_signal.
 */
T_DECL(test_eventlink_wait_signal, "eventlink wait_signal", T_META_ASROOT(YES))
{
	kern_return_t kr;
	mach_port_t port_pair[2];
	pthread_t pthread;
	mach_port_t self = mach_thread_self();
	uint64_t count = 0;

	/* Create an eventlink and associate threads to it */
	kr = test_eventlink_create(port_pair);
	if (kr != KERN_SUCCESS) {
		return;
	}

	pthread = thread_create_for_test(test_eventlink_wait_then_signal, (void *)(uintptr_t)port_pair[0]);

	sleep(5);

	/* Associate thread and wait_signal the eventlink */
	kr = mach_eventlink_associate(port_pair[1], self, 0, 0, 0, 0, MELA_OPTION_NONE);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_associate for object 2");

	/* Wait on the eventlink with timeout */
	kr = mach_eventlink_signal_wait_until(port_pair[1], &count, 0, MELSW_OPTION_NONE,
	    KERN_CLOCK_MACH_ABSOLUTE_TIME, 0);

	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_signal_wait_until");
	T_EXPECT_EQ(count, (uint64_t)1, "mach_eventlink_signal_wait_until returned correct count value");

	pthread_join(pthread, NULL);

	mach_port_deallocate(mach_task_self(), port_pair[0]);
	mach_port_deallocate(mach_task_self(), port_pair[1]);
}

/*
 * Test 12: Test eventlink wait_signal with no wait.
 *
 * Create an eventlink object, associate threads and test wait_signal with no wait.
 */
T_DECL(test_eventlink_wait_signal_no_wait, "eventlink wait_signal with no wait", T_META_ASROOT(YES))
{
	kern_return_t kr;
	mach_port_t port_pair[2];
	pthread_t pthread;
	mach_port_t self = mach_thread_self();
	uint64_t count = 0;

	/* Create an eventlink and associate threads to it */
	kr = test_eventlink_create(port_pair);
	if (kr != KERN_SUCCESS) {
		return;
	}

	pthread = thread_create_for_test(test_eventlink_wait_then_wait_signal_with_no_wait, (void *)(uintptr_t)port_pair[0]);

	sleep(5);

	/* Associate thread and wait_signal the eventlink */
	kr = mach_eventlink_associate(port_pair[1], self, 0, 0, 0, 0, MELA_OPTION_NONE);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_associate for object 2");

	/* Wait on the eventlink with timeout */
	kr = mach_eventlink_signal_wait_until(port_pair[1], &count, 0, MELSW_OPTION_NONE,
	    KERN_CLOCK_MACH_ABSOLUTE_TIME, 0);

	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_signal_wait_until");
	T_EXPECT_EQ(count, (uint64_t)1, "mach_eventlink_signal_wait_until returned correct count value");

	pthread_join(pthread, NULL);

	mach_port_deallocate(mach_task_self(), port_pair[0]);
	mach_port_deallocate(mach_task_self(), port_pair[1]);
}

/*
 * Test 13: Test eventlink wait_signal with prepost.
 *
 * Create an eventlink object, associate threads and test wait_signal with prepost.
 */
T_DECL(test_eventlink_wait_signal_prepost, "eventlink wait_signal with prepost", T_META_ASROOT(YES))
{
	kern_return_t kr;
	mach_port_t port_pair[2];
	pthread_t pthread;
	mach_port_t self = mach_thread_self();
	uint64_t count = 0;

	/* Create an eventlink and associate threads to it */
	kr = test_eventlink_create(port_pair);
	if (kr != KERN_SUCCESS) {
		return;
	}

	pthread = thread_create_for_test(test_eventlink_wait_then_wait_signal_with_prepost, (void *)(uintptr_t)port_pair[0]);

	sleep(5);

	/* Associate thread and wait_signal the eventlink */
	kr = mach_eventlink_associate(port_pair[1], self, 0, 0, 0, 0, MELA_OPTION_NONE);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_associate for object 2");

	/* Wait on the eventlink with timeout */
	kr = mach_eventlink_signal_wait_until(port_pair[1], &count, 0, MELSW_OPTION_NONE,
	    KERN_CLOCK_MACH_ABSOLUTE_TIME, 0);

	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_signal_wait_until");
	T_EXPECT_EQ(count, (uint64_t)1, "mach_eventlink_signal_wait_until returned correct count value");

	pthread_join(pthread, NULL);

	mach_port_deallocate(mach_task_self(), port_pair[0]);
	mach_port_deallocate(mach_task_self(), port_pair[1]);
}

/*
 * Test 14: Test eventlink wait_signal with associate on wait option.
 *
 * Create an eventlink object, set associate on wait on one side and test wait_signal.
 */
T_DECL(test_eventlink_wait_signal_associate_on_wait, "eventlink wait_signal associate on wait", T_META_ASROOT(YES))
{
	kern_return_t kr;
	mach_port_t port_pair[2];
	pthread_t pthread;
	uint64_t count = 0;

	/* Create an eventlink and associate threads to it */
	kr = test_eventlink_create(port_pair);
	if (kr != KERN_SUCCESS) {
		return;
	}

	pthread = thread_create_for_test(test_eventlink_wait_then_signal, (void *)(uintptr_t)port_pair[0]);

	sleep(5);

	/* Set associate on wait and wait_signal the eventlink */
	kr = mach_eventlink_associate(port_pair[1], MACH_PORT_NULL, 0, 0, 0, 0, MELA_OPTION_ASSOCIATE_ON_WAIT);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_associate with associate on wait for object 2");

	/* Wait on the eventlink with timeout */
	kr = mach_eventlink_signal_wait_until(port_pair[1], &count, 0, MELSW_OPTION_NONE,
	    KERN_CLOCK_MACH_ABSOLUTE_TIME, 0);

	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_signal_wait_until");
	T_EXPECT_EQ(count, (uint64_t)1, "mach_eventlink_signal_wait_until returned correct count value");

	/* Remove associate on wait option */
	kr = mach_eventlink_disassociate(port_pair[1], MELD_OPTION_NONE);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_disassociate");

	/* Wait on the eventlink with timeout */
	kr = mach_eventlink_signal_wait_until(port_pair[1], &count, 0, MELSW_OPTION_NONE,
	    KERN_CLOCK_MACH_ABSOLUTE_TIME, 0);

	T_EXPECT_MACH_ERROR(kr, KERN_INVALID_ARGUMENT, "mach_eventlink_wait_until returned expected error");

	pthread_join(pthread, NULL);

	mach_port_deallocate(mach_task_self(), port_pair[0]);
	mach_port_deallocate(mach_task_self(), port_pair[1]);
}

/*
 * Test 15: Test eventlink wait_signal_loop.
 *
 * Create an eventlink object, associate threads and test wait_signal in a loop.
 */
T_DECL(test_eventlink_wait_signal_loop, "eventlink wait_signal in loop", T_META_ASROOT(YES))
{
	kern_return_t kr;
	mach_port_t port_pair[2];
	pthread_t pthread;
	mach_port_t self = mach_thread_self();
	uint64_t count = 0;
	int i;

	/* Create an eventlink and associate threads to it */
	kr = test_eventlink_create(port_pair);
	if (kr != KERN_SUCCESS) {
		return;
	}

	pthread = thread_create_for_test(test_eventlink_wait_then_signal_loop, (void *)(uintptr_t)port_pair[0]);

	/* Associate thread and wait_signal the eventlink */
	kr = mach_eventlink_associate(port_pair[1], self, 0, 0, 0, 0, MELA_OPTION_NONE);
	T_ASSERT_MACH_SUCCESS(kr, "mach_eventlink_associate for object 2");

	for (i = 0; i < 100; i++) {
		/* Wait on the eventlink with timeout */
		kr = mach_eventlink_signal_wait_until(port_pair[1], &count, 0, MELSW_OPTION_NONE,
		    KERN_CLOCK_MACH_ABSOLUTE_TIME, 0);

		T_ASSERT_MACH_SUCCESS(kr, "main thread: mach_eventlink_signal_wait_until");
		T_EXPECT_EQ(count, (uint64_t)(i + 1), "main thread: mach_eventlink_signal_wait_until returned correct count value");
	}

	pthread_join(pthread, NULL);

	mach_port_deallocate(mach_task_self(), port_pair[0]);
	mach_port_deallocate(mach_task_self(), port_pair[1]);
}
