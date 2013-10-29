#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <pthread.h>
#include <sys/mman.h>
#include <dispatch/dispatch.h>
#include <sys/sysctl.h>

#include "excserver.h"

/*
 * Test program that sets up a Mach exception handler,
 * then performs 1000 invalid memory accesses and makes
 * sure all thread_get_state variants can be executed
 * from inside the exception handler.
 */
void *handler(void *);
void *spin(void *);
dispatch_semaphore_t start_sema;
volatile int iteration;

#define COUNT 10000

int main(int argc, char *argv[]) {
	int ret;
	pthread_t handle_thread;
	char *buffer = valloc(4096);
	int i;
	int ncpu;
	size_t ncpucount = sizeof(ncpu);

	start_sema = dispatch_semaphore_create(0);

	ret = sysctlbyname("hw.ncpu", &ncpu, &ncpucount, NULL, 0);
	if (ret)
		err(1, "sysctlbyname");	

	for (i=0; i < ncpu; i++) {
		pthread_t spin_thread;

		ret = pthread_create(&spin_thread, NULL, spin, NULL);
		if (ret)
			err(1, "pthread_create");
	}

	sleep(1);
	ret = pthread_create(&handle_thread, NULL, handler, NULL);
	if (ret)
		err(1, "pthread_create");

	dispatch_semaphore_wait(start_sema, DISPATCH_TIME_FOREVER);

	for (iteration = 0; iteration < COUNT; iteration++) {
		ret = mprotect(buffer, 4096, PROT_NONE);
		if (ret != 0)
			err(1, "mprotect");

		usleep(1000);

		volatile float a = ((float)iteration)/2.4f;
		*buffer = '!';
	}

	return 0;
}

void *handler(void *arg __unused) {
	kern_return_t kret;
	mach_port_t exception_port;

	kret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
							  &exception_port);
	if (kret != KERN_SUCCESS)
		errx(1, "mach_port_allocate: %s (%d)", mach_error_string(kret), kret);

	kret = mach_port_insert_right(mach_task_self(), exception_port, exception_port, MACH_MSG_TYPE_MAKE_SEND);
	if (kret != KERN_SUCCESS)
		errx(1, "mach_port_insert_right: %s (%d)", mach_error_string(kret), kret);

	kret = task_set_exception_ports(mach_task_self(),
									EXC_MASK_BAD_ACCESS,
									exception_port,
									EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
									0);
	if (kret != KERN_SUCCESS)
		errx(1, "task_set_exception_ports: %s (%d)", mach_error_string(kret), kret);
	
	dispatch_semaphore_signal(start_sema);

	kret = mach_msg_server(mach_exc_server, MACH_MSG_SIZE_RELIABLE, exception_port, 0);
	if (kret != KERN_SUCCESS)
		errx(1, "mach_msg_server: %s (%d)", mach_error_string(kret), kret);	

	return NULL;
}

kern_return_t catch_mach_exception_raise
(
	mach_port_t exception_port,
	mach_port_t thread,
	mach_port_t task,
	exception_type_t exception,
	mach_exception_data_t code,
	mach_msg_type_number_t codeCnt
)
{
	int ret;
	kern_return_t kret;
	thread_state_flavor_t flavors[128];
	thread_state_data_t state;
	mach_msg_type_number_t count;
	int i, flcount;

//	printf("Successfully caught EXC_BAD_ACCESS %s(%d) at 0x%016llx\n", mach_error_string((int)code[0]), (int)code[0], code[1]);

	count = sizeof(flavors)/sizeof(natural_t);
	kret = thread_get_state(thread, THREAD_STATE_FLAVOR_LIST_NEW, (thread_state_t)flavors, &count);
	if (kret == KERN_INVALID_ARGUMENT) {
		/* try older query */
		count = sizeof(flavors)/sizeof(natural_t);
		kret = thread_get_state(thread, THREAD_STATE_FLAVOR_LIST, (thread_state_t)flavors, &count);
		if (kret != KERN_SUCCESS)
			errx(1, "thread_get_state(THREAD_STATE_FLAVOR_LIST): %s (%d)", mach_error_string(kret), kret);
	} else if (kret != KERN_SUCCESS)
		errx(1, "thread_get_state(THREAD_STATE_FLAVOR_LIST_NEW): %s (%d)", mach_error_string(kret), kret);

	flcount = count;
	for (i=0; i < flcount; i++) {
		thread_state_flavor_t flavor;

		flavor = flavors[(i + iteration) % flcount];
		count = THREAD_STATE_MAX;
		kret = thread_get_state(thread, flavor, (thread_state_t)state, &count);
		if (kret != KERN_SUCCESS)
			errx(1, "thread_get_state(%d): %s (%d)", flavor, mach_error_string(kret), kret);
	}

	ret = mprotect((void *)code[1], 4096, PROT_WRITE);
	if (ret != 0)
		err(1, "mprotect");

	return KERN_SUCCESS;
}

kern_return_t catch_mach_exception_raise_state
(
	mach_port_t exception_port,
	exception_type_t exception,
	const mach_exception_data_t code,
	mach_msg_type_number_t codeCnt,
	int *flavor,
	const thread_state_t old_state,
	mach_msg_type_number_t old_stateCnt,
	thread_state_t new_state,
	mach_msg_type_number_t *new_stateCnt
)
{
	errx(1, "Unsupported catch_mach_exception_raise_state");
	return KERN_NOT_SUPPORTED;
}

kern_return_t catch_mach_exception_raise_state_identity
(
	mach_port_t exception_port,
	mach_port_t thread,
	mach_port_t task,
	exception_type_t exception,
	mach_exception_data_t code,
	mach_msg_type_number_t codeCnt,
	int *flavor,
	thread_state_t old_state,
	mach_msg_type_number_t old_stateCnt,
	thread_state_t new_state,
	mach_msg_type_number_t *new_stateCnt
)
{
	errx(1, "Unsupported catch_mach_exception_raise_state_identity");
	return KERN_NOT_SUPPORTED;
}

void *spin(void *arg __unused) {
	volatile unsigned int a;

	while (1) {
		a++;
	}

	return NULL;
}
