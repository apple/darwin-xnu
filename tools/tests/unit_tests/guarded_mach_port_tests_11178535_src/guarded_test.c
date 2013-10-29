#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <mach/mach.h>
#include <mach/port.h>
#include <mach/mach_port.h>
#include <mach/mach_init.h>

#define CONTEXT_VALUE1 0x12345678
#define CONTEXT_VALUE2 0x11111111

char *pname;

static void usage(void)
{
        printf("usage: %s [test number]\n", pname);
	printf("Test 0: Test case for constructing a mach port with options\n");
	printf("Test 1: Test case for destructing guarded mach port\n");
	printf("Test 2: Test case for destroying guarded mach port\n");
	printf("Test 3: Test case for mod_ref() guarded mach port\n");
	printf("Test 4: Test case for guarding mach port\n");
	printf("Test 5: Test case for unguarding mach port\n");
	printf("Test 6: Test case for unguarding a non-guarded port\n");
	printf("Test 7: Test case for guarding a mach port with context\n");
	printf("Test 8: Test case for mach_port_get_context()\n");
	printf("Test 9: Test case for mach_port_set_context()\n");
}

/* Test case for constructing a mach port with options */
void construct_mach_port();
/* Test case for destructing guarded mach port */
void destruct_guarded_mach_port();
/* Test case for destroying guarded mach port */
void destroy_guarded_mach_port();
/* Test case for mod_ref() guarded mach port */
void mod_ref_guarded_mach_port();
/* Test case for guarding mach port */
void guard_mach_port();
/*  Test case for unguarding mach port */
void unguard_mach_port();
/* Test case for unguarding a non-guarded port */
void unguard_nonguarded_mach_port();
/* Test case for guarding a mach port with context */
void guard_port_with_context();
/* Test case for mach_port_get_context() */
void get_context_mach_port();
/* Test case for mach_port_set_context() */
void set_context_mach_port();

int main(int argc, char *argv[])
{
	int option, fd;
	
	pname = argv[0];
	if (argc != 2) {
		usage();
                exit(1);
	}
	printf("Test Program invoked with option [%s]\n", argv[1]);
	option = atoi(argv[1]);

	
	switch(option) {

		case 0:
			construct_mach_port();
			break;
		case 1:
			destruct_guarded_mach_port();
			break;
		case 2:
			destroy_guarded_mach_port();
			break;
		case 3:
			mod_ref_guarded_mach_port();
			break;
		case 4:
			guard_mach_port();
			break;
		case 5:
			unguard_mach_port();
			break;
		case 6:
			unguard_nonguarded_mach_port();
			break;
		case 7:
			guard_port_with_context();
			break;
		case 8:
			get_context_mach_port();
			break;
		case 9:
			set_context_mach_port();
			break;
		default:
			usage();
			exit(1);
	}

	return 0;
}

void construct_mach_port()
{
	mach_port_t port;
	mach_port_options_t options;
	mach_port_context_t gval = CONTEXT_VALUE1;
	mach_port_context_t g;
	int kret;

	printf("Testing All mach_port_construct() options...\n");

	printf("No options specified: ");
	options.flags = 0;
	kret = mach_port_construct(mach_task_self(), &options, 0, &port);
	if (kret == KERN_SUCCESS)
		printf("[PASSED]\n");
	else
		goto failed;

	printf("Options MPO_GUARD: ");
	options.flags = MPO_CONTEXT_AS_GUARD;
	kret = mach_port_construct(mach_task_self(), &options, gval, &port);
	if (kret == KERN_SUCCESS)
		printf("[PASSED]\n");
	else
		goto failed;


	printf("Options MPO_GUARD|MPO_STRICT: ");
	options.flags = MPO_CONTEXT_AS_GUARD|MPO_STRICT;
	kret = mach_port_construct(mach_task_self(), &options, gval, &port);
	if (kret == KERN_SUCCESS) {
		kret = mach_port_get_context(mach_task_self(), port, &g);
		if (kret != KERN_SUCCESS || g != 0)
			goto failed;
		else
			printf("[PASSED]\n");
	}
	else
		goto failed;

	printf("Options MPO_QLIMIT: ");
	options.flags = MPO_QLIMIT;
	mach_port_limits_t limits = { MACH_PORT_QLIMIT_SMALL };
	options.mpl = limits;
	kret = mach_port_construct(mach_task_self(), &options, 0, &port);
	if (kret == KERN_SUCCESS)
		printf("[PASSED]\n");
	else
		goto failed;
	
	printf("Options MPO_TEMPOWNER: ");
	options.flags = MPO_TEMPOWNER;
	kret = mach_port_construct(mach_task_self(), &options, 0, &port);
	if (kret == KERN_SUCCESS)
		printf("[PASSED]\n");
	else
		goto failed;

	printf("Options MPO_IMPORTANCE_RECEIVER: ");
	options.flags = MPO_IMPORTANCE_RECEIVER;
	kret = mach_port_construct(mach_task_self(), &options, 0, &port);
	if (kret == KERN_SUCCESS)
		printf("[PASSED]\n");
	else
		goto failed;

	printf("Options MPO_INSERT_SEND_RIGHT: ");
	options.flags = MPO_INSERT_SEND_RIGHT;
	kret = mach_port_construct(mach_task_self(), &options, 0, &port);
	if (kret == KERN_SUCCESS)
		printf("[PASSED]\n");
	else
		goto failed;

	printf("No options specified (Construct Port-Set): ");
	options.flags = 0;
	kret = mach_port_construct(mach_task_self(), &options, 0, &port);
	if (kret == KERN_SUCCESS)
		printf("[PASSED]\n");
	else
		goto failed;

	printf("...Complete\n");
	return;

failed:
	printf("[FAILED %d]\n", kret);
	exit(1);
}

void destruct_guarded_mach_port()
{
	mach_port_t port;
	mach_port_options_t options;
	mach_port_context_t gval = CONTEXT_VALUE1;
	int kret;

	printf("Destructing guarded mach port with correct guard: ");
	options.flags = (MPO_CONTEXT_AS_GUARD);

	kret = mach_port_construct(mach_task_self(), &options, gval, &port);
	if (kret != KERN_SUCCESS)
		exit(1);
	
	kret = mach_port_destruct(mach_task_self(), port, 0, gval);
	if (kret == KERN_SUCCESS)
		printf("[PASSED]\n");
	else
		goto failed;

	printf("Destructing guarded mach ports with incorrect send right count: ");
	options.flags = (MPO_CONTEXT_AS_GUARD);

	kret = mach_port_construct(mach_task_self(), &options, gval, &port);
	if (kret != KERN_SUCCESS)
		exit(1);
	
	kret = mach_port_destruct(mach_task_self(), port, -1, gval);
	if (kret != KERN_SUCCESS)
		printf("[PASSED]\n");
	else
		goto failed;
	
	printf("Destructing guarded mach ports with correct send right and correct guard: ");
	options.flags = (MPO_CONTEXT_AS_GUARD|MPO_INSERT_SEND_RIGHT);

	kret = mach_port_construct(mach_task_self(), &options, gval, &port);
	if (kret != KERN_SUCCESS)
		exit(1);
	
	kret = mach_port_destruct(mach_task_self(), port, -1, gval);
	if (kret == KERN_SUCCESS)
		printf("[PASSED]\n");
	else
		goto failed;
	
	printf("Destructing guarded mach port with incorrect guard (Expecting exception)...\n");
	kret = mach_port_construct(mach_task_self(), &options, gval, &port);
	if (kret != KERN_SUCCESS)
		exit(1);

	kret = mach_port_destruct(mach_task_self(), port, 0, 0);
	if (kret == KERN_SUCCESS)
		goto failed;
	return;

failed:
	printf("[FAILED]\n");
	exit(1);

}

void destroy_guarded_mach_port()
{
	mach_port_t port;
	mach_port_options_t options;
	mach_port_context_t gval = CONTEXT_VALUE1;
	int kret;

	printf("Destroying guarded mach port (Expecting exception)...\n");
	options.flags = (MPO_CONTEXT_AS_GUARD);

	kret = mach_port_construct(mach_task_self(), &options, gval, &port);
	if (kret != KERN_SUCCESS)
		exit(1);
	
	kret = mach_port_destroy(mach_task_self(), port);
	if (kret == KERN_SUCCESS) {
		printf("[FAILED]\n");
		exit(1);
	}

	return;
}

void mod_ref_guarded_mach_port()
{
	mach_port_t port;
	mach_port_options_t options;
	mach_port_context_t gval = CONTEXT_VALUE1;
	int kret;
	
	printf("mach_port_mod_refs() guarded mach port (Expecting exception)...\n");
	options.flags = (MPO_CONTEXT_AS_GUARD);

	kret = mach_port_construct(mach_task_self(), &options, gval, &port);
	if (kret != KERN_SUCCESS)
		exit(1);
	
	kret = mach_port_mod_refs(mach_task_self(), port, MACH_PORT_RIGHT_RECEIVE, -1);
	if (kret == KERN_SUCCESS) {
		printf("[FAILED]\n");
		exit(1);
	}

	return;
}

void guard_mach_port()
{
	mach_port_t port;
	mach_port_options_t options;
	mach_port_context_t gval = CONTEXT_VALUE1;
	int kret;

	printf("Testing guarding a non-guarded mach port: ");
	kret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
	if (kret != KERN_SUCCESS)
		exit(1);
	
	kret = mach_port_guard(mach_task_self(), port, gval, 0);
	if (kret == KERN_SUCCESS)
		printf("[PASSED]\n");
	else
		goto failed;
	
	printf("Testing guarding a guarded mach port: ");
	kret = mach_port_guard(mach_task_self(), port, CONTEXT_VALUE2, 0);
	if (kret != KERN_SUCCESS)
		printf("[PASSED]\n");
	else
		goto failed;
	
	return;

failed:
	printf("[FAILED]\n");
	exit(1);
	
}

void unguard_mach_port()
{
	mach_port_t port;
	mach_port_options_t options;
	mach_port_context_t gval = CONTEXT_VALUE1;
	int kret;
	
	printf("Testing unguard with correct guard: \n");

	options.flags = (MPO_CONTEXT_AS_GUARD);

	kret = mach_port_construct(mach_task_self(), &options, gval, &port);
	if (kret != KERN_SUCCESS)
		exit(1);

	kret = mach_port_unguard(mach_task_self(), port, gval);
	if (kret == KERN_SUCCESS)
		printf("[PASSED]\n");
	else
		goto failed;
	
	printf("Testing unguard with incorrect guard (Expecting Exception)... \n");
	kret = mach_port_construct(mach_task_self(), &options, gval, &port);
	if (kret != KERN_SUCCESS)
		exit(1);
	kret = mach_port_unguard(mach_task_self(), port, CONTEXT_VALUE2);
	if (kret == KERN_SUCCESS)
		goto failed;
	
	return;

failed:
	printf("[FAILED]\n");
	exit(1);
	
}

void unguard_nonguarded_mach_port()
{
	mach_port_t port;
	mach_port_options_t options;
	mach_port_context_t gval = CONTEXT_VALUE1;
	int kret;
	
	printf("Testing mach_port_unguard() for non-guarded port (Expecting exception)...\n");

	options.flags = 0;

	kret = mach_port_construct(mach_task_self(), &options, 0, &port);
	if (kret != KERN_SUCCESS)
		exit(1);
	kret = mach_port_unguard(mach_task_self(), port, gval);
	if (kret == KERN_SUCCESS) {
		printf("[FAILED]\n");
		exit(1);
	}

	return;
}

void guard_port_with_context()
{
	mach_port_t port;
	mach_port_options_t options;
	mach_port_context_t gval = CONTEXT_VALUE1;
	int kret;

	printf("Testing mach_port_guard() for a port with context: ");
	kret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
	if (kret != KERN_SUCCESS)
		exit(1);
		
	kret = mach_port_set_context(mach_task_self(), port, gval);
	if (kret != KERN_SUCCESS)
		exit(1);
	kret = mach_port_guard(mach_task_self(), port, gval, 0);
	if (kret != KERN_SUCCESS)
		printf("[PASSED]\n");
	else {
		printf("[FAILED]\n");
		exit(1);
	}
	return;
}

void get_context_mach_port()
{
	mach_port_t port;
	mach_port_options_t options;
	mach_port_context_t gval = CONTEXT_VALUE1;
	mach_port_context_t g;
	int kret;
	
	options.flags = (MPO_CONTEXT_AS_GUARD);

	printf("Testing get_context() for non-strict guarded port: ");

	kret = mach_port_construct(mach_task_self(), &options, gval, &port);
	if (kret != KERN_SUCCESS)
		exit(1);
	
	kret = mach_port_get_context(mach_task_self(), port, &g);
	if (kret != KERN_SUCCESS || g != gval)
		goto failed;
	else
		printf("[PASSED]\n");
	
	printf("Testing get_context() for strict guarded port: ");
	options.flags = (MPO_CONTEXT_AS_GUARD|MPO_STRICT);

	kret = mach_port_construct(mach_task_self(), &options, gval, &port);
	if (kret != KERN_SUCCESS)
		exit(1);
	
	kret = mach_port_get_context(mach_task_self(), port, &g);
	if (kret != KERN_SUCCESS || g != 0)
		goto failed;
	else
		printf("[PASSED]\n");
	
	printf("Testing get_context() for strict guard port (guarded using mach_port_guard): ");
	kret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
	if (kret != KERN_SUCCESS)
		exit(1);
	kret = mach_port_guard(mach_task_self(), port, gval, 1);
	if (kret != KERN_SUCCESS)
		exit(1);
	kret = mach_port_get_context(mach_task_self(), port, &g);
	if (kret != KERN_SUCCESS || g != 0)
		goto failed;
	else
		printf("[PASSED]\n");

	printf("Testing get_context() for non-guarded port with context: ");
	kret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
	if (kret != KERN_SUCCESS)
		exit(1);
	kret = mach_port_set_context(mach_task_self(), port, gval);
	if (kret != KERN_SUCCESS)
		exit(1);
	kret = mach_port_get_context(mach_task_self(), port, &g);
	if (kret != KERN_SUCCESS || g != gval)
		goto failed;
	else
		printf("[PASSED]\n");

	return;
	

failed:
	printf("[FAILED]\n");
	exit(1);
}

void set_context_mach_port()
{
	mach_port_t port;
	mach_port_options_t options;
	mach_port_context_t gval = CONTEXT_VALUE1;
	mach_port_context_t g;
	int kret;

	printf("Testing set_context() with non-guarded port: ");
	kret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
	if (kret != KERN_SUCCESS)
		exit(1);
	kret = mach_port_set_context(mach_task_self(), port, gval);
	if (kret != KERN_SUCCESS)
		goto failed;
	else
		printf("[PASSED]\n");
	
	printf("Testing setting context on non-guarded port with pre-existing context: ");
	kret = mach_port_set_context(mach_task_self(), port, CONTEXT_VALUE2);
	if (kret != KERN_SUCCESS)
		goto failed;
	else
		printf("[PASSED]\n");
	
	printf("Testing setting context on strict guarded port (Expecting Exception)...\n");

	options.flags = (MPO_CONTEXT_AS_GUARD|MPO_STRICT);

	kret = mach_port_construct(mach_task_self(), &options, gval, &port);
	if (kret != KERN_SUCCESS)
		exit(1);

	kret = mach_port_set_context(mach_task_self(), port, CONTEXT_VALUE2);
	if (kret == KERN_SUCCESS)
		goto failed;
	
	return;

failed:
	printf("[FAILED]\n");
	exit(1);
}

	
	

