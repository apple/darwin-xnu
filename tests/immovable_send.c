#include <darwintest.h>
#include <servers/bootstrap.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <darwintest_multiprocess.h>
#include <excserver.h>
#include <spawn.h>
#include <spawn_private.h>
#include <libproc_internal.h>
#include <signal.h>

#include <IOKit/IOKitLib.h>

#define TASK_EXC_GUARD_MP_DELIVER 0x10
#define MAX_ARGV 2

extern char **environ;

kern_return_t
catch_mach_exception_raise_state(mach_port_t exception_port,
    exception_type_t exception,
    const mach_exception_data_t code,
    mach_msg_type_number_t code_count,
    int * flavor,
    const thread_state_t old_state,
    mach_msg_type_number_t old_state_count,
    thread_state_t new_state,
    mach_msg_type_number_t * new_state_count)
{
#pragma unused(exception_port, exception, code, code_count, flavor, old_state, old_state_count, new_state, new_state_count)
	T_FAIL("Unsupported catch_mach_exception_raise_state");
	return KERN_NOT_SUPPORTED;
}

kern_return_t
catch_mach_exception_raise_state_identity(mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t code_count,
    int * flavor,
    thread_state_t old_state,
    mach_msg_type_number_t old_state_count,
    thread_state_t new_state,
    mach_msg_type_number_t * new_state_count)
{
#pragma unused(exception_port, thread, task, exception, code, code_count, flavor, old_state, old_state_count, new_state, new_state_count)
	T_FAIL("Unsupported catch_mach_exception_raise_state_identity");
	return KERN_NOT_SUPPORTED;
}

kern_return_t
catch_mach_exception_raise(mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t code_count)
{
#pragma unused(exception_port, task, thread, code_count)
	T_ASSERT_EQ(exception, EXC_GUARD, "exception type");
	T_LOG("Exception raised with exception code : %llx\n", *code);
	T_END;
	return KERN_SUCCESS;
}

typedef struct {
	mach_msg_header_t   header;
	mach_msg_body_t     body;
	mach_msg_port_descriptor_t port_descriptor;
	mach_msg_trailer_t  trailer;            // subtract this when sending
} ipc_complex_message;

struct args {
	char *server_port_name;
	mach_port_t server_port;
};

void parse_args(struct args *args);
void server_setup(struct args* args);
void* exception_server_thread(void *arg);
mach_port_t create_exception_port(void);

#define TEST_TIMEOUT    10

void
parse_args(struct args *args)
{
	args->server_port_name = "TEST_IMMOVABLE_SEND";
	args->server_port = MACH_PORT_NULL;
}

/* Create a mach IPC listener which will respond to the client's message */
void
server_setup(struct args *args)
{
	kern_return_t ret;
	mach_port_t bsport;

	ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
	    &args->server_port);
	T_ASSERT_MACH_SUCCESS(ret, "server: mach_port_allocate()");

	ret = mach_port_insert_right(mach_task_self(), args->server_port, args->server_port,
	    MACH_MSG_TYPE_MAKE_SEND);
	T_ASSERT_MACH_SUCCESS(ret, "server: mach_port_insert_right()");

	ret = task_get_bootstrap_port(mach_task_self(), &bsport);
	T_ASSERT_MACH_SUCCESS(ret, "server: task_get_bootstrap_port()");

	ret = bootstrap_register(bsport, args->server_port_name, args->server_port);
	T_ASSERT_MACH_SUCCESS(ret, "server: bootstrap_register()");

	T_LOG("server: waiting for IPC messages from client on port '%s'.\n",
	    args->server_port_name);
}

mach_port_t
create_exception_port()
{
	kern_return_t kret;
	mach_port_t exc_port = MACH_PORT_NULL;
	mach_port_t task = mach_task_self();

	kret = mach_port_allocate(task, MACH_PORT_RIGHT_RECEIVE, &exc_port);
	T_EXPECT_MACH_SUCCESS(kret, "mach_port_allocate exc_port");

	kret = mach_port_insert_right(task, exc_port, exc_port, MACH_MSG_TYPE_MAKE_SEND);
	T_EXPECT_MACH_SUCCESS(kret, "mach_port_insert_right exc_port");

	return exc_port;
}

void *
exception_server_thread(void *arg)
{
	kern_return_t kr;
	mach_port_t exc_port = *(mach_port_t *)arg;
	T_EXPECT_NE(exc_port, MACH_PORT_NULL, "exception port is not null");

	/* Handle exceptions on exc_port */
	kr = mach_msg_server(mach_exc_server, 4096, exc_port, 0);
	T_EXPECT_MACH_SUCCESS(kr, "mach_msg_server");

	return NULL;
}

T_DECL(catch_exception, "Send guard port descriptor to another process", T_META_IGNORECRASHES(".*immovable_send_client.*"))
{
	uint32_t task_exc_guard = 0;
	size_t te_size = sizeof(&task_exc_guard);
	kern_return_t kr;
	mach_msg_type_number_t  maskCount = 1;
	exception_mask_t        mask;
	exception_handler_t     handler;
	exception_behavior_t    behavior;
	thread_state_flavor_t   flavor;
	mach_port_t             task = mach_task_self();
	struct args*            server_args = (struct args*)malloc(sizeof(struct args));
	posix_spawnattr_t       attrs;
	char *test_prog_name = "./immovable_send_client";
	char *child_args[MAX_ARGV];

	T_LOG("Check if task_exc_guard exception has been enabled\n");
	sysctlbyname("kern.task_exc_guard_default", &task_exc_guard, &te_size, NULL, 0);
	//TODO: check if sysctlbyname is successful

	/* Create the bootstrap port */
	parse_args(server_args);
	server_setup(server_args);

	/* Create the exception port for the server */
	mach_port_t exc_port = create_exception_port();
	T_EXPECT_NOTNULL(exc_port, "Create a new exception port");

	pthread_t s_exc_thread;

	/* Create exception serving thread */
	int ret = pthread_create(&s_exc_thread, NULL, exception_server_thread, &exc_port);
	T_EXPECT_POSIX_SUCCESS(ret, "pthread_create exception_server_thread");

	/* Get current exception ports */
	kr = task_get_exception_ports(task, EXC_MASK_GUARD, &mask,
	    &maskCount, &handler, &behavior, &flavor);
	T_EXPECT_MACH_SUCCESS(kr, "task_get_exception_ports");

	/* Initialize posix_spawn attributes */
	posix_spawnattr_init(&attrs);

	int err = posix_spawnattr_setexceptionports_np(&attrs, EXC_MASK_GUARD, exc_port,
	    (exception_behavior_t) (EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES), 0);
	T_EXPECT_POSIX_SUCCESS(err, "posix_spawnattr_setflags");

	child_args[0] = test_prog_name;
	child_args[1] = NULL;

	err = posix_spawn(NULL, child_args[0], NULL, &attrs, &child_args[0], environ);
	T_EXPECT_POSIX_SUCCESS(err, "posix_spawn immovable_send_client");

	int child_status;
	/* Wait for child and check for exception */
	if (-1 == wait4(-1, &child_status, 0, NULL)) {
		T_FAIL("wait4: child mia");
	}

	if (WIFEXITED(child_status) && WEXITSTATUS(child_status)) {
		T_LOG("Child exited with status = %x", child_status);
	}

	sigsuspend(0);
}
