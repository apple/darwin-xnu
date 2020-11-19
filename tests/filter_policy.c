#include <servers/bootstrap.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <pthread.h>

#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif

#include <darwintest.h>
#include <darwintest_utils.h>
#include <darwintest_multiprocess.h>

#define MACH_RCV_OPTIONS  (MACH_RCV_MSG | MACH_RCV_LARGE | MACH_RCV_LARGE_IDENTITY | \
	            MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AV) | \
	            MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0))

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true), T_META_NAMESPACE("xnu.ipc"));

typedef struct {
	mach_msg_header_t   header;
	mach_msg_mac_trailer_t  trailer;            // subtract this when sending
} ipc_simple_message;

static ipc_simple_message icm_request = {};

struct args {
	const char *progname;
	int verbose;
	int num_msgs;
	char *server_port_name;
	mach_port_t server_port;
	int request_msg_size;
	void *request_msg;
};

void parse_args(struct args *args);
void* create_buffer(int *buffer_size);
void client(struct args *args);
void server_setup(struct args* args);
void *server(void *thread_args);

void
parse_args(struct args *args)
{
	args->verbose = 0;
	args->server_port_name = "TEST_FILTER_POLICY";
	args->server_port = MACH_PORT_NULL;
	args->num_msgs = 1;
	args->request_msg_size = sizeof(ipc_simple_message);
	args->request_msg = &icm_request;
}

/* Create a mach IPC listener which will respond to the client's message */
void
server_setup(struct args* args)
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

/* Server process loop
 *
 * Listens for message.
 *
 */
void *
server(void *thread_args)
{
	mach_msg_header_t *request;
	mach_msg_option_t rcvoption = MACH_RCV_OPTIONS;
	kern_return_t ret;
	mach_msg_trailer_t *tlr = NULL;
	mach_msg_mac_trailer_t *mac_tlr;
	mach_msg_filter_id filter_policy_id = 0;
	pid_t pid = getpid();
	struct args *args = (struct args*)thread_args;

	request = (mach_msg_header_t *)args->request_msg;

	T_LOG("server(%d): Awaiting message", pid);
	ret = mach_msg(request,
	    rcvoption,
	    0,
	    sizeof(ipc_simple_message),
	    args->server_port,
	    MACH_MSG_TIMEOUT_NONE,
	    MACH_PORT_NULL);

	T_ASSERT_MACH_SUCCESS(ret, "server: mach_msg receive");
	T_ASSERT_EQ(request->msgh_id, 500, "server: msg id = %d", request->msgh_id);

	tlr = (mach_msg_trailer_t *)((unsigned char *)request +
	    round_msg(request->msgh_size));
	// The trailer should always be of format zero.
	if (tlr->msgh_trailer_type == MACH_MSG_TRAILER_FORMAT_0) {
		if (tlr->msgh_trailer_size >= sizeof(mach_msg_mac_trailer_t)) {
			mac_tlr = (mach_msg_mac_trailer_t *)tlr;
			filter_policy_id = mac_tlr->msgh_ad;
		}
	}

	T_LOG("server: received the filter policy id = %d", filter_policy_id);
	T_ASSERT_EQ(filter_policy_id, MACH_MSG_FILTER_POLICY_ALLOW, "server: filter policy allow sentinel");
	mach_msg_destroy(request);

	return NULL;
}

T_HELPER_DECL(client_not_filtered, "Send a message to the server which shouldn't be filtered")
{
	T_LOG("client(%d): Prepare to send a message", getpid());
	struct args args = {};
	mach_port_t bsport;

	parse_args(&args);
	args.request_msg_size -= sizeof(mach_msg_mac_trailer_t);

	//Find the bootstrap port
	kern_return_t ret = task_get_bootstrap_port(mach_task_self(), &bsport);
	T_ASSERT_MACH_SUCCESS(ret, "client: task_get_bootstrap_port()");

	//Look up the service port
	ret = bootstrap_look_up(bsport, (char *)args.server_port_name,
	    &args.server_port);
	T_ASSERT_MACH_SUCCESS(ret, "client: bootstrap_look_up()");

	//Construct the message
	mach_msg_header_t *request = (mach_msg_header_t *)args.request_msg;
	request->msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0, 0, 0);
	request->msgh_size = (mach_msg_size_t)args.request_msg_size;
	request->msgh_remote_port = args.server_port;
	request->msgh_local_port = MACH_PORT_NULL;
	request->msgh_id = 500;

	T_LOG("client: Sending request");
	ret = mach_msg_send(request);
	T_ASSERT_MACH_SUCCESS(ret, "client: mach_msg_send()");
}

T_DECL(filter_policy_id, "Send a message and check the filter policy id received in the trailer")
{
	struct args args = {};
	dt_helper_t helpers[1];
	pthread_t server_thread;

	T_SETUPBEGIN;
	parse_args(&args);
	server_setup(&args);
	T_SETUPEND;

	helpers[0] = dt_fork_helper("client_not_filtered");
	int ret = pthread_create(&server_thread, NULL, server, &args);
	T_ASSERT_POSIX_SUCCESS(ret, "pthread_create server_thread");
	pthread_detach(server_thread);

	dt_run_helpers(helpers, 1, 30);
}
