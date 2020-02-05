#include <darwintest.h>
#include <servers/bootstrap.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <unistd.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

typedef struct {
	mach_msg_header_t   header;
	mach_msg_body_t     body;
	mach_msg_guarded_port_descriptor_t guarded_port_descriptor1;
	mach_msg_guarded_port_descriptor_t guarded_port_descriptor2;
	mach_msg_trailer_t  trailer;            // subtract this when sending
} ipc_complex_message;

static ipc_complex_message icm_request = {};

struct args {
	const char *progname;
	int verbose;
	int voucher;
	int num_msgs;
	const char *server_port_name;
	mach_port_t server_port;
	mach_port_t reply_port;
	mach_port_t voucher_port;
	int request_msg_size;
	void *request_msg;
	int reply_msg_size;
	void *reply_msg;
	mach_port_t sp_voucher_port;
	uint32_t persona_id;
	long client_pid;
};

void parse_args(struct args *args);
void* create_buffer(int *buffer_size);
void client(struct args *args);
void server_setup(struct args* args);
void server(struct args *args);

void
parse_args(struct args *args)
{
	args->verbose = 0;
	args->voucher = 0;
	args->server_port_name = "TEST";
	args->server_port = MACH_PORT_NULL;
	args->reply_port = MACH_PORT_NULL;
	args->voucher_port = MACH_PORT_NULL;
	args->num_msgs = 1;
	args->request_msg_size = sizeof(ipc_complex_message);
	args->request_msg = &icm_request;
	args->client_pid = getpid();
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
void
server(struct args *args)
{
	mach_msg_header_t *request;
	mach_msg_option_t rcvoption;
	kern_return_t ret;

	request = (mach_msg_header_t *)args->request_msg;

	rcvoption = MACH_RCV_MSG | MACH_RCV_INTERRUPT | MACH_RCV_GUARDED_DESC;

	T_LOG("server: Awaiting message\n");
	ret = mach_msg(request,
	    rcvoption,
	    0,
	    sizeof(ipc_complex_message),
	    args->server_port,
	    MACH_MSG_TIMEOUT_NONE,
	    MACH_PORT_NULL);

	T_ASSERT_MACH_SUCCESS(ret, "server: mach_msg receive");

	ipc_complex_message *request_complexmsg = (ipc_complex_message *)request;
	T_ASSERT_NE(request_complexmsg->guarded_port_descriptor1.name, 0, "server: Should not receive mach_port_null; name = %x", request_complexmsg->guarded_port_descriptor1.name);
	T_ASSERT_EQ(request_complexmsg->guarded_port_descriptor1.type, MACH_MSG_GUARDED_PORT_DESCRIPTOR, "server: Received a guarded port descriptor");
	T_ASSERT_EQ(request_complexmsg->guarded_port_descriptor1.disposition, MACH_MSG_TYPE_PORT_RECEIVE, "server: Received a receive right");
	T_ASSERT_EQ(request_complexmsg->guarded_port_descriptor1.context, (unsigned long)request, "server: Received a port with correct context = %p", request);
	T_LOG("Guard flags = %d", request_complexmsg->guarded_port_descriptor1.flags);

	T_ASSERT_NE(request_complexmsg->guarded_port_descriptor2.name, 0, "server: Should not receive mach_port_null; name = %x", request_complexmsg->guarded_port_descriptor2.name);
	T_ASSERT_EQ(request_complexmsg->guarded_port_descriptor2.type, MACH_MSG_GUARDED_PORT_DESCRIPTOR, "server: Received a guarded port descriptor");
	T_ASSERT_EQ(request_complexmsg->guarded_port_descriptor2.disposition, MACH_MSG_TYPE_PORT_RECEIVE, "server: Received a receive right");
	T_ASSERT_EQ(request_complexmsg->guarded_port_descriptor2.context, (unsigned long)request, "server: Received a port with correct context = %p", request);

	mach_port_status_t status;
	mach_msg_type_number_t status_size = MACH_PORT_RECEIVE_STATUS_COUNT;

	kern_return_t kr = mach_port_get_attributes(mach_task_self(), request_complexmsg->guarded_port_descriptor1.name,
	    MACH_PORT_RECEIVE_STATUS, (mach_port_info_t)&status, &status_size);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_get_attributes for descriptor 1");
	T_LOG("Status flags %d", status.mps_flags);
	T_ASSERT_NE(0, (status.mps_flags & MACH_PORT_STATUS_FLAG_GUARD_IMMOVABLE_RECEIVE), "Imm rcv bit is set for descriptor1");

	kr = mach_port_get_attributes(mach_task_self(), request_complexmsg->guarded_port_descriptor2.name,
	    MACH_PORT_RECEIVE_STATUS, (mach_port_info_t)&status, &status_size);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_get_attributes for descriptor 2");
	T_LOG("Status flags %d", status.mps_flags);
	T_ASSERT_NE(0, (status.mps_flags & MACH_PORT_STATUS_FLAG_GUARD_IMMOVABLE_RECEIVE), "Imm rcv bit is set for descriptor2");

	mach_msg_destroy(request);
}

void
client(struct args *args)
{
	//Find the bootstrap port
	mach_port_t bsport;
	mach_port_t guarded_port;
	mach_port_t unguarded_port;

	kern_return_t ret = task_get_bootstrap_port(mach_task_self(), &bsport);
	T_ASSERT_MACH_SUCCESS(ret, "client: task_get_bootstrap_port()");

	//Look up the service port
	ret = bootstrap_look_up(bsport, (char *)args->server_port_name,
	    &args->server_port);
	T_ASSERT_MACH_SUCCESS(ret, "client: bootstrap_look_up()");

	//Create the unguarded port
	ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE,
	    &unguarded_port);
	T_ASSERT_MACH_SUCCESS(ret, "client: mach_port_allocate() reply port");

	mach_port_options_t opts = {
		.flags = MPO_CONTEXT_AS_GUARD
	};

	ret = mach_port_construct(mach_task_self(), &opts, 0x10, &guarded_port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "mach_port_construct");

	//Construct the message
	mach_msg_header_t *request = (mach_msg_header_t *)args->request_msg;
	request->msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE,
	    0, 0) | MACH_MSGH_BITS_COMPLEX;
	request->msgh_size = (mach_msg_size_t)args->request_msg_size;
	request->msgh_remote_port = args->server_port;
	request->msgh_local_port = args->reply_port;
	request->msgh_id = 1;

	ipc_complex_message *complexmsg = (ipc_complex_message *)request;
	complexmsg->body.msgh_descriptor_count = 2;
	complexmsg->guarded_port_descriptor1.name = guarded_port;
	complexmsg->guarded_port_descriptor1.disposition = MACH_MSG_TYPE_MOVE_RECEIVE;
	complexmsg->guarded_port_descriptor1.flags = MACH_MSG_GUARD_FLAGS_IMMOVABLE_RECEIVE;
	complexmsg->guarded_port_descriptor1.context = 0x10;
	complexmsg->guarded_port_descriptor1.type = MACH_MSG_GUARDED_PORT_DESCRIPTOR;

	complexmsg->guarded_port_descriptor2.name = unguarded_port;
	complexmsg->guarded_port_descriptor2.disposition = MACH_MSG_TYPE_MOVE_RECEIVE;
	complexmsg->guarded_port_descriptor2.flags = MACH_MSG_GUARD_FLAGS_IMMOVABLE_RECEIVE | MACH_MSG_GUARD_FLAGS_UNGUARDED_ON_SEND;
	complexmsg->guarded_port_descriptor2.context = 0;
	complexmsg->guarded_port_descriptor2.type = MACH_MSG_GUARDED_PORT_DESCRIPTOR;

	mach_msg_option_t option = MACH_SEND_MSG;

	//Listen for the reply on the reply port
	T_LOG("client: Sending request\n");
	ret = mach_msg(request,
	    option,
	    (mach_msg_size_t)args->request_msg_size,
	    0,
	    MACH_PORT_NULL,
	    MACH_MSG_TIMEOUT_NONE,
	    MACH_PORT_NULL);
	T_ASSERT_MACH_SUCCESS(ret, "client: mach_msg_overwrite()");
}

T_DECL(mo_immovable_receive, "Send a message containing a guard port descriptor for an immovable receive right")
{
	struct args args = {};
	parse_args(&args);
	args.request_msg_size -= sizeof(mach_msg_trailer_t);
	args.reply_msg_size -= sizeof(mach_msg_trailer_t);

	//Create the server
	pid_t pid = fork();
	if (pid == 0) {
		T_LOG("Server is up");
		server_setup(&args);
		server(&args);
		exit(0);
	}

	sleep(2);
	T_LOG("Preparing client to send a request");
	client(&args);
	T_ASSERT_POSIX_SUCCESS(waitpid(pid, NULL, 0), "waitpid()");
}
