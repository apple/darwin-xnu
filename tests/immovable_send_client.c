#include <darwintest.h>
#include <servers/bootstrap.h>
#include <mach/mach.h>
#include <mach/message.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <darwintest_multiprocess.h>
#include <IOKit/IOKitLib.h>

typedef struct {
	mach_msg_header_t   header;
	mach_msg_body_t     body;
	mach_msg_port_descriptor_t port_descriptor;
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

static void
parse_args(struct args *args)
{
	args->verbose = 0;
	args->voucher = 0;
	args->server_port_name = "TEST_IMMOVABLE_SEND";
	args->server_port = MACH_PORT_NULL;
	args->reply_port = MACH_PORT_NULL;
	args->voucher_port = MACH_PORT_NULL;
	args->num_msgs = 1;
	args->request_msg_size = sizeof(ipc_complex_message) - sizeof(mach_msg_trailer_t);
	//args->reply_msg_size = sizeof(ipc_complex_message2) - sizeof(mach_msg_trailer_t);
	args->request_msg = &icm_request;
	args->reply_msg = NULL;
	args->client_pid = getpid();
}

int
main()
{
	struct args client_args = {};
	parse_args(&client_args);

	/* Find the bootstrap port */
	mach_port_t bsport;
	kern_return_t ret = task_get_bootstrap_port(mach_task_self(), &bsport);
	if (ret) {
		mach_error("client: task_get_bootstrap_port()", ret);
		exit(1);
	}

	printf("client: Look up bootstrap service port\n");
	ret = bootstrap_look_up(bsport, client_args.server_port_name,
	    &client_args.server_port);
	if (ret) {
		mach_error("client: bootstrap_look_up()", ret);
		exit(1);
	}

	printf("client: Look up the ioconnect service port to be sent\n");
	io_service_t amfi = IO_OBJECT_NULL;
	io_connect_t connect = IO_OBJECT_NULL;
	IOReturn ioret;

	amfi = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("AppleMobileFileIntegrity"));
	if (amfi == IO_OBJECT_NULL) {
		fprintf(stderr, "client: unable to find AppleMobileFileIntegrity service\n");
		exit(1);
	}
	ioret = IOServiceOpen(amfi, mach_task_self(), 0, &connect);
	if (ioret != kIOReturnSuccess) {
		fprintf(stderr, "client: unable to open user client: 0x%x\n", ret);
		exit(1);
	}

	printf("client: Found the matching io_connect port = %d\n", connect);

	/* Construct the message */
	mach_msg_header_t *request = (mach_msg_header_t *)client_args.request_msg;
	request->msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND, 0,
	    0, 0) | MACH_MSGH_BITS_COMPLEX;
	request->msgh_size = (mach_msg_size_t)client_args.request_msg_size;
	request->msgh_remote_port = client_args.server_port;
	request->msgh_local_port = MACH_PORT_NULL;
	request->msgh_id = 1;

	ipc_complex_message *complexmsg = (ipc_complex_message *)request;
	complexmsg->body.msgh_descriptor_count = 1;
	complexmsg->port_descriptor.name = connect;
	complexmsg->port_descriptor.disposition = MACH_MSG_TYPE_MOVE_SEND;
	complexmsg->port_descriptor.type = MACH_MSG_PORT_DESCRIPTOR;

	mach_msg_option_t option = MACH_SEND_MSG;

	printf("client: Sending request (expecting it to fail) \n");
	mach_msg_return_t mret = mach_msg(request,
	    option,
	    (mach_msg_size_t)client_args.request_msg_size,
	    0,
	    MACH_PORT_NULL,
	    MACH_MSG_TIMEOUT_NONE,
	    MACH_PORT_NULL);

	printf("client: mach_msg returned %x\n", mret);
	if (mret != MACH_SEND_INVALID_RIGHT) {
		mach_error("client: mach_msg", mret);
		exit(1);
	}

	printf("It should never reach here\n");

	return 0;
}
