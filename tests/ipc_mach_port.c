#include <darwintest.h>
#include <darwintest_multiprocess.h>
#include <launch.h>
#include <servers/bootstrap.h>
#include <sys/sysctl.h>
#include "exc_helpers.h"

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipc"),
	T_META_RUN_CONCURRENTLY(true));

#pragma mark - helpers

#define SERVICE_NAME  "com.apple.xnu.test.mach_port"

struct one_port_msg {
	mach_msg_header_t          header;
	mach_msg_body_t            body;
	mach_msg_port_descriptor_t port_descriptor;
	mach_msg_trailer_t         trailer;            // subtract this when sending
};

static mach_port_t
server_checkin(void)
{
	mach_port_t mp;
	kern_return_t kr;

	kr = bootstrap_check_in(bootstrap_port, SERVICE_NAME, &mp);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "bootstrap_check_in");
	return mp;
}

static mach_port_t
server_lookup(void)
{
	mach_port_t mp;
	kern_return_t kr;

	kr = bootstrap_look_up(bootstrap_port, SERVICE_NAME, &mp);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "bootstrap_look_up");
	return mp;
}

static mach_port_t
make_sr_port(void)
{
	mach_port_options_t opts = {
		.flags = MPO_INSERT_SEND_RIGHT,
	};
	kern_return_t kr;
	mach_port_t port;

	kr = mach_port_construct(mach_task_self(), &opts, 0ull, &port);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "mach_port_construct");
	return port;
}

static void
destroy_port(mach_port_t port, bool receive, int srights)
{
	kern_return_t kr;

	if (srights) {
		kr = mach_port_mod_refs(mach_task_self(), port,
		    MACH_PORT_RIGHT_SEND, -srights);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "srights -= %d", srights);
	}
	if (receive) {
		kr = mach_port_mod_refs(mach_task_self(), port,
		    MACH_PORT_RIGHT_RECEIVE, -1);
		T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "receive -= 1");
	}
}

static void
send_port(
	mach_msg_id_t        id,
	mach_port_t          dest,
	mach_port_t          right,
	mach_msg_type_name_t disp)
{
	struct one_port_msg msg = {
		.header = {
			.msgh_remote_port = dest,
			.msgh_bits        = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_COPY_SEND,
	    0, MACH_MSG_TYPE_MOVE_SEND, MACH_MSGH_BITS_COMPLEX),
			.msgh_id          = id,
			.msgh_size        = offsetof(struct one_port_msg, trailer),
		},
		.body = {
			.msgh_descriptor_count = 1,
		},
		.port_descriptor = {
			.name        = right,
			.disposition = disp,
			.type        = MACH_MSG_PORT_DESCRIPTOR,
		},
	};
	kern_return_t kr;

	kr = mach_msg(&msg.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
	    msg.header.msgh_size, 0, MACH_PORT_NULL, 10000, 0);

	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "send(%d)", id);
}

#pragma mark - basic test about right deduplication

static mach_port_t
receive_port(
	mach_msg_id_t        expected_id,
	mach_port_t          rcv_port,
	mach_msg_type_name_t expected_disp)
{
	struct one_port_msg msg = { };
	kern_return_t kr;

	T_LOG("waiting for message %d", expected_id);
	kr = mach_msg(&msg.header, MACH_RCV_MSG, 0,
	    sizeof(msg), rcv_port, 0, 0);
	T_QUIET; T_ASSERT_MACH_SUCCESS(kr, "receive(%d)", expected_id);
	T_QUIET; T_ASSERT_EQ(msg.header.msgh_id, expected_id, "message id matches");
	T_QUIET; T_ASSERT_NE(msg.header.msgh_bits & MACH_MSGH_BITS_COMPLEX, 0,
	    "message is complex");
	T_QUIET; T_ASSERT_EQ(msg.body.msgh_descriptor_count, 1, "message has one right");
	T_QUIET; T_ASSERT_EQ(msg.port_descriptor.disposition, expected_disp,
	    "port has right disposition");
	return msg.port_descriptor.name;
}

T_HELPER_DECL(right_dedup_server, "right_dedup_server")
{
	mach_port_t svc_port = server_checkin();
	mach_port_t ports[3];

	ports[0] = receive_port(1, svc_port, MACH_MSG_TYPE_MOVE_RECEIVE);
	ports[1] = receive_port(2, svc_port, MACH_MSG_TYPE_MOVE_SEND);
	ports[2] = receive_port(3, svc_port, MACH_MSG_TYPE_MOVE_SEND);
	T_ASSERT_EQ(ports[0], ports[1], "receive, send, send");
	T_ASSERT_EQ(ports[0], ports[2], "receive, send, send");
	destroy_port(ports[0], true, 2);

	ports[0] = receive_port(4, svc_port, MACH_MSG_TYPE_MOVE_SEND);
	ports[1] = receive_port(5, svc_port, MACH_MSG_TYPE_MOVE_RECEIVE);
	ports[2] = receive_port(6, svc_port, MACH_MSG_TYPE_MOVE_SEND);
	T_ASSERT_EQ(ports[0], ports[1], "send, receive, send");
	T_ASSERT_EQ(ports[0], ports[2], "send, receive, send");
	destroy_port(ports[0], true, 2);

	ports[0] = receive_port(7, svc_port, MACH_MSG_TYPE_MOVE_SEND);
	ports[1] = receive_port(8, svc_port, MACH_MSG_TYPE_MOVE_SEND);
	ports[2] = receive_port(9, svc_port, MACH_MSG_TYPE_MOVE_RECEIVE);
	T_ASSERT_EQ(ports[0], ports[1], "send, send, receive");
	T_ASSERT_EQ(ports[0], ports[2], "send, send, receive");
	destroy_port(ports[0], true, 2);

	T_END;
}

T_HELPER_DECL(right_dedup_client, "right_dedup_client")
{
	mach_port_t svc_port = server_lookup();
	mach_port_t port;

	port = make_sr_port();
	send_port(1, svc_port, port, MACH_MSG_TYPE_MOVE_RECEIVE);
	send_port(2, svc_port, port, MACH_MSG_TYPE_COPY_SEND);
	send_port(3, svc_port, port, MACH_MSG_TYPE_MOVE_SEND);

	port = make_sr_port();
	send_port(4, svc_port, port, MACH_MSG_TYPE_COPY_SEND);
	send_port(5, svc_port, port, MACH_MSG_TYPE_MOVE_RECEIVE);
	send_port(6, svc_port, port, MACH_MSG_TYPE_MOVE_SEND);

	port = make_sr_port();
	send_port(7, svc_port, port, MACH_MSG_TYPE_COPY_SEND);
	send_port(8, svc_port, port, MACH_MSG_TYPE_MOVE_SEND);
	send_port(9, svc_port, port, MACH_MSG_TYPE_MOVE_RECEIVE);
}

T_DECL(right_dedup, "make sure right deduplication works")
{
	dt_helper_t helpers[] = {
		dt_launchd_helper_domain("com.apple.xnu.test.mach_port.plist",
	    "right_dedup_server", NULL, LAUNCH_SYSTEM_DOMAIN),
		dt_fork_helper("right_dedup_client"),
	};
	dt_run_helpers(helpers, 2, 600);
}
