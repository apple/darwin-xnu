#include "mach_vm_tests.h"
boolean_t debug = TRUE;

int
main()
{
	dispatch_source_t parentSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_PROC, (uintptr_t)getppid(), DISPATCH_PROC_EXIT, NULL);
	dispatch_source_set_event_handler(parentSource, ^{
		T_LOG("Event handler got invoked. Parent process died. Exiting");
		exit(1);
	});
	dispatch_activate(parentSource);

	const char *serviceName = MACH_VM_TEST_SERVICE_NAME;

	kern_return_t ret;
	mach_port_t bootstrap;
	task_get_bootstrap_port(mach_task_self(), &bootstrap);

	mach_port_t port;
	mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated"
	ret = bootstrap_register2(bootstrap, (char *)serviceName, port, BOOTSTRAP_ALLOW_LOOKUP);
#pragma clang diagnostic pop

	mach_msg_size_t messageSize = sizeof(ipc_message_t) + sizeof(mach_msg_trailer_t) + 64;
	ipc_message_t *message = (ipc_message_t *)calloc(1, messageSize);

	message->header.msgh_bits = MACH_MSGH_BITS_ZERO;
	message->header.msgh_size = messageSize;
	message->header.msgh_remote_port = MACH_PORT_NULL;
	message->header.msgh_local_port = port;

	ret = mach_msg(&message->header, MACH_RCV_MSG, 0, messageSize, port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	if (ret == KERN_SUCCESS) {
		if (MACH_MSGH_BITS_REMOTE(message->header.msgh_bits) == MACH_MSG_TYPE_PORT_SEND) {
			persistentReplyPort = message->header.msgh_remote_port;
			mach_port_mod_refs(mach_task_self(), persistentReplyPort, MACH_PORT_RIGHT_SEND, 1);
		}
	}

	mach_server_make_memory_entry(port);
	mach_server_remap(port);
	mach_server_read(port, VM_OP_READ);
	//mach_server_read(port, VM_OP_WRITE);
	mach_server_read(port, VM_OP_READ_OVERWRITE);


	message->header.msgh_bits = MACH_MSGH_BITS_ZERO;
	message->header.msgh_size = messageSize;
	message->header.msgh_remote_port = MACH_PORT_NULL;
	message->header.msgh_local_port = port;

	mach_server_construct_header(message, port);
	message->vm_op = VM_OP_EXIT;
	ret = mach_msg(&message->header, MACH_SEND_MSG, message->header.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	if (ret != KERN_SUCCESS) {
		T_LOG("ERROR: Failed to send message to client: (%d) %s\n", ret, mach_error_string(ret));
		return 1;
	}

	(void)parentSource;

	return 0;
}
