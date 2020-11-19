#include "mach_vm_tests.h"

T_GLOBAL_META(T_META_NAMESPACE("xnu.vm"));

extern char **environ;

static void
spawn_process(char *action, char *serviceName, char *extraArg,
    mach_port_t *server_Port, pid_t *serverPid, boolean_t use4k);

static void mach_client(void);

mach_port_t serverPort;
static pid_t serverPid;

boolean_t debug = TRUE;

void
spawn_process(char *action, char *serviceName, char *extraArg,
    mach_port_t *server_Port, pid_t *server_Pid, boolean_t use4k)
{
	char buffer[PATH_MAX];
	char *argv[10] = {0};
	int arg_index = 0;
	pid_t pid = -1;
	int r = proc_pidpath(getpid(), buffer, sizeof(buffer));
	T_ASSERT_NE(r, -1, "proc_pidpath");
	r = (int)strlcat(buffer, "_server", sizeof(buffer));
	T_ASSERT_LT(r, (int)sizeof(buffer), "strlcat");

	if (use4k) {
		int supported = 0;
		size_t supported_size = sizeof(supported);

		r = sysctlbyname("debug.vm_mixed_pagesize_supported", &supported, &supported_size, NULL, 0);
		if (r == 0 && supported) {
			T_LOG("Using %s to spawn process with 4k", VM_SPAWN_TOOL);
			argv[arg_index++] = VM_SPAWN_TOOL;
		} else {
			/*
			 * We didnt find debug.vm.mixed_page.supported OR its set to 0.
			 * Skip the test.
			 */
			T_SKIP("Hardware doesn't support 4K pages, skipping test...");
			exit(0);
		}
	}
	argv[arg_index++] = (char *)&buffer[0];
	argv[arg_index++] = (char *)action;
	argv[arg_index++] = (char *)serviceName;
	argv[arg_index++] = (char *)extraArg;
	argv[arg_index++] = NULL;

	printf("posix_spawn with argv: ");
	for (r = 0; r <= arg_index; r++) {
		printf("%s ", argv[r]);
	}
	printf("\n");

	T_LOG("Spawning %s process(%s) with service name %s at %s\n", action, buffer, serviceName, buffer);


	posix_spawn_file_actions_t actions;
	posix_spawn_file_actions_init(&actions);

	T_ASSERT_POSIX_ZERO(posix_spawn(&pid, buffer, &actions, NULL, argv, environ), "spawn %s", serviceName);
	posix_spawn_file_actions_destroy(&actions);

	kern_return_t ret;
	mach_port_t servicePort;
	int attempts = 0;
	const int kMaxAttempts = 10;
	do {
		sleep(1);
		ret = bootstrap_look_up(bootstrap_port, serviceName, &servicePort);
		attempts++;
	} while (ret == BOOTSTRAP_UNKNOWN_SERVICE && attempts < kMaxAttempts);

	if (ret != KERN_SUCCESS) {
		printf("ERROR: Failed bootstrap lookup for process with mach service name '%s': (%d) %s\n", serviceName, ret, mach_error_string(ret));
		if (pid > 0) {
			kill(pid, SIGKILL);
		}
		T_FAIL("Failed bootstrap lookup for process with mach service");
	}

	*server_Port = servicePort;
	*server_Pid = pid;
	T_LOG("Server pid=%d port 0x%x", pid, servicePort);
}




void
mach_client()
{
	mach_port_t replyPort;
	T_ASSERT_POSIX_ZERO(mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &replyPort), "create recieve port");
	T_ASSERT_POSIX_ZERO(mach_port_insert_right(mach_task_self(), replyPort, replyPort, MACH_MSG_TYPE_MAKE_SEND), "insert send port");

	ipc_message_t message;
	bzero(&message, sizeof(message));
	message.header.msgh_id = 1;

	message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_COPY_SEND);
	message.header.msgh_remote_port = serverPort;
	message.header.msgh_local_port = replyPort;
	message.header.msgh_size = sizeof(message);

	/* reply creation is not necessary in this case.
	 *  mach_msg_size_t replySize = sizeof(ipc_message_t) + sizeof(mach_msg_trailer_t) + 64;
	 *  ipc_message_t *reply = calloc(1, replySize);
	 */
	T_LOG("sending message to %d of size %u", message.header.msgh_remote_port, message.header.msgh_size);
	kern_return_t ret = mach_msg(&message.header, MACH_SEND_MSG, message.header.msgh_size, 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	T_ASSERT_MACH_SUCCESS(ret, "mach_msg to serverProcess");
	mach_vm_client(replyPort);
	T_LOG("Sending SIGKILL to server(%d)", serverPid);
	kill(serverPid, SIGKILL);
}

T_DECL(memory_share_tests,
    "test vm memory sharing between client and server process with different process PAGE_SIZE",
    T_META_ASROOT(true))
{
	boolean_t use4k = FALSE;
	char serviceName[64];

	struct sigaction action = {
		.sa_handler = SIG_IGN,
		.sa_flags = SA_NOCLDWAIT
	};
	sigaction(SIGCHLD, &action, NULL);

	if (getenv("USE4K")) {
		use4k = TRUE;
	}

	if (getenv("QUIET")) {
		debug = FALSE;
	}

	T_LOG("running with use4k=%d debug=%d", use4k, (int)debug);

	strcpy(serviceName, MACH_VM_TEST_SERVICE_NAME);

	spawn_process("machserver", serviceName, NULL, &serverPort, &serverPid, use4k);
	mach_client();
}

T_DECL_REF(memory_share_tests_4k, memory_share_tests, "vm memory sharing with 4k processes",
    T_META_ENVVAR("USE4K=YES"),
    T_META_ASROOT(true)
    );
