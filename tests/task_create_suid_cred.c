#include <mach/mach.h>

#include <bootstrap.h>
#include <darwintest.h>
#include <darwintest_multiprocess.h>
#include <spawn.h>
#include <unistd.h>

#if defined(UNENTITLED)

/*
 * Creating an suid credential should fail without an entitlement.
 */
T_DECL(task_create_suid_cred_unentitled, "task_create_suid_cred (no entitlment)", T_META_ASROOT(true))
{
	kern_return_t ret = KERN_FAILURE;
	suid_cred_t sc = SUID_CRED_NULL;

	ret = task_create_suid_cred(mach_task_self(), "/usr/bin/id", 0, &sc);
	T_ASSERT_MACH_ERROR(ret, KERN_NO_ACCESS, "create a new suid cred for id (no entitlement)");
}

#else /* ENTITLED */

extern char **environ;
static const char *server_name = "com.apple.xnu.test.task_create_suid_cred";

/*
 * This is a positive test case which spawns /usr/bin/id with a properly created
 * suid credential and verifies that it correctly produces "euid=0"
 * Not running as root.
 */
static void
test_id_cred(suid_cred_t sc_id)
{
	posix_spawnattr_t attr;
	posix_spawn_file_actions_t file_actions;
	pid_t pid = -1;
	int status = -1;
	char template[] = "/tmp/suid_cred.XXXXXX";
	char *path = NULL;
	FILE *file = NULL;
	char *line = NULL;
	size_t linecap = 0;
	ssize_t linelen = 0;
	char *id[] = {"/usr/bin/id", NULL};
	kern_return_t ret = KERN_FAILURE;

	/* Send stdout to a temporary file. */
	path = mktemp(template);
	T_QUIET; T_ASSERT_NOTNULL(path, NULL);

	ret = posix_spawn_file_actions_init(&file_actions);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, NULL);

	ret = posix_spawn_file_actions_addopen(&file_actions, 1, path,
	    O_WRONLY | O_CREAT | O_TRUNC, 0666);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, NULL);

	ret = posix_spawnattr_init(&attr);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, NULL);
	T_QUIET; T_ASSERT_NOTNULL(attr, NULL);

	// Attach the suid cred port
	ret = posix_spawnattr_setsuidcredport_np(&attr, sc_id);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, NULL);

	ret = posix_spawnp(&pid, id[0], &file_actions, &attr, id, environ);
	T_ASSERT_POSIX_ZERO(ret, "spawn with suid cred");

	ret = posix_spawnattr_destroy(&attr);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, NULL);

	ret = posix_spawn_file_actions_destroy(&file_actions);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, NULL);

	// Wait for id to finish executing and exit.
	do {
		ret = waitpid(pid, &status, 0);
	} while (ret < 0 && errno == EINTR);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(ret, NULL);

	// Read from the temp file and verify that euid is 0.
	file = fopen(path, "re");
	T_QUIET; T_ASSERT_NOTNULL(file, NULL);

	linelen = getline(&line, &linecap, file);
	T_QUIET; T_ASSERT_GT_LONG(linelen, 0L, NULL);

	T_ASSERT_NOTNULL(strstr(line, "euid=0"), "verify that euid is zero");

	free(line);
	ret = fclose(file);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, NULL);

	ret = unlink(path);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, NULL);
}

/*
 * This is a negative test case which tries to spawn /usr/bin/id with a
 * previously used credential.  It is expected that posix_spawn() fails.
 * sc_id should have already been used to successfully spawn /usr/bin/id.
 */
static void
test_id_cred_reuse(suid_cred_t sc_id)
{
	posix_spawnattr_t attr;
	char *id[] = {"/usr/bin/id", NULL};
	kern_return_t ret = KERN_FAILURE;

	ret = posix_spawnattr_init(&attr);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, NULL);
	T_QUIET; T_ASSERT_NOTNULL(attr, NULL);

	// Attach the suid cred port
	ret = posix_spawnattr_setsuidcredport_np(&attr, sc_id);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, NULL);

	ret = posix_spawnp(NULL, id[0], NULL, &attr, id, environ);
	T_ASSERT_NE(ret, 0, "spawn with used suid cred");

	ret = posix_spawnattr_destroy(&attr);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, NULL);
}

/*
 * This is a negative test case which tries to spawn /usr/bin/id with a
 * credential for /bin/ls. It is expected that posix_spawn() fails.
 */
static void
test_ls_cred(suid_cred_t sc_ls)
{
	posix_spawnattr_t attr;
	char *id[] = {"/usr/bin/id", NULL};
	kern_return_t ret = KERN_FAILURE;

	ret = posix_spawnattr_init(&attr);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, NULL);
	T_QUIET; T_ASSERT_NOTNULL(attr, NULL);

	// Attach the suid cred port
	ret = posix_spawnattr_setsuidcredport_np(&attr, sc_ls);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, NULL);

	ret = posix_spawnp(NULL, id[0], NULL, &attr, id, environ);
	T_ASSERT_NE(ret, 0, "spawn with bad suid cred");

	ret = posix_spawnattr_destroy(&attr);
	T_QUIET; T_ASSERT_POSIX_ZERO(ret, NULL);
}

/*
 * The privileged/entitled "server" which creates suid credentials to pass to a
 * client. Two creds are created, one for /usr/bin/id and the other for /bin/ls.
 * It waits for the client to contact and replies with the above ports.
 */
T_HELPER_DECL(suid_cred_server_helper, "suid cred server")
{
	mach_port_t server_port = MACH_PORT_NULL;
	kern_return_t ret = KERN_FAILURE;
	suid_cred_t sc_id = SUID_CRED_NULL;
	suid_cred_t sc_ls = SUID_CRED_NULL;
	mach_msg_empty_rcv_t rmsg = {};
	struct {
		mach_msg_header_t          header;
		mach_msg_body_t            body;
		mach_msg_port_descriptor_t id_port;
		mach_msg_port_descriptor_t ls_port;
	} smsg = {};

	T_SETUPBEGIN;

	ret = bootstrap_check_in(bootstrap_port, server_name, &server_port);
	T_ASSERT_MACH_SUCCESS(ret, NULL);

	T_SETUPEND;

	// Wait for a message to reply to.
	rmsg.header.msgh_size = sizeof(rmsg);
	rmsg.header.msgh_local_port = server_port;

	ret = mach_msg_receive(&rmsg.header);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, NULL);

	// Setup the reply.
	smsg.header.msgh_remote_port = rmsg.header.msgh_remote_port;
	smsg.header.msgh_local_port = MACH_PORT_NULL;
	smsg.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0) | MACH_MSGH_BITS_COMPLEX;
	smsg.header.msgh_size = sizeof(smsg);

	smsg.body.msgh_descriptor_count = 2;

	// Create an suid cred for 'id'
	ret = task_create_suid_cred(mach_task_self(), "/usr/bin/id", 0, &sc_id);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "create a new suid cred for id");
	T_QUIET; T_ASSERT_NE(sc_id, SUID_CRED_NULL, NULL);

	smsg.id_port.name = sc_id;
	smsg.id_port.disposition = MACH_MSG_TYPE_COPY_SEND;
	smsg.id_port.type = MACH_MSG_PORT_DESCRIPTOR;

	// Create an suid cred for 'ls'
	ret = task_create_suid_cred(mach_task_self(), "/bin/ls", 0, &sc_ls);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, "create a new suid cred for ls");
	T_QUIET; T_ASSERT_NE(sc_ls, SUID_CRED_NULL, NULL);

	smsg.ls_port.name = sc_ls;
	smsg.ls_port.disposition = MACH_MSG_TYPE_COPY_SEND;
	smsg.ls_port.type = MACH_MSG_PORT_DESCRIPTOR;

	ret = mach_msg_send(&smsg.header);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, NULL);
}

/*
 * The unprivileged "client" which requests suid credentials from the "server",
 * and runs some test cases with those credentials:
 *  - A positive test case to spawn something with euid 0
 *  - A negative test case to check that a cred can't be used twice
 *  - A negative test case to check that only the approved binary can be used
 *  with the credential.
 */
T_HELPER_DECL(suid_cred_client_helper, "suid cred client")
{
	mach_port_t server_port = MACH_PORT_NULL;
	mach_port_t client_port = MACH_PORT_NULL;
	kern_return_t ret = KERN_FAILURE;
	suid_cred_t sc_id = SUID_CRED_NULL;
	suid_cred_t sc_ls = SUID_CRED_NULL;
	mach_msg_empty_send_t smsg = {};
	struct {
		mach_msg_header_t          header;
		mach_msg_body_t            body;
		mach_msg_port_descriptor_t id_port;
		mach_msg_port_descriptor_t ls_port;
		mach_msg_trailer_t         trailer;
	} rmsg = {};

	uid_t euid = geteuid();

	T_SETUPBEGIN;

	// Make sure the effective UID is non-root.
	if (euid == 0) {
		ret = setuid(501);
		T_ASSERT_POSIX_ZERO(ret, "setuid");
	}

	/*
	 * As this can race with the "server" starting, give it time to
	 * start up.
	 */
	for (int i = 0; i < 30; i++) {
		ret = bootstrap_look_up(bootstrap_port, server_name, &server_port);
		if (ret != BOOTSTRAP_UNKNOWN_SERVICE) {
			break;
		}
		sleep(1);
	}

	T_QUIET; T_ASSERT_NE(server_port, MACH_PORT_NULL, NULL);

	// Create a report to receive the reply on.
	ret = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &client_port);
	T_ASSERT_MACH_SUCCESS(ret, NULL);

	T_SETUPEND;

	// Request the SUID cred ports
	smsg.header.msgh_remote_port = server_port;
	smsg.header.msgh_local_port = client_port;
	smsg.header.msgh_bits = MACH_MSGH_BITS_SET(MACH_MSG_TYPE_MOVE_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE, 0, 0);
	smsg.header.msgh_size = sizeof(smsg);

	ret = mach_msg_send(&smsg.header);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, NULL);

	// Wait for the reply.
	rmsg.header.msgh_size = sizeof(rmsg);
	rmsg.header.msgh_local_port = client_port;

	ret = mach_msg_receive(&rmsg.header);
	T_QUIET; T_ASSERT_MACH_SUCCESS(ret, NULL);

	sc_id = rmsg.id_port.name;
	T_QUIET; T_ASSERT_NE(sc_id, SUID_CRED_NULL, NULL);
	test_id_cred(sc_id);
	test_id_cred_reuse(sc_id);

	sc_ls = rmsg.ls_port.name;
	T_QUIET; T_ASSERT_NE(sc_ls, SUID_CRED_NULL, NULL);
	test_ls_cred(sc_ls);
}

T_DECL(task_create_suid_cred, "task_create_suid_cred", T_META_ASROOT(true))
{
	dt_helper_t helpers[] = {
		dt_launchd_helper_domain("com.apple.xnu.test.task_create_suid_cred.plist",
	    "suid_cred_server_helper", NULL, LAUNCH_SYSTEM_DOMAIN),
		dt_fork_helper("suid_cred_client_helper"),
	};

	dt_run_helpers(helpers, sizeof(helpers) / sizeof(helpers[0]), 60);
}

/*
 * Creating an suid credential should fail for non-root (even if entitled).
 */
T_DECL(task_create_suid_cred_no_root, "task_create_suid_cred (no root)", T_META_ASROOT(true))
{
	kern_return_t ret = KERN_FAILURE;
	suid_cred_t sc = SUID_CRED_NULL;
	uid_t euid = geteuid();

	// Make sure the effective UID is non-root.
	if (euid == 0) {
		ret = setuid(501);
		T_QUIET; T_ASSERT_POSIX_ZERO(ret, "setuid");
	}

	ret = task_create_suid_cred(mach_task_self(), "/usr/bin/id", 0, &sc);
	T_ASSERT_MACH_ERROR(ret, KERN_NO_ACCESS, "create a new suid cred for id (non-root)");
}

#endif /* ENTITLED */
