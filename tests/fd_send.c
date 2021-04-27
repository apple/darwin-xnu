#include <darwintest.h>
#include <darwintest_utils.h>
#include <dispatch/dispatch.h>
#include <mach/mach.h>
#include <signal.h>
#include <sys/socket.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.fd"),
	T_META_RUN_CONCURRENTLY(true));


#define SOCKETPAIR(pair) \
	T_ASSERT_POSIX_SUCCESS(socketpair(PF_LOCAL, SOCK_STREAM, 0, pair), "socketpair")


static errno_t
send_fd(int sock, int fd)
{
	struct iovec iovec[1];
	struct msghdr msg;
	struct cmsghdr *cmsghdrp;
	char buf[CMSG_SPACE(sizeof(int))];

	iovec[0].iov_base = "";
	iovec[0].iov_len = 1;
	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = iovec;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = CMSG_SPACE(sizeof(int));

	cmsghdrp = CMSG_FIRSTHDR(&msg);
	cmsghdrp->cmsg_len = CMSG_LEN(sizeof(int));
	cmsghdrp->cmsg_level = SOL_SOCKET;
	cmsghdrp->cmsg_type = SCM_RIGHTS;

	memcpy(CMSG_DATA(cmsghdrp), &fd, sizeof(fd));

	if (sendmsg(sock, &msg, 0) < 0) {
		return errno;
	}

	return 0;
}

static errno_t
recv_fd(int sock, int *fdp)
{
	u_char c;
	struct iovec iovec[1];
	struct msghdr msg;
	struct cmsghdr *cmsghdrp;
	char buf[CMSG_SPACE(sizeof(int))];

	iovec[0].iov_base = &c;
	iovec[0].iov_len = 1;

	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_iov = iovec;
	msg.msg_iovlen = 1;
	msg.msg_control = buf;
	msg.msg_controllen = CMSG_SPACE(sizeof(int));
	msg.msg_flags = 0;

	if (recvmsg(sock, &msg, 0) < 0) {
		return errno;
	}

	cmsghdrp = CMSG_FIRSTHDR(&msg);
	if (cmsghdrp == NULL) {
		return ENOENT;
	}

	if (cmsghdrp->cmsg_len != CMSG_LEN(sizeof(int))) {
		return ENOENT;
	}
	if (cmsghdrp->cmsg_level != SOL_SOCKET) {
		return ENOENT;
	}
	if (cmsghdrp->cmsg_type != SCM_RIGHTS) {
		return ENOENT;
	}

	memcpy(fdp, CMSG_DATA(cmsghdrp), sizeof(*fdp));
	return 0;
}

T_DECL(send, "test for 30465592")
{
	int pair[2], fd, status;
	pid_t child;

	T_ASSERT_POSIX_SUCCESS(socketpair(PF_LOCAL, SOCK_STREAM, 0, pair),
	    "socketpair");

	child = fork();
	if (child != 0) {
		fd = open("/dev/null", O_RDWR);
		T_ASSERT_POSIX_SUCCESS(fd, "open(/dev/null)");

		T_ASSERT_EQ(send_fd(pair[0], fd), 0, "send_fd");
		T_ASSERT_POSIX_SUCCESS(close(fd), "close(fd)");

		T_EXPECT_POSIX_SUCCESS(waitpid(child, &status, 0), "waitpid");
	} else {
		T_QUIET; T_ASSERT_EQ(recv_fd(pair[1], &fd), 0, "recv_fd");
		T_QUIET; T_ASSERT_NE(fd, -1, "received a proper fd");
		T_QUIET; T_EXPECT_POSIX_SUCCESS(close(fd), "close(fd)");
		raise(SIGKILL); /* do not confuse the test system */
	}
}

T_DECL(send_kill, "test for 30465592")
{
	int pair[2], fd, status;
	pid_t child;

	T_QUIET; SOCKETPAIR(pair);

	child = fork();
	if (child != 0) {
		fd = open("/dev/null", O_RDWR);
		T_ASSERT_POSIX_SUCCESS(fd, "open(/dev/null)");

		T_ASSERT_EQ(send_fd(pair[0], fd), 0, "send_fd");
		T_ASSERT_POSIX_SUCCESS(close(fd), "close(fd)");

		T_EXPECT_POSIX_SUCCESS(kill(child, SIGKILL), "kill(child)");

		T_EXPECT_POSIX_SUCCESS(waitpid(child, &status, 0), "waitpid");
	} else {
		T_QUIET; T_ASSERT_EQ(recv_fd(pair[1], &fd), 0, "recv_fd");
		T_QUIET; T_ASSERT_NE(fd, -1, "received a proper fd");
		T_QUIET; T_EXPECT_POSIX_SUCCESS(close(fd), "close(fd)");
		raise(SIGKILL); /* do not confuse the test system */
	}
}

T_DECL(send_sock, "test for 30465592")
{
	int pair[2], fd, status;
	pid_t child;

	T_QUIET; SOCKETPAIR(pair);

	child = fork();
	if (child != 0) {
		int sock[2];

		T_QUIET; SOCKETPAIR(sock);

		T_ASSERT_EQ(send_fd(pair[0], sock[0]), 0, "send_fd");
		T_ASSERT_POSIX_SUCCESS(close(sock[0]), "close(sock[0])");
		T_ASSERT_POSIX_SUCCESS(close(sock[1]), "close(sock[1])");

		T_EXPECT_POSIX_SUCCESS(waitpid(child, &status, 0), "waitpid");
	} else {
		T_QUIET; T_ASSERT_EQ(recv_fd(pair[1], &fd), 0, "recv_fd");
		T_QUIET; T_ASSERT_NE(fd, -1, "received a proper fd");
		T_QUIET; T_EXPECT_POSIX_SUCCESS(close(fd), "close(fd)");
		raise(SIGKILL); /* do not confuse the test system */
	}
}

T_DECL(send_stress, "test for 67133384")
{
	int fd;

	fd = open("/dev/null", O_RDWR);
	T_ASSERT_POSIX_SUCCESS(fd, "open(/dev/null)");

	dispatch_apply(10, NULL, ^(size_t worker) {
		dispatch_queue_t q = dispatch_queue_create("receiver", NULL);
		dispatch_group_t g = dispatch_group_create();
		int pairbuf[2], *pair = pairbuf;
		int n = 1000;

		SOCKETPAIR(pair);

		dispatch_group_async(g, q, ^{
			int tmp;

			for (int i = 0; i < n; i++) {
			        T_QUIET; T_ASSERT_EQ(recv_fd(pair[1], &tmp), 0, "recv_fd");
			        T_QUIET; T_ASSERT_NE(tmp, -1, "received a proper fd");
			        T_QUIET; T_EXPECT_POSIX_SUCCESS(close(tmp), "close(tmp)");
			}
		});
		dispatch_release(q);

		for (int i = 0; i < n; i++) {
		        int tmp = dup(fd);
		        T_QUIET; T_ASSERT_POSIX_SUCCESS(tmp, "dup");
		        T_QUIET; T_ASSERT_EQ(send_fd(pair[0], tmp), 0, "send_fd");
		        T_QUIET; T_EXPECT_POSIX_SUCCESS(close(tmp), "close(tmp)");
		}
		dispatch_group_wait(g, DISPATCH_TIME_FOREVER);

		T_PASS("sent and received %d fds in worker %zd", n, worker);

		T_QUIET; T_EXPECT_POSIX_SUCCESS(close(pair[0]), "close(pair[0])");
		T_QUIET; T_EXPECT_POSIX_SUCCESS(close(pair[1]), "close(pair[1])");
	});
}
