#include <darwintest.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

T_DECL(socket_poll_close_25786011, "Tests an invalid poll call to a socket and then calling close.", T_META_LTEPHASE(LTE_POSTINIT))
{
	int my_socket, ret;

	my_socket = socket(PF_LOCAL, SOCK_STREAM, 0);
	T_WITH_ERRNO; T_ASSERT_TRUE(my_socket > 0, "create socket");

	/*
	 * Setup a pollfd that we know will return an error when we try
	 * to create a knote for it. We specify a BSD vnode specific event
	 * for a socket.
	 */
	struct pollfd my_pollfd = {
		.fd = my_socket,
		.events = POLLEXTEND
	};

	/*
	 * Previously the call to kevent_register() in the kernel from this call
	 * would leak an iocount reference on the fileproc, which would cause any
	 * subsequent calls to close() on the associated fd to block indefinitely.
	 */
	ret = poll(&my_pollfd, 1, 0);
	T_WITH_ERRNO; T_ASSERT_TRUE(ret == 1, "poll returned %d", ret);

	ret = close(my_socket);
	T_ASSERT_POSIX_ZERO(ret, "close on socket with fd %d\n", my_socket);

	T_PASS("socket_poll_close_25786011 PASSED");
}
