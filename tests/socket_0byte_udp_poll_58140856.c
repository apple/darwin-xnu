#include <darwintest.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

#define TEST_ADDR "127.0.0.1"
#define TEST_PORT 4242

static struct {
	int fd;
	struct sockaddr_in addr;
} server;

static void
server_listen(void)
{
	int r;

	server.fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(server.fd, "socket");

	memset(&server.addr, 0, sizeof(server.addr));
	server.addr.sin_family = AF_INET;
	server.addr.sin_port = htons(TEST_PORT);

	inet_pton(AF_INET, TEST_ADDR, &server.addr.sin_addr);

	r = bind(server.fd, (struct sockaddr*) &server.addr, sizeof(server.addr));
	T_ASSERT_POSIX_SUCCESS(r, "bind");
}

static void
send_message(void)
{
	int fd;
	struct msghdr msg;
	struct iovec iov;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	T_ASSERT_POSIX_SUCCESS(fd, "socket");

	memset(&msg, 0, sizeof(msg));

	msg.msg_name = &server.addr;
	msg.msg_namelen = sizeof(server.addr);

	iov.iov_base = "";
	iov.iov_len = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	ssize_t r = sendmsg(fd, &msg, 0);
	T_ASSERT_EQ(r, (ssize_t)iov.iov_len, "sendmsg");

	close(fd);
}

static void
server_poll(void)
{
	int kq;
	struct kevent event = {
		.flags  = EV_ADD,
		.filter = EVFILT_READ,
		.ident  = (unsigned long)server.fd,
	};
	int r;

	kq = kqueue();
	T_ASSERT_POSIX_SUCCESS(kq, "kqueue");

	/* Add and poll */
	r = kevent(kq, &event, 1, &event, 1, NULL);
	T_EXPECT_EQ(r, 1, "should return an event");

	close(kq);
}

T_DECL(socket_0byte_udp_poll_58140856,
    "Tests that 0-sized UDP packets wake up kevent")
{
	T_LOG("Starting...\n");

	/* Listen on UDP port */
	server_listen();

	T_LOG("Server bound to [%s]:%d\n", TEST_ADDR, TEST_PORT);

	/* Send 0-UDP packet to that port */
	send_message();

	T_LOG("Sent message to server\n");

	/* Poll kqueue events */
	server_poll();

	T_LOG("Got kqueue event\n");

	close(server.fd);
}
