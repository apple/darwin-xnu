/* -*- Mode: c; tab-width: 8; indent-tabs-mode: 1; c-basic-offset: 8; -*- */

#include <darwintest.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>

static bool debug;

static int
sock_open_common(int pf, int type)
{
	int     s;

	s = socket(pf, type, 0);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(s, "socket(%d, %d, 0)", pf, type);
	return s;
}

static int
sock_open(int type)
{
	return sock_open_common(PF_INET, type);
}

static int
sock_bind(int s, int port)
{
	struct sockaddr_in      sin = {
		.sin_len = sizeof(sin),
		.sin_family = AF_INET,
	};

	sin.sin_port = htons(port);
	return bind(s, (const struct sockaddr *)&sin, sizeof(sin));
}

static int
sockv6_open(int type)
{
	return sock_open_common(PF_INET6, type);
}

static int
sockv6_bind(int s, int port)
{
	struct sockaddr_in6             sin6 = {
		.sin6_len = sizeof(sin6),
		.sin6_family = AF_INET6,
	};

	sin6.sin6_port = htons(port);
	return bind(s, (const struct sockaddr *)&sin6, sizeof(sin6));
}

static uint16_t
sock_get_port(int sockfd)
{
	int                             error;
	uint16_t                        p;
	union sockaddr_in_4_6   sin;
	socklen_t                       sin_len;

	sin_len = sizeof(sin);
	bzero(&sin, sin_len);
	error = getsockname(sockfd, (struct sockaddr *)&sin, &sin_len);
	T_QUIET;
	T_EXPECT_POSIX_ZERO(error, "getsockname(%d)", sockfd);
	if (error != 0) {
		return 0;
	}
	switch (sin.sa.sa_family) {
	case AF_INET:
		p = sin.sin.sin_port;
		break;
	case AF_INET6:
		p = sin.sin6.sin6_port;
		break;
	default:
		T_ASSERT_FAIL("unknown address family %d\n",
		    sin.sa.sa_family);
		p = 0;
		break;
	}
	return p;
}

typedef struct {
	bool    v6;
	int             socket_count;
	int *   socket_list;
} SocketInfo, * SocketInfoRef;

static void
bind_sockets(SocketInfoRef info, const char * msg)
{
	for (int i = 0; i < info->socket_count; i++) {
		int             error;
		uint16_t        port;

		if (info->v6) {
			error = sockv6_bind(info->socket_list[i], 0);
		} else {
			error = sock_bind(info->socket_list[i], 0);
		}
		port = sock_get_port(info->socket_list[i]);
		if (debug) {
			T_LOG( "%s: fd %d port is %d error %d",
			    msg, info->socket_list[i], ntohs(port), error);
		}
	}
	return;
}

static void *
second_thread(void * arg)
{
	SocketInfoRef   info = (SocketInfoRef)arg;

	bind_sockets(info, "second");
	return NULL;
}

static void
multithreaded_bind_test(bool v6, int socket_count)
{
	int             error;
	SocketInfo      info;
	int     socket_list[socket_count];
	pthread_t       thread;

	info.v6 = v6;
	for (int i = 0; i < socket_count; i++) {
		if (v6) {
			socket_list[i] = sockv6_open(SOCK_STREAM);
		} else {
			socket_list[i] = sock_open(SOCK_STREAM);
		}
	}
	info.socket_count = socket_count;
	info.socket_list = socket_list;
	error = pthread_create(&thread, NULL, second_thread, &info);
	T_QUIET;
	T_ASSERT_POSIX_ZERO(error, "pthread_create");

	/* compete with second thread */
	bind_sockets(&info, "main");
	error = pthread_join(thread, NULL);
	T_QUIET;
	T_ASSERT_POSIX_ZERO(error, "pthread_join");

	for (int i = 0; i < socket_count; i++) {
		error = close(socket_list[i]);
		T_QUIET;
		T_ASSERT_POSIX_ZERO(error, "close socket %d", socket_list[i]);
	}
}

static void
run_multithreaded_bind_test(int number_of_runs, bool v6, int socket_count)
{
	for (int i = 0; i < number_of_runs; i++) {
		multithreaded_bind_test(v6, socket_count);
	}
	T_PASS("multithreaded_bind_test %s", v6 ? "IPv6" : "IPv4");
}

T_DECL(socket_bind_35685803,
    "multithreaded bind IPv4 socket as root",
    T_META_ASROOT(false),
    T_META_CHECK_LEAKS(false))
{
	run_multithreaded_bind_test(100, false, 100);
}

T_DECL(socket_bind_35685803_root,
    "multithreaded bind IPv4 socket",
    T_META_ASROOT(true))
{
	run_multithreaded_bind_test(100, false, 100);
}

T_DECL(socket_bind_35685803_v6,
    "multithreaded bind IPv6 socket as root",
    T_META_ASROOT(false),
    T_META_CHECK_LEAKS(false))
{
	run_multithreaded_bind_test(100, true, 100);
}

T_DECL(socket_bind_35685803_v6_root,
    "multithreaded bind IPv6 socket",
    T_META_ASROOT(true))
{
	run_multithreaded_bind_test(100, true, 100);
}
