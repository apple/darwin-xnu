/* -*- Mode: c; tab-width: 8; indent-tabs-mode: 1; c-basic-offset: 8; -*- */

#include <darwintest.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

static int
sockv6_open(void)
{
	int     s;

	s = socket(AF_INET6, SOCK_DGRAM, 0);
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(s, "socket(AF_INET6, SOCK_DGRAM, 0)");
	return s;
}

static int
sockv6_bind(int s, in_port_t port)
{
	struct sockaddr_in6     sin6;

	bzero(&sin6, sizeof(sin6));
	sin6.sin6_len = sizeof(sin6);
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = port;
	return bind(s, (const struct sockaddr *)&sin6, sizeof(sin6));
}

static void
sockv6_set_v6only(int s)
{
	int             on = 1;
	int             ret;

	ret = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
	T_QUIET;
	T_ASSERT_POSIX_SUCCESS(ret, "setsockopt(%d, IPV6_ONLY)", s);
}

static bool
alloc_and_bind_ports(in_port_t port_start, in_port_t port_end,
    int bind_attempts)
{
	int     bound_count = 0;
	bool    success = true;

	for (in_port_t i = port_start; success && i <= port_end; i++) {
		int     s6 = -1;
		int     s6_other = -1;
		int     ret;

		s6 = sockv6_open();
		sockv6_set_v6only(s6);
		if (sockv6_bind(s6, i) != 0) {
			/* find the next available port */
			goto loop_done;
		}
		s6_other = sockv6_open();
		ret = sockv6_bind(s6_other, i);
		T_WITH_ERRNO;
		T_QUIET;
		T_ASSERT_TRUE(ret != 0, "socket %d bind %d", s6_other, i);
		/*
		 * After bind fails, try binding to a different port.
		 * For non-root user, this will panic without the fix for
		 * <rdar://problem/35243417>.
		 */
		if (sockv6_bind(s6_other, i + 1) == 0) {
			bound_count++;
			if (bound_count >= bind_attempts) {
				break;
			}
		}
loop_done:
		if (s6 >= 0) {
			close(s6);
		}
		if (s6_other >= 0) {
			close(s6_other);
		}
	}
	T_ASSERT_TRUE(bound_count == bind_attempts,
	    "number of successful binds %d (out of %d)",
	    bound_count, bind_attempts);
	return success;
}


T_DECL(socket_bind_35243417,
    "bind IPv6 only UDP socket, then bind IPv6 socket.",
    T_META_ASROOT(false),
    T_META_CHECK_LEAKS(false))
{
	alloc_and_bind_ports(1, 65534, 10);
}

T_DECL(socket_bind_35243417_root,
    "bind IPv6 only UDP socket, then bind IPv6 socket.",
    T_META_ASROOT(true))
{
	alloc_and_bind_ports(1, 65534, 10);
}
