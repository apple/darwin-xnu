#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <fcntl.h>
#include <pthread.h>
#include <sys/kern_control.h>
#include <sys/kern_event.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <unistd.h>
#include <uuid/uuid.h>

#include <darwintest.h>

static int finished = 0;

#ifndef KEV_NETAGENT_SUBCLASS
#define KEV_NETAGENT_SUBCLASS 9
#endif

#ifndef NETAGENT_MESSAGE_TYPE_REGISTER
#define NETAGENT_MESSAGE_TYPE_REGISTER 1
#endif

#ifndef NETAGENT_MESSAGE_TYPE_UNREGISTER
#define NETAGENT_MESSAGE_TYPE_UNREGISTER 2
#endif

struct netagent_message_header {
	uint8_t message_type;
	uint8_t message_flags;
	uint32_t message_id;
	uint32_t message_error;
	uint32_t message_payload_length;
};

struct kev_msg {
	uint32_t total_size;
	uint32_t vendor_code;
	uint32_t kev_class;
	uint32_t kev_subclass;
	uint32_t id;
	uint32_t event_code;
};

struct kev_netagent_data {
	uuid_t netagent_uuid;
};

struct netagent {
	uuid_t netagent_uuid;
	char netagent_domain[32];
	char netagent_type[32];
	char netagent_desc[128];
	uint32_t netagent_flags;
	uint32_t netagent_data_size;
	/*uint8_t netagent_data[0];*/
};

static void *
register_sockopt_racer(void *data)
{
	int s = *(int *)data;
	struct {
		struct netagent_message_header header;
		struct netagent netagent;
	} msg;

	bzero(&msg, sizeof(msg));
	msg.header.message_type = NETAGENT_MESSAGE_TYPE_REGISTER;
	msg.header.message_payload_length = sizeof(struct netagent);

	while (!finished) {
		send(s, &msg, sizeof(msg), 0);
	}

	return NULL;
}

static void *
register_message_racer(void *data)
{
	int s = *(int *)data;
	struct netagent netagent;

	bzero(&netagent, sizeof(netagent));
	while (!finished) {
		setsockopt(s, SYSPROTO_CONTROL, NETAGENT_MESSAGE_TYPE_REGISTER, &netagent, sizeof(netagent));
	}

	return NULL;
}

#define SIZEOF_STRUCT_NETAGENT_WRAPPER 280

static void *
unregister_racer(void *data)
{
	int s = *(int *)data;
	uint8_t spraybuf[SIZEOF_STRUCT_NETAGENT_WRAPPER];

	memset(spraybuf, 0x41, sizeof(spraybuf));

	while (!finished) {
		setsockopt(s, SYSPROTO_CONTROL, NETAGENT_MESSAGE_TYPE_UNREGISTER, NULL, 0);
		ioctl(-1, _IOW('x', 0, spraybuf), spraybuf);
	}

	return NULL;
}

#define NITERS 200000

static size_t
data_available(int sock)
{
	int n = 0;
	socklen_t nlen = sizeof(n);

	getsockopt(sock, SOL_SOCKET, SO_NREAD, &n, &nlen);
	return (size_t)n;
}

T_DECL(netagent_race_infodisc_56244905, "Netagent race between register and post event.")
{
	int s;
	int evsock;
	pthread_t reg_th;
	pthread_t unreg_th;
	struct kev_request kev_req = {
		.vendor_code = KEV_VENDOR_APPLE,
		.kev_class = KEV_NETWORK_CLASS,
		.kev_subclass = KEV_NETAGENT_SUBCLASS
	};
	struct ctl_info ci;
	struct sockaddr_ctl sc;
	struct {
		struct kev_msg msg;
		struct kev_netagent_data nd;
	} ev;
	int n;
	int retry;
	unsigned long leaked;

	T_SETUPBEGIN;
	/* set up the event socket so we can receive notifications: */
	T_ASSERT_POSIX_SUCCESS(evsock = socket(AF_SYSTEM, SOCK_RAW, SYSPROTO_EVENT), NULL);
	T_ASSERT_POSIX_SUCCESS(ioctl(evsock, SIOCSKEVFILT, &kev_req), NULL);

	/* this is the socket we'll race on: */
	T_ASSERT_POSIX_SUCCESS(s = socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL), NULL);

	/* connect to netagent: */
	bzero(&ci, sizeof(ci));
	strcpy(ci.ctl_name, "com.apple.net.netagent");
	T_ASSERT_POSIX_SUCCESS(ioctl(s, CTLIOCGINFO, &ci), NULL);

	bzero(&sc, sizeof(sc));
	sc.sc_id = ci.ctl_id;

	T_ASSERT_POSIX_SUCCESS(connect(s, (const struct sockaddr *)&sc, sizeof(sc)), NULL);
	T_SETUPEND;

	/* variant 1: */
	/* spin off the racer threads: */
	T_ASSERT_POSIX_ZERO(pthread_create(&reg_th, NULL, register_message_racer, &s), NULL);
	T_ASSERT_POSIX_ZERO(pthread_create(&unreg_th, NULL, unregister_racer, &s), NULL);

	/* keep going until we're done: */
	for (n = 0; n < NITERS; ++n) {
		bzero(&ev, sizeof(ev));

		for (retry = 0; retry < 20; ++retry) {
			if (data_available(evsock) >= sizeof(ev) &&
			    sizeof(ev) == recv(evsock, &ev, sizeof(ev), 0)) {
				goto check1;
			}
		}

		continue;

check1:
		if (ev.nd.netagent_uuid[0] != 0) {
			finished = 1;
			memcpy(&leaked, ev.nd.netagent_uuid, sizeof(leaked));
			T_ASSERT_FAIL("netagent register event leaked data: 0x%08lx", leaked);
		}
	}

	finished = 1;

	T_ASSERT_POSIX_ZERO(pthread_join(reg_th, NULL), NULL);
	T_ASSERT_POSIX_ZERO(pthread_join(unreg_th, NULL), NULL);

	finished = 0;

	/* variant 2: */
	/* spin off the racer threads: */
	T_ASSERT_POSIX_ZERO(pthread_create(&reg_th, NULL, register_sockopt_racer, &s), NULL);
	T_ASSERT_POSIX_ZERO(pthread_create(&unreg_th, NULL, unregister_racer, &s), NULL);

	/* keep going until we're done: */
	for (n = 0; n < NITERS; ++n) {
		bzero(&ev, sizeof(ev));

		for (retry = 0; retry < 20; ++retry) {
			if (data_available(evsock) >= sizeof(ev) &&
			    sizeof(ev) == recv(evsock, &ev, sizeof(ev), 0)) {
				goto check2;
			}
		}

		continue;

check2:
		if (ev.nd.netagent_uuid[0] != 0) {
			finished = 1;
			memcpy(&leaked, ev.nd.netagent_uuid, sizeof(leaked));
			T_ASSERT_FAIL("netagent register event leaked data: 0x%08lx", leaked);
		}
	}

	finished = 1;

	T_ASSERT_POSIX_ZERO(pthread_join(reg_th, NULL), NULL);
	T_ASSERT_POSIX_ZERO(pthread_join(unreg_th, NULL), NULL);
}
