#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <unistd.h>

#include <darwintest.h>

struct netagent_message_header {
	uint8_t message_type;
	uint8_t message_flags;
	uint8_t padding[2];
	uint32_t message_id;
	uint32_t message_error;
	uint32_t message_payload_length;
};

T_DECL(netagent_kctl_header_infodisc_56190773, "Zero out padding in netagent_message_header.")
{
	int s;
	struct sockaddr_ctl sc;
	struct ctl_info ci;
	struct netagent_message_header m;

	T_SETUPBEGIN;
	T_ASSERT_POSIX_SUCCESS(s = socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL), NULL);

	bzero(&ci, sizeof(ci));
	strcpy(ci.ctl_name, "com.apple.net.netagent");

	T_ASSERT_POSIX_SUCCESS(ioctl(s, CTLIOCGINFO, &ci), NULL);

	bzero(&sc, sizeof(sc));
	sc.sc_id = ci.ctl_id;
	T_ASSERT_POSIX_SUCCESS(connect(s, (const struct sockaddr *)&sc, sizeof(sc)), NULL);

	T_SETUPEND;

	bzero(&m, sizeof(m));
	T_ASSERT_POSIX_SUCCESS(send(s, &m, sizeof(m), 0), NULL);

	T_ASSERT_POSIX_SUCCESS(recv(s, &m, sizeof(m), 0), NULL);
	T_ASSERT_EQ(m.padding[0], 0, NULL);
	T_ASSERT_EQ(m.padding[1], 0, NULL);
}
