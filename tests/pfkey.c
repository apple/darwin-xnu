#include <darwintest.h>
#include <darwintest_utils.h>
#include <dispatch/dispatch.h>
#include <net/pfkeyv2.h>
#include <netinet6/ipsec.h>
#include <arpa/inet.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.pfkey"),
	T_META_ASROOT(true),
	T_META_CHECK_LEAKS(false));

#define MAX_SPD_CHECK       100
#define TEST_SRC_ADDRESS_IPv4           "192.168.2.2"
#define TEST_DST_ADDRESS_IPv4           "192.168.2.3"
#define TEST_SRC_ADDRESS_IPv6           "fd04:5c6b:8df7:7092:0000:0000:0000:0002"
#define TEST_DST_ADDRESS_IPv6           "fd04:5c6b:8df7:7092:0000:0000:0000:0003"
#define TEST_MIGRATE_SRC_ADDRESS_IPv4   "192.168.2.10"
#define TEST_MIGRATE_DST_ADDRESS_IPv4   "192.168.2.11"
#define TEST_MIGRATE_SRC_ADDRESS_IPv6   "fd04:5c6b:8df7:7092:0000:0000:0002:0000"
#define TEST_MIGRATE_DST_ADDRESS_IPv6   "fd04:5c6b:8df7:7092:0000:0000:0003:0000"

typedef enum {
	TEST_INVALID = 0,
	TEST_SADB_X_GET_OVERFLOW_60822136 = 1,
	TEST_SADB_X_SPDENABLE_OVERFLOW_60822924 = 2,
	TEST_SADB_X_SPDDISABLE_OVERFLOW_60822956 = 3,
	TEST_SADB_UPDATE_USE_AFTER_FREE_60679513 = 4,
	TEST_SADB_DUMP_HEAP_OVERFLOW_60768729 = 5,
	TEST_SADB_POLICY_DUMP_HEAP_OVERFLOW_60769680 = 6,
	TEST_SADB_GETSASTAT_OOB_READ_60822823 = 7,
	TEST_SADB_GETSASTAT_OOB_READ_SUCCESS = 8,
	TEST_SADB_EXT_MIGRATE_ADDRESS_IPv4 = 9,
	TEST_SADB_EXT_MIGRATE_ADDRESS_IPv6 = 10,
	TEST_SADB_EXT_MIGRATE_BAD_ADDRESS = 11,
} test_identifier;

static test_identifier test_id = TEST_INVALID;
static dispatch_source_t pfkey_source = NULL;

static void pfkey_cleanup(void);

static void pfkey_process_message_test_60822136(uint8_t **mhp, int pfkey_socket);
static void pfkey_process_message_test_60822924(uint8_t **mhp, int pfkey_socket);
static void pfkey_process_message_test_60822956(uint8_t **mhp, int pfkey_socket);
static void pfkey_process_message_test_60679513(uint8_t **mhp, int pfkey_socket);
static void pfkey_process_message_test_60768729(uint8_t **mhp, int pfkey_socket);
static void pfkey_process_message_test_60769680(uint8_t **mhp, int pfkey_socket);
static void pfkey_process_message_test_60822823(uint8_t **mhp, int pfkey_socket);
static void pfkey_process_message_test_60822823_1(uint8_t **mhp, int pfkey_socket);
static void pfkey_process_message_test_60687183(uint8_t **mhp, int pfkey_socket);
static void pfkey_process_message_test_60687183_1(uint8_t **mhp, int pfkey_socket);
static void pfkey_process_message_test_60687183_2(uint8_t **mhp, int pfkey_socket);

static void(*const process_pfkey_message_tests[])(uint8_t * *mhp, int pfkey_socket) =
{
	NULL,
	pfkey_process_message_test_60822136,    // TEST_SADB_X_GET_OVERFLOW_60822136
	pfkey_process_message_test_60822924,    // TEST_SADB_X_SPDENABLE_OVERFLOW_60822924
	pfkey_process_message_test_60822956,    // TEST_SADB_X_SPDDISABLE_OVERFLOW_60822956
	pfkey_process_message_test_60679513,    // TEST_SADB_UPDATE_USE_AFTER_FREE_60679513
	pfkey_process_message_test_60768729,    // TEST_SADB_DUMP_HEAP_OVERFLOW_60768729
	pfkey_process_message_test_60769680,    // TEST_SADB_POLICY_DUMP_HEAP_OVERFLOW_60769680
	pfkey_process_message_test_60822823,    // TEST_SADB_GETSASTAT_OOB_READ_60822823
	pfkey_process_message_test_60822823_1,  // TEST_SADB_GETSASTAT_OOB_READ_SUCCESS
	pfkey_process_message_test_60687183,    // TEST_SADB_EXT_MIGRATE_ADDRESS_IPv4
	pfkey_process_message_test_60687183_1,  // TEST_SADB_EXT_MIGRATE_ADDRESS_IPv6
	pfkey_process_message_test_60687183_2,  // TEST_SADB_EXT_MIGRATE_BAD_ADDRESS
};

static void
pfkey_align(struct sadb_msg *msg, uint8_t **mhp)
{
	struct sadb_ext *ext;
	int i;
	uint8_t *p;
	uint8_t *ep;     /* XXX should be passed from upper layer */

	/* validity check */
	T_QUIET; T_ASSERT_NOTNULL(msg, "pfkey align msg");
	T_QUIET; T_ASSERT_NOTNULL(mhp, "pfkey align mhp");

	/* initialize */
	for (i = 0; i < SADB_EXT_MAX + 1; i++) {
		mhp[i] = NULL;
	}

	mhp[0] = (void *)msg;

	/* initialize */
	p = (void *) msg;
	ep = p + PFKEY_UNUNIT64(msg->sadb_msg_len);

	/* skip base header */
	p += sizeof(struct sadb_msg);

	while (p < ep) {
		ext = (void *)p;
		T_QUIET; T_ASSERT_GE_PTR((void *)ep, (void *)(p + sizeof(*ext)), "pfkey extension header beyond end of buffer");
		T_QUIET; T_ASSERT_GE_ULONG((unsigned long)PFKEY_EXTLEN(ext), sizeof(*ext), "pfkey extension shorter than extension header");
		T_QUIET; T_ASSERT_GE_PTR((void *)ep, (void *)(p + PFKEY_EXTLEN(ext)), "pfkey extension length beyond end of buffer");

		T_QUIET; T_EXPECT_NULL(mhp[ext->sadb_ext_type], "duplicate extension type %u payload", ext->sadb_ext_type);

		/* set pointer */
		switch (ext->sadb_ext_type) {
		case SADB_EXT_SA:
		case SADB_EXT_LIFETIME_CURRENT:
		case SADB_EXT_LIFETIME_HARD:
		case SADB_EXT_LIFETIME_SOFT:
		case SADB_EXT_ADDRESS_SRC:
		case SADB_EXT_ADDRESS_DST:
		case SADB_EXT_ADDRESS_PROXY:
		case SADB_EXT_KEY_AUTH:
		/* XXX should to be check weak keys. */
		case SADB_EXT_KEY_ENCRYPT:
		/* XXX should to be check weak keys. */
		case SADB_EXT_IDENTITY_SRC:
		case SADB_EXT_IDENTITY_DST:
		case SADB_EXT_SENSITIVITY:
		case SADB_EXT_PROPOSAL:
		case SADB_EXT_SUPPORTED_AUTH:
		case SADB_EXT_SUPPORTED_ENCRYPT:
		case SADB_EXT_SPIRANGE:
		case SADB_X_EXT_POLICY:
		case SADB_X_EXT_SA2:
		case SADB_EXT_SESSION_ID:
		case SADB_EXT_SASTAT:
#ifdef SADB_X_EXT_NAT_T_TYPE
		case SADB_X_EXT_NAT_T_TYPE:
		case SADB_X_EXT_NAT_T_SPORT:
		case SADB_X_EXT_NAT_T_DPORT:
		case SADB_X_EXT_NAT_T_OA:
#endif
#ifdef SADB_X_EXT_TAG
		case SADB_X_EXT_TAG:
#endif
#ifdef SADB_X_EXT_PACKET
		case SADB_X_EXT_PACKET:
#endif
		case SADB_X_EXT_IPSECIF:
		case SADB_X_EXT_ADDR_RANGE_SRC_START:
		case SADB_X_EXT_ADDR_RANGE_SRC_END:
		case SADB_X_EXT_ADDR_RANGE_DST_START:
		case SADB_X_EXT_ADDR_RANGE_DST_END:
#ifdef SADB_MIGRATE
		case SADB_EXT_MIGRATE_ADDRESS_SRC:
		case SADB_EXT_MIGRATE_ADDRESS_DST:
		case SADB_X_EXT_MIGRATE_IPSECIF:
#endif
			mhp[ext->sadb_ext_type] = (void *)ext;
			break;
		default:
			T_FAIL("bad extension type %u", ext->sadb_ext_type);
			T_END;
		}

		p += PFKEY_EXTLEN(ext);
	}

	T_QUIET; T_EXPECT_EQ_PTR((void *)ep, (void *)p, "invalid pfkey message length");
	return;
}


static void
recv_pfkey_message(int pfkey_socket)
{
	uint8_t buffer[8192] __attribute__((aligned(4)));
	struct iovec iovecs[1] = {
		{ buffer, sizeof(buffer) },
	};
	struct msghdr msg = {
		NULL,
		0,
		iovecs,
		sizeof(iovecs) / sizeof(iovecs[0]),
		NULL,
		0,
		0,
	};

	do {
		ssize_t result = -1;
		memset(buffer, 0, sizeof(buffer));
		T_QUIET; T_ASSERT_POSIX_SUCCESS(result = recvmsg(pfkey_socket, &msg, 0), NULL);

		if (result > 0) {
			T_QUIET; T_ASSERT_GE_ULONG((size_t)result, sizeof(struct sadb_msg), "Invalid PFKey message size: %zu", result);
			struct sadb_msg *hdr = (struct sadb_msg *)buffer;
			uint8_t *mhp[SADB_EXT_MAX + 1];
			pfkey_align(hdr, mhp);
			(*process_pfkey_message_tests[test_id])(mhp, pfkey_socket);
		} else if (result == 0) {
			T_LOG("PFKey socket received EOF");
			break;
		}
	} while (1);
}

static void
send_pfkey_spd_add_message(int pfkey_socket, uint8_t proto)
{
	uint8_t payload[MCLBYTES] __attribute__ ((aligned(32)));
	bzero(payload, sizeof(payload));
	uint16_t tlen = 0;

	struct sadb_msg *msg_payload = (struct sadb_msg *)payload;
	msg_payload->sadb_msg_version = PF_KEY_V2;
	msg_payload->sadb_msg_type = SADB_X_SPDADD;
	msg_payload->sadb_msg_errno = 0;
	msg_payload->sadb_msg_satype = SADB_SATYPE_UNSPEC;
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	msg_payload->sadb_msg_reserved = 0;
	msg_payload->sadb_msg_seq = 0;
	msg_payload->sadb_msg_pid = (u_int32_t)getpid();
	tlen += sizeof(*msg_payload);

	struct sadb_address *src_address_payload = (struct sadb_address *)(void *)(payload + tlen);
	src_address_payload->sadb_address_exttype = SADB_EXT_ADDRESS_SRC & 0xffff;
	src_address_payload->sadb_address_proto = proto & 0xff;
	src_address_payload->sadb_address_prefixlen = (sizeof(struct in_addr) << 3);
	src_address_payload->sadb_address_reserved = 0;
	tlen += sizeof(*src_address_payload);

	struct sockaddr_in *src = (struct sockaddr_in *)(void *)(payload + tlen);
	T_QUIET; T_ASSERT_EQ_INT(inet_pton(AF_INET, TEST_SRC_ADDRESS_IPv4, &src->sin_addr), 1, "src address fail");
	src->sin_family = AF_INET;
	src->sin_len = sizeof(*src);
	uint16_t len = sizeof(*src_address_payload) + PFKEY_ALIGN8(src->sin_len);
	src_address_payload->sadb_address_len = PFKEY_UNIT64(len);
	tlen += PFKEY_ALIGN8(src->sin_len);

	struct sadb_address *dst_address_payload = (struct sadb_address *)(void *)(payload + tlen);
	dst_address_payload->sadb_address_exttype = SADB_EXT_ADDRESS_DST & 0xffff;
	dst_address_payload->sadb_address_proto = proto & 0xff;
	dst_address_payload->sadb_address_prefixlen = (sizeof(struct in_addr) << 3);
	dst_address_payload->sadb_address_reserved = 0;
	tlen += sizeof(*dst_address_payload);

	struct sockaddr_in *dst = (struct sockaddr_in *)(void *)(payload + tlen);
	T_QUIET; T_ASSERT_EQ_INT(inet_pton(AF_INET, TEST_DST_ADDRESS_IPv4, &dst->sin_addr), 1, "dst address fail");
	dst->sin_family = AF_INET;
	dst->sin_len = sizeof(*dst);
	len = sizeof(*dst_address_payload) + PFKEY_ALIGN8(dst->sin_len);
	dst_address_payload->sadb_address_len = PFKEY_UNIT64(len);
	tlen += PFKEY_ALIGN8(dst->sin_len);

	struct sadb_lifetime *lifetime_payload = (struct sadb_lifetime *)(void *)(payload + tlen);
	lifetime_payload->sadb_lifetime_len = PFKEY_UNIT64(sizeof(*lifetime_payload));
	lifetime_payload->sadb_lifetime_exttype = SADB_EXT_LIFETIME_HARD;
	tlen += sizeof(*lifetime_payload);

	struct sadb_x_policy *policy_payload = (struct sadb_x_policy *)(void *)(payload + tlen);
	policy_payload->sadb_x_policy_len = PFKEY_UNIT64(sizeof(*policy_payload));
	policy_payload->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	policy_payload->sadb_x_policy_type = IPSEC_POLICY_DISCARD;
	policy_payload->sadb_x_policy_dir = IPSEC_DIR_OUTBOUND;
	tlen += sizeof(*policy_payload);

	// Update the total length
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(send(pfkey_socket, payload, (size_t)PFKEY_UNUNIT64(msg_payload->sadb_msg_len), 0), "pfkey send spd add");
}

static void
send_pfkey_spd_get_message(int pfkey_socket, uint32_t policy_id)
{
	uint8_t payload[MCLBYTES]  __attribute__ ((aligned(32)));
	bzero(payload, sizeof(payload));
	uint16_t tlen = 0;

	struct sadb_msg *msg_payload = (struct sadb_msg *)(void *)payload;
	msg_payload->sadb_msg_version = PF_KEY_V2;
	msg_payload->sadb_msg_type = SADB_X_SPDGET;
	msg_payload->sadb_msg_errno = 0;
	msg_payload->sadb_msg_satype = SADB_SATYPE_UNSPEC;
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	msg_payload->sadb_msg_reserved = 0;
	msg_payload->sadb_msg_seq = 0;
	msg_payload->sadb_msg_pid = (uint32_t)getpid();
	tlen += sizeof(*msg_payload);

	struct sadb_x_policy *policy_payload = (struct sadb_x_policy *)(void *)(payload + tlen);
	policy_payload->sadb_x_policy_len = PFKEY_UNIT64(sizeof(*policy_payload));
	policy_payload->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	policy_payload->sadb_x_policy_id = policy_id;
	tlen += sizeof(*policy_payload);

	// Update the total length
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(send(pfkey_socket, payload, (size_t)PFKEY_UNUNIT64(msg_payload->sadb_msg_len), 0), "pfkey send spd get failed");
}

static void
send_pfkey_spd_enable_message(int pfkey_socket, uint32_t policy_id)
{
	uint8_t payload[MCLBYTES]  __attribute__ ((aligned(32)));
	bzero(payload, sizeof(payload));
	uint16_t tlen = 0;

	struct sadb_msg *msg_payload = (struct sadb_msg *)(void *)payload;
	msg_payload->sadb_msg_version = PF_KEY_V2;
	msg_payload->sadb_msg_type = SADB_X_SPDENABLE;
	msg_payload->sadb_msg_errno = 0;
	msg_payload->sadb_msg_satype = SADB_SATYPE_UNSPEC;
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	msg_payload->sadb_msg_reserved = 0;
	msg_payload->sadb_msg_seq = 0;
	msg_payload->sadb_msg_pid = (uint32_t)getpid();
	tlen += sizeof(*msg_payload);

	struct sadb_x_policy *policy_payload = (struct sadb_x_policy *)(void *)(payload + tlen);
	policy_payload->sadb_x_policy_len = PFKEY_UNIT64(sizeof(*policy_payload));
	policy_payload->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	policy_payload->sadb_x_policy_id = policy_id;
	tlen += sizeof(*policy_payload);

	// Update the total length
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(send(pfkey_socket, payload, (size_t)PFKEY_UNUNIT64(msg_payload->sadb_msg_len), 0), "pfkey send spd enable failed");
}

static void
send_pfkey_spd_disable_message(int pfkey_socket, uint32_t policy_id)
{
	uint8_t payload[MCLBYTES]  __attribute__ ((aligned(32)));
	bzero(payload, sizeof(payload));
	uint16_t tlen = 0;

	struct sadb_msg *msg_payload = (struct sadb_msg *)(void *)payload;
	msg_payload->sadb_msg_version = PF_KEY_V2;
	msg_payload->sadb_msg_type = SADB_X_SPDDISABLE;
	msg_payload->sadb_msg_errno = 0;
	msg_payload->sadb_msg_satype = SADB_SATYPE_UNSPEC;
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	msg_payload->sadb_msg_reserved = 0;
	msg_payload->sadb_msg_seq = 0;
	msg_payload->sadb_msg_pid = (uint32_t)getpid();
	tlen += sizeof(*msg_payload);

	struct sadb_x_policy *policy_payload = (struct sadb_x_policy *)(void *)(payload + tlen);
	policy_payload->sadb_x_policy_len = PFKEY_UNIT64(sizeof(*policy_payload));
	policy_payload->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	policy_payload->sadb_x_policy_id = policy_id;
	tlen += sizeof(*policy_payload);

	// Update the total length
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(send(pfkey_socket, payload, (size_t)PFKEY_UNUNIT64(msg_payload->sadb_msg_len), 0), "pfkey send spd disable failed");
}

static void
send_pfkey_spd_delete_message(int pfkey_socket, uint32_t policy_id)
{
	uint8_t payload[MCLBYTES]  __attribute__ ((aligned(32)));
	bzero(payload, sizeof(payload));
	uint16_t tlen = 0;

	struct sadb_msg *msg_payload = (struct sadb_msg *)payload;
	msg_payload->sadb_msg_version = PF_KEY_V2;
	msg_payload->sadb_msg_type = SADB_X_SPDDELETE2;
	msg_payload->sadb_msg_errno = 0;
	msg_payload->sadb_msg_satype = SADB_SATYPE_UNSPEC;
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	msg_payload->sadb_msg_reserved = 0;
	msg_payload->sadb_msg_seq = 0;
	msg_payload->sadb_msg_pid = (uint32_t)getpid();
	tlen += sizeof(*msg_payload);

	struct sadb_x_policy *policy_payload = (struct sadb_x_policy *)(void *)(payload + tlen);
	policy_payload->sadb_x_policy_len = PFKEY_UNIT64(sizeof(*policy_payload));
	policy_payload->sadb_x_policy_exttype = SADB_X_EXT_POLICY;
	policy_payload->sadb_x_policy_id = policy_id;
	tlen += sizeof(*policy_payload);

	// Update the total length
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(send(pfkey_socket, payload, (size_t)PFKEY_UNUNIT64(msg_payload->sadb_msg_len), 0), "pfkey send spd delete failed");
}

static void
send_pfkey_spd_dump_message(int pfkey_socket)
{
	uint8_t payload[MCLBYTES]  __attribute__ ((aligned(32)));
	bzero(payload, sizeof(payload));
	uint16_t tlen = 0;

	struct sadb_msg *msg_payload = (struct sadb_msg *)(void *)payload;
	msg_payload->sadb_msg_version = PF_KEY_V2;
	msg_payload->sadb_msg_type = SADB_X_SPDDUMP;
	msg_payload->sadb_msg_errno = 0;
	msg_payload->sadb_msg_satype = SADB_SATYPE_UNSPEC;
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	msg_payload->sadb_msg_reserved = 0;
	msg_payload->sadb_msg_seq = 0;
	msg_payload->sadb_msg_pid = (uint32_t)getpid();
	tlen += sizeof(*msg_payload);

	// Update the total length
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(send(pfkey_socket, payload, (size_t)PFKEY_UNUNIT64(msg_payload->sadb_msg_len), 0), "pfkey send spd dump failed");
}

static void
send_pfkey_flush_sp(int pfkey_socket)
{
	uint8_t payload[MCLBYTES] __attribute__ ((aligned(32)));
	bzero(payload, sizeof(payload));
	uint16_t tlen = 0;

	struct sadb_msg *msg_payload = (struct sadb_msg *)payload;
	msg_payload->sadb_msg_version = PF_KEY_V2;
	msg_payload->sadb_msg_type = SADB_X_SPDFLUSH;
	msg_payload->sadb_msg_errno = 0;
	msg_payload->sadb_msg_satype = SADB_SATYPE_UNSPEC;
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	msg_payload->sadb_msg_reserved = 0;
	msg_payload->sadb_msg_seq = 0;
	msg_payload->sadb_msg_pid = (u_int32_t)getpid();
	tlen += sizeof(*msg_payload);

	// Update the total length
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(send(pfkey_socket, payload, (size_t)PFKEY_UNUNIT64(msg_payload->sadb_msg_len), 0), "pfkey flush security policies");
}

static void
send_pkey_get_spi(int pfkey_socket)
{
	uint8_t payload[MCLBYTES] __attribute__ ((aligned(32)));
	bzero(payload, sizeof(payload));
	uint16_t tlen = 0;

	struct sadb_msg *msg_payload = (struct sadb_msg *)payload;
	msg_payload->sadb_msg_version = PF_KEY_V2;
	msg_payload->sadb_msg_type = SADB_GETSPI;
	msg_payload->sadb_msg_errno = 0;
	msg_payload->sadb_msg_satype = SADB_SATYPE_ESP;
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	msg_payload->sadb_msg_reserved = 0;
	msg_payload->sadb_msg_seq = 0;
	msg_payload->sadb_msg_pid = (u_int32_t)getpid();
	tlen += sizeof(*msg_payload);

	struct sadb_x_sa2 *sa2_payload = (struct sadb_x_sa2 *)(void *)(payload + tlen);
	sa2_payload->sadb_x_sa2_len = PFKEY_UNIT64(sizeof(*sa2_payload));
	sa2_payload->sadb_x_sa2_exttype = SADB_X_EXT_SA2;
	sa2_payload->sadb_x_sa2_mode = IPSEC_MODE_TRANSPORT;
	sa2_payload->sadb_x_sa2_reqid = 0;
	tlen += sizeof(*sa2_payload);

	struct sadb_address *src_address_payload = (struct sadb_address *)(void *)(payload + tlen);
	src_address_payload->sadb_address_exttype = SADB_EXT_ADDRESS_SRC & 0xffff;
	src_address_payload->sadb_address_proto = IPSEC_ULPROTO_ANY & 0xff;
	src_address_payload->sadb_address_prefixlen = (sizeof(struct in_addr) << 3);
	src_address_payload->sadb_address_reserved = 0;
	tlen += sizeof(*src_address_payload);

	struct sockaddr_in *src = (struct sockaddr_in *)(void *)(payload + tlen);
	T_QUIET; T_ASSERT_EQ_INT(inet_pton(AF_INET, TEST_SRC_ADDRESS_IPv4, &src->sin_addr), 1, "src address fail");
	src->sin_family = AF_INET;
	src->sin_len = sizeof(*src);
	uint16_t len = sizeof(*src_address_payload) + PFKEY_ALIGN8(src->sin_len);
	src_address_payload->sadb_address_len = PFKEY_UNIT64(len);
	tlen += PFKEY_ALIGN8(src->sin_len);

	struct sadb_address *dst_address_payload = (struct sadb_address *)(void *)(payload + tlen);
	dst_address_payload->sadb_address_exttype = SADB_EXT_ADDRESS_DST & 0xffff;
	dst_address_payload->sadb_address_proto = IPSEC_ULPROTO_ANY & 0xff;
	dst_address_payload->sadb_address_prefixlen = (sizeof(struct in_addr) << 3);
	dst_address_payload->sadb_address_reserved = 0;
	tlen += sizeof(*dst_address_payload);

	struct sockaddr_in *dst = (struct sockaddr_in *)(void *)(payload + tlen);
	T_QUIET; T_ASSERT_EQ_INT(inet_pton(AF_INET, TEST_DST_ADDRESS_IPv4, &dst->sin_addr), 1, "dst address fail");
	dst->sin_family = AF_INET;
	dst->sin_len = sizeof(*dst);
	len = sizeof(*dst_address_payload) + PFKEY_ALIGN8(dst->sin_len);
	dst_address_payload->sadb_address_len = PFKEY_UNIT64(len);
	tlen += PFKEY_ALIGN8(dst->sin_len);

	// Update the total length
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(send(pfkey_socket, payload, (size_t)PFKEY_UNUNIT64(msg_payload->sadb_msg_len), 0), "pfkey send get spi");
}

static void
send_pkey_add_sa(int pfkey_socket, uint32_t spi, const char *src, const char *dst, int family)
{
	uint8_t payload[MCLBYTES] __attribute__ ((aligned(32)));
	bzero(payload, sizeof(payload));
	uint16_t tlen = 0;

	struct sadb_msg *msg_payload = (struct sadb_msg *)payload;
	msg_payload->sadb_msg_version = PF_KEY_V2;
	msg_payload->sadb_msg_type = SADB_ADD;
	msg_payload->sadb_msg_errno = 0;
	msg_payload->sadb_msg_satype = SADB_SATYPE_ESP;
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	msg_payload->sadb_msg_reserved = 0;
	msg_payload->sadb_msg_seq = 0;
	msg_payload->sadb_msg_pid = (u_int32_t)getpid();
	tlen += sizeof(*msg_payload);

	struct sadb_sa_2 *sa2_payload = (struct sadb_sa_2 *)(void *)(payload + tlen);
	sa2_payload->sa.sadb_sa_len = PFKEY_UNIT64(sizeof(*sa2_payload));
	sa2_payload->sa.sadb_sa_exttype = SADB_EXT_SA;
	sa2_payload->sa.sadb_sa_spi = htonl(spi);
	sa2_payload->sa.sadb_sa_replay = 4;
	sa2_payload->sa.sadb_sa_state = SADB_SASTATE_LARVAL;
	sa2_payload->sa.sadb_sa_auth = SADB_X_AALG_SHA2_256;
	sa2_payload->sa.sadb_sa_encrypt = SADB_X_EALG_AESCBC;
	sa2_payload->sa.sadb_sa_flags |= (SADB_X_EXT_NATT | SADB_X_EXT_NATT_KEEPALIVE);
	sa2_payload->sadb_sa_natt_src_port = htons(4500);
	sa2_payload->sadb_sa_natt_port = 4500;
	sa2_payload->sadb_sa_natt_interval = 20;
	sa2_payload->sadb_sa_natt_offload_interval = 0;
	tlen += sizeof(*sa2_payload);

	struct sadb_x_sa2 *sa2_x_payload = (struct sadb_x_sa2 *)(void *)(payload + tlen);
	sa2_x_payload->sadb_x_sa2_len = PFKEY_UNIT64(sizeof(*sa2_x_payload));
	sa2_x_payload->sadb_x_sa2_exttype = SADB_X_EXT_SA2;
	sa2_x_payload->sadb_x_sa2_mode = IPSEC_MODE_TRANSPORT;
	sa2_x_payload->sadb_x_sa2_reqid = 0;
	tlen += sizeof(*sa2_x_payload);

	uint8_t prefixlen = (family == AF_INET) ? (sizeof(struct in_addr) << 3) : (sizeof(struct in6_addr) << 3);

	struct sadb_address *src_address_payload = (struct sadb_address *)(void *)(payload + tlen);
	src_address_payload->sadb_address_exttype = SADB_EXT_ADDRESS_SRC & 0xffff;
	src_address_payload->sadb_address_proto = IPSEC_ULPROTO_ANY & 0xff;
	src_address_payload->sadb_address_prefixlen = prefixlen;
	src_address_payload->sadb_address_reserved = 0;
	tlen += sizeof(*src_address_payload);

	if (family == AF_INET) {
		struct sockaddr_in *src4 = (struct sockaddr_in *)(void *)(payload + tlen);
		T_QUIET; T_ASSERT_EQ_INT(inet_pton(AF_INET, src, &src4->sin_addr), 1, "src address fail");
		src4->sin_family = AF_INET;
		src4->sin_len = sizeof(*src4);
		uint16_t len = sizeof(*src_address_payload) + PFKEY_ALIGN8(src4->sin_len);
		src_address_payload->sadb_address_len = PFKEY_UNIT64(len);
		tlen += PFKEY_ALIGN8(src4->sin_len);
	} else {
		struct sockaddr_in6 *src6 = (struct sockaddr_in6 *)(void *)(payload + tlen);
		T_QUIET; T_ASSERT_EQ_INT(inet_pton(AF_INET6, src, &src6->sin6_addr), 1, "src address fail");
		src6->sin6_family = AF_INET6;
		src6->sin6_len = sizeof(*src6);
		uint16_t len = sizeof(*src_address_payload) + PFKEY_ALIGN8(src6->sin6_len);
		src_address_payload->sadb_address_len = PFKEY_UNIT64(len);
		tlen += PFKEY_ALIGN8(src6->sin6_len);
	}

	struct sadb_address *dst_address_payload = (struct sadb_address *)(void *)(payload + tlen);
	dst_address_payload->sadb_address_exttype = SADB_EXT_ADDRESS_DST & 0xffff;
	dst_address_payload->sadb_address_proto = IPSEC_ULPROTO_ANY & 0xff;
	dst_address_payload->sadb_address_prefixlen = prefixlen;
	dst_address_payload->sadb_address_reserved = 0;
	tlen += sizeof(*dst_address_payload);

	if (family == AF_INET) {
		struct sockaddr_in *dst4 = (struct sockaddr_in *)(void *)(payload + tlen);
		T_QUIET; T_ASSERT_EQ_INT(inet_pton(AF_INET, dst, &dst4->sin_addr), 1, "dst address fail");
		dst4->sin_family = AF_INET;
		dst4->sin_len = sizeof(*dst4);
		uint16_t len = sizeof(*dst_address_payload) + PFKEY_ALIGN8(dst4->sin_len);
		dst_address_payload->sadb_address_len = PFKEY_UNIT64(len);
		tlen += PFKEY_ALIGN8(dst4->sin_len);
	} else {
		struct sockaddr_in6 *dst6 = (struct sockaddr_in6 *)(void *)(payload + tlen);
		T_QUIET; T_ASSERT_EQ_INT(inet_pton(AF_INET6, dst, &dst6->sin6_addr), 1, "dst address fail");
		dst6->sin6_family = AF_INET6;
		dst6->sin6_len = sizeof(*dst6);
		uint16_t len = sizeof(*dst_address_payload) + PFKEY_ALIGN8(dst6->sin6_len);
		dst_address_payload->sadb_address_len = PFKEY_UNIT64(len);
		tlen += PFKEY_ALIGN8(dst6->sin6_len);
	}

	struct sadb_key *encrypt_key_payload = (struct sadb_key *)(void *)(payload + tlen);
	uint16_t len = sizeof(*encrypt_key_payload) + PFKEY_ALIGN8(32);
	encrypt_key_payload->sadb_key_len = PFKEY_UNIT64(len);
	encrypt_key_payload->sadb_key_exttype = SADB_EXT_KEY_ENCRYPT;
	encrypt_key_payload->sadb_key_bits = (uint16_t)(32 << 3);
	encrypt_key_payload->sadb_key_reserved = 0;
	tlen += sizeof(*encrypt_key_payload);
	arc4random_buf(payload + tlen, 32);
	tlen += PFKEY_ALIGN8(32);

	struct sadb_key *auth_key_payload = (struct sadb_key *)(void *)(payload + tlen);
	len = sizeof(*auth_key_payload) + PFKEY_ALIGN8(32);
	auth_key_payload->sadb_key_len = PFKEY_UNIT64(len);
	auth_key_payload->sadb_key_exttype = SADB_EXT_KEY_AUTH;
	auth_key_payload->sadb_key_bits = (uint16_t)(32 << 3);
	auth_key_payload->sadb_key_reserved = 0;
	tlen += sizeof(*auth_key_payload);
	arc4random_buf(payload + tlen, 32);
	tlen += PFKEY_ALIGN8(32);

	struct sadb_lifetime *hard_lifetime_payload = (struct sadb_lifetime *)(void *)(payload + tlen);
	hard_lifetime_payload->sadb_lifetime_len = PFKEY_UNIT64(sizeof(*hard_lifetime_payload));
	hard_lifetime_payload->sadb_lifetime_exttype = SADB_EXT_LIFETIME_HARD;
	tlen += sizeof(*hard_lifetime_payload);

	struct sadb_lifetime *soft_lifetime_payload = (struct sadb_lifetime *)(void *)(payload + tlen);
	soft_lifetime_payload->sadb_lifetime_len = PFKEY_UNIT64(sizeof(*soft_lifetime_payload));
	soft_lifetime_payload->sadb_lifetime_exttype = SADB_EXT_LIFETIME_SOFT;
	tlen += sizeof(*soft_lifetime_payload);

	// Update the total length
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(send(pfkey_socket, payload, (size_t)PFKEY_UNUNIT64(msg_payload->sadb_msg_len), 0), "pfkey send update sa");
}

static void
send_pkey_update_sa(int pfkey_socket, uint32_t spi)
{
	uint8_t payload[MCLBYTES] __attribute__ ((aligned(32)));
	bzero(payload, sizeof(payload));
	uint16_t tlen = 0;

	struct sadb_msg *msg_payload = (struct sadb_msg *)payload;
	msg_payload->sadb_msg_version = PF_KEY_V2;
	msg_payload->sadb_msg_type = SADB_UPDATE;
	msg_payload->sadb_msg_errno = 0;
	msg_payload->sadb_msg_satype = SADB_SATYPE_ESP;
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	msg_payload->sadb_msg_reserved = 0;
	msg_payload->sadb_msg_seq = 0;
	msg_payload->sadb_msg_pid = (u_int32_t)getpid();
	tlen += sizeof(*msg_payload);

	struct sadb_sa_2 *sa2_payload = (struct sadb_sa_2 *)(void *)(payload + tlen);
	sa2_payload->sa.sadb_sa_len = PFKEY_UNIT64(sizeof(*sa2_payload));
	sa2_payload->sa.sadb_sa_exttype = SADB_EXT_SA;
	sa2_payload->sa.sadb_sa_spi = htonl(spi);
	sa2_payload->sa.sadb_sa_replay = 4;
	sa2_payload->sa.sadb_sa_state = SADB_SASTATE_LARVAL;
	sa2_payload->sa.sadb_sa_auth = SADB_X_AALG_SHA2_256;
	sa2_payload->sa.sadb_sa_encrypt = SADB_X_EALG_AESCBC;
	sa2_payload->sa.sadb_sa_flags |= (SADB_X_EXT_NATT | SADB_X_EXT_NATT_KEEPALIVE);
	sa2_payload->sadb_sa_natt_src_port = htons(4500);
	sa2_payload->sadb_sa_natt_port = 0;     // Bad value to trigger failure
	sa2_payload->sadb_sa_natt_interval = 20;
	sa2_payload->sadb_sa_natt_offload_interval = 0;
	tlen += sizeof(*sa2_payload);

	struct sadb_x_sa2 *sa2_x_payload = (struct sadb_x_sa2 *)(void *)(payload + tlen);
	sa2_x_payload->sadb_x_sa2_len = PFKEY_UNIT64(sizeof(*sa2_x_payload));
	sa2_x_payload->sadb_x_sa2_exttype = SADB_X_EXT_SA2;
	sa2_x_payload->sadb_x_sa2_mode = IPSEC_MODE_TRANSPORT;
	sa2_x_payload->sadb_x_sa2_reqid = 0;
	tlen += sizeof(*sa2_x_payload);

	struct sadb_address *src_address_payload = (struct sadb_address *)(void *)(payload + tlen);
	src_address_payload->sadb_address_exttype = SADB_EXT_ADDRESS_SRC & 0xffff;
	src_address_payload->sadb_address_proto = IPSEC_ULPROTO_ANY & 0xff;
	src_address_payload->sadb_address_prefixlen = (sizeof(struct in_addr) << 3);
	src_address_payload->sadb_address_reserved = 0;
	tlen += sizeof(*src_address_payload);

	struct sockaddr_in *src = (struct sockaddr_in *)(void *)(payload + tlen);
	T_QUIET; T_ASSERT_EQ_INT(inet_pton(AF_INET, TEST_SRC_ADDRESS_IPv4, &src->sin_addr), 1, "src address fail");
	src->sin_family = AF_INET;
	src->sin_len = sizeof(*src);
	uint16_t len = sizeof(*src_address_payload) + PFKEY_ALIGN8(src->sin_len);
	src_address_payload->sadb_address_len = PFKEY_UNIT64(len);
	tlen += PFKEY_ALIGN8(src->sin_len);

	struct sadb_address *dst_address_payload = (struct sadb_address *)(void *)(payload + tlen);
	dst_address_payload->sadb_address_exttype = SADB_EXT_ADDRESS_DST & 0xffff;
	dst_address_payload->sadb_address_proto = IPSEC_ULPROTO_ANY & 0xff;
	dst_address_payload->sadb_address_prefixlen = (sizeof(struct in_addr) << 3);
	dst_address_payload->sadb_address_reserved = 0;
	tlen += sizeof(*dst_address_payload);

	struct sockaddr_in *dst = (struct sockaddr_in *)(void *)(payload + tlen);
	T_QUIET; T_ASSERT_EQ_INT(inet_pton(AF_INET, TEST_DST_ADDRESS_IPv4, &dst->sin_addr), 1, "dst address fail");
	dst->sin_family = AF_INET;
	dst->sin_len = sizeof(*dst);
	len = sizeof(*dst_address_payload) + PFKEY_ALIGN8(dst->sin_len);
	dst_address_payload->sadb_address_len = PFKEY_UNIT64(len);
	tlen += PFKEY_ALIGN8(dst->sin_len);

	struct sadb_key *encrypt_key_payload = (struct sadb_key *)(void *)(payload + tlen);
	len = sizeof(*encrypt_key_payload) + PFKEY_ALIGN8(32);
	encrypt_key_payload->sadb_key_len = PFKEY_UNIT64(len);
	encrypt_key_payload->sadb_key_exttype = SADB_EXT_KEY_ENCRYPT;
	encrypt_key_payload->sadb_key_bits = (uint16_t)(32 << 3);
	encrypt_key_payload->sadb_key_reserved = 0;
	tlen += sizeof(*encrypt_key_payload);
	arc4random_buf(payload + tlen, 32);
	tlen += PFKEY_ALIGN8(32);

	struct sadb_key *auth_key_payload = (struct sadb_key *)(void *)(payload + tlen);
	len = sizeof(*auth_key_payload) + PFKEY_ALIGN8(32);
	auth_key_payload->sadb_key_len = PFKEY_UNIT64(len);
	auth_key_payload->sadb_key_exttype = SADB_EXT_KEY_AUTH;
	auth_key_payload->sadb_key_bits = (uint16_t)(32 << 3);
	auth_key_payload->sadb_key_reserved = 0;
	tlen += sizeof(*auth_key_payload);
	arc4random_buf(payload + tlen, 32);
	tlen += PFKEY_ALIGN8(32);

	struct sadb_lifetime *hard_lifetime_payload = (struct sadb_lifetime *)(void *)(payload + tlen);
	hard_lifetime_payload->sadb_lifetime_len = PFKEY_UNIT64(sizeof(*hard_lifetime_payload));
	hard_lifetime_payload->sadb_lifetime_exttype = SADB_EXT_LIFETIME_HARD;
	tlen += sizeof(*hard_lifetime_payload);

	struct sadb_lifetime *soft_lifetime_payload = (struct sadb_lifetime *)(void *)(payload + tlen);
	soft_lifetime_payload->sadb_lifetime_len = PFKEY_UNIT64(sizeof(*soft_lifetime_payload));
	soft_lifetime_payload->sadb_lifetime_exttype = SADB_EXT_LIFETIME_SOFT;
	tlen += sizeof(*soft_lifetime_payload);

	// Update the total length
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(send(pfkey_socket, payload, (size_t)PFKEY_UNUNIT64(msg_payload->sadb_msg_len), 0), "pfkey send update sa");
}

static void
send_pkey_migrate_sa(int pfkey_socket, uint32_t spi, const char *src, const char *dst, int family,
    const char *migrate_src, const char *migrate_dst, int migrate_family)
{
	uint8_t payload[MCLBYTES] __attribute__ ((aligned(32)));
	bzero(payload, sizeof(payload));
	uint16_t tlen = 0;

	struct sadb_msg *msg_payload = (struct sadb_msg *)payload;
	msg_payload->sadb_msg_version = PF_KEY_V2;
	msg_payload->sadb_msg_type = SADB_MIGRATE;
	msg_payload->sadb_msg_errno = 0;
	msg_payload->sadb_msg_satype = SADB_SATYPE_ESP;
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	msg_payload->sadb_msg_reserved = 0;
	msg_payload->sadb_msg_seq = 0;
	msg_payload->sadb_msg_pid = (u_int32_t)getpid();
	tlen += sizeof(*msg_payload);

	struct sadb_sa_2 *sa2_payload = (struct sadb_sa_2 *)(void *)(payload + tlen);
	sa2_payload->sa.sadb_sa_len = PFKEY_UNIT64(sizeof(*sa2_payload));
	sa2_payload->sa.sadb_sa_exttype = SADB_EXT_SA;
	sa2_payload->sa.sadb_sa_spi = htonl(spi);
	sa2_payload->sa.sadb_sa_replay = 4;
	sa2_payload->sa.sadb_sa_state = SADB_SASTATE_LARVAL;
	sa2_payload->sa.sadb_sa_auth = SADB_X_AALG_SHA2_256;
	sa2_payload->sa.sadb_sa_encrypt = SADB_X_EALG_AESCBC;
	sa2_payload->sa.sadb_sa_flags |= (SADB_X_EXT_NATT | SADB_X_EXT_NATT_KEEPALIVE);
	sa2_payload->sadb_sa_natt_src_port = htons(4500);
	sa2_payload->sadb_sa_natt_port = 0;     // Bad value to trigger failure
	sa2_payload->sadb_sa_natt_interval = 20;
	sa2_payload->sadb_sa_natt_offload_interval = 0;
	tlen += sizeof(*sa2_payload);

	struct sadb_x_sa2 *sa2_x_payload = (struct sadb_x_sa2 *)(void *)(payload + tlen);
	sa2_x_payload->sadb_x_sa2_len = PFKEY_UNIT64(sizeof(*sa2_x_payload));
	sa2_x_payload->sadb_x_sa2_exttype = SADB_X_EXT_SA2;
	sa2_x_payload->sadb_x_sa2_mode = IPSEC_MODE_TRANSPORT;
	sa2_x_payload->sadb_x_sa2_reqid = 0;
	tlen += sizeof(*sa2_x_payload);

	uint8_t prefixlen = (family == AF_INET) ? (sizeof(struct in_addr) << 3) : (sizeof(struct in6_addr) << 3);

	struct sadb_address *src_address_payload = (struct sadb_address *)(void *)(payload + tlen);
	src_address_payload->sadb_address_exttype = SADB_EXT_ADDRESS_SRC & 0xffff;
	src_address_payload->sadb_address_proto = IPSEC_ULPROTO_ANY & 0xff;
	src_address_payload->sadb_address_prefixlen = prefixlen;
	src_address_payload->sadb_address_reserved = 0;
	tlen += sizeof(*src_address_payload);

	if (family == AF_INET) {
		struct sockaddr_in *src4 = (struct sockaddr_in *)(void *)(payload + tlen);
		T_QUIET; T_ASSERT_EQ_INT(inet_pton(AF_INET, src, &src4->sin_addr), 1, "src address fail");
		src4->sin_family = AF_INET;
		src4->sin_len = sizeof(*src4);
		uint16_t len = sizeof(*src_address_payload) + PFKEY_ALIGN8(src4->sin_len);
		src_address_payload->sadb_address_len = PFKEY_UNIT64(len);
		tlen += PFKEY_ALIGN8(src4->sin_len);
	} else {
		struct sockaddr_in6 *src6 = (struct sockaddr_in6 *)(void *)(payload + tlen);
		T_QUIET; T_ASSERT_EQ_INT(inet_pton(AF_INET6, src, &src6->sin6_addr), 1, "src address fail");
		src6->sin6_family = AF_INET6;
		src6->sin6_len = sizeof(*src6);
		uint16_t len = sizeof(*src_address_payload) + PFKEY_ALIGN8(src6->sin6_len);
		src_address_payload->sadb_address_len = PFKEY_UNIT64(len);
		tlen += PFKEY_ALIGN8(src6->sin6_len);
	}

	struct sadb_address *dst_address_payload = (struct sadb_address *)(void *)(payload + tlen);
	dst_address_payload->sadb_address_exttype = SADB_EXT_ADDRESS_DST & 0xffff;
	dst_address_payload->sadb_address_proto = IPSEC_ULPROTO_ANY & 0xff;
	dst_address_payload->sadb_address_prefixlen = prefixlen;
	dst_address_payload->sadb_address_reserved = 0;
	tlen += sizeof(*dst_address_payload);

	if (family == AF_INET) {
		struct sockaddr_in *dst4 = (struct sockaddr_in *)(void *)(payload + tlen);
		T_QUIET; T_ASSERT_EQ_INT(inet_pton(AF_INET, dst, &dst4->sin_addr), 1, "dst address fail");
		dst4->sin_family = AF_INET;
		dst4->sin_len = sizeof(*dst4);
		uint16_t len = sizeof(*dst_address_payload) + PFKEY_ALIGN8(dst4->sin_len);
		dst_address_payload->sadb_address_len = PFKEY_UNIT64(len);
		tlen += PFKEY_ALIGN8(dst4->sin_len);
	} else {
		struct sockaddr_in6 *dst6 = (struct sockaddr_in6 *)(void *)(payload + tlen);
		T_QUIET; T_ASSERT_EQ_INT(inet_pton(AF_INET6, dst, &dst6->sin6_addr), 1, "dst address fail");
		dst6->sin6_family = AF_INET6;
		dst6->sin6_len = sizeof(*dst6);
		uint16_t len = sizeof(*dst_address_payload) + PFKEY_ALIGN8(dst6->sin6_len);
		dst_address_payload->sadb_address_len = PFKEY_UNIT64(len);
		tlen += PFKEY_ALIGN8(dst6->sin6_len);
	}

	prefixlen = (migrate_family == AF_INET) ? (sizeof(struct in_addr) << 3) : (sizeof(struct in6_addr) << 3);

	struct sadb_address *migrate_src_address_payload = (struct sadb_address *)(void *)(payload + tlen);
	migrate_src_address_payload->sadb_address_exttype = SADB_EXT_MIGRATE_ADDRESS_SRC & 0xffff;
	migrate_src_address_payload->sadb_address_proto = IPSEC_ULPROTO_ANY & 0xff;
	migrate_src_address_payload->sadb_address_prefixlen = prefixlen;
	migrate_src_address_payload->sadb_address_reserved = 0;
	tlen += sizeof(*migrate_src_address_payload);

	if (migrate_family == AF_INET) {
		struct sockaddr_in *migrate_src4 = (struct sockaddr_in *)(void *)(payload + tlen);
		T_QUIET; T_ASSERT_EQ_INT(inet_pton(AF_INET, migrate_src, &migrate_src4->sin_addr), 1, "migrate src fail");
		migrate_src4->sin_family = AF_INET;
		migrate_src4->sin_len = sizeof(*migrate_src4);
		uint16_t len = sizeof(*migrate_src_address_payload) + PFKEY_ALIGN8(migrate_src4->sin_len);
		migrate_src_address_payload->sadb_address_len = PFKEY_UNIT64(len);
		tlen += PFKEY_ALIGN8(migrate_src4->sin_len);
	} else if (migrate_family == AF_INET6) {
		struct sockaddr_in6 *migrate_src6 = (struct sockaddr_in6 *)(void *)(payload + tlen);
		T_QUIET; T_ASSERT_EQ_INT(inet_pton(AF_INET6, migrate_src, &migrate_src6->sin6_addr), 1, "migrate src fail");
		migrate_src6->sin6_family = AF_INET6;
		migrate_src6->sin6_len = sizeof(*migrate_src6);
		uint16_t len = sizeof(*migrate_src_address_payload) + PFKEY_ALIGN8(migrate_src6->sin6_len);
		migrate_src_address_payload->sadb_address_len = PFKEY_UNIT64(len);
		tlen += PFKEY_ALIGN8(migrate_src6->sin6_len);
	} else if (migrate_family == AF_CHAOS) {
		struct sockaddr_in6 *migrate_src6 = (struct sockaddr_in6 *)(void *)(payload + tlen);
		T_QUIET; T_ASSERT_EQ_INT(inet_pton(AF_INET6, migrate_src, &migrate_src6->sin6_addr), 1, "migrate src fail");
		migrate_src6->sin6_family = AF_INET6;
		migrate_src6->sin6_len = sizeof(*migrate_src6) + 100; // Bad value to trigger exploit
		uint16_t len = sizeof(*migrate_src_address_payload) + PFKEY_ALIGN8(migrate_src6->sin6_len);
		migrate_src_address_payload->sadb_address_len = PFKEY_UNIT64(len);
		tlen += PFKEY_ALIGN8(migrate_src6->sin6_len);
	}

	struct sadb_address *migrate_dst_address_payload = (struct sadb_address *)(void *)(payload + tlen);
	migrate_dst_address_payload->sadb_address_exttype = SADB_EXT_MIGRATE_ADDRESS_DST & 0xffff;
	migrate_dst_address_payload->sadb_address_proto = IPSEC_ULPROTO_ANY & 0xff;
	migrate_dst_address_payload->sadb_address_prefixlen = prefixlen;
	migrate_dst_address_payload->sadb_address_reserved = 0;

	tlen += sizeof(*migrate_dst_address_payload);

	if (migrate_family == AF_INET) {
		struct sockaddr_in *migrate_dst4 = (struct sockaddr_in *)(void *)(payload + tlen);
		T_QUIET; T_ASSERT_EQ_INT(inet_pton(AF_INET, migrate_dst, &migrate_dst4->sin_addr), 1, "migrate dst fail");
		migrate_dst4->sin_family = AF_INET;
		migrate_dst4->sin_len = sizeof(*migrate_dst4);
		uint16_t len = sizeof(*migrate_dst_address_payload) + PFKEY_ALIGN8(migrate_dst4->sin_len);
		migrate_dst_address_payload->sadb_address_len = PFKEY_UNIT64(len);
		tlen += PFKEY_ALIGN8(migrate_dst4->sin_len);
	} else if (migrate_family == AF_INET6) {
		struct sockaddr_in6 *migrate_dst6 = (struct sockaddr_in6 *)(void *)(payload + tlen);
		T_QUIET; T_ASSERT_EQ_INT(inet_pton(AF_INET6, migrate_dst, &migrate_dst6->sin6_addr), 1, "migrate dst fail");
		migrate_dst6->sin6_family = AF_INET6;
		migrate_dst6->sin6_len = sizeof(*migrate_dst6);
		uint16_t len = sizeof(*migrate_dst_address_payload) + PFKEY_ALIGN8(migrate_dst6->sin6_len);
		migrate_dst_address_payload->sadb_address_len = PFKEY_UNIT64(len);
		tlen += PFKEY_ALIGN8(migrate_dst6->sin6_len);
	} else if (migrate_family == AF_CHAOS) {
		struct sockaddr_in6 *migrate_dst6 = (struct sockaddr_in6 *)(void *)(payload + tlen);
		T_QUIET; T_ASSERT_EQ_INT(inet_pton(AF_INET6, migrate_dst, &migrate_dst6->sin6_addr), 1, "migrate dst fail");
		migrate_dst6->sin6_family = AF_INET6;
		migrate_dst6->sin6_len = sizeof(*migrate_dst6) + 100; // Bad value to trigger exploit
		uint16_t len = sizeof(*migrate_dst_address_payload) + PFKEY_ALIGN8(migrate_dst6->sin6_len);
		migrate_dst_address_payload->sadb_address_len = PFKEY_UNIT64(len);
		tlen += PFKEY_ALIGN8(migrate_dst6->sin6_len);
	}

	// Update the total length
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(send(pfkey_socket, payload, (size_t)PFKEY_UNUNIT64(msg_payload->sadb_msg_len), 0), "pfkey send migrate sa");
}

static void
send_pfkey_get_sa_stat(int pfkey_socket, uint32_t spi, uint32_t stat_length)
{
	uint8_t payload[MCLBYTES] __attribute__ ((aligned(32)));
	bzero(payload, sizeof(payload));
	uint16_t tlen = 0;

	struct sadb_msg *msg_payload = (struct sadb_msg *)payload;
	msg_payload->sadb_msg_version = PF_KEY_V2;
	msg_payload->sadb_msg_type = SADB_GETSASTAT;
	msg_payload->sadb_msg_errno = 0;
	msg_payload->sadb_msg_satype = SADB_SATYPE_UNSPEC;
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	msg_payload->sadb_msg_reserved = 0;
	msg_payload->sadb_msg_seq = 0;
	msg_payload->sadb_msg_pid = (u_int32_t)getpid();
	tlen += sizeof(*msg_payload);

	struct sadb_session_id *session_id_payload = (struct sadb_session_id *)(void *)(payload + tlen);
	session_id_payload->sadb_session_id_len = PFKEY_UNIT64(sizeof(*session_id_payload));
	session_id_payload->sadb_session_id_exttype = SADB_EXT_SESSION_ID;
	session_id_payload->sadb_session_id_v[0] = 1;
	tlen += sizeof(*session_id_payload);

	struct sadb_sastat *sadb_stat_payload = (struct sadb_sastat *)(void *)(payload + tlen);
	uint16_t length = sizeof(*sadb_stat_payload) + PFKEY_ALIGN8(sizeof(struct sastat));
	sadb_stat_payload->sadb_sastat_len = PFKEY_UNIT64(length);
	sadb_stat_payload->sadb_sastat_exttype = SADB_EXT_SASTAT;
	sadb_stat_payload->sadb_sastat_dir = IPSEC_DIR_OUTBOUND;
	sadb_stat_payload->sadb_sastat_list_len = stat_length;
	tlen += sizeof(*sadb_stat_payload);

	struct sastat *sastat_payload =  (struct sastat *)(void *)(payload + tlen);
	sastat_payload->spi = htonl(spi);
	tlen += PFKEY_ALIGN8(sizeof(*sastat_payload));

	// Update the total length
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(send(pfkey_socket, payload, (size_t)PFKEY_UNUNIT64(msg_payload->sadb_msg_len), 0), "pfkey send get sa stat");
}

static void
send_pkey_delete_sa(int pfkey_socket, uint32_t spi)
{
	uint8_t payload[MCLBYTES] __attribute__ ((aligned(32)));
	bzero(payload, sizeof(payload));
	uint16_t tlen = 0;

	struct sadb_msg *msg_payload = (struct sadb_msg *)payload;
	msg_payload->sadb_msg_version = PF_KEY_V2;
	msg_payload->sadb_msg_type = SADB_DELETE;
	msg_payload->sadb_msg_errno = 0;
	msg_payload->sadb_msg_satype = SADB_SATYPE_ESP;
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	msg_payload->sadb_msg_reserved = 0;
	msg_payload->sadb_msg_seq = 0;
	msg_payload->sadb_msg_pid = (u_int32_t)getpid();
	tlen += sizeof(*msg_payload);

	struct sadb_sa_2 *sa2_payload = (struct sadb_sa_2 *)(void *)(payload + tlen);
	sa2_payload->sa.sadb_sa_len = PFKEY_UNIT64(sizeof(*sa2_payload));
	sa2_payload->sa.sadb_sa_exttype = SADB_EXT_SA;
	sa2_payload->sa.sadb_sa_spi = htonl(spi);
	tlen += sizeof(*sa2_payload);

	struct sadb_address *src_address_payload = (struct sadb_address *)(void *)(payload + tlen);
	src_address_payload->sadb_address_exttype = SADB_EXT_ADDRESS_SRC & 0xffff;
	src_address_payload->sadb_address_proto = IPSEC_ULPROTO_ANY & 0xff;
	src_address_payload->sadb_address_prefixlen = (sizeof(struct in_addr) << 3);
	src_address_payload->sadb_address_reserved = 0;
	tlen += sizeof(*src_address_payload);

	struct sockaddr_in *src = (struct sockaddr_in *)(void *)(payload + tlen);
	T_QUIET; T_ASSERT_EQ_INT(inet_pton(AF_INET, TEST_SRC_ADDRESS_IPv4, &src->sin_addr), 1, "migrate src fail");
	src->sin_family = AF_INET;
	src->sin_len = sizeof(*src);
	uint16_t len = sizeof(*src_address_payload) + PFKEY_ALIGN8(src->sin_len);
	src_address_payload->sadb_address_len = PFKEY_UNIT64(len);
	tlen += PFKEY_ALIGN8(src->sin_len);

	struct sadb_address *dst_address_payload = (struct sadb_address *)(void *)(payload + tlen);
	dst_address_payload->sadb_address_exttype = SADB_EXT_ADDRESS_DST & 0xffff;
	dst_address_payload->sadb_address_proto = IPSEC_ULPROTO_ANY & 0xff;
	dst_address_payload->sadb_address_prefixlen = (sizeof(struct in_addr) << 3);
	dst_address_payload->sadb_address_reserved = 0;
	tlen += sizeof(*dst_address_payload);

	struct sockaddr_in *dst = (struct sockaddr_in *)(void *)(payload + tlen);
	T_QUIET; T_ASSERT_EQ_INT(inet_pton(AF_INET, TEST_DST_ADDRESS_IPv4, &dst->sin_addr), 1, "migrate dst fail");
	dst->sin_family = AF_INET;
	dst->sin_len = sizeof(*dst);
	len = sizeof(*dst_address_payload) + PFKEY_ALIGN8(dst->sin_len);
	dst_address_payload->sadb_address_len = PFKEY_UNIT64(len);
	tlen += PFKEY_ALIGN8(dst->sin_len);

	// Update the total length
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(send(pfkey_socket, payload, (size_t)PFKEY_UNUNIT64(msg_payload->sadb_msg_len), 0), "pfkey send delete sa");
}

static void
send_pfkey_sa_dump_message(int pfkey_socket)
{
	uint8_t payload[MCLBYTES]  __attribute__ ((aligned(32)));
	bzero(payload, sizeof(payload));
	uint16_t tlen = 0;

	struct sadb_msg *msg_payload = (struct sadb_msg *)(void *)payload;
	msg_payload->sadb_msg_version = PF_KEY_V2;
	msg_payload->sadb_msg_type = SADB_DUMP;
	msg_payload->sadb_msg_errno = 0;
	msg_payload->sadb_msg_satype = SADB_SATYPE_UNSPEC;
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	msg_payload->sadb_msg_reserved = 0;
	msg_payload->sadb_msg_seq = 0;
	msg_payload->sadb_msg_pid = (uint32_t)getpid();
	tlen += sizeof(*msg_payload);

	// Update the total length
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(send(pfkey_socket, payload, (size_t)PFKEY_UNUNIT64(msg_payload->sadb_msg_len), 0), "pfkey send sa dump failed");
}

static void
send_pfkey_flush_sa(int pfkey_socket)
{
	uint8_t payload[MCLBYTES] __attribute__ ((aligned(32)));
	bzero(payload, sizeof(payload));
	uint16_t tlen = 0;

	struct sadb_msg *msg_payload = (struct sadb_msg *)payload;
	msg_payload->sadb_msg_version = PF_KEY_V2;
	msg_payload->sadb_msg_type = SADB_FLUSH;
	msg_payload->sadb_msg_errno = 0;
	msg_payload->sadb_msg_satype = SADB_SATYPE_UNSPEC;
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	msg_payload->sadb_msg_reserved = 0;
	msg_payload->sadb_msg_seq = 0;
	msg_payload->sadb_msg_pid = (u_int32_t)getpid();
	tlen += sizeof(*msg_payload);

	// Update the total length
	msg_payload->sadb_msg_len = PFKEY_UNIT64(tlen);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(send(pfkey_socket, payload, (size_t)PFKEY_UNUNIT64(msg_payload->sadb_msg_len), 0), "pfkey flush sa");
}

static void
pfkey_cleanup(void)
{
	if (pfkey_source != NULL) {
		int pfkey_socket = (int)dispatch_source_get_handle(pfkey_source);
		if (pfkey_socket > 0) {
			send_pfkey_flush_sa(pfkey_socket);
			send_pfkey_flush_sp(pfkey_socket);
		}
		dispatch_source_cancel(pfkey_source);
		pfkey_source = NULL;
	}
}

static int
pfkey_setup_socket(void)
{
	int pfkey_socket = -1;
	int bufsiz = 0;
	const unsigned long newbufk = 1536;
	unsigned long oldmax;
	size_t  oldmaxsize = sizeof(oldmax);
	unsigned long newmax = newbufk * (1024 + 128);

	T_QUIET; T_ASSERT_POSIX_SUCCESS(pfkey_socket = socket(PF_KEY, SOCK_RAW, PF_KEY_V2), NULL);

	if (sysctlbyname("kern.ipc.maxsockbuf", &oldmax, &oldmaxsize, &newmax, sizeof(newmax)) != 0) {
		bufsiz = 233016;        /* Max allowed by default */
	} else {
		bufsiz = newbufk * 1024;
	}

	T_QUIET; T_ASSERT_POSIX_SUCCESS(setsockopt(pfkey_socket, SOL_SOCKET, SO_SNDBUF, &bufsiz, sizeof(bufsiz)), "pfkey set snd socket buf failed %d", bufsiz);
	T_QUIET; T_ASSERT_POSIX_SUCCESS(setsockopt(pfkey_socket, SOL_SOCKET, SO_RCVBUF, &bufsiz, sizeof(bufsiz)), "pfkey set recv socket buf failed %d", bufsiz);

	pfkey_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, (uintptr_t)pfkey_socket, 0, dispatch_get_main_queue());
	T_QUIET; T_ASSERT_NOTNULL(pfkey_source, "dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, ...)");
	dispatch_source_set_event_handler(pfkey_source, ^{
		recv_pfkey_message(pfkey_socket);
	});
	dispatch_source_set_cancel_handler(pfkey_source, ^{
		close(pfkey_socket);
	});
	dispatch_resume(pfkey_source);
	return pfkey_socket;
}

static void
pfkey_process_message_test_60822136(uint8_t **mhp, int pfkey_socket)
{
	struct sadb_msg *message = (struct sadb_msg *)(void *)mhp[0];
	static int counter = 0;
	static uint32_t policy_id = 0;

	if (message->sadb_msg_pid != (uint32_t)getpid()) {
		return;
	}

	if (message->sadb_msg_errno) {
		T_QUIET; T_ASSERT_EQ(message->sadb_msg_type, SADB_X_SPDDUMP, "SADB error for type %u", message->sadb_msg_type);
		pfkey_cleanup();
		T_END;
	}

	switch (message->sadb_msg_type) {
	case SADB_X_SPDADD:
	{
		struct sadb_x_policy *policy_message = (struct sadb_x_policy *)(void *)mhp[SADB_X_EXT_POLICY];
		T_QUIET; T_ASSERT_NOTNULL(policy_message, "spd add policy message is NULL");
		policy_id = policy_message->sadb_x_policy_id;
		T_LOG("Added policy id %u", policy_id);
		send_pfkey_spd_get_message(pfkey_socket, policy_id);;
		break;
	}
	case SADB_X_SPDGET:
	{
		struct sadb_x_policy *policy_message = (struct sadb_x_policy *)(void *)mhp[SADB_X_EXT_POLICY];
		T_QUIET; T_ASSERT_NOTNULL(policy_message, "spd get policy message is NULL");
		T_QUIET; T_ASSERT_EQ(policy_id, policy_message->sadb_x_policy_id, "spd_get: spid mismatch %u != %u", policy_id, policy_message->sadb_x_policy_id);
		if (counter < MAX_SPD_CHECK) {
			counter++;
			send_pfkey_spd_get_message(pfkey_socket, policy_id);
		} else {
			T_LOG("Deleting policy id %u", policy_id);
			send_pfkey_spd_delete_message(pfkey_socket, policy_id);
		}
		break;
	}
	case SADB_X_SPDDELETE2:
	{
		struct sadb_x_policy *policy_message = (struct sadb_x_policy *)(void *)mhp[SADB_X_EXT_POLICY];
		T_QUIET; T_ASSERT_NOTNULL(policy_message, "spd delete2 policy message is NULL");
		T_QUIET; T_ASSERT_EQ(policy_id, policy_message->sadb_x_policy_id, "spd_delete2: spid mismatch %u != %u", policy_id, policy_message->sadb_x_policy_id);
		T_LOG("Deleted policy id %u", policy_id);
		sleep(2);
		send_pfkey_spd_dump_message(pfkey_socket);
		break;
	}
	case SADB_X_SPDDUMP:
	{
		struct sadb_x_policy *policy_message = (struct sadb_x_policy *)(void *)mhp[SADB_X_EXT_POLICY];
		T_QUIET; T_ASSERT_NOTNULL(policy_message, "spd dump policy message is NULL");
		T_QUIET; T_ASSERT_EQ(policy_id, policy_message->sadb_x_policy_id, "spd_dump: spid mismatch %u != %u", policy_id, policy_message->sadb_x_policy_id);
		T_FAIL("Policy id %u still exists", policy_id);
		pfkey_cleanup();
		T_END;
	}
	case SADB_FLUSH:
	case SADB_X_SPDFLUSH:
		break;
	default:
		T_FAIL("bad SADB message type %u", message->sadb_msg_type);
		T_END;
	}
	return;
}

static void
pfkey_process_message_test_60822924(uint8_t **mhp, int pfkey_socket)
{
	struct sadb_msg *message = (struct sadb_msg *)(void *)mhp[0];
	static int counter = 0;
	static uint32_t policy_id = 0;

	if (message->sadb_msg_pid != (uint32_t)getpid()) {
		return;
	}

	if (message->sadb_msg_errno) {
		T_QUIET; T_ASSERT_EQ(message->sadb_msg_type, SADB_X_SPDDUMP, "SADB error for type %u", message->sadb_msg_type);
		pfkey_cleanup();
		T_END;
	}

	switch (message->sadb_msg_type) {
	case SADB_X_SPDADD:
	{
		struct sadb_x_policy *policy_message = (struct sadb_x_policy *)(void *)mhp[SADB_X_EXT_POLICY];
		T_QUIET; T_ASSERT_NOTNULL(policy_message, "spd add policy message is NULL");
		policy_id = policy_message->sadb_x_policy_id;
		T_LOG("Added policy id %u", policy_id);
		send_pfkey_spd_enable_message(pfkey_socket, policy_id);;
		break;
	}
	case SADB_X_SPDENABLE:
	{
		struct sadb_x_policy *policy_message = (struct sadb_x_policy *)(void *)mhp[SADB_X_EXT_POLICY];
		T_QUIET; T_ASSERT_NOTNULL(policy_message, "spd enable policy message is NULL");
		T_QUIET; T_ASSERT_EQ(policy_id, policy_message->sadb_x_policy_id, "spd_enable: spid mismatch %u != %u", policy_id, policy_message->sadb_x_policy_id);
		if (counter < MAX_SPD_CHECK) {
			counter++;
			send_pfkey_spd_enable_message(pfkey_socket, policy_id);
		} else {
			T_LOG("Deleting policy id %u", policy_id);
			send_pfkey_spd_delete_message(pfkey_socket, policy_id);
		}
		break;
	}
	case SADB_X_SPDDELETE2:
	{
		struct sadb_x_policy *policy_message = (struct sadb_x_policy *)(void *)mhp[SADB_X_EXT_POLICY];
		T_QUIET; T_ASSERT_NOTNULL(policy_message, "spd delete2 policy message is NULL");
		T_QUIET; T_ASSERT_EQ(policy_id, policy_message->sadb_x_policy_id, "spd_delete2: spid mismatch %u != %u", policy_id, policy_message->sadb_x_policy_id);
		T_LOG("Deleted policy id %u", policy_id);
		sleep(2);
		send_pfkey_spd_dump_message(pfkey_socket);
		break;
	}
	case SADB_X_SPDDUMP:
	{
		struct sadb_x_policy *policy_message = (struct sadb_x_policy *)(void *)mhp[SADB_X_EXT_POLICY];
		T_QUIET; T_ASSERT_NOTNULL(policy_message, "spd dump policy message is NULL");
		T_QUIET; T_ASSERT_EQ(policy_id, policy_message->sadb_x_policy_id, "spd_dump: spid mismatch %u != %u", policy_id, policy_message->sadb_x_policy_id);
		T_FAIL("Policy id %u still exists", policy_id);
		pfkey_cleanup();
		T_END;
	}
	case SADB_FLUSH:
	case SADB_X_SPDFLUSH:
		break;
	default:
		T_FAIL("bad SADB message type %u", message->sadb_msg_type);
		T_END;
	}
	return;
}

static void
pfkey_process_message_test_60822956(uint8_t **mhp, int pfkey_socket)
{
	struct sadb_msg *message = (struct sadb_msg *)(void *)mhp[0];
	static int counter = 0;
	static uint32_t policy_id = 0;

	if (message->sadb_msg_pid != (uint32_t)getpid()) {
		return;
	}

	if (message->sadb_msg_errno) {
		T_QUIET; T_ASSERT_EQ(message->sadb_msg_type, SADB_X_SPDDUMP, "SADB error for type %u", message->sadb_msg_type);
		pfkey_cleanup();
		T_END;
	}

	switch (message->sadb_msg_type) {
	case SADB_X_SPDADD:
	{
		struct sadb_x_policy *policy_message = (struct sadb_x_policy *)(void *)mhp[SADB_X_EXT_POLICY];
		T_QUIET; T_ASSERT_NOTNULL(policy_message, "spd add policy message is NULL");
		policy_id = policy_message->sadb_x_policy_id;
		T_LOG("Added policy id %u", policy_id);
		send_pfkey_spd_disable_message(pfkey_socket, policy_id);;
		break;
	}
	case SADB_X_SPDDISABLE:
	{
		struct sadb_x_policy *policy_message = (struct sadb_x_policy *)(void *)mhp[SADB_X_EXT_POLICY];
		T_QUIET; T_ASSERT_NOTNULL(policy_message, "spd disable policy message is NULL");
		T_QUIET; T_ASSERT_EQ(policy_id, policy_message->sadb_x_policy_id, "spd_disable: spid mismatch %u != %u", policy_id, policy_message->sadb_x_policy_id);
		if (counter < MAX_SPD_CHECK) {
			counter++;
			send_pfkey_spd_disable_message(pfkey_socket, policy_id);
		} else {
			T_LOG("Deleting policy id %u", policy_id);
			send_pfkey_spd_delete_message(pfkey_socket, policy_id);
		}
		break;
	}
	case SADB_X_SPDDELETE2:
	{
		struct sadb_x_policy *policy_message = (struct sadb_x_policy *)(void *)mhp[SADB_X_EXT_POLICY];
		T_QUIET; T_ASSERT_NOTNULL(policy_message, "spd delete2 policy message is NULL");
		T_QUIET; T_ASSERT_EQ(policy_id, policy_message->sadb_x_policy_id, "spd_delete2: spid mismatch %u != %u", policy_id, policy_message->sadb_x_policy_id);
		T_LOG("Deleted policy id %u", policy_id);
		sleep(2);
		send_pfkey_spd_dump_message(pfkey_socket);
		break;
	}
	case SADB_X_SPDDUMP:
	{
		struct sadb_x_policy *policy_message = (struct sadb_x_policy *)(void *)mhp[SADB_X_EXT_POLICY];
		T_QUIET; T_ASSERT_NOTNULL(policy_message, "spd dump policy message is NULL");
		T_QUIET; T_ASSERT_EQ(policy_id, policy_message->sadb_x_policy_id, "spd_dump: spid mismatch %u != %u", policy_id, policy_message->sadb_x_policy_id);
		T_FAIL("Policy id %u still exists", policy_id);
		pfkey_cleanup();
		T_END;
	}
	case SADB_FLUSH:
	case SADB_X_SPDFLUSH:
		break;
	default:
		T_FAIL("bad SADB message type %u", message->sadb_msg_type);
		T_END;
	}
	return;
}

static void
pfkey_process_message_test_60679513(uint8_t **mhp, int pfkey_socket)
{
	struct sadb_msg *message = (struct sadb_msg *)(void *)mhp[0];
	static uint32_t spi = 0;

	if (message->sadb_msg_pid != (uint32_t)getpid()) {
		return;
	}

	if (message->sadb_msg_errno) {
		T_QUIET; T_ASSERT_EQ(message->sadb_msg_type, SADB_UPDATE, "SADB error for type %u", message->sadb_msg_type);
	}

	switch (message->sadb_msg_type) {
	case SADB_GETSPI:
	{
		struct sadb_sa *sa_message = (struct sadb_sa *)(void *)mhp[SADB_EXT_SA];
		T_QUIET; T_ASSERT_NOTNULL(sa_message, "sa get spi message is NULL");
		spi = ntohl(sa_message->sadb_sa_spi);
		T_LOG("get spi 0x%x", spi);
		send_pkey_update_sa(pfkey_socket, spi);
		break;
	}
	case SADB_UPDATE:
	{
		struct sadb_sa *sa_message = (struct sadb_sa *)(void *)mhp[SADB_EXT_SA];
		T_QUIET; T_ASSERT_NOTNULL(sa_message, "update sa message is NULL");
		T_QUIET; T_ASSERT_EQ(spi, ntohl(sa_message->sadb_sa_spi), "sadb update: spi mismatch %u != %u", spi, ntohl(sa_message->sadb_sa_spi));
		T_LOG("update sa 0x%x", spi);
		send_pkey_delete_sa(pfkey_socket, spi);
		break;
	}
	case SADB_DELETE:
	{
		struct sadb_sa *sa_message = (struct sadb_sa *)(void *)mhp[SADB_EXT_SA];
		T_QUIET; T_ASSERT_NOTNULL(sa_message, "delete sa message is NULL");
		T_QUIET; T_ASSERT_EQ(spi, ntohl(sa_message->sadb_sa_spi), "sadb delete: spi mismatch %u != %u", spi, ntohl(sa_message->sadb_sa_spi));
		T_LOG("delete sa 0x%x", spi);
		pfkey_cleanup();
		T_END;
	}
	case SADB_FLUSH:
	case SADB_X_SPDFLUSH:
		break;
	default:
		T_FAIL("bad SADB message type %u", message->sadb_msg_type);
		T_END;
	}
	return;
}

static void
pfkey_process_message_test_60768729(uint8_t **mhp, int pfkey_socket)
{
	struct sadb_msg *message = (struct sadb_msg *)(void *)mhp[0];
	uint32_t spi = 0;
	static int counter = 0;

	if (message->sadb_msg_pid != (uint32_t)getpid()) {
		return;
	}

	T_QUIET; T_ASSERT_EQ(message->sadb_msg_errno, 0, "SADB error for type %u", message->sadb_msg_type);

	switch (message->sadb_msg_type) {
	case SADB_GETSPI:
	{
		struct sadb_sa *sa_message = (struct sadb_sa *)(void *)mhp[SADB_EXT_SA];
		T_QUIET; T_ASSERT_NOTNULL(sa_message, "sa get spi message is NULL");
		spi = ntohl(sa_message->sadb_sa_spi);
		counter++;
		if (counter <= 1000) {
			send_pkey_get_spi(pfkey_socket);
		} else {
			T_LOG("SADB added 1000 Larval SPIs");
			send_pfkey_sa_dump_message(pfkey_socket);
		}
		break;
	}
	case SADB_DUMP:
	{
		counter--;
		if (counter == 0) {
			T_PASS("SADB dump successful");
			pfkey_cleanup();
			T_END;
		}
		break;
	}

	case SADB_FLUSH:
	case SADB_X_SPDFLUSH:
		break;
	default:
		T_FAIL("bad SADB message type %u", message->sadb_msg_type);
		T_END;
	}
	return;
}

static void
pfkey_process_message_test_60769680(uint8_t **mhp, int pfkey_socket)
{
	struct sadb_msg *message = (struct sadb_msg *)(void *)mhp[0];
	static uint8_t counter = 0;

	if (message->sadb_msg_pid != (uint32_t)getpid()) {
		return;
	}

	T_QUIET; T_ASSERT_EQ(message->sadb_msg_errno, 0, "SADB error for type %u error %d", message->sadb_msg_type, message->sadb_msg_errno);

	switch (message->sadb_msg_type) {
	case SADB_X_SPDADD:
	{
		struct sadb_x_policy *policy_message = (struct sadb_x_policy *)(void *)mhp[SADB_X_EXT_POLICY];
		T_QUIET; T_ASSERT_NOTNULL(policy_message, "spd add policy message is NULL");
		counter++;
		if (counter <= 240) {
			send_pfkey_spd_add_message(pfkey_socket, counter + 1);
		} else {
			T_LOG("SADB added 240 security policies");
			send_pfkey_spd_dump_message(pfkey_socket);
		}
		break;
	}
	case SADB_X_SPDDUMP:
	{
		counter--;
		if (counter == 0) {
			T_PASS("SADB policy dump successful");
			pfkey_cleanup();
			T_END;
		}
		break;
	}

	case SADB_FLUSH:
	case SADB_X_SPDFLUSH:
		break;
	default:
		T_FAIL("bad SADB message type %u", message->sadb_msg_type);
		T_END;
	}
	return;
}

static void
pfkey_process_message_test_60822823(uint8_t **mhp, int pfkey_socket)
{
	struct sadb_msg *message = (struct sadb_msg *)(void *)mhp[0];
	static uint32_t spi = 0;

	if (message->sadb_msg_pid != (uint32_t)getpid()) {
		return;
	}

	if (message->sadb_msg_errno != 0) {
		T_QUIET; T_ASSERT_EQ(message->sadb_msg_type, SADB_GETSASTAT, "SADB error for type %u error %d", message->sadb_msg_type, message->sadb_msg_errno);
		T_QUIET; T_ASSERT_EQ(message->sadb_msg_errno, EINVAL, "SADB error for type %u error %d", message->sadb_msg_type, message->sadb_msg_errno);
		T_PASS("SADB get SA Stat received EINVAL");
		T_END;
	}

	switch (message->sadb_msg_type) {
	case SADB_ADD:
	{
		struct sadb_sa *sa_message = (struct sadb_sa *)(void *)mhp[SADB_EXT_SA];
		T_QUIET; T_ASSERT_NOTNULL(sa_message, "add sa message is NULL");
		spi = ntohl(sa_message->sadb_sa_spi);
		T_LOG("added sa 0x%x", spi);
		send_pfkey_get_sa_stat(pfkey_socket, spi, 5);
		break;
	}
	case SADB_GETSASTAT:
	{
		T_FAIL("get sa stat should fail %u", message->sadb_msg_type);
		T_END;
	}
	case SADB_FLUSH:
	case SADB_X_SPDFLUSH:
		break;
	default:
		T_FAIL("bad SADB message type %u", message->sadb_msg_type);
		T_END;
	}
	return;
}

static void
pfkey_process_message_test_60822823_1(uint8_t **mhp, int pfkey_socket)
{
	struct sadb_msg *message = (struct sadb_msg *)(void *)mhp[0];
	static uint32_t spi = 0;

	if (message->sadb_msg_pid != (uint32_t)getpid()) {
		return;
	}

	T_QUIET; T_ASSERT_EQ(message->sadb_msg_errno, 0, "SADB error for type %u error %d", message->sadb_msg_type, message->sadb_msg_errno);

	switch (message->sadb_msg_type) {
	case SADB_ADD:
	{
		struct sadb_sa *sa_message = (struct sadb_sa *)(void *)mhp[SADB_EXT_SA];
		T_QUIET; T_ASSERT_NOTNULL(sa_message, "add sa message is NULL");
		spi = ntohl(sa_message->sadb_sa_spi);
		T_LOG("added sa 0x%x", spi);
		send_pfkey_get_sa_stat(pfkey_socket, spi, 1);
		break;
	}
	case SADB_GETSASTAT:
	{
		struct sadb_session_id *session_id = (struct sadb_session_id *)(void *)mhp[SADB_EXT_SESSION_ID];
		T_QUIET; T_ASSERT_NOTNULL(session_id, "session id is NULL");
		T_QUIET; T_EXPECT_EQ_ULLONG(session_id->sadb_session_id_v[0], 1ULL, "Session id is not equal");
		T_PASS("get sa stat success %u", message->sadb_msg_type);
		T_END;
	}
	case SADB_FLUSH:
	case SADB_X_SPDFLUSH:
		break;
	default:
		T_FAIL("bad SADB message type %u", message->sadb_msg_type);
		T_END;
	}
	return;
}

static void
pfkey_process_message_test_60687183(uint8_t **mhp, int pfkey_socket)
{
	struct sadb_msg *message = (struct sadb_msg *)(void *)mhp[0];
	static uint32_t spi = 0;

	if (message->sadb_msg_pid != (uint32_t)getpid()) {
		return;
	}

	T_QUIET; T_ASSERT_EQ(message->sadb_msg_errno, 0, "SADB error for type %u error %d", message->sadb_msg_type, message->sadb_msg_errno);

	switch (message->sadb_msg_type) {
	case SADB_ADD:
	{
		struct sadb_sa *sa_message = (struct sadb_sa *)(void *)mhp[SADB_EXT_SA];
		T_QUIET; T_ASSERT_NOTNULL(sa_message, "add sa message is NULL");
		spi = ntohl(sa_message->sadb_sa_spi);
		T_LOG("added sa 0x%x", spi);
		send_pkey_migrate_sa(pfkey_socket, spi, TEST_SRC_ADDRESS_IPv4, TEST_DST_ADDRESS_IPv4, AF_INET,
		    TEST_MIGRATE_SRC_ADDRESS_IPv4, TEST_MIGRATE_DST_ADDRESS_IPv4, AF_INET);
		break;
	}
	case SADB_MIGRATE:
	{
		T_PASS("migrate SA success");
		T_END;
	}
	case SADB_FLUSH:
	case SADB_X_SPDFLUSH:
		break;
	default:
		T_FAIL("bad SADB message type %u", message->sadb_msg_type);
		T_END;
	}
	return;
}

static void
pfkey_process_message_test_60687183_1(uint8_t **mhp, int pfkey_socket)
{
	struct sadb_msg *message = (struct sadb_msg *)(void *)mhp[0];
	static uint32_t spi = 0;

	if (message->sadb_msg_pid != (uint32_t)getpid()) {
		return;
	}

	T_QUIET; T_ASSERT_EQ(message->sadb_msg_errno, 0, "SADB error for type %u error %d", message->sadb_msg_type, message->sadb_msg_errno);

	switch (message->sadb_msg_type) {
	case SADB_ADD:
	{
		struct sadb_sa *sa_message = (struct sadb_sa *)(void *)mhp[SADB_EXT_SA];
		T_QUIET; T_ASSERT_NOTNULL(sa_message, "add sa message is NULL");
		spi = ntohl(sa_message->sadb_sa_spi);
		T_LOG("added sa 0x%x", spi);
		send_pkey_migrate_sa(pfkey_socket, spi, TEST_SRC_ADDRESS_IPv6, TEST_DST_ADDRESS_IPv6, AF_INET6,
		    TEST_MIGRATE_SRC_ADDRESS_IPv6, TEST_MIGRATE_DST_ADDRESS_IPv6, AF_INET6);
		break;
	}
	case SADB_MIGRATE:
	{
		T_PASS("migrate SA success");
		T_END;
	}
	case SADB_FLUSH:
	case SADB_X_SPDFLUSH:
		break;
	default:
		T_FAIL("bad SADB message type %u", message->sadb_msg_type);
		T_END;
	}
	return;
}

static void
pfkey_process_message_test_60687183_2(uint8_t **mhp, int pfkey_socket)
{
	struct sadb_msg *message = (struct sadb_msg *)(void *)mhp[0];
	static uint32_t spi = 0;

	if (message->sadb_msg_pid != (uint32_t)getpid()) {
		return;
	}

	if (message->sadb_msg_errno != 0) {
		T_QUIET; T_ASSERT_EQ(message->sadb_msg_type, SADB_MIGRATE, "SADB error for type %u error %d", message->sadb_msg_type, message->sadb_msg_errno);
		T_QUIET; T_ASSERT_EQ(message->sadb_msg_errno, EINVAL, "SADB error for type %u error %d", message->sadb_msg_type, message->sadb_msg_errno);
		T_PASS("SADB migrate SA received EINVAL");
		T_END;
	}

	T_QUIET; T_ASSERT_EQ(message->sadb_msg_errno, 0, "SADB error for type %u error %d", message->sadb_msg_type, message->sadb_msg_errno);

	switch (message->sadb_msg_type) {
	case SADB_ADD:
	{
		struct sadb_sa *sa_message = (struct sadb_sa *)(void *)mhp[SADB_EXT_SA];
		T_QUIET; T_ASSERT_NOTNULL(sa_message, "add sa message is NULL");
		spi = ntohl(sa_message->sadb_sa_spi);
		T_LOG("added sa 0x%x", spi);
		send_pkey_migrate_sa(pfkey_socket, spi, TEST_SRC_ADDRESS_IPv6, TEST_DST_ADDRESS_IPv6, AF_INET6,
		    TEST_MIGRATE_SRC_ADDRESS_IPv6, TEST_MIGRATE_DST_ADDRESS_IPv6, AF_CHAOS);
		break;
	}
	case SADB_MIGRATE:
	{
		T_FAIL("migrate SA test for bad address failed");
		T_END;
	}
	case SADB_FLUSH:
	case SADB_X_SPDFLUSH:
		break;
	default:
		T_FAIL("bad SADB message type %u", message->sadb_msg_type);
		T_END;
	}
	return;
}

T_DECL(sadb_x_get_60822136, "security policy reference count overflow")
{
	test_id = TEST_SADB_X_GET_OVERFLOW_60822136;

	int pfkey_socket = pfkey_setup_socket();
	send_pfkey_flush_sa(pfkey_socket);
	send_pfkey_flush_sp(pfkey_socket);
	send_pfkey_spd_add_message(pfkey_socket, IPSEC_ULPROTO_ANY);

	dispatch_main();
}

T_DECL(sadb_x_spd_enable_60822924, "security policy reference count overflow")
{
	test_id = TEST_SADB_X_SPDENABLE_OVERFLOW_60822924;

	int pfkey_socket = pfkey_setup_socket();
	send_pfkey_flush_sa(pfkey_socket);
	send_pfkey_flush_sp(pfkey_socket);
	send_pfkey_spd_add_message(pfkey_socket, IPSEC_ULPROTO_ANY);

	dispatch_main();
}

T_DECL(sadb_x_spd_disable_60822956, "security policy reference count overflow")
{
	test_id = TEST_SADB_X_SPDDISABLE_OVERFLOW_60822956;

	int pfkey_socket = pfkey_setup_socket();
	send_pfkey_flush_sa(pfkey_socket);
	send_pfkey_flush_sp(pfkey_socket);
	send_pfkey_spd_add_message(pfkey_socket, IPSEC_ULPROTO_ANY);

	dispatch_main();
}

T_DECL(sadb_update_60679513, "security association use after free")
{
	test_id = TEST_SADB_UPDATE_USE_AFTER_FREE_60679513;

	int pfkey_socket = pfkey_setup_socket();
	send_pfkey_flush_sa(pfkey_socket);
	send_pfkey_flush_sp(pfkey_socket);
	send_pkey_get_spi(pfkey_socket);

	dispatch_main();
}

T_DECL(sadb_dump_60768729, "security association sa dump heap overflow")
{
	test_id = TEST_SADB_DUMP_HEAP_OVERFLOW_60768729;

	int pfkey_socket = pfkey_setup_socket();
	T_ATEND(pfkey_cleanup);
	send_pfkey_flush_sa(pfkey_socket);
	send_pfkey_flush_sp(pfkey_socket);
	send_pkey_get_spi(pfkey_socket);

	dispatch_main();
}

T_DECL(sadb_policy_dump_60769680, "security association sa policy dump heap overflow")
{
	test_id = TEST_SADB_POLICY_DUMP_HEAP_OVERFLOW_60769680;

	int pfkey_socket = pfkey_setup_socket();
	T_ATEND(pfkey_cleanup);
	send_pfkey_flush_sa(pfkey_socket);
	send_pfkey_flush_sp(pfkey_socket);
	send_pfkey_spd_add_message(pfkey_socket, 1);

	dispatch_main();
}

T_DECL(sadb_get_sastat_oob_60769680, "security association get sa stat oob read")
{
	test_id = TEST_SADB_GETSASTAT_OOB_READ_60822823;

	int pfkey_socket = pfkey_setup_socket();
	T_ATEND(pfkey_cleanup);
	send_pfkey_flush_sa(pfkey_socket);
	send_pfkey_flush_sp(pfkey_socket);
	send_pkey_add_sa(pfkey_socket, 0x12345678, TEST_SRC_ADDRESS_IPv4, TEST_DST_ADDRESS_IPv4, AF_INET);

	dispatch_main();
}

T_DECL(sadb_get_sastat_success, "security association get sa stat")
{
	test_id = TEST_SADB_GETSASTAT_OOB_READ_SUCCESS;

	int pfkey_socket = pfkey_setup_socket();
	T_ATEND(pfkey_cleanup);
	send_pfkey_flush_sa(pfkey_socket);
	send_pfkey_flush_sp(pfkey_socket);
	send_pkey_add_sa(pfkey_socket, 0x12345678, TEST_SRC_ADDRESS_IPv4, TEST_DST_ADDRESS_IPv4, AF_INET);

	dispatch_main();
}

T_DECL(sadb_key_migrate_address_ipv4, "security association migrate address ipv4")
{
	test_id = TEST_SADB_EXT_MIGRATE_ADDRESS_IPv4;

	int pfkey_socket = pfkey_setup_socket();
	T_ATEND(pfkey_cleanup);
	send_pfkey_flush_sa(pfkey_socket);
	send_pfkey_flush_sp(pfkey_socket);
	send_pkey_add_sa(pfkey_socket, 0x12345678, TEST_SRC_ADDRESS_IPv4, TEST_DST_ADDRESS_IPv4, AF_INET);

	dispatch_main();
}

T_DECL(sadb_key_migrate_address_ipv6, "security association migrate address ipv6")
{
	test_id = TEST_SADB_EXT_MIGRATE_ADDRESS_IPv6;

	int pfkey_socket = pfkey_setup_socket();
	T_ATEND(pfkey_cleanup);
	send_pfkey_flush_sa(pfkey_socket);
	send_pfkey_flush_sp(pfkey_socket);
	send_pkey_add_sa(pfkey_socket, 0x12345678, TEST_SRC_ADDRESS_IPv6, TEST_DST_ADDRESS_IPv6, AF_INET6);

	dispatch_main();
}

T_DECL(sadb_key_migrate_bad_address, "security association migrate bad address")
{
	test_id = TEST_SADB_EXT_MIGRATE_BAD_ADDRESS;

	int pfkey_socket = pfkey_setup_socket();
	T_ATEND(pfkey_cleanup);
	send_pfkey_flush_sa(pfkey_socket);
	send_pfkey_flush_sp(pfkey_socket);
	send_pkey_add_sa(pfkey_socket, 0x12345678, TEST_SRC_ADDRESS_IPv6, TEST_DST_ADDRESS_IPv6, AF_INET6);

	dispatch_main();
}
