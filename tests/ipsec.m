#import <darwintest.h>
#import <darwintest_utils.h>
#import <dispatch/dispatch.h>
#import <net/pfkeyv2.h>
#import <netinet6/ipsec.h>
#import <arpa/inet.h>
#import <NetworkExtension/NetworkExtensionPrivate.h>
#import <System/net/bpf.h>
#import <System/netinet/ip.h>
#import <System/netinet/ip6.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ipsec"),
	T_META_ASROOT(true),
	T_META_CHECK_LEAKS(false));

typedef enum {
	TEST_INVALID = 0,
	TEST_IPSEC_IPv4_ENCAPSULATE_PANIC = 1,
	TEST_IPSEC_IPv6_ENCAPSULATE_PANIC = 2,
} test_identifier;

#define TEST_SRC_ADDRESS_IPv4                           "10.0.0.2"
#define TEST_DST_ADDRESS_IPv4                           "10.0.0.3"
#define TEST_IPSEC_IPv4_INTERFACE_ADDRESS               "192.168.10.10"
#define TEST_IPSEC_IPv6_INTERFACE_ADDRESS               "fdd3:0f89:9afd:9b9c::1234"
#define TEST_DELEGATE_IPSEC_INTERFACE_ADDRESS           "192.168.20.10"
#define TEST_IPSEC_IPv4_INTERFACE_MASK                  "255.255.255.255"
#define TEST_IPSEC_IPv6_INTERFACE_MASK                  "ffff:ffff:ffff:ffff::"

static test_identifier test_id = TEST_INVALID;
static dispatch_source_t pfkey_source = NULL;
static NEVirtualInterfaceRef ipsecInterface = NULL;
static NEVirtualInterfaceRef delegateIPsecInterface = NULL;
static int bpf_fd = -1;

static void bpf_write(int fd);
static void pfkey_cleanup(void);
static void pfkey_process_message_test_encapsulate_panic(uint8_t **mhp, int pfkey_socket);

static void(*const process_pfkey_message_tests[])(uint8_t * *mhp, int pfkey_socket) =
{
	NULL,
	pfkey_process_message_test_encapsulate_panic,    // TEST_IPSEC_IPv4_ENCAPSULATE_PANIC
	pfkey_process_message_test_encapsulate_panic,    // TEST_IPSEC_IPv6_ENCAPSULATE_PANIC
};

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
	sa2_x_payload->sadb_x_sa2_mode = IPSEC_MODE_TUNNEL;
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

	CFStringRef ipsecIfName = NEVirtualInterfaceCopyName(ipsecInterface);
	T_QUIET; T_ASSERT_NOTNULL(ipsecIfName, "failed to get ipsec interface name");
	char ifname[IFNAMSIZ];
	CFStringGetCString(ipsecIfName, ifname, IFNAMSIZ, kCFStringEncodingUTF8);

	CFStringRef delegateIPsecIfName = NEVirtualInterfaceCopyName(delegateIPsecInterface);
	T_QUIET; T_ASSERT_NOTNULL(delegateIPsecIfName, "failed to get delegate ipsec interface name");
	char delegateIfname[IFNAMSIZ];
	CFStringGetCString(delegateIPsecIfName, delegateIfname, IFNAMSIZ, kCFStringEncodingUTF8);

	struct sadb_x_ipsecif *ipsec_if_payload = (struct sadb_x_ipsecif *)(void *)(payload + tlen);
	ipsec_if_payload->sadb_x_ipsecif_len = PFKEY_UNIT64(sizeof(*ipsec_if_payload));
	ipsec_if_payload->sadb_x_ipsecif_exttype = SADB_X_EXT_IPSECIF;
	strncpy(ipsec_if_payload->sadb_x_ipsecif_ipsec_if, ifname, strlen(ifname));
	strncpy(ipsec_if_payload->sadb_x_ipsecif_outgoing_if, delegateIfname, strlen(delegateIfname));
	tlen += sizeof(*ipsec_if_payload);

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
		}
		dispatch_source_cancel(pfkey_source);
		pfkey_source = NULL;
	}
}

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
pfkey_process_message_test_encapsulate_panic(uint8_t **mhp, __unused int pfkey_socket)
{
	struct sadb_msg *message = (struct sadb_msg *)(void *)mhp[0];
	static uint32_t spi = 0;
	static uint8_t added_sa_counter = 0;

	if (message->sadb_msg_pid != (uint32_t)getpid()) {
		return;
	}

	if (message->sadb_msg_errno != 0) {
		T_FAIL("SADB add SA received error %d", message->sadb_msg_errno);
		T_END;
	}

	switch (message->sadb_msg_type) {
	case SADB_ADD:
	{
		struct sadb_sa *sa_message = (struct sadb_sa *)(void *)mhp[SADB_EXT_SA];
		T_QUIET; T_ASSERT_NOTNULL(sa_message, "add sa message is NULL");
		spi = ntohl(sa_message->sadb_sa_spi);
		T_LOG("added sa 0x%x", spi);
		added_sa_counter++;
		if (added_sa_counter == 2) {
			bpf_write(bpf_fd);
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

static int
bpf_new(void)
{
	char bpfdev[256];
	int i;
	int fd = -1;

	for (i = 0; true; i++) {
		snprintf(bpfdev, sizeof(bpfdev), "/dev/bpf%d", i);
		fd = open(bpfdev, O_RDWR, 0);
		if (fd >= 0) {
			break;
		}
		if (errno != EBUSY) {
			break;
		}
	}
	return fd;
}

static int
bpf_setif(int fd, const char *en_name)
{
	struct ifreq ifr;

	strlcpy(ifr.ifr_name, en_name, sizeof(ifr.ifr_name));
	return ioctl(fd, BIOCSETIF, &ifr);
}

static int
bpf_sethdr_complete(int fd)
{
	u_int8_t hdr_complete = 1;
	return ioctl(fd, BIOCSHDRCMPLT, &hdr_complete);
}

static void
bpf_write(int fd)
{
	if (test_id == TEST_IPSEC_IPv4_ENCAPSULATE_PANIC) {
		char buffer[500];
		struct ip *ipheader = (void *)buffer;
		ipheader->ip_v = IPVERSION;
		ipheader->ip_hl = (sizeof(struct ip) - 4) >> 2;
		ipheader->ip_ttl = MAXTTL;
		ipheader->ip_p = IPPROTO_UDP;
		T_QUIET; T_ASSERT_POSIX_SUCCESS(write(fd, buffer, 500), "bpf write call failed");
		T_PASS("wrote bad ip header successfully");
		T_END;
	} else if (test_id == TEST_IPSEC_IPv6_ENCAPSULATE_PANIC) {
		struct ip6_hdr ip6 = {0};
		ip6.ip6_vfc |= IPV6_VERSION;
		T_QUIET; T_ASSERT_POSIX_SUCCESS(write(fd, &ip6, sizeof(ip6) - 4), "bpf write call failed");
		T_PASS("wrote bad ipv6 header successfully");
		T_END;
	}
}

static void
bpf_socket_setup(void)
{
	int status = -1;

	bpf_fd = bpf_new();
	T_QUIET; T_ASSERT_NE(bpf_fd, -1, "failed to create bpf file descriptor");

	CFStringRef ipsecIfName = NEVirtualInterfaceCopyName(ipsecInterface);
	T_QUIET; T_ASSERT_NOTNULL(ipsecIfName, "failed to get ipsec interface name");

	char ifname[IFNAMSIZ];
	CFStringGetCString(ipsecIfName, ifname, IFNAMSIZ, kCFStringEncodingUTF8);

	status = bpf_setif(bpf_fd, ifname);
	T_QUIET; T_ASSERT_NE(status, -1, "failed to set bpf interface");

	status = bpf_sethdr_complete(bpf_fd);
	T_QUIET; T_ASSERT_NE(status, -1, "failed to set bpf header complete");
}

static NEVirtualInterfaceRef
ipsec_interface_setup(CFStringRef interfaceAddress, CFStringRef interfaceMask)
{
	Boolean status = FALSE;

	NEVirtualInterfaceRef interface = NEVirtualInterfaceCreate(NULL, kNEVirtualInterfaceValTypeIPSec, dispatch_get_main_queue(), NULL);
	T_QUIET; T_ASSERT_NOTNULL(interface, "ipsec interface creation failed");
	status = NEVirtualInterfaceSetMTU(interface, 1400);
	if (status == FALSE) {
		T_FAIL("Failed to set MTU on ipsec interface");
		T_END;
	}

	status = NEVirtualInterfaceAddAddress(interface, interfaceAddress, interfaceMask);
	if (status == FALSE) {
		T_FAIL("Failed to set address on ipsec interface");
		T_END;
	}

	CFStringRef ipsecIfName = NEVirtualInterfaceCopyName(interface);
	T_QUIET; T_ASSERT_NOTNULL(ipsecIfName, "failed to get ipsec interface name");

	char ifname[IFNAMSIZ];
	CFStringGetCString(ipsecIfName, ifname, IFNAMSIZ, kCFStringEncodingUTF8);

	T_LOG("%s interface setup", ifname);
	return interface;
}

static void
ipsec_interface_set_delegate(NEVirtualInterfaceRef interface, CFStringRef delegateInterfaceName)
{
	Boolean status = NEVirtualInterfaceSetDelegateInterface(interface, delegateInterfaceName);
	if (status == FALSE) {
		T_FAIL("Failed to set delegate on ipsec interface");
		T_END;
	}

	return;
}

static void
ipsec_cleanup(void)
{
	pfkey_cleanup();

	if (ipsecInterface != NULL) {
		NEVirtualInterfaceInvalidate(ipsecInterface);
		ipsecInterface = NULL;
	}

	if (delegateIPsecInterface != NULL) {
		NEVirtualInterfaceInvalidate(delegateIPsecInterface);
		delegateIPsecInterface = NULL;
	}

	if (bpf_fd != -1) {
		close(bpf_fd);
		bpf_fd = -1;
	}
}

T_DECL(ipsec_ipv4_encapsulate_panic_63139357, "ipsec: outer ip header length less than 20")
{
	test_id = TEST_IPSEC_IPv4_ENCAPSULATE_PANIC;

	T_ATEND(ipsec_cleanup);

	ipsecInterface = ipsec_interface_setup(CFSTR(TEST_IPSEC_IPv4_INTERFACE_ADDRESS), CFSTR(TEST_IPSEC_IPv4_INTERFACE_MASK));
	delegateIPsecInterface = ipsec_interface_setup(CFSTR(TEST_DELEGATE_IPSEC_INTERFACE_ADDRESS), CFSTR(TEST_IPSEC_IPv4_INTERFACE_MASK));

	CFStringRef delegateIPsecIfName = NEVirtualInterfaceCopyName(delegateIPsecInterface);
	T_QUIET; T_ASSERT_NOTNULL(delegateIPsecIfName, "failed to get ipsec interface name");
	ipsec_interface_set_delegate(ipsecInterface, delegateIPsecIfName);

	bpf_socket_setup();

	int pfkey_socket = pfkey_setup_socket();
	send_pfkey_flush_sa(pfkey_socket);

	send_pkey_add_sa(pfkey_socket, 0x12345678, TEST_SRC_ADDRESS_IPv4, TEST_DST_ADDRESS_IPv4, AF_INET);
	send_pkey_add_sa(pfkey_socket, 0x23456789, TEST_SRC_ADDRESS_IPv4, TEST_DST_ADDRESS_IPv4, AF_INET);

	dispatch_main();
}

T_DECL(ipsec_ipv6_encapsulate_panic_63139357, "ipsec: payload less than IPv6 header")
{
	test_id = TEST_IPSEC_IPv6_ENCAPSULATE_PANIC;

	T_ATEND(ipsec_cleanup);

	ipsecInterface = ipsec_interface_setup(CFSTR(TEST_IPSEC_IPv6_INTERFACE_ADDRESS), CFSTR(TEST_IPSEC_IPv6_INTERFACE_MASK));
	delegateIPsecInterface = ipsec_interface_setup(CFSTR(TEST_DELEGATE_IPSEC_INTERFACE_ADDRESS), CFSTR(TEST_IPSEC_IPv4_INTERFACE_MASK));

	CFStringRef delegateIPsecIfName = NEVirtualInterfaceCopyName(delegateIPsecInterface);
	T_QUIET; T_ASSERT_NOTNULL(delegateIPsecIfName, "failed to get ipsec interface name");
	ipsec_interface_set_delegate(ipsecInterface, delegateIPsecIfName);

	bpf_socket_setup();

	int pfkey_socket = pfkey_setup_socket();
	send_pfkey_flush_sa(pfkey_socket);

	send_pkey_add_sa(pfkey_socket, 0x12345678, TEST_SRC_ADDRESS_IPv4, TEST_DST_ADDRESS_IPv4, AF_INET);
	send_pkey_add_sa(pfkey_socket, 0x23456789, TEST_SRC_ADDRESS_IPv4, TEST_DST_ADDRESS_IPv4, AF_INET);

	dispatch_main();
}
