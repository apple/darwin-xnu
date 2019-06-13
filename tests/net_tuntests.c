
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/event.h>
#include <uuid/uuid.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/kern_control.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>

#include <net/if.h>
#include <net/if_ipsec.h>
#include <net/if_utun.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <net/pfkeyv2.h>
#include <netinet6/ipsec.h>

#include <darwintest.h>
#include <darwintest_utils.h>

#include <skywalk/os_skywalk_private.h> // for SK_FEATURE_*

T_GLOBAL_META(T_META_NAMESPACE("xnu.net.tun"));

#if 0
static void
log_hexdump(const void *inp, size_t len)
{
	unsigned i, off = 0;
	char buf[9+16*3+1];
	for (i = 0; i < len; i++) {
		if (i % 16 == 0)
			off = (unsigned)snprintf(buf, sizeof(buf), "%08x:", i);
		off += (unsigned)snprintf(buf+off, sizeof(buf)-off, " %02x", (((const uint8_t *)inp)[i]) & 0xff);
		if (i % 16 == 15)
			T_LOG("%s", buf);
		}
		if (len % 16)
			T_LOG("%s", buf);
}
#endif

static uint64_t
get_skywalk_features(void)
{
	uint64_t features = 0;
	size_t len = sizeof(features);
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(sysctlbyname("kern.skywalk.features", &features, &len, NULL, 0), NULL);
	T_QUIET; T_ASSERT_EQ(len, sizeof(features), NULL);
	T_QUIET; T_ASSERT_TRUE(features & SK_FEATURE_SKYWALK, NULL);
	return features;
}

static bool g_is_ipsec_test;
static bool g_is_utun_test;
static int g_OPT_ENABLE_NETIF = -1;
static int g_OPT_ENABLE_FLOWSWITCH = -1;
static int g_OPT_ENABLE_CHANNEL = -1;
static int g_OPT_GET_CHANNEL_UUID = -1;
static int g_OPT_IFNAME = -1;
static char *g_CONTROL_NAME = NULL;

static void
setup_ipsec_test(void)
{
	T_LOG("Configuring for ipsec tests");
	g_OPT_ENABLE_NETIF = IPSEC_OPT_ENABLE_NETIF;
	g_OPT_ENABLE_FLOWSWITCH = IPSEC_OPT_ENABLE_FLOWSWITCH;
	g_OPT_ENABLE_CHANNEL = IPSEC_OPT_ENABLE_CHANNEL;
	g_OPT_GET_CHANNEL_UUID = IPSEC_OPT_GET_CHANNEL_UUID;
	g_OPT_IFNAME = IPSEC_OPT_IFNAME;
	g_CONTROL_NAME = IPSEC_CONTROL_NAME;
	g_is_ipsec_test = true;
}

static void
setup_utun_test(void)
{
	T_LOG("Configuring for utun tests");
	g_OPT_ENABLE_NETIF = UTUN_OPT_ENABLE_NETIF;
	g_OPT_ENABLE_FLOWSWITCH = UTUN_OPT_ENABLE_FLOWSWITCH;
	g_OPT_ENABLE_CHANNEL = UTUN_OPT_ENABLE_CHANNEL;
	g_OPT_GET_CHANNEL_UUID = UTUN_OPT_GET_CHANNEL_UUID;
	g_OPT_IFNAME = UTUN_OPT_IFNAME;
	g_CONTROL_NAME = UTUN_CONTROL_NAME;
	g_is_utun_test = true;
}

static void
check_enables(int tunsock, int enable_netif, int enable_flowswitch, int enable_channel, uuid_t uuid)
{
	int scratch;
	socklen_t scratchlen, uuidlen;
	uuid_t scratchuuid;
	if (!uuid) {
		uuid = scratchuuid;
	}

	//T_LOG("checking tunsock %d", tunsock);

	scratchlen = sizeof(scratch);
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_NETIF,
			&scratch, &scratchlen), NULL);
	T_QUIET; T_EXPECT_EQ_ULONG((unsigned long )scratchlen, sizeof(scratch), NULL);
	T_QUIET; T_EXPECT_EQ(scratch, enable_netif, NULL);

	scratchlen = sizeof(scratch);
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_FLOWSWITCH,
			&scratch, &scratchlen), NULL);
	T_QUIET; T_EXPECT_EQ_ULONG((unsigned long )scratchlen, sizeof(scratch), NULL);
	if (get_skywalk_features() & SK_FEATURE_NETNS) {
		if (enable_netif) {
			T_QUIET; T_EXPECT_EQ(scratch, enable_flowswitch, NULL);
		} else {
			T_QUIET; T_EXPECT_EQ(scratch, 0, NULL);
		}
	} else {
		T_QUIET; T_EXPECT_EQ(scratch, 0, NULL);
	}

	scratchlen = sizeof(scratch);
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_CHANNEL,
			&scratch, &scratchlen), NULL);
	T_QUIET; T_EXPECT_EQ_ULONG((unsigned long )scratchlen, sizeof(scratch), NULL);
	if (g_is_ipsec_test && !enable_netif) {
		T_QUIET; T_EXPECT_EQ(scratch, 0, NULL);
	} else {
		T_QUIET; T_EXPECT_EQ(scratch, enable_channel, NULL);
	}

	if (scratch) {
		uuid_clear(uuid);
		uuidlen = sizeof(uuid_t);
		T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_GET_CHANNEL_UUID,
				uuid, &uuidlen), NULL);
		T_QUIET; T_EXPECT_EQ_ULONG((unsigned long )uuidlen, sizeof(uuid_t), NULL);
		T_QUIET; T_EXPECT_FALSE(uuid_is_null(uuid), NULL);
	} else {
		uuid_clear(uuid);
		uuidlen = sizeof(uuid_t);
		T_QUIET; T_EXPECT_POSIX_FAILURE(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_GET_CHANNEL_UUID,
				uuid, &uuidlen), ENXIO, NULL);
		T_QUIET; T_EXPECT_EQ_ULONG((unsigned long )uuidlen, sizeof(uuid_t), NULL);
		T_QUIET; T_EXPECT_TRUE(uuid_is_null(uuid), NULL);
	}
}

static void
tunsock_get_ifname(int s, char ifname[IFXNAMSIZ])
{
	socklen_t optlen = IFXNAMSIZ;
	T_QUIET; T_WITH_ERRNO; T_ASSERT_POSIX_ZERO(getsockopt(s, SYSPROTO_CONTROL, g_OPT_IFNAME, ifname, &optlen), NULL);
	T_QUIET; T_ASSERT_TRUE(optlen > 0, NULL);
	T_QUIET; T_ASSERT_TRUE(ifname[optlen-1] == '\0', NULL);
	T_QUIET; T_ASSERT_TRUE(strlen(ifname)+1 == optlen, "got ifname \"%s\" len %zd expected %u", ifname, strlen(ifname), optlen);
}

static short
ifnet_get_flags(int s, const char ifname[IFNAMSIZ])
{
	struct ifreq	ifr;
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifr), NULL);
	return ifr.ifr_flags;
}

static void
ifnet_add_addr4(const char ifname[IFNAMSIZ], struct in_addr *addr, struct in_addr *mask, struct in_addr *broadaddr)
{
	struct sockaddr_in *sin;
	struct in_aliasreq ifra;
	int s;

	T_QUIET; T_EXPECT_POSIX_SUCCESS(s = socket(AF_INET, SOCK_DGRAM, 0), NULL);

	memset(&ifra, 0, sizeof(ifra));
	strlcpy(ifra.ifra_name, ifname, sizeof(ifra.ifra_name));

	if (addr != NULL) {
		sin = &ifra.ifra_addr;
		sin->sin_len = sizeof(*sin);
		sin->sin_family = AF_INET;
		sin->sin_addr = *addr;
	}

	if (mask != NULL) {
		sin = &ifra.ifra_mask;
		sin->sin_len = sizeof(*sin);
		sin->sin_family = AF_INET;
		sin->sin_addr = *mask;
	}

	if (broadaddr != NULL || (addr != NULL &&
		  (ifnet_get_flags(s, ifname) & IFF_POINTOPOINT) != 0)) {
		sin = &ifra.ifra_broadaddr;
		sin->sin_len = sizeof(*sin);
		sin->sin_family = AF_INET;
		sin->sin_addr = (broadaddr != NULL) ? *broadaddr : *addr;
	}

	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(ioctl(s, SIOCAIFADDR, &ifra), NULL);

	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(close(s), NULL);
}

static int g_pfkeyso = -1;
static struct in_addr g_addr1, g_addr2;

static void
create_sa(const char ifname[IFXNAMSIZ], uint8_t type, uint32_t spi, struct in_addr *src, struct in_addr *dst)
{
	if (g_pfkeyso == -1) {
		T_QUIET; T_EXPECT_POSIX_SUCCESS(g_pfkeyso = socket(PF_KEY, SOCK_RAW, PF_KEY_V2), NULL);
	}

	/*
		<base, SA, (lifetime(HS),) address(SD), (address(P),)
		key(AE), (identity(SD),) (sensitivity)>
	*/

	struct {
		struct sadb_msg msg __attribute((aligned(sizeof (uint64_t))));
		struct sadb_key key  __attribute((aligned(sizeof (uint64_t))));
		struct sadb_sa sa  __attribute((aligned(sizeof (uint64_t))));
		struct sadb_x_sa2 sa2  __attribute((aligned(sizeof (uint64_t))));
		struct sadb_x_ipsecif ipsecif __attribute((aligned(sizeof (uint64_t))));
		struct {
			struct sadb_address addr __attribute((aligned(sizeof (uint64_t))));
			struct sockaddr_in saddr __attribute((aligned(sizeof (uint64_t))));
		} src;
		struct {
			struct sadb_address addr __attribute((aligned(sizeof (uint64_t))));
			struct sockaddr_in saddr __attribute((aligned(sizeof (uint64_t))));
		} dst;
	} addcmd;

	memset(&addcmd, 0, sizeof(addcmd));

	addcmd.msg.sadb_msg_version = PF_KEY_V2;
	addcmd.msg.sadb_msg_type = type;
	addcmd.msg.sadb_msg_errno = 0;
	addcmd.msg.sadb_msg_satype = SADB_SATYPE_ESP;
	addcmd.msg.sadb_msg_len = PFKEY_UNIT64(sizeof(addcmd));
	addcmd.msg.sadb_msg_reserved = 0;
	addcmd.msg.sadb_msg_seq = 0;
	addcmd.msg.sadb_msg_pid = (unsigned)getpid();

	addcmd.key.sadb_key_len = PFKEY_UNIT64(sizeof(addcmd.key));
	addcmd.key.sadb_key_exttype = SADB_EXT_KEY_ENCRYPT;
  addcmd.key.sadb_key_bits = 0;
  addcmd.key.sadb_key_reserved = 0;

  addcmd.sa.sadb_sa_len = PFKEY_UNIT64(sizeof(addcmd.sa));
  addcmd.sa.sadb_sa_exttype = SADB_EXT_SA;
  addcmd.sa.sadb_sa_spi = htonl(spi);
  addcmd.sa.sadb_sa_replay = 0;
  addcmd.sa.sadb_sa_state = 0;
  addcmd.sa.sadb_sa_auth = SADB_AALG_NONE;
  addcmd.sa.sadb_sa_encrypt = SADB_EALG_NULL;
  addcmd.sa.sadb_sa_flags = SADB_X_EXT_CYCSEQ;

	addcmd.sa2.sadb_x_sa2_len = PFKEY_UNIT64(sizeof(addcmd.sa2));
	addcmd.sa2.sadb_x_sa2_exttype = SADB_X_EXT_SA2;
	addcmd.sa2.sadb_x_sa2_mode = IPSEC_MODE_ANY;
	addcmd.sa2.sadb_x_sa2_alwaysexpire = 1;
	addcmd.sa2.sadb_x_sa2_flags = SADB_X_EXT_SA2_DELETE_ON_DETACH;
	addcmd.sa2.sadb_x_sa2_sequence = 0;
	addcmd.sa2.sadb_x_sa2_reqid = 0;

	addcmd.ipsecif.sadb_x_ipsecif_len = PFKEY_UNIT64(sizeof(addcmd.ipsecif));
	addcmd.ipsecif.sadb_x_ipsecif_exttype = SADB_X_EXT_IPSECIF;
	memset(addcmd.ipsecif.sadb_x_ipsecif_internal_if, 0, sizeof(addcmd.ipsecif.sadb_x_ipsecif_internal_if));
	memset(addcmd.ipsecif.sadb_x_ipsecif_outgoing_if, 0, sizeof(addcmd.ipsecif.sadb_x_ipsecif_outgoing_if));
	strlcpy(addcmd.ipsecif.sadb_x_ipsecif_ipsec_if, ifname, sizeof(addcmd.ipsecif.sadb_x_ipsecif_ipsec_if));
	addcmd.ipsecif.sadb_x_ipsecif_init_disabled = 0;
	addcmd.ipsecif.reserved = 0;

  addcmd.src.addr.sadb_address_len = PFKEY_UNIT64(sizeof(addcmd.src));
  addcmd.src.addr.sadb_address_exttype = SADB_EXT_ADDRESS_SRC;
  addcmd.src.addr.sadb_address_proto = IPSEC_ULPROTO_ANY;
  addcmd.src.addr.sadb_address_prefixlen = sizeof(struct in_addr) << 3; //XXX Why?
	addcmd.src.addr.sadb_address_reserved = 0;
	addcmd.src.saddr.sin_len = sizeof(addcmd.src.saddr);
	addcmd.src.saddr.sin_family = AF_INET;
	addcmd.src.saddr.sin_port = htons(0);
	addcmd.src.saddr.sin_addr = *src;

  addcmd.dst.addr.sadb_address_len = PFKEY_UNIT64(sizeof(addcmd.dst));
  addcmd.dst.addr.sadb_address_exttype = SADB_EXT_ADDRESS_DST;
  addcmd.dst.addr.sadb_address_proto = IPSEC_ULPROTO_ANY;
	addcmd.dst.addr.sadb_address_prefixlen = sizeof(struct in_addr) << 3; //XXX Why?
	addcmd.dst.addr.sadb_address_reserved = 0;
	addcmd.dst.saddr.sin_len = sizeof(addcmd.dst.saddr);
	addcmd.dst.saddr.sin_family = AF_INET;
	addcmd.dst.saddr.sin_port = htons(0);
	addcmd.dst.saddr.sin_addr = *dst;

	//log_hexdump(&addcmd, sizeof(addcmd));

	ssize_t slen;
	T_QUIET; T_EXPECT_POSIX_SUCCESS(slen = send(g_pfkeyso, &addcmd, sizeof(addcmd), 0), NULL);
	T_QUIET; T_EXPECT_EQ(slen, (ssize_t)sizeof(addcmd), NULL);
}

static int
create_tunsock(int enable_netif, int enable_flowswitch, int enable_channel)
{
	int tunsock;
	struct ctl_info kernctl_info;
	struct sockaddr_ctl kernctl_addr;
	uuid_t uuid;
	socklen_t uuidlen;

startover:

	T_QUIET; T_EXPECT_POSIX_SUCCESS(tunsock = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL), NULL);

	memset(&kernctl_info, 0, sizeof(kernctl_info));
	strlcpy(kernctl_info.ctl_name, g_CONTROL_NAME, sizeof(kernctl_info.ctl_name));
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(ioctl(tunsock, CTLIOCGINFO, &kernctl_info), NULL);

	memset(&kernctl_addr, 0, sizeof(kernctl_addr));
	kernctl_addr.sc_len = sizeof(kernctl_addr);
	kernctl_addr.sc_family = AF_SYSTEM;
	kernctl_addr.ss_sysaddr = AF_SYS_CONTROL;
	kernctl_addr.sc_id = kernctl_info.ctl_id;
	kernctl_addr.sc_unit = 0;

	//T_LOG("enable_netif = %d, enable_flowswitch = %d, enable_channel = %d",
	//enable_netif, enable_channel, enable_flowswitch);

	T_QUIET; T_EXPECT_POSIX_FAILURE(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_NETIF,
			&enable_netif, sizeof(enable_netif)), EINVAL, NULL);
	T_QUIET; T_EXPECT_POSIX_FAILURE(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_FLOWSWITCH,
			&enable_flowswitch, sizeof(enable_flowswitch)), EINVAL, NULL);
	T_QUIET; T_EXPECT_POSIX_FAILURE(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_CHANNEL,
			&enable_channel, sizeof(enable_channel)), EINVAL, NULL);
	uuid_clear(uuid);
	uuidlen = sizeof(uuid_t);
	T_QUIET; T_EXPECT_POSIX_FAILURE(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_GET_CHANNEL_UUID,
			uuid, &uuidlen), EINVAL, NULL);
	T_QUIET; T_EXPECT_EQ_ULONG((unsigned long )uuidlen, sizeof(uuid_t), NULL);
	T_QUIET; T_EXPECT_TRUE(uuid_is_null(uuid), NULL);

	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(bind(tunsock, (struct sockaddr *)&kernctl_addr, sizeof(kernctl_addr)), NULL);

	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_NETIF,
				&enable_netif, sizeof(enable_netif)), NULL);
	T_QUIET; T_EXPECT_POSIX_FAILURE(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_FLOWSWITCH,
			&enable_flowswitch, sizeof(enable_flowswitch)), EINVAL, NULL);
	T_QUIET; T_EXPECT_POSIX_FAILURE(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_CHANNEL,
			&enable_channel, sizeof(enable_channel)), EINVAL, NULL);
	uuid_clear(uuid);
	uuidlen = sizeof(uuid_t);
	T_QUIET; T_EXPECT_POSIX_FAILURE(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_GET_CHANNEL_UUID,
			uuid, &uuidlen), ENXIO, NULL);
	T_QUIET; T_EXPECT_EQ_ULONG((unsigned long )uuidlen, sizeof(uuid_t), NULL);
	T_QUIET; T_EXPECT_TRUE(uuid_is_null(uuid), NULL);

	int error = connect(tunsock, (struct sockaddr *)&kernctl_addr, sizeof(kernctl_addr));
	if (error == -1 && errno == EBUSY) {
		/* XXX remove this retry nonsense when this is fixed:
		 * <rdar://problem/37340313> creating an interface without specifying specific interface name should not return EBUSY
		 */
		close(tunsock);
		T_LOG("connect got EBUSY, sleeping 1 second before retry");
		sleep(1);
		goto startover;
	}
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(error, "connect()");

	T_QUIET; T_EXPECT_POSIX_FAILURE(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_NETIF,
			&enable_netif, sizeof(enable_netif)), EINVAL, NULL);

	if (get_skywalk_features() & SK_FEATURE_NETNS) {
		if (enable_netif) {
			T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_FLOWSWITCH,
					&enable_flowswitch, sizeof(enable_flowswitch)), NULL);
		} else {
			T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_FAILURE(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_FLOWSWITCH,
					&enable_flowswitch, sizeof(enable_flowswitch)), ENOENT, NULL);
		}
	} else {
		T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_FAILURE(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_FLOWSWITCH,
				&enable_flowswitch, sizeof(enable_flowswitch)), ENOTSUP, NULL);
	}

	if (enable_channel) {
		if (g_is_ipsec_test && !enable_netif) {
			/* ipsec doesn't support channels without a netif */
			T_QUIET; T_EXPECT_POSIX_FAILURE(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_CHANNEL,
					&enable_channel, sizeof(enable_channel)), EOPNOTSUPP, NULL);
			uuid_clear(uuid);
			uuidlen = sizeof(uuid_t);
			T_QUIET; T_EXPECT_POSIX_FAILURE(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_GET_CHANNEL_UUID,
					uuid, &uuidlen), ENXIO, NULL);
			T_QUIET; T_EXPECT_EQ_ULONG((unsigned long )uuidlen, sizeof(uuid_t), NULL);
			T_QUIET; T_EXPECT_TRUE(uuid_is_null(uuid), NULL);
		} else {
			T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_CHANNEL,
					&enable_channel, sizeof(enable_channel)), NULL);
			uuid_clear(uuid);
			uuidlen = sizeof(uuid_t);
			T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_GET_CHANNEL_UUID,
					uuid, &uuidlen), NULL);
			T_QUIET; T_EXPECT_EQ_ULONG((unsigned long )uuidlen, sizeof(uuid_t), NULL);
			T_QUIET; T_EXPECT_FALSE(uuid_is_null(uuid), NULL);
		}
	} else {
		T_QUIET; T_EXPECT_POSIX_FAILURE(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_CHANNEL,
				&enable_channel, sizeof(enable_channel)), ENXIO, NULL);
		uuid_clear(uuid);
		uuidlen = sizeof(uuid_t);
		T_QUIET; T_EXPECT_POSIX_FAILURE(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_GET_CHANNEL_UUID,
				uuid, &uuidlen), ENXIO, NULL);
		T_QUIET; T_EXPECT_EQ_ULONG((unsigned long )uuidlen, sizeof(uuid_t), NULL);
		T_QUIET; T_EXPECT_TRUE(uuid_is_null(uuid), NULL);
	}

	check_enables(tunsock, enable_netif, enable_flowswitch, enable_channel, uuid);

	//T_LOG("Returning tunsock %d", tunsock);

	return tunsock;
}

#if 0
static void
ipsec_stats(void)
{
	struct ifmibdata ifmd;

		len = sizeof(struct ifmibdata);
		name[3] = IFMIB_IFDATA;
		name[4] = interesting_row;
		name[5] = IpFDATA_GENERAL;
		if (sysctl(name, 6, &ifmd, &len, (void *)0, 0) == -1)
			err(1, "sysctl IFDATA_GENERAL %d", interesting_row);
}
#endif

static void
permute_enables(void)
{
	int tunsock;
	T_EXPECT_GE(tunsock = create_tunsock(false, false, false), 0, NULL);
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(close(tunsock), NULL);
	T_EXPECT_GE(tunsock = create_tunsock(false, false, true), 0, NULL);
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(close(tunsock), NULL);
	T_EXPECT_GE(tunsock = create_tunsock(false, true, false), 0, NULL);
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(close(tunsock), NULL);
	T_EXPECT_GE(tunsock = create_tunsock(false, true, true), 0, NULL);
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(close(tunsock), NULL);
	T_EXPECT_GE(tunsock = create_tunsock(true, false, false), 0, NULL);
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(close(tunsock), NULL);
	T_EXPECT_GE(tunsock = create_tunsock(true, false, true), 0, NULL);
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(close(tunsock), NULL);
	T_EXPECT_GE(tunsock = create_tunsock(true, true, false), 0, NULL);
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(close(tunsock), NULL);
	T_EXPECT_GE(tunsock = create_tunsock(true, true, true), 0, NULL);
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(close(tunsock), NULL);
}

T_DECL(ipsec_enables, "This test checks combinations of netif/channel/flowswitch on ipsec")
{
	setup_ipsec_test();
	permute_enables();
}

T_DECL(utun_enables, "This test checks combinations of netif/channel/flowswitch on utun")
{
	setup_utun_test();
	permute_enables();
}

static int g_tunsock = -1;

static void
cleanup_tunsock(void)
{
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(close(g_tunsock), NULL);
	T_QUIET; T_EXPECT_POSIX_FAILURE(close(g_tunsock), EBADF, NULL);
	if (g_is_ipsec_test) {
		T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(close(g_pfkeyso), NULL);
		T_QUIET; T_EXPECT_POSIX_FAILURE(close(g_pfkeyso), EBADF, NULL);
	}
}

static void
setup_tunsock(void)
{
	T_ASSERT_GE(g_tunsock = create_tunsock(true, false, true), 0, NULL);
	T_ATEND(cleanup_tunsock);

	char ifname[IFXNAMSIZ];
	tunsock_get_ifname(g_tunsock, ifname);

	T_LOG("Created interface %s", ifname);

	uint32_t ifaddr = (10 << 24) | ((unsigned)getpid()&0xffff) << 8 | 160;
	struct in_addr mask;
	g_addr1.s_addr = htonl(ifaddr);
	g_addr2.s_addr = htonl(ifaddr+1);
	mask.s_addr = htonl(0xffffffff);

	ifnet_add_addr4(ifname, &g_addr1, &mask, &g_addr2);

	if (g_is_ipsec_test) {
		create_sa(ifname, SADB_ADD, 12345, &g_addr1, &g_addr2);
		create_sa(ifname, SADB_ADD, 12346, &g_addr2, &g_addr1);
	}
}

T_DECL(setup_ipsec, "This test sets up an ipsec interface")
{
	setup_ipsec_test();
	setup_tunsock();
}

T_DECL(setup_utun, "This test sets up a utun interface")
{
	setup_utun_test();
	setup_tunsock();
}
