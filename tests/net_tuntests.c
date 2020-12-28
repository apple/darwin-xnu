/* -*- compile-command: "xcrun --sdk iphoneos.internal make net_tuntests" -*- */

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <uuid/uuid.h>
#include <arpa/inet.h>
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

/* Disable all these test until <rdar://problem/49124468> is fixed */
T_GLOBAL_META(T_META_ENABLED(false));

#if 0
#undef T_QUIET
#define T_QUIET
#endif

#if 0
static void
log_hexdump(const void *inp, size_t len)
{
	unsigned i, off = 0;
	char buf[9 + 16 * 3 + 1];
	for (i = 0; i < len; i++) {
		if (i % 16 == 0) {
			off = (unsigned)snprintf(buf, sizeof(buf), "%08x:", i);
		}
		off += (unsigned)snprintf(buf + off, sizeof(buf) - off, " %02x", (((const uint8_t *)inp)[i]) & 0xff);
		if (i % 16 == 15) {
			T_LOG("%s", buf);
		}
	}
	if (len % 16) {
		T_LOG("%s", buf);
	}
}
#else
static void
log_hexdump(const void *inp, size_t len)
{
#pragma unused(inp, len)
}
#endif

static bool
is_netagent_enabled(void)
{
	int enabled = 0;
	size_t len = sizeof(enabled);
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(sysctlbyname("net.link.generic.system.enable_netagent", &enabled, &len, NULL, 0), NULL);
	T_QUIET; T_ASSERT_EQ(len, sizeof(enabled), NULL);
	return enabled == 1;
}

static bool g_is_ipsec_test;
static bool g_is_utun_test;
static int g_OPT_ENABLE_NETIF = -1;
static int g_OPT_ENABLE_FLOWSWITCH = -1;
static int g_OPT_ENABLE_CHANNEL = -1;
static int g_OPT_GET_CHANNEL_UUID = -1;
static int g_OPT_IFNAME = -1;
static char *g_CONTROL_NAME = NULL;

static int create_tunsock_old(int enable_netif, int enable_flowswitch, int channel_count, uuid_t uuid[]);
static int create_tunsock_new(int enable_netif, int enable_flowswitch, int channel_count, uuid_t uuid[]);
static int (*create_tunsock)(int enable_netif, int enable_flowswitch, int channel_count, uuid_t uuid[]);

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
	create_tunsock = create_tunsock_new;
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
	create_tunsock = create_tunsock_old;
	g_is_utun_test = true;
}

static bool
setblocking(int s, bool blocking)
{
	int flags;
	bool ret;

	T_QUIET; T_EXPECT_POSIX_SUCCESS(flags = fcntl(s, F_GETFL, 0), NULL);

	ret = !(flags & O_NONBLOCK);

	if (blocking) {
		flags &= ~O_NONBLOCK;
	} else {
		flags |= O_NONBLOCK;
	}

#if 0
	T_LOG("Setting fd %d from %s to %s\n",
	    s, ret ? "blocking" : "nonblocking",
	    blocking ? "blocking" : "nonblocking");
#endif

	T_QUIET; T_EXPECT_POSIX_SUCCESS(flags = fcntl(s, F_SETFL, flags), NULL);

	return ret;
}


static void
check_enables(int tunsock, int enable_netif, int enable_flowswitch, int channel_count, uuid_t uuid[])
{
	int scratch;
	socklen_t scratchlen, uuidlen;
	uuid_t scratchuuid[channel_count];
	if (!uuid) {
		uuid = scratchuuid;
	}

	//T_LOG("checking tunsock %d", tunsock);

	if (g_is_ipsec_test && channel_count && !enable_netif) {
		/* Unfortunately, the connect incorrectly unwinds the bind if it get an error.
		 * until that is fixed, expect EINVAL here
		 */
		scratchlen = sizeof(scratch);
		T_QUIET; T_EXPECT_POSIX_FAILURE(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_NETIF,
		    &scratch, &scratchlen), EINVAL, NULL);
		T_QUIET; T_EXPECT_POSIX_FAILURE(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_FLOWSWITCH,
		    &scratch, &scratchlen), EINVAL, NULL);
		T_QUIET; T_EXPECT_POSIX_FAILURE(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_CHANNEL,
		    &scratch, &scratchlen), EINVAL, NULL);
		for (int i = 0; i < channel_count; i++) {
			uuid_clear(uuid[i]);
		}
		uuidlen = sizeof(uuid_t) * (unsigned int)channel_count;
		T_QUIET; T_EXPECT_POSIX_FAILURE(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_GET_CHANNEL_UUID,
		    uuid, &uuidlen), EINVAL, NULL);
		for (int i = 0; i < channel_count; i++) {
			T_QUIET; T_EXPECT_TRUE(uuid_is_null(uuid[i]), NULL);
		}
		return;
	}


	scratchlen = sizeof(scratch);
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_NETIF,
	    &scratch, &scratchlen), NULL);
	T_QUIET; T_EXPECT_EQ_ULONG((unsigned long)scratchlen, sizeof(scratch), NULL);
	T_QUIET; T_EXPECT_EQ(scratch, enable_netif, NULL);

	scratchlen = sizeof(scratch);
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_FLOWSWITCH,
	    &scratch, &scratchlen), NULL);
	T_QUIET; T_EXPECT_EQ_ULONG((unsigned long)scratchlen, sizeof(scratch), NULL);
	if (is_netagent_enabled()) {
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
	T_QUIET; T_EXPECT_EQ_ULONG((unsigned long)scratchlen, sizeof(scratch), NULL);
	if (g_is_ipsec_test && !enable_netif) {
		T_QUIET; T_EXPECT_EQ(scratch, 0, NULL);
	} else {
		T_QUIET; T_EXPECT_EQ(scratch, (int)channel_count, NULL);
	}

	if (scratch) {
		for (int i = 0; i < channel_count; i++) {
			uuid_clear(uuid[i]);
		}
		uuidlen = sizeof(uuid_t) * (unsigned int)channel_count;
		T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_GET_CHANNEL_UUID,
		    uuid, &uuidlen), NULL);
		T_QUIET; T_EXPECT_EQ_ULONG((unsigned long)uuidlen, sizeof(uuid_t) * (unsigned long)channel_count, NULL);
		for (int i = 0; i < channel_count; i++) {
			T_QUIET; T_EXPECT_FALSE(uuid_is_null(uuid[i]), NULL);
		}
	} else {
		for (int i = 0; i < channel_count; i++) {
			uuid_clear(uuid[i]);
		}
		uuidlen = sizeof(uuid_t) * (unsigned int)channel_count;
		T_QUIET; T_EXPECT_POSIX_FAILURE(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_GET_CHANNEL_UUID,
		    uuid, &uuidlen), ENXIO, NULL);
		T_QUIET; T_EXPECT_EQ_ULONG((unsigned long)uuidlen, sizeof(uuid_t) * (unsigned long)channel_count, NULL);
		for (int i = 0; i < channel_count; i++) {
			T_QUIET; T_EXPECT_TRUE(uuid_is_null(uuid[i]), NULL);
		}
	}
}

static void
tunsock_get_ifname(int s, char ifname[IFXNAMSIZ])
{
	socklen_t optlen = IFXNAMSIZ;
	T_QUIET; T_WITH_ERRNO; T_ASSERT_POSIX_ZERO(getsockopt(s, SYSPROTO_CONTROL, g_OPT_IFNAME, ifname, &optlen), NULL);
	T_QUIET; T_ASSERT_TRUE(optlen > 0, NULL);
	T_QUIET; T_ASSERT_TRUE(ifname[optlen - 1] == '\0', NULL);
	T_QUIET; T_ASSERT_TRUE(strlen(ifname) + 1 == optlen, "got ifname \"%s\" len %zd expected %u", ifname, strlen(ifname), optlen);
}

static short
ifnet_get_flags(int s, const char ifname[IFNAMSIZ])
{
	struct ifreq    ifr;
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
	 *       <base, SA, (lifetime(HS),) address(SD), (address(P),)
	 *       key(AE), (identity(SD),) (sensitivity)>
	 */

	struct {
		struct sadb_msg msg __attribute((aligned(sizeof(uint64_t))));
		struct sadb_key key  __attribute((aligned(sizeof(uint64_t))));
		struct sadb_sa sa  __attribute((aligned(sizeof(uint64_t))));
		struct sadb_x_sa2 sa2  __attribute((aligned(sizeof(uint64_t))));
		struct sadb_x_ipsecif ipsecif __attribute((aligned(sizeof(uint64_t))));
		struct {
			struct sadb_address addr __attribute((aligned(sizeof(uint64_t))));
			struct sockaddr_in saddr __attribute((aligned(sizeof(uint64_t))));
		} src;
		struct {
			struct sadb_address addr __attribute((aligned(sizeof(uint64_t))));
			struct sockaddr_in saddr __attribute((aligned(sizeof(uint64_t))));
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

	log_hexdump(&addcmd, sizeof(addcmd));

	ssize_t slen;
	T_QUIET; T_EXPECT_POSIX_SUCCESS(slen = send(g_pfkeyso, &addcmd, sizeof(addcmd), 0), NULL);
	T_QUIET; T_EXPECT_EQ(slen, (ssize_t)sizeof(addcmd), NULL);
}

/* This version of the test expects channels to be enabled after connect.
 * Once the utun driver is converted, switch to create_tunsock_new
 */
static int
create_tunsock_old(int enable_netif, int enable_flowswitch, int channel_count, uuid_t uuid[])
{
	int tunsock;
	struct ctl_info kernctl_info;
	struct sockaddr_ctl kernctl_addr;
	uuid_t scratchuuid[channel_count];
	if (!uuid) {
		uuid = scratchuuid;
	}
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

	T_LOG("%s: enable_netif = %d, enable_flowswitch = %d, channel_count = %d",
	    __func__, enable_netif, enable_flowswitch, channel_count);

	T_QUIET; T_EXPECT_POSIX_FAILURE(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_NETIF,
	    &enable_netif, sizeof(enable_netif)), EINVAL, NULL);
	T_QUIET; T_EXPECT_POSIX_FAILURE(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_FLOWSWITCH,
	    &enable_flowswitch, sizeof(enable_flowswitch)), EINVAL, NULL);
	T_QUIET; T_EXPECT_POSIX_FAILURE(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_CHANNEL,
	    &channel_count, sizeof(channel_count)), EINVAL, NULL);
	for (int i = 0; i < channel_count; i++) {
		uuid_clear(uuid[i]);
	}
	uuidlen = sizeof(uuid_t) * (unsigned int)channel_count;
	T_QUIET; T_EXPECT_POSIX_FAILURE(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_GET_CHANNEL_UUID,
	    uuid, &uuidlen), EINVAL, NULL);
	T_QUIET; T_EXPECT_EQ_ULONG((unsigned long)uuidlen, sizeof(uuid_t) * (unsigned long)channel_count, NULL);
	for (int i = 0; i < channel_count; i++) {
		T_QUIET; T_EXPECT_TRUE(uuid_is_null(uuid[i]), NULL);
	}

	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(bind(tunsock, (struct sockaddr *)&kernctl_addr, sizeof(kernctl_addr)), NULL);

	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_NETIF,
	    &enable_netif, sizeof(enable_netif)), NULL);
	T_QUIET; T_EXPECT_POSIX_FAILURE(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_FLOWSWITCH,
	    &enable_flowswitch, sizeof(enable_flowswitch)), EINVAL, NULL);
	T_QUIET; T_EXPECT_POSIX_FAILURE(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_CHANNEL,
	    &channel_count, sizeof(channel_count)), EINVAL, NULL);
	for (int i = 0; i < channel_count; i++) {
		uuid_clear(uuid[i]);
	}
	uuidlen = sizeof(uuid_t) * (unsigned int)channel_count;
	T_QUIET; T_EXPECT_POSIX_FAILURE(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_GET_CHANNEL_UUID,
	    uuid, &uuidlen), ENXIO, NULL);
	T_QUIET; T_EXPECT_EQ_ULONG((unsigned long)uuidlen, sizeof(uuid_t) * (unsigned long)channel_count, NULL);
	for (int i = 0; i < channel_count; i++) {
		T_QUIET; T_EXPECT_TRUE(uuid_is_null(uuid[i]), NULL);
	}

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

	if (is_netagent_enabled()) {
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

	if (channel_count) {
		if (g_is_ipsec_test && !enable_netif) {
			/* ipsec doesn't support channels without a netif */
			T_QUIET; T_EXPECT_POSIX_FAILURE(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_CHANNEL,
			    &channel_count, sizeof(channel_count)), EOPNOTSUPP, NULL);
			for (int i = 0; i < channel_count; i++) {
				uuid_clear(uuid[i]);
			}
			uuidlen = sizeof(uuid_t) * (unsigned int)channel_count;
			T_QUIET; T_EXPECT_POSIX_FAILURE(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_GET_CHANNEL_UUID,
			    uuid, &uuidlen), ENXIO, NULL);
			T_QUIET; T_EXPECT_EQ_ULONG((unsigned long)uuidlen, sizeof(uuid_t) * (unsigned long)channel_count, NULL);
			for (int i = 0; i < channel_count; i++) {
				T_QUIET; T_EXPECT_TRUE(uuid_is_null(uuid[i]), NULL);
			}
		} else {
			T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_CHANNEL,
			    &channel_count, sizeof(channel_count)), NULL);
			for (int i = 0; i < channel_count; i++) {
				uuid_clear(uuid[i]);
			}
			uuidlen = sizeof(uuid_t) * (unsigned int)channel_count;
			T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_GET_CHANNEL_UUID,
			    uuid, &uuidlen), NULL);
			T_QUIET; T_EXPECT_EQ_ULONG((unsigned long)uuidlen, sizeof(uuid_t) * (unsigned long)channel_count, NULL);
			for (int i = 0; i < channel_count; i++) {
				T_QUIET; T_EXPECT_FALSE(uuid_is_null(uuid[i]), NULL);
			}
		}
	} else {
		T_QUIET; T_EXPECT_POSIX_FAILURE(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_CHANNEL,
		    &channel_count, sizeof(channel_count)), ENXIO, NULL);
		for (int i = 0; i < channel_count; i++) {
			uuid_clear(uuid[i]);
		}
		uuidlen = sizeof(uuid_t) * (unsigned int)channel_count;
		T_QUIET; T_EXPECT_POSIX_FAILURE(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_GET_CHANNEL_UUID,
		    uuid, &uuidlen), ENXIO, NULL);
		T_QUIET; T_EXPECT_EQ_ULONG((unsigned long)uuidlen, sizeof(uuid_t) * (unsigned long)channel_count, NULL);
		for (int i = 0; i < channel_count; i++) {
			T_QUIET; T_EXPECT_TRUE(uuid_is_null(uuid[i]), NULL);
		}
	}

	check_enables(tunsock, enable_netif, enable_flowswitch, channel_count, uuid);

	//T_LOG("Returning tunsock %d", tunsock);

	return tunsock;
}

/* This version of the test expects channels to be enabled before connect
 * Once the utun driver is converted, rename this to just create_tunsock
 */
static int
create_tunsock_new(int enable_netif, int enable_flowswitch, int channel_count, uuid_t uuid[])
{
	int tunsock;
	struct ctl_info kernctl_info;
	struct sockaddr_ctl kernctl_addr;
	uuid_t scratchuuid[channel_count];
	if (!uuid) {
		uuid = scratchuuid;
	}
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

	T_LOG("%s: enable_netif = %d, enable_flowswitch = %d, channel_count = %d",
	    __func__, enable_netif, enable_flowswitch, channel_count);

	T_QUIET; T_EXPECT_POSIX_FAILURE(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_NETIF,
	    &enable_netif, sizeof(enable_netif)), EINVAL, NULL);
	T_QUIET; T_EXPECT_POSIX_FAILURE(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_FLOWSWITCH,
	    &enable_flowswitch, sizeof(enable_flowswitch)), EINVAL, NULL);
	T_QUIET; T_EXPECT_POSIX_FAILURE(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_CHANNEL,
	    &channel_count, sizeof(channel_count)), EINVAL, NULL);
	for (int i = 0; i < channel_count; i++) {
		uuid_clear(uuid[i]);
	}
	uuidlen = sizeof(uuid_t) * (unsigned int)channel_count;
	T_QUIET; T_EXPECT_POSIX_FAILURE(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_GET_CHANNEL_UUID,
	    uuid, &uuidlen), EINVAL, NULL);
	T_QUIET; T_EXPECT_EQ_ULONG((unsigned long)uuidlen, sizeof(uuid_t) * (unsigned long)channel_count, NULL);
	for (int i = 0; i < channel_count; i++) {
		T_QUIET; T_EXPECT_TRUE(uuid_is_null(uuid[i]), NULL);
	}

	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(bind(tunsock, (struct sockaddr *)&kernctl_addr, sizeof(kernctl_addr)), NULL);

	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_NETIF,
	    &enable_netif, sizeof(enable_netif)), NULL);
	T_QUIET; T_EXPECT_POSIX_FAILURE(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_FLOWSWITCH,
	    &enable_flowswitch, sizeof(enable_flowswitch)), EINVAL, NULL);
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_CHANNEL,
	    &channel_count, sizeof(channel_count)), NULL);

	for (int i = 0; i < channel_count; i++) {
		uuid_clear(uuid[i]);
	}
	uuidlen = sizeof(uuid_t) * (unsigned int)channel_count;
	T_QUIET; T_EXPECT_POSIX_FAILURE(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_GET_CHANNEL_UUID,
	    uuid, &uuidlen), ENXIO, NULL);
	T_QUIET; T_EXPECT_EQ_ULONG((unsigned long)uuidlen, sizeof(uuid_t) * (unsigned long)channel_count, NULL);
	for (int i = 0; i < channel_count; i++) {
		T_QUIET; T_EXPECT_TRUE(uuid_is_null(uuid[i]), NULL);
	}

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
	if (g_is_ipsec_test && channel_count && !enable_netif) {
		/* ipsec doesn't support channels without a netif */
		T_QUIET; T_EXPECT_POSIX_FAILURE(error, ENOTSUP, "connect() == -1 && errno == ENOTSUP");
	} else {
		T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(error, "connect() == 0");
	}

	T_QUIET; T_EXPECT_POSIX_FAILURE(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_NETIF,
	    &enable_netif, sizeof(enable_netif)), EINVAL, NULL);

	if (g_is_ipsec_test && channel_count && !enable_netif) {
		/* Connect failed above, so we get EINVAL */
		T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_FAILURE(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_FLOWSWITCH,
		    &enable_flowswitch, sizeof(enable_flowswitch)), EINVAL, NULL);
	} else {
		if (is_netagent_enabled()) {
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
	}

	T_QUIET; T_EXPECT_POSIX_FAILURE(setsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_ENABLE_CHANNEL,
	    &channel_count, sizeof(channel_count)), EINVAL, NULL);

	for (int i = 0; i < channel_count; i++) {
		uuid_clear(uuid[i]);
	}
	uuidlen = sizeof(uuid_t) * (unsigned int)channel_count;
	if (!channel_count || (g_is_ipsec_test && channel_count && !enable_netif)) {
		/* ipsec doesn't support channels without a netif */
		if (g_is_ipsec_test && channel_count && !enable_netif) {
			/* Unfortunately, the connect incorrectly unwinds the bind if it get an error.
			 * until that is fixed, expect EINVAL here
			 */
			T_QUIET; T_EXPECT_POSIX_FAILURE(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_GET_CHANNEL_UUID,
			    uuid, &uuidlen), EINVAL, NULL);
		} else {
			T_QUIET; T_EXPECT_POSIX_FAILURE(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_GET_CHANNEL_UUID,
			    uuid, &uuidlen), ENXIO, NULL);
		}
		T_QUIET; T_EXPECT_EQ_ULONG((unsigned long)uuidlen, sizeof(uuid_t) * (unsigned long)channel_count, NULL);
		for (int i = 0; i < channel_count; i++) {
			T_QUIET; T_EXPECT_TRUE(uuid_is_null(uuid[i]), NULL);
		}
	} else {
		uuidlen = sizeof(uuid_t) * (unsigned int)channel_count;
		T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(getsockopt(tunsock, SYSPROTO_CONTROL, g_OPT_GET_CHANNEL_UUID,
		    uuid, &uuidlen), NULL);
		T_QUIET; T_EXPECT_EQ_ULONG((unsigned long)uuidlen, sizeof(uuid_t) * (unsigned long)channel_count, NULL);
		for (int i = 0; i < channel_count; i++) {
			T_QUIET; T_EXPECT_FALSE(uuid_is_null(uuid[i]), NULL);
		}
	}

	check_enables(tunsock, enable_netif, enable_flowswitch, channel_count, uuid);

	//T_LOG("Returning tunsock %d", tunsock);

	return tunsock;
}

static int (*create_tunsock)(int enable_netif, int enable_flowswitch, int channel_count, uuid_t uuid[]) = create_tunsock_new;

#if 0
static void
ipsec_stats(void)
{
	struct ifmibdata ifmd;

	len = sizeof(struct ifmibdata);
	name[3] = IFMIB_IFDATA;
	name[4] = interesting_row;
	name[5] = IpFDATA_GENERAL;
	if (sysctl(name, 6, &ifmd, &len, (void *)0, 0) == -1) {
		err(1, "sysctl IFDATA_GENERAL %d", interesting_row);
	}
}
#endif

static void
permute_enables(void)
{
	int tunsock;
	T_EXPECT_GE(tunsock = create_tunsock(false, false, false, NULL), 0, NULL);
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(close(tunsock), NULL);
	T_EXPECT_GE(tunsock = create_tunsock(false, false, true, NULL), 0, NULL);
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(close(tunsock), NULL);
	T_EXPECT_GE(tunsock = create_tunsock(false, true, false, NULL), 0, NULL);
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(close(tunsock), NULL);
	T_EXPECT_GE(tunsock = create_tunsock(false, true, true, NULL), 0, NULL);
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(close(tunsock), NULL);
	T_EXPECT_GE(tunsock = create_tunsock(true, false, false, NULL), 0, NULL);
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(close(tunsock), NULL);
	T_EXPECT_GE(tunsock = create_tunsock(true, false, true, NULL), 0, NULL);
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(close(tunsock), NULL);
	T_EXPECT_GE(tunsock = create_tunsock(true, true, false, NULL), 0, NULL);
	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(close(tunsock), NULL);
	T_EXPECT_GE(tunsock = create_tunsock(true, true, true, NULL), 0, NULL);
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
setup_tunsock(int channel_count, uuid_t uuids[])
{
	T_ASSERT_GE(g_tunsock = create_tunsock(true, false, channel_count, uuids), 0, NULL);
	T_ATEND(cleanup_tunsock);

	char ifname[IFXNAMSIZ];
	tunsock_get_ifname(g_tunsock, ifname);

	T_LOG("Created interface %s", ifname);

	uint32_t ifaddr = (10 << 24) | ((unsigned)getpid() & 0xffff) << 8 | 160;
	struct in_addr mask;
	g_addr1.s_addr = htonl(ifaddr);
	g_addr2.s_addr = htonl(ifaddr + 1);
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
	setup_tunsock(1, NULL);
}

T_DECL(setup_utun, "This test sets up a utun interface")
{
	setup_utun_test();
	setup_tunsock(1, NULL);
}

static const int SOCKET_TRAFFIC_CLASSES[] = {
	SO_TC_BK_SYS, // BK
	SO_TC_BK,  // BK
	SO_TC_BE,  // BE
	SO_TC_RD,  // BE
	SO_TC_OAM, // BE
	SO_TC_AV,  // VI
	SO_TC_RV,  // VI
	SO_TC_VI,  // VI
	SO_TC_VO,  // VO
	SO_TC_CTL, // VO
};

// this should match ipsec_find_tx_ring_by_svc in ipsec driver
static const int SOCKET_TC_TO_RING[] = {
	3,
	3,
	2,
	2,
	2,
	1,
	1,
	1,
	0,
	0,
};

/* How many sockets map to this ring */
static const int RING_TO_TC_COUNT[] = {
	2, 3, 3, 2,
};

static void
setup_channels_and_rings(int kq, int channel_count, channel_t channels[], channel_ring_t rxrings[], channel_ring_t txrings[], uuid_t uuids[], int cfds[])
{
	setup_tunsock(channel_count, uuids);

#if 0
	// give time to enable a tcpdump if desired
	T_LOG("Sleeping 10");
	sleep(10);
	T_LOG("Done");
#endif

	for (int ri = 0; ri < channel_count; ri++) {
		if (rxrings) {
			T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(channels[ri] = os_channel_create(uuids[ri], 0), NULL);
			T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(rxrings[ri] = os_channel_rx_ring(channels[ri],
			    os_channel_ring_id(channels[ri], CHANNEL_FIRST_RX_RING)), NULL);
		}
		if (txrings) {
			T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(channels[ri] = os_channel_create(uuids[ri], 0), NULL);
			T_QUIET; T_WITH_ERRNO; T_ASSERT_NOTNULL(rxrings[ri] = os_channel_rx_ring(channels[ri],
			    os_channel_ring_id(channels[ri], CHANNEL_FIRST_TX_RING)), NULL);
		}

		struct kevent kev;
		T_QUIET; T_EXPECT_POSIX_SUCCESS(cfds[ri] = os_channel_get_fd(channels[ri]), NULL);
		EV_SET(&kev, cfds[ri], EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, (void *)(uintptr_t)ri);
		T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(kevent(kq, &kev, 1, NULL, 0, NULL), NULL);
	}
}

static void
cleanup_channels_and_rings(int channel_count, channel_t channels[], channel_ring_t rxrings[], channel_ring_t txrings[], uuid_t uuids[])
{
	for (int ri = 0; ri < channel_count; ri++) {
		if (rxrings) {
			rxrings[ri] = NULL;
		}
		if (txrings) {
			rxrings[ri] = NULL;
		}
		os_channel_destroy(channels[ri]);
		channels[ri] = NULL;
		uuid_clear(uuids[ri]);
	}
}

static void
setup_sockets(int sockets[SO_TC_MAX], int type)
{
	for (int si = 0; si < SO_TC_MAX; si++) {
		T_QUIET; T_EXPECT_POSIX_SUCCESS(sockets[si] = socket(PF_INET, type, 0), NULL);

		T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(setsockopt(sockets[si], SOL_SOCKET,
		    SO_TRAFFIC_CLASS, &SOCKET_TRAFFIC_CLASSES[si], sizeof(SOCKET_TRAFFIC_CLASSES[si])), NULL);

		// XXX setsockopt(IP_BOUND_IF) here?

		struct sockaddr_in sin;
		memset(&sin, 0, sizeof(sin));
		sin.sin_len = sizeof(sin);
		sin.sin_family = AF_INET;
		sin.sin_addr = g_addr1;

		T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(bind(sockets[si], (struct sockaddr *)&sin, sizeof(sin)), NULL);

		char sbuf[INET6_ADDRSTRLEN];
		inet_ntop(sin.sin_family, &sin.sin_addr.s_addr, sbuf, sizeof(sbuf));
#if 0
		T_LOG("%s socket %d bound to %s port %d",
		    type == SOCK_DGRAM ? "udp" : type == SOCK_STREAM ? "tcp" : "???",
		    sockets[si], sbuf, ntohs(sin.sin_port));
#endif
		setblocking(sockets[si], false);
	}
}

static void
cleanup_sockets(int sockets[SO_TC_MAX])
{
	for (int si = 0; si < SO_TC_MAX; si++) {
		T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(close(sockets[si]), NULL);
		sockets[si] = -1;
	}
}

static void
drain_ring(channel_ring_t rxring)
{
	uint32_t i, sc = os_channel_available_slot_count(rxring);
	channel_slot_t rxprev = NULL;
	for (i = 0; i < sc; i++) {
		slot_prop_t rxprop;
		channel_slot_t rxslot;

		memset(&rxprop, 0, sizeof(rxprop));
		T_QUIET; T_WITH_ERRNO; T_EXPECT_NOTNULL(rxslot = os_channel_get_next_slot(rxring, rxprev, &rxprop), NULL);
		T_QUIET; T_ASSERT_NE_UINT(0, rxprop.sp_len, NULL);
		T_QUIET; T_ASSERT_NOTNULL((void *)rxprop.sp_buf_ptr, NULL);

		log_hexdump((void *)rxprop.sp_buf_ptr, rxprop.sp_len);

		rxprev = rxslot;
	}
	if (sc) {
		T_QUIET; T_EXPECT_POSIX_ZERO(os_channel_advance_slot(rxring, rxprev), NULL);
	}
}

static void
send_one_packet(int s, int type)
{
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_addr = g_addr2;
	sin.sin_port = ntohs(12345);

	if (type == SOCK_STREAM) {
		T_QUIET; T_EXPECT_POSIX_FAILURE(connect(s, (struct sockaddr *)&sin, sizeof(sin)), EINPROGRESS, NULL);
	}
	if (type == SOCK_DGRAM) {
		T_QUIET; T_WITH_ERRNO; T_EXPECT_EQ_LONG((long)sizeof(s), sendto(s, &s, sizeof(s), 0,
		    (struct sockaddr *)&sin, sizeof(sin)), NULL);
	}
}

static void
expect_empty_rings(int channel_count, channel_ring_t rings[])
{
	/* Check all the rings and make sure there are no packets */
	for (int ri = 0; ri < channel_count; ri++) {
		T_QUIET; T_EXPECT_EQ_UINT(0U, os_channel_available_slot_count(rings[ri]), NULL);
	}
}

static void
xfer_1_packet_singly(int channel_count, int type)
{
	uuid_t uuids[channel_count];
	channel_t channels[channel_count];
	int sockets[SO_TC_MAX];
	channel_ring_t rxrings[channel_count];
	int cfds[channel_count];
	int kq;

	T_QUIET; T_EXPECT_POSIX_SUCCESS(kq = kqueue(), NULL);

	setup_channels_and_rings(kq, channel_count, channels, rxrings, NULL, uuids, cfds);

	setup_sockets(sockets, type);

	for (int si = 0; si < SO_TC_MAX; si++) {
		expect_empty_rings(channel_count, rxrings);

		send_one_packet(sockets[si], type);

		int expected_ring = channel_count == 1 ? 0 : SOCKET_TC_TO_RING[si];

		/* Wait for the packet delivery and check that it's only one packet and on the correct ring */
		struct kevent kev[channel_count + 1];
		int nev;
		memset(kev, 0, sizeof(kev));
		struct timespec to = { 0, 100 * NSEC_PER_MSEC }; // 100 ms
		T_QUIET; T_EXPECT_POSIX_SUCCESS(nev = kevent(kq, NULL, 0, kev, channel_count + 1, &to), NULL);
		T_QUIET; T_EXPECT_EQ_INT(nev, 1, NULL);
		T_QUIET; T_EXPECT_EQ_PTR((void *)kev[0].ident, (void *)(uintptr_t)cfds[expected_ring], NULL);
		T_QUIET; T_EXPECT_EQ_PTR(kev[0].udata, (void *)(uintptr_t)expected_ring, NULL);
		T_QUIET; T_EXPECT_EQ_SHORT(kev[0].filter, (short)EVFILT_READ, NULL);
		T_QUIET; T_EXPECT_FALSE(kev[0].flags & EV_ERROR, NULL);

		/* Make sure it comes out the expected interface */
		for (int ri = 0; ri < channel_count; ri++) {
			errno = 0;

			uint32_t sc = os_channel_available_slot_count(rxrings[ri]);

			/* Check that the packet appears only on the expected ring and
			 * is the only packet on the expected ring.
			 */
			T_QUIET; T_EXPECT_EQ_UINT(ri == expected_ring, sc, NULL);

			if ((ri == expected_ring) == sc) {
				T_PASS("tc index %d ring %d expected ring %d slot count %u", si, ri, expected_ring, sc);
			} else {
				T_FAIL("tc index %d ring %d expected ring %d slot count %u", si, ri, expected_ring, sc);
			}

			drain_ring(rxrings[ri]);
		}
	}

	cleanup_sockets(sockets);

	cleanup_channels_and_rings(channel_count, channels, rxrings, NULL, uuids);

	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(close(kq), NULL);
}

T_DECL(ipsec35889979u1s, "transfers 1 packet at a time of each sevice class over udp to a single ring")
{
	setup_ipsec_test();
	xfer_1_packet_singly(1, SOCK_DGRAM);
}

T_DECL(ipsec35889979u4s, "transfers 1 packet at a time of each sevice class over udp to 4 rings")
{
	setup_ipsec_test();
	xfer_1_packet_singly(4, SOCK_DGRAM);
}

T_DECL(ipsec35889979t1s, "transfers 1 packet at a time of each sevice class over tcp to a single ring")
{
	setup_ipsec_test();
	xfer_1_packet_singly(1, SOCK_STREAM);
}


T_DECL(ipsec35889979t4s, "transfers 1 packet at a time of each sevice class over tcp to 4 rings",
    /* This test will fail because tcp syn packets get elevated
     * due to ack prioritization
     */
    T_META_ENABLED(false))
{
	setup_ipsec_test();
	xfer_1_packet_singly(4, SOCK_STREAM);
}

static void
xfer_1_packet_together(int channel_count, int type)
{
	uuid_t uuids[channel_count];
	channel_t channels[channel_count];
	int sockets[SO_TC_MAX];
	channel_ring_t rxrings[channel_count];
	int cfds[channel_count];
	int kq;

	T_QUIET; T_EXPECT_POSIX_SUCCESS(kq = kqueue(), NULL);

	setup_channels_and_rings(kq, channel_count, channels, rxrings, NULL, uuids, cfds);

	setup_sockets(sockets, type);

	for (int si = 0; si < SO_TC_MAX; si++) {
		expect_empty_rings(channel_count, rxrings);

		send_one_packet(sockets[si], type);
	}

	/* Sleep to make sure all packets get delivered */
	struct timespec to = { 0, 100 * NSEC_PER_MSEC }; // 100 ms
	nanosleep(&to, NULL);

	/* Wait for the packet delivery and check that all rings event */
	struct kevent kev[channel_count + 1];
	int nev;
	memset(kev, 0, sizeof(kev));
	T_QUIET; T_EXPECT_POSIX_SUCCESS(nev = kevent(kq, NULL, 0, kev, channel_count + 1, &to), NULL);
	T_QUIET; T_EXPECT_EQ_INT(nev, channel_count, NULL);

	uint32_t found[channel_count];
	memset(found, 0, sizeof(found));
	for (int e = 0; e < nev; e++) {
		T_LOG("kevent %lu filter 0x%4x flags 0x%04x fflags 0x%08x data %"PRIdPTR" udata %p",
		    kev[e].ident, kev[e].filter, kev[e].flags, kev[e].fflags, kev[e].data, kev[e].udata);

		T_QUIET; T_ASSERT_GE_PTR(kev[e].udata, (void *)0, NULL);
		T_QUIET; T_ASSERT_LT_PTR(kev[e].udata, (void *)(intptr_t)channel_count, NULL);
		int ri = (int)kev[e].udata;
		T_QUIET; T_EXPECT_EQ_UINT(found[ri], 0U, NULL);

		T_QUIET; T_EXPECT_EQ_ULONG(kev[e].ident, (uintptr_t)cfds[ri], NULL);
		T_QUIET; T_EXPECT_EQ_SHORT(kev[e].filter, (short)EVFILT_READ, NULL);
		T_QUIET; T_EXPECT_FALSE(kev[e].flags & EV_ERROR, NULL);

		if (channel_count == 1) {
			T_QUIET; T_EXPECT_EQ_LONG(kev[e].data, (long)SO_TC_MAX, NULL);
		} else {
			T_QUIET; T_EXPECT_EQ_LONG(kev[e].data, (long)RING_TO_TC_COUNT[ri], NULL);
		}

		found[ri] += (uint32_t)kev[e].data;
	}
	/* Check that something came out of all rings */
	for (int ri = 0; ri < channel_count; ri++) {
		T_QUIET; T_EXPECT_NE_UINT(found[ri], 0U, NULL);
	}

	/* Make sure it comes out the expected interface */
	for (int ri = 0; ri < channel_count; ri++) {
		uint32_t sc = os_channel_available_slot_count(rxrings[ri]);
		if (channel_count == 1) {
			if (sc == SO_TC_MAX) {
				T_PASS("ring %d got %"PRIu32" slots expecting %"PRIu32"", ri, sc, SO_TC_MAX);
			} else {
				T_FAIL("ring %d got %"PRIu32" slots expecting %"PRIu32"", ri, sc, SO_TC_MAX);
			}
		} else {
			if (sc == (uint32_t)RING_TO_TC_COUNT[ri]) {
				T_PASS("ring %d got %"PRIu32" slots expecting %"PRIu32"", ri, sc, (uint32_t)RING_TO_TC_COUNT[ri]);
			} else {
				T_FAIL("ring %d got %"PRIu32" slots expecting %"PRIu32"", ri, sc, (uint32_t)RING_TO_TC_COUNT[ri]);
			}
		}

		drain_ring(rxrings[ri]);
	}

	cleanup_sockets(sockets);

	cleanup_channels_and_rings(channel_count, channels, rxrings, NULL, uuids);

	T_QUIET; T_WITH_ERRNO; T_EXPECT_POSIX_ZERO(close(kq), NULL);
}

T_DECL(ipsec35889979u1m, "transfers 1 packet together of each sevice class over udp to a single ring")
{
	setup_ipsec_test();
	xfer_1_packet_together(1, SOCK_DGRAM);
}

T_DECL(ipsec35889979u4m, "transfers 1 packet together of each sevice class over udp to 4 rings")
{
	setup_ipsec_test();
	xfer_1_packet_together(4, SOCK_DGRAM);
}

T_DECL(ipsec35889979t1m, "transfers 1 packet together of each sevice class over tcp to a single ring")
{
	setup_ipsec_test();
	xfer_1_packet_together(1, SOCK_STREAM);
}

T_DECL(ipsec35889979t4m, "transfers 1 packet together of each sevice class over tcp to 4 rings",
    /* This test will fail because tcp syn packets get elevated
     * due to ack prioritization
     */
    T_META_ENABLED(false))
{
	setup_ipsec_test();
	xfer_1_packet_together(4, SOCK_STREAM);
}
