/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

/*
 * Copyright (c) 1982, 1986, 1993
 *      The Regents of the University of California.  All rights reserved.
 */

/*
 * Kernel Debugging Protocol UDP implementation.
 */

#include <mach/boolean.h>
#include <mach/mach_types.h>
#include <mach/exception_types.h>
#include <kern/cpu_data.h>
#include <kern/debug.h>
#include <kern/clock.h>

#include <kdp/kdp_core.h>
#include <kdp/kdp_internal.h>
#include <kdp/kdp_en_debugger.h>
#include <kdp/kdp_callout.h>
#include <kdp/kdp_udp.h>
#if CONFIG_SERIAL_KDP
#include <kdp/kdp_serial.h>
#endif

#include <vm/vm_map.h>
#include <vm/vm_protos.h>
#include <vm/vm_kern.h> /* kernel_map */

#include <mach/memory_object_types.h>
#include <machine/pal_routines.h>

#include <sys/msgbuf.h>

/* we just want the link status flags, so undef KERNEL_PRIVATE for this
 * header file. */
#undef KERNEL_PRIVATE
#include <net/if_media.h> 
#define KERNEL_PRIVATE

#include <string.h>

#include <IOKit/IOPlatformExpert.h>
#include <libkern/version.h>

#define DO_ALIGN	1	      /* align all packet data accesses */
#define KDP_SERIAL_IPADDR  0xABADBABE /* IP address used for serial KDP */
#define LINK_UP_STATUS     (IFM_AVALID | IFM_ACTIVE)

extern int kdp_getc(void);
extern int reattach_wait;

/* only used by IONetworkingFamily */
typedef uint32_t (*kdp_link_t)(void);
typedef boolean_t (*kdp_mode_t)(boolean_t);
void 	kdp_register_link(kdp_link_t link, kdp_mode_t mode);
void 	kdp_unregister_link(kdp_link_t link, kdp_mode_t mode);

static u_short ip_id;                          /* ip packet ctr, for ids */

/*	@(#)udp_usrreq.c	2.2 88/05/23 4.0NFSSRC SMI;	from UCB 7.1 6/5/86	*/

/*
 * UDP protocol implementation.
 * Per RFC 768, August, 1980.
 */
#define UDP_TTL	60 /* deflt time to live for UDP packets */
int	udp_ttl = UDP_TTL;
static unsigned char	exception_seq;

static struct {
    unsigned char	data[KDP_MAXPACKET];
    unsigned int	off, len;
    boolean_t		input;
} pkt, saved_reply;

struct kdp_manual_pkt manual_pkt;

struct {
    struct {
	struct in_addr		in;
	struct ether_addr	ea;
    } loc;
    struct {
	struct in_addr		in;
	struct ether_addr	ea;
    } rmt;
} adr;

static const char
*exception_message[] = {
    "Unknown",
    "Memory access",		/* EXC_BAD_ACCESS */
    "Failed instruction",	/* EXC_BAD_INSTRUCTION */
    "Arithmetic",		/* EXC_ARITHMETIC */
    "Emulation",		/* EXC_EMULATION */
    "Software",			/* EXC_SOFTWARE */
    "Breakpoint"		/* EXC_BREAKPOINT */
};

volatile int kdp_flag = 0;

static kdp_send_t    kdp_en_send_pkt;
static kdp_receive_t kdp_en_recv_pkt;
static kdp_link_t    kdp_en_linkstatus;
static kdp_mode_t    kdp_en_setmode;

#if CONFIG_SERIAL_KDP
static void kdp_serial_send(void *rpkt, unsigned int rpkt_len);
#define KDP_SERIAL_ENABLED()  (kdp_en_send_pkt == kdp_serial_send)
#else
#define KDP_SERIAL_ENABLED()  (0)
#endif

static uint32_t kdp_current_ip_address = 0;
static struct ether_addr kdp_current_mac_address = {{0, 0, 0, 0, 0, 0}};
static void *kdp_current_ifp;

static void kdp_handler( void *);

static uint32_t panic_server_ip = 0; 
static uint32_t parsed_router_ip = 0;
static uint32_t router_ip = 0;
static uint32_t target_ip = 0;

static boolean_t save_ip_in_nvram = FALSE;

static volatile boolean_t panicd_specified = FALSE;
static boolean_t router_specified = FALSE;
static boolean_t corename_specified = FALSE;
static unsigned int panicd_port = CORE_REMOTE_PORT;

static struct ether_addr etherbroadcastaddr = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};

static struct ether_addr router_mac = {{0, 0, 0 , 0, 0, 0}};
static struct ether_addr destination_mac = {{0, 0, 0 , 0, 0, 0}};
static struct ether_addr temp_mac = {{0, 0, 0 , 0, 0, 0}};
static struct ether_addr current_resolved_MAC = {{0, 0, 0 , 0, 0, 0}};

static boolean_t flag_panic_dump_in_progress = FALSE;
static boolean_t flag_router_mac_initialized = FALSE;
static boolean_t flag_dont_abort_panic_dump  = FALSE;

static boolean_t flag_arp_resolved = FALSE;

static unsigned int panic_timeout = 100000;
static unsigned int last_panic_port = CORE_REMOTE_PORT;

#define KDP_THROTTLE_VALUE       (10ULL * NSEC_PER_SEC)

uint32_t kdp_crashdump_pkt_size = 512;
#define KDP_LARGE_CRASHDUMP_PKT_SIZE (1440 - 6 - sizeof(struct udpiphdr))
static char panicd_ip_str[20];
static char router_ip_str[20];
static char corename_str[50];

static unsigned int panic_block = 0;
volatile unsigned int kdp_trigger_core_dump = 0;
__private_extern__ volatile unsigned int flag_kdp_trigger_reboot = 0;

extern unsigned int not_in_kdp;

extern unsigned int disableConsoleOutput;

extern void 		kdp_call(void);
extern boolean_t 	kdp_call_kdb(void);
extern int 		kern_dump(void);

extern int inet_aton(const char *cp, struct in_addr *pin);
extern int inet_ntoa2(struct in_addr * pin, char * cp, const int len);

void *	kdp_get_interface(void);
void    kdp_set_gateway_mac(void *gatewaymac);
void 	kdp_set_ip_and_mac_addresses(struct in_addr *ipaddr, struct ether_addr *);
void 	kdp_set_interface(void *interface, const struct ether_addr *macaddr);

void 			kdp_disable_arp(void);
static void 		kdp_arp_reply(struct ether_arp *);
static void 		kdp_process_arp_reply(struct ether_arp *);
static boolean_t 	kdp_arp_resolve(uint32_t, struct ether_addr *);

static volatile unsigned	kdp_reentry_deadline;

static uint32_t kdp_crashdump_feature_mask = KDP_FEATURE_LARGE_CRASHDUMPS | KDP_FEATURE_LARGE_PKT_SIZE;
uint32_t kdp_feature_large_crashdumps, kdp_feature_large_pkt_size;

char kdp_kernelversion_string[256];

static boolean_t	gKDPDebug = FALSE;
#define KDP_DEBUG(...) if (gKDPDebug) printf(__VA_ARGS__);

int kdp_snapshot = 0;
static int stack_snapshot_ret = 0;
static unsigned stack_snapshot_bytes_traced = 0;

static void *stack_snapshot_buf;
static uint32_t stack_snapshot_bufsize;
static int stack_snapshot_pid;
static uint32_t stack_snapshot_flags;
static uint32_t stack_snapshot_dispatch_offset;

static unsigned int old_debugger;

#define SBLOCKSZ (2048)
uint64_t kdp_dump_start_time = 0;
uint64_t kdp_min_superblock_dump_time = ~1ULL;
uint64_t kdp_max_superblock_dump_time = 0;
uint64_t kdp_superblock_dump_time = 0;
uint64_t kdp_superblock_dump_start_time = 0;

void
kdp_snapshot_preflight(int pid, void * tracebuf, uint32_t tracebuf_size,
    uint32_t flags, uint32_t dispatch_offset);

void
kdp_snapshot_postflight(void);

extern int
kdp_stackshot(int pid, void *tracebuf, uint32_t tracebuf_size,
    uint32_t flags, uint32_t dispatch_offset, uint32_t *pbytesTraced);

int
kdp_stack_snapshot_geterror(void);

int
kdp_stack_snapshot_bytes_traced(void);

static thread_call_t
kdp_timer_call;

static void
kdp_ml_enter_debugger_wrapper(__unused void *param0, __unused void *param1) {
	kdp_ml_enter_debugger();
}

static void
kdp_timer_callout_init(void) {
	kdp_timer_call = thread_call_allocate(kdp_ml_enter_debugger_wrapper, NULL);
}


/* only send/receive data if the link is up */
inline static void wait_for_link(void)
{
    static int first = 0;

    if (!kdp_en_linkstatus)
        return;

    while (((*kdp_en_linkstatus)() & LINK_UP_STATUS) != LINK_UP_STATUS) {
        if (first)
            continue;

        first = 1;
        printf("Waiting for link to become available.\n");
        kprintf("Waiting for link to become available.\n");
    }
}


inline static void kdp_send_data(void *packet, unsigned int len)
{
    wait_for_link();
    (*kdp_en_send_pkt)(packet, len);
}


inline static void kdp_receive_data(void *packet, unsigned int *len,
                                    unsigned int timeout)
{
    wait_for_link();
    (*kdp_en_recv_pkt)(packet, len, timeout);
}


void kdp_register_link(kdp_link_t link, kdp_mode_t mode)
{
        kdp_en_linkstatus = link;
        kdp_en_setmode    = mode;
}

void kdp_unregister_link(__unused kdp_link_t link, __unused kdp_mode_t mode)
{
        kdp_en_linkstatus = NULL;
        kdp_en_setmode    = NULL;
}

void
kdp_register_send_receive(
	kdp_send_t	send, 
	kdp_receive_t	receive)
{
	unsigned int	debug = 0;

	PE_parse_boot_argn("debug", &debug, sizeof (debug));


	if (!debug)
		return;

	kdp_en_send_pkt   = send;
	kdp_en_recv_pkt   = receive;

	if (debug & DB_KDP_BP_DIS)
		kdp_flag |= KDP_BP_DIS;   
	if (debug & DB_KDP_GETC_ENA)
		kdp_flag |= KDP_GETC_ENA;   
	if (debug & DB_ARP)
		kdp_flag |= KDP_ARP;

	if (debug & DB_KERN_DUMP_ON_PANIC)
		kdp_flag |= KDP_PANIC_DUMP_ENABLED;
	if (debug & DB_KERN_DUMP_ON_NMI)
		kdp_flag |= PANIC_CORE_ON_NMI;

	if (debug & DB_DBG_POST_CORE)
		kdp_flag |= DBG_POST_CORE;

	if (debug & DB_PANICLOG_DUMP)
		kdp_flag |= PANIC_LOG_DUMP;

	if (PE_parse_boot_argn("_panicd_ip", panicd_ip_str, sizeof (panicd_ip_str)))
		panicd_specified = TRUE;

	if ((debug & DB_REBOOT_POST_CORE) && (panicd_specified == TRUE))
		kdp_flag |= REBOOT_POST_CORE;

	if (PE_parse_boot_argn("_router_ip", router_ip_str, sizeof (router_ip_str)))
		router_specified = TRUE;

	if (!PE_parse_boot_argn("panicd_port", &panicd_port, sizeof (panicd_port)))
		panicd_port = CORE_REMOTE_PORT;

	if (PE_parse_boot_argn("_panicd_corename", &corename_str, sizeof (corename_str)))
		corename_specified = TRUE;

	kdp_flag |= KDP_READY;
	if (current_debugger == NO_CUR_DB)
		current_debugger = KDP_CUR_DB;
	if ((kdp_current_ip_address != 0) && halt_in_debugger) {
		kdp_call(); 
		halt_in_debugger=0;
	}
}

void
kdp_unregister_send_receive(
	__unused kdp_send_t	send, 
	__unused kdp_receive_t	receive)
{
	if (current_debugger == KDP_CUR_DB)
		current_debugger = NO_CUR_DB;
	kdp_flag &= ~KDP_READY;
	kdp_en_send_pkt   = NULL;
	kdp_en_recv_pkt   = NULL;
}

/* Cache stack snapshot parameters in preparation for a trace */
void
kdp_snapshot_preflight(int pid, void * tracebuf, uint32_t tracebuf_size, uint32_t flags, uint32_t dispatch_offset)
{
	stack_snapshot_pid = pid;
	stack_snapshot_buf = tracebuf;
	stack_snapshot_bufsize = tracebuf_size;
	stack_snapshot_flags = flags;
	stack_snapshot_dispatch_offset = dispatch_offset;
	kdp_snapshot++;
	/* Mark this debugger as active, since the polled mode driver that 
	 * ordinarily does this may not be enabled (yet), or since KDB may be
	 * the primary debugger.
	 */
	old_debugger = current_debugger;
	if (old_debugger != KDP_CUR_DB) {
		current_debugger = KDP_CUR_DB;
	}
}

void
kdp_snapshot_postflight(void)
{
	kdp_snapshot--;
	if ((kdp_en_send_pkt == NULL) || (old_debugger == KDB_CUR_DB))
		current_debugger = old_debugger;
}

int
kdp_stack_snapshot_geterror(void)
{
	return stack_snapshot_ret;
}

int
kdp_stack_snapshot_bytes_traced(void)
{
	return stack_snapshot_bytes_traced;
}

static void
kdp_schedule_debugger_reentry(unsigned interval) {
	uint64_t deadline;;

	clock_interval_to_deadline(interval, 1000 * 1000, &deadline);
	thread_call_enter_delayed(kdp_timer_call, deadline);
}

static void
enaddr_copy(
	void	*src,
	void	*dst
)
{
	bcopy((char *)src, (char *)dst, sizeof (struct ether_addr));
}

static unsigned short
ip_sum(
	unsigned char	*c,
	unsigned int	hlen
	)
{
	unsigned int	high, low, sum;
    
	high = low = 0;
	while (hlen-- > 0) {
		low += c[1] + c[3];
		high += c[0] + c[2];
	
		c += sizeof (int);
	}
    
	sum = (high << 8) + low;
	sum = (sum >> 16) + (sum & 65535);
    
	return (sum > 65535 ? sum - 65535 : sum);
}

static void
kdp_reply(
          unsigned short		reply_port,
          const boolean_t         sideband
          )
{
	struct udpiphdr		aligned_ui, *ui = &aligned_ui;
	struct ip		aligned_ip, *ip = &aligned_ip;
	struct in_addr		tmp_ipaddr;
	struct ether_addr	tmp_enaddr;
	struct ether_header	*eh = NULL;
    
	if (!pkt.input)
		kdp_panic("kdp_reply");
	
	pkt.off -= (unsigned int)sizeof (struct udpiphdr);

#if DO_ALIGN    
	bcopy((char *)&pkt.data[pkt.off], (char *)ui, sizeof(*ui));
#else
	ui = (struct udpiphdr *)&pkt.data[pkt.off];
#endif
	ui->ui_next = ui->ui_prev = 0;
	ui->ui_x1 = 0;
	ui->ui_pr = IPPROTO_UDP;
	ui->ui_len = htons((u_short)pkt.len + sizeof (struct udphdr));
	tmp_ipaddr = ui->ui_src;
	ui->ui_src = ui->ui_dst;
	ui->ui_dst = tmp_ipaddr;
	ui->ui_sport = htons(KDP_REMOTE_PORT);
	ui->ui_dport = reply_port;
	ui->ui_ulen = ui->ui_len;
	ui->ui_sum = 0;
#if DO_ALIGN
	bcopy((char *)ui, (char *)&pkt.data[pkt.off], sizeof(*ui));
	bcopy((char *)&pkt.data[pkt.off], (char *)ip, sizeof(*ip));
#else
	ip = (struct ip *)&pkt.data[pkt.off];
#endif
	ip->ip_len = htons(sizeof (struct udpiphdr) + pkt.len);
	ip->ip_v = IPVERSION;
	ip->ip_id = htons(ip_id++);
	ip->ip_hl = sizeof (struct ip) >> 2;
	ip->ip_ttl = udp_ttl;
	ip->ip_sum = 0;
	ip->ip_sum = htons(~ip_sum((unsigned char *)ip, ip->ip_hl));
#if DO_ALIGN
	bcopy((char *)ip, (char *)&pkt.data[pkt.off], sizeof(*ip));
#endif
    
	pkt.len += (unsigned int)sizeof (struct udpiphdr);
    
	pkt.off -= (unsigned int)sizeof (struct ether_header);
    
	eh = (struct ether_header *)&pkt.data[pkt.off];
	enaddr_copy(eh->ether_shost, &tmp_enaddr);
	enaddr_copy(eh->ether_dhost, eh->ether_shost);
	enaddr_copy(&tmp_enaddr, eh->ether_dhost);
	eh->ether_type = htons(ETHERTYPE_IP);
    
	pkt.len += (unsigned int)sizeof (struct ether_header);
    
	// save reply for possible retransmission
	assert(pkt.len <= KDP_MAXPACKET);
	if (!sideband)
		bcopy((char *)&pkt, (char *)&saved_reply, sizeof(saved_reply));

	kdp_send_data(&pkt.data[pkt.off], pkt.len);

	// increment expected sequence number
	if (!sideband) 
		exception_seq++;
}

static void
kdp_send(
    unsigned short		remote_port
)
{
    struct udpiphdr		aligned_ui, *ui = &aligned_ui;
    struct ip			aligned_ip, *ip = &aligned_ip;
    struct ether_header		*eh;
    
    if (pkt.input)
	kdp_panic("kdp_send");

    pkt.off -= (unsigned int)sizeof (struct udpiphdr);

#if DO_ALIGN
    bcopy((char *)&pkt.data[pkt.off], (char *)ui, sizeof(*ui));
#else
    ui = (struct udpiphdr *)&pkt.data[pkt.off];
#endif
    ui->ui_next = ui->ui_prev = 0;
    ui->ui_x1 = 0;
    ui->ui_pr = IPPROTO_UDP;
    ui->ui_len = htons((u_short)pkt.len + sizeof (struct udphdr));
    ui->ui_src = adr.loc.in;
    ui->ui_dst = adr.rmt.in;
    ui->ui_sport = htons(KDP_REMOTE_PORT);
    ui->ui_dport = remote_port;
    ui->ui_ulen = ui->ui_len;
    ui->ui_sum = 0;
#if DO_ALIGN
    bcopy((char *)ui, (char *)&pkt.data[pkt.off], sizeof(*ui));
    bcopy((char *)&pkt.data[pkt.off], (char *)ip, sizeof(*ip));
#else
    ip = (struct ip *)&pkt.data[pkt.off];
#endif
    ip->ip_len = htons(sizeof (struct udpiphdr) + pkt.len);
    ip->ip_v = IPVERSION;
    ip->ip_id = htons(ip_id++);
    ip->ip_hl = sizeof (struct ip) >> 2;
    ip->ip_ttl = udp_ttl;
    ip->ip_sum = 0;
    ip->ip_sum = htons(~ip_sum((unsigned char *)ip, ip->ip_hl));
#if DO_ALIGN
    bcopy((char *)ip, (char *)&pkt.data[pkt.off], sizeof(*ip));
#endif
    
    pkt.len += (unsigned int)sizeof (struct udpiphdr);
    
    pkt.off -= (unsigned int)sizeof (struct ether_header);
    
    eh = (struct ether_header *)&pkt.data[pkt.off];
    enaddr_copy(&adr.loc.ea, eh->ether_shost);
    enaddr_copy(&adr.rmt.ea, eh->ether_dhost);
    eh->ether_type = htons(ETHERTYPE_IP);
    
    pkt.len += (unsigned int)sizeof (struct ether_header);
    kdp_send_data(&pkt.data[pkt.off], pkt.len);
}


inline static void debugger_if_necessary(void)
{
    if ((current_debugger == KDP_CUR_DB) && halt_in_debugger) {
        kdp_call();
        halt_in_debugger=0;
    }
}


/* We don't interpret this pointer, we just give it to the bsd stack
   so it can decide when to set the MAC and IP info. We'll
   early initialize the MAC/IP info if we can so that we can use
   KDP early in boot. These values may subsequently get over-written
   when the interface gets initialized for real.
*/
void
kdp_set_interface(void *ifp, const struct ether_addr *macaddr)
{
	char kdpstr[80];
        struct in_addr addr = { 0 };
        unsigned int len;
        
	kdp_current_ifp = ifp;

        if (PE_parse_boot_argn("kdp_ip_addr", kdpstr, sizeof(kdpstr))) {
            /* look for a static ip address */
            if (inet_aton(kdpstr, &addr) == FALSE)
                goto done;

            goto config_network;
        }

        /* use saved ip address */
        save_ip_in_nvram = TRUE;

        len = sizeof(kdpstr);
        if (PEReadNVRAMProperty("_kdp_ipstr", kdpstr, &len) == FALSE)
            goto done;

        kdpstr[len < sizeof(kdpstr) ? len : sizeof(kdpstr) - 1] = '\0';
        if (inet_aton(kdpstr, &addr) == FALSE)
            goto done;

config_network:
        kdp_current_ip_address = addr.s_addr;
        if (macaddr)
            kdp_current_mac_address = *macaddr;

        /* we can't drop into the debugger at this point because the
           link will likely not be up. when getDebuggerLinkStatus() support gets
           added to the appropriate network drivers, adding the
           following will enable this capability:
           debugger_if_necessary();
        */
done:
        return;
}

void *
kdp_get_interface(void)
{
	return kdp_current_ifp;
}

void 
kdp_set_ip_and_mac_addresses(
	struct in_addr		*ipaddr, 
	struct ether_addr	*macaddr)
{
        static uint64_t last_time    = (uint64_t) -1;
        static uint64_t throttle_val = 0;
        uint64_t cur_time;
        char addr[16];

        if (kdp_current_ip_address == ipaddr->s_addr) 
            goto done;

        /* don't replace if serial debugging is configured */
        if (!KDP_SERIAL_ENABLED() ||
            (kdp_current_ip_address != KDP_SERIAL_IPADDR)) {
            kdp_current_mac_address = *macaddr;
            kdp_current_ip_address  = ipaddr->s_addr;
        }

        if (save_ip_in_nvram == FALSE)
            goto done;

        if (inet_ntoa2(ipaddr, addr, sizeof(addr)) == FALSE)
            goto done;

        /* throttle writes if needed */
        if (!throttle_val)
            nanoseconds_to_absolutetime(KDP_THROTTLE_VALUE, &throttle_val);

        cur_time = mach_absolute_time();
        if (last_time == (uint64_t) -1 ||
            ((cur_time - last_time) > throttle_val)) {
            PEWriteNVRAMProperty("_kdp_ipstr", addr, 
                                 (const unsigned int) strlen(addr));
        }
        last_time = cur_time;

done:
        debugger_if_necessary();
}

void
kdp_set_gateway_mac(void *gatewaymac)
{
    router_mac = *(struct ether_addr *)gatewaymac;
    flag_router_mac_initialized = TRUE;
} 

struct ether_addr 
kdp_get_mac_addr(void)
{
  return kdp_current_mac_address;
}

unsigned int 
kdp_get_ip_address(void)
{
  return (unsigned int)kdp_current_ip_address;
}

void
kdp_disable_arp(void)
{
	kdp_flag &= ~(DB_ARP);
}

static void
kdp_arp_dispatch(void)
{
	struct ether_arp	aligned_ea, *ea = &aligned_ea;
	unsigned		arp_header_offset;

	arp_header_offset = (unsigned)sizeof(struct ether_header) + pkt.off;
	memcpy((void *)ea, (void *)&pkt.data[arp_header_offset], sizeof(*ea));

	switch(ntohs(ea->arp_op)) {
	case ARPOP_REQUEST:
		kdp_arp_reply(ea);
		break;
	case ARPOP_REPLY:
		kdp_process_arp_reply(ea);
		break;
	default:
		return;
	}
}

static void
kdp_process_arp_reply(struct ether_arp *ea)
{
	/* Are we interested in ARP replies? */
	if (flag_arp_resolved == TRUE)
		return;

	/* Did we receive a reply from the right source? */
	if (((struct in_addr *)(ea->arp_spa))->s_addr != target_ip)
	  return;

	flag_arp_resolved = TRUE;
	current_resolved_MAC = *(struct ether_addr *) (ea->arp_sha);

	return;
}

/* ARP responses are enabled when the DB_ARP bit of the debug boot arg
 * is set.
 */

static void 
kdp_arp_reply(struct ether_arp *ea)
{
	struct ether_header	*eh;

	struct in_addr 		isaddr, itaddr, myaddr;
	struct ether_addr	my_enaddr;

	eh = (struct ether_header *)&pkt.data[pkt.off];
	pkt.off += (unsigned int)sizeof(struct ether_header);

	if(ntohs(ea->arp_op) != ARPOP_REQUEST)
	  return;

	myaddr.s_addr = kdp_get_ip_address();
	my_enaddr = kdp_get_mac_addr();

	if ((ntohl(myaddr.s_addr) == 0) ||
	    ((my_enaddr.ether_addr_octet[0] & 0xff) == 0
		 && (my_enaddr.ether_addr_octet[1] & 0xff) == 0
		 && (my_enaddr.ether_addr_octet[2] & 0xff) == 0
		 && (my_enaddr.ether_addr_octet[3] & 0xff) == 0
		 && (my_enaddr.ether_addr_octet[4] & 0xff) == 0
		 && (my_enaddr.ether_addr_octet[5] & 0xff) == 0
		 ))
		return;

	(void)memcpy((void *)&isaddr, (void *)ea->arp_spa, sizeof (isaddr));
	(void)memcpy((void *)&itaddr, (void *)ea->arp_tpa, sizeof (itaddr));

	if (itaddr.s_addr == myaddr.s_addr) {
		(void)memcpy((void *)ea->arp_tha, (void *)ea->arp_sha, sizeof(ea->arp_sha));
		(void)memcpy((void *)ea->arp_sha, (void *)&my_enaddr, sizeof(ea->arp_sha));

		(void)memcpy((void *)ea->arp_tpa, (void *) ea->arp_spa, sizeof(ea->arp_spa));
		(void)memcpy((void *)ea->arp_spa, (void *) &itaddr, sizeof(ea->arp_spa));

		ea->arp_op = htons(ARPOP_REPLY);
		ea->arp_pro = htons(ETHERTYPE_IP); 
		(void)memcpy(eh->ether_dhost, ea->arp_tha, sizeof(eh->ether_dhost));
		(void)memcpy(eh->ether_shost, &my_enaddr, sizeof(eh->ether_shost));
		eh->ether_type = htons(ETHERTYPE_ARP);
		(void)memcpy(&pkt.data[pkt.off], ea, sizeof(*ea));
		pkt.off -= (unsigned int)sizeof (struct ether_header);
		/* pkt.len is still the length we want, ether_header+ether_arp */
		kdp_send_data(&pkt.data[pkt.off], pkt.len);
	}
}

static void
kdp_poll(void)
{
	struct ether_header	*eh = NULL;
	struct udpiphdr		aligned_ui, *ui = &aligned_ui;
	struct ip		aligned_ip, *ip = &aligned_ip;
	static int		msg_printed;

	if (pkt.input)
		kdp_panic("kdp_poll");
 
	if (!kdp_en_recv_pkt || !kdp_en_send_pkt) {
		if( msg_printed == 0) {
			msg_printed = 1;
			printf("kdp_poll: no debugger device\n");
		}
		return;
	}

	pkt.off = pkt.len = 0;
	kdp_receive_data(pkt.data, &pkt.len, 3/* ms */);

	if (pkt.len == 0)
		return;

	if (pkt.len >= sizeof(struct ether_header))
	{
		eh = (struct ether_header *)&pkt.data[pkt.off];  
	
		if (kdp_flag & KDP_ARP)
		{
			if (ntohs(eh->ether_type) == ETHERTYPE_ARP)
			{
				kdp_arp_dispatch();
				return;
			}
		}
	}

	if (pkt.len < (sizeof (struct ether_header) + sizeof (struct udpiphdr)))
		return;

	pkt.off += (unsigned int)sizeof (struct ether_header);
	if (ntohs(eh->ether_type) != ETHERTYPE_IP) {
		return;
	}

#if DO_ALIGN
	bcopy((char *)&pkt.data[pkt.off], (char *)ui, sizeof(*ui));
	bcopy((char *)&pkt.data[pkt.off], (char *)ip, sizeof(*ip));
#else
	ui = (struct udpiphdr *)&pkt.data[pkt.off];
	ip = (struct ip *)&pkt.data[pkt.off];
#endif

	pkt.off += (unsigned int)sizeof (struct udpiphdr);
	if (ui->ui_pr != IPPROTO_UDP) {
		return;
	}
 
	if (ip->ip_hl > (sizeof (struct ip) >> 2)) {
		return;
	}

	if (ntohs(ui->ui_dport) != KDP_REMOTE_PORT) {
		if (panicd_port == (ntohs(ui->ui_dport)) && 
		    flag_panic_dump_in_progress) {
			last_panic_port = ui->ui_sport;
		}
		else
			return;
	}
	/* If we receive a kernel debugging packet whilst a 
	 * core dump is in progress, abort the transfer and 
	 * enter the debugger if not told otherwise. 
	 */
	else
		if (flag_panic_dump_in_progress)
		{
			if (!flag_dont_abort_panic_dump) {
				abort_panic_transfer();
			}
			return;
		}

	if (!kdp.is_conn && !flag_panic_dump_in_progress) {
		enaddr_copy(eh->ether_dhost, &adr.loc.ea);
		adr.loc.in = ui->ui_dst;

		enaddr_copy(eh->ether_shost, &adr.rmt.ea);
		adr.rmt.in = ui->ui_src;
	}

	/*
	 * Calculate kdp packet length.
	 */
	pkt.len = ntohs((u_short)ui->ui_ulen) - (unsigned int)sizeof (struct udphdr);
	pkt.input = TRUE;
}

/* Create and transmit an ARP resolution request for the target IP address.
 * This is modeled on ether_inet_arp()/RFC 826.
 */

static void
transmit_ARP_request(uint32_t ip_addr)
{
	struct ether_header	*eh = (struct ether_header *) &pkt.data[0];
	struct ether_arp	*ea = (struct ether_arp *) &pkt.data[sizeof(struct ether_header)];

 	KDP_DEBUG("Transmitting ARP request\n");
	/* Populate the ether_header */
	eh->ether_type = htons(ETHERTYPE_ARP);
	enaddr_copy(&kdp_current_mac_address, eh->ether_shost);
	enaddr_copy(&etherbroadcastaddr, eh->ether_dhost);

	/* Populate the ARP header */
	ea->arp_pro = htons(ETHERTYPE_IP);
	ea->arp_hln = sizeof(ea->arp_sha);
	ea->arp_pln = sizeof(ea->arp_spa);
	ea->arp_hrd = htons(ARPHRD_ETHER);
	ea->arp_op = htons(ARPOP_REQUEST);

	/* Target fields */
	enaddr_copy(&etherbroadcastaddr, ea->arp_tha);
	memcpy(ea->arp_tpa, (void *) &ip_addr, sizeof(ip_addr));

	/* Source fields */
	enaddr_copy(&kdp_current_mac_address, ea->arp_sha);
	memcpy(ea->arp_spa, (void *) &kdp_current_ip_address, sizeof(kdp_current_ip_address));

	pkt.off = 0;
	pkt.len = sizeof(struct ether_header) + sizeof(struct ether_arp);
	/* Transmit */
	kdp_send_data(&pkt.data[pkt.off], pkt.len);
}

static boolean_t
kdp_arp_resolve(uint32_t arp_target_ip, struct ether_addr *resolved_MAC)
{
	int poll_count = 256; /* ~770 ms modulo broadcast/delayed traffic? */
	char tretries = 0;

#define NUM_ARP_TX_RETRIES 5

	target_ip = arp_target_ip;
	flag_arp_resolved = FALSE;

TRANSMIT_RETRY:
	pkt.off = pkt.len = 0;

	tretries++;

	if (tretries >= NUM_ARP_TX_RETRIES) {
		return FALSE;
	}

	KDP_DEBUG("ARP TX attempt #%d \n", tretries);

	transmit_ARP_request(arp_target_ip);

	while (!pkt.input && !flag_arp_resolved && flag_panic_dump_in_progress && --poll_count) {
		kdp_poll();
	}

	if (flag_arp_resolved) {
		*resolved_MAC = current_resolved_MAC;
		return TRUE;
	}
	
	if (!flag_panic_dump_in_progress || pkt.input) /* we received a debugging packet, bail*/
	{
		printf("Received a debugger packet,transferring control to debugger\n");
		/* Indicate that we should wait in the debugger when we return */
		kdp_flag |= DBG_POST_CORE;
		pkt.input = FALSE;
		return FALSE;
	}
	else /* We timed out */
		if (0 == poll_count) {
			poll_count = 256;
			goto TRANSMIT_RETRY;
		}
	return FALSE;
}

static void
kdp_handler(
    void	*saved_state
)
{
    unsigned short		reply_port;
    kdp_hdr_t			aligned_hdr, *hdr = &aligned_hdr;

    kdp.saved_state = saved_state;  // see comment in kdp_raise_exception

    do {
	while (!pkt.input)
	    kdp_poll();
	    		
#if DO_ALIGN
	bcopy((char *)&pkt.data[pkt.off], (char *)hdr, sizeof(*hdr));
#else
	hdr = (kdp_hdr_t *)&pkt.data[pkt.off];
#endif

	// ignore replies -- we're not expecting them anyway.
	if (hdr->is_reply) {
	    goto again;
	}
	
	if (hdr->request == KDP_REATTACH)
	  exception_seq = hdr->seq;

	// check for retransmitted request
	if (hdr->seq == (exception_seq - 1)) {
	    /* retransmit last reply */
	    kdp_send_data(&saved_reply.data[saved_reply.off],
                          saved_reply.len);
	    goto again;
	} else if ((hdr->seq != exception_seq) &&
                   (hdr->request != KDP_CONNECT)) {
	    printf("kdp: bad sequence %d (want %d)\n",
			hdr->seq, exception_seq);
	    goto again;
	}
	
	/* This is a manual side-channel to the main KDP protocol.
	 * A client like GDB/kgmacros can manually construct 
	 * a request, set the input flag, issue a dummy KDP request,
	 * and then manually collect the result
	 */
	if (manual_pkt.input) {
	  kdp_hdr_t *manual_hdr = (kdp_hdr_t *)&manual_pkt.data;
	  unsigned short manual_port_unused = 0;
	  if (!manual_hdr->is_reply) {
	    /* process */
	    kdp_packet((unsigned char *)&manual_pkt.data,
		       (int *)&manual_pkt.len,
		       &manual_port_unused);
	  }
	  manual_pkt.input = 0;
	}

	if (kdp_packet((unsigned char*)&pkt.data[pkt.off], 
			(int *)&pkt.len, 
			(unsigned short *)&reply_port)) {
            boolean_t sideband = FALSE;

            /* if it's an already connected error message, 
             * send a sideband reply for that. for successful connects,
             * make sure the sequence number is correct. */
            if (hdr->request == KDP_CONNECT) {
                kdp_connect_reply_t *rp = 
			(kdp_connect_reply_t *) &pkt.data[pkt.off];
                kdp_error_t err = rp->error;

                if (err == KDPERR_NO_ERROR) {
                    exception_seq = hdr->seq;
                } else if (err == KDPERR_ALREADY_CONNECTED) {
                    sideband = TRUE;
                }
            } 

	    kdp_reply(reply_port, sideband);
	}

again:
	pkt.input = FALSE;
    } while (kdp.is_halted);
}

static void
kdp_connection_wait(void)
{
	unsigned short		reply_port;
	struct ether_addr	kdp_mac_addr = kdp_get_mac_addr();
	unsigned int		ip_addr = ntohl(kdp_get_ip_address());

	/*
	 * Do both a printf() and a kprintf() of the MAC and IP so that
	 * they will print out on headless machines but not be added to
	 * the panic.log
	 */

        if (KDP_SERIAL_ENABLED()) {
            printf("Using serial KDP.\n");
            kprintf("Using serial KDP.\n");
        } else {
            printf( "ethernet MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
                    kdp_mac_addr.ether_addr_octet[0] & 0xff,
                    kdp_mac_addr.ether_addr_octet[1] & 0xff,
                    kdp_mac_addr.ether_addr_octet[2] & 0xff,
                    kdp_mac_addr.ether_addr_octet[3] & 0xff,
                    kdp_mac_addr.ether_addr_octet[4] & 0xff,
                    kdp_mac_addr.ether_addr_octet[5] & 0xff);
		
            kprintf( "ethernet MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
                     kdp_mac_addr.ether_addr_octet[0] & 0xff,
                     kdp_mac_addr.ether_addr_octet[1] & 0xff,
                     kdp_mac_addr.ether_addr_octet[2] & 0xff,
                     kdp_mac_addr.ether_addr_octet[3] & 0xff,
                     kdp_mac_addr.ether_addr_octet[4] & 0xff,
                     kdp_mac_addr.ether_addr_octet[5] & 0xff);
		
            printf( "ip address: %d.%d.%d.%d\n",
                    (ip_addr & 0xff000000) >> 24,
                    (ip_addr & 0xff0000) >> 16,
                    (ip_addr & 0xff00) >> 8,
                    (ip_addr & 0xff));
            
            kprintf( "ip address: %d.%d.%d.%d\n",
                     (ip_addr & 0xff000000) >> 24,
                     (ip_addr & 0xff0000) >> 16,
                     (ip_addr & 0xff00) >> 8,
                     (ip_addr & 0xff));
        }
            
	printf("\nWaiting for remote debugger connection.\n");
	kprintf("\nWaiting for remote debugger connection.\n");


	if (reattach_wait == 0) {
		if((kdp_flag & KDP_GETC_ENA) && (0 != kdp_getc()))
		{
			printf("Options.....    Type\n");
			printf("------------    ----\n");
			printf("continue....    'c'\n");
			printf("reboot......    'r'\n");
		}
	} else
		reattach_wait = 0;
    
	exception_seq = 0;

	do {
		kdp_hdr_t aligned_hdr, *hdr = &aligned_hdr;
	
		while (!pkt.input) {
			if (kdp_flag & KDP_GETC_ENA) {
				switch(kdp_getc()) {
				case 'c':
					printf("Continuing...\n");
					return;
				case 'r':
					printf("Rebooting...\n");
					kdp_machine_reboot();
					break;
				default:
					break;
		    		}
			}
			kdp_poll();
		}

#if DO_ALIGN
		bcopy((char *)&pkt.data[pkt.off], (char *)hdr, sizeof(*hdr));
#else
		hdr = (kdp_hdr_t *)&pkt.data[pkt.off];
#endif
		if (hdr->request == KDP_HOSTREBOOT) {
			kdp_machine_reboot();
			/* should not return! */
		}
		if (((hdr->request == KDP_CONNECT) || (hdr->request == KDP_REATTACH)) &&
			!hdr->is_reply && (hdr->seq == exception_seq)) {
		    if (kdp_packet((unsigned char *)&pkt.data[pkt.off], 
				(int *)&pkt.len, 
				(unsigned short *)&reply_port))
			    kdp_reply(reply_port, FALSE);
		    if (hdr->request == KDP_REATTACH) {
				reattach_wait = 0;
				hdr->request=KDP_DISCONNECT;
				exception_seq = 0;
			}
		}

		pkt.input = FALSE;
	} while (!kdp.is_conn);
    
	if (current_debugger == KDP_CUR_DB)
		active_debugger=1;
	printf("Connected to remote debugger.\n");
	kprintf("Connected to remote debugger.\n");
}

static void
kdp_send_exception(
    unsigned int		exception,
    unsigned int		code,
    unsigned int		subcode
)
{
    unsigned short		remote_port;
    unsigned int		timeout_count = 100;
    unsigned int                poll_timeout;

    do {
	pkt.off = sizeof (struct ether_header) + sizeof (struct udpiphdr);
	kdp_exception((unsigned char *)&pkt.data[pkt.off], 
			(int *)&pkt.len, 
			(unsigned short *)&remote_port,
			(unsigned int)exception, 
			(unsigned int)code, 
			(unsigned int)subcode);

	kdp_send(remote_port);
    
	poll_timeout = 50;
	while(!pkt.input && poll_timeout)
	  {
	    kdp_poll();
	    poll_timeout--;
	  }

	if (pkt.input) {
	    if (!kdp_exception_ack(&pkt.data[pkt.off], pkt.len)) {
		pkt.input = FALSE;
	    }
	}

	pkt.input = FALSE;

	if (kdp.exception_ack_needed)
	    kdp_us_spin(250000);

    } while (kdp.exception_ack_needed && timeout_count--);
    
    if (kdp.exception_ack_needed) {
	// give up & disconnect
	printf("kdp: exception ack timeout\n");
	if (current_debugger == KDP_CUR_DB)
    	active_debugger=0;
	kdp_reset();
    }
}

void
kdp_raise_exception(
    unsigned int		exception,
    unsigned int		code,
    unsigned int		subcode,
    void			*saved_state
)
{
    int			index;
    unsigned int	initial_not_in_kdp = not_in_kdp;

    not_in_kdp = 0;
    /* Was a system trace requested ? */
    if (kdp_snapshot && (!panic_active()) && (panic_caller == 0)) {
	    stack_snapshot_ret = kdp_stackshot(stack_snapshot_pid,
	    stack_snapshot_buf, stack_snapshot_bufsize,
	    stack_snapshot_flags, stack_snapshot_dispatch_offset, 
		&stack_snapshot_bytes_traced);
	    not_in_kdp = initial_not_in_kdp;
	    return;
    }

    disable_preemption();

    if (saved_state == 0) 
	printf("kdp_raise_exception with NULL state\n");

    index = exception;
    if (exception != EXC_BREAKPOINT) {
	if (exception > EXC_BREAKPOINT || exception < EXC_BAD_ACCESS) {
	    index = 0;
	}
	printf("%s exception (%x,%x,%x)\n",
		exception_message[index],
		exception, code, subcode);
    }

    kdp_sync_cache();

    /* XXX WMG it seems that sometimes it doesn't work to let kdp_handler
     * do this. I think the client and the host can get out of sync.
     */
    kdp.saved_state = saved_state;
    kdp.kdp_cpu = cpu_number();
    kdp.kdp_thread = current_thread();

    if (kdp_en_setmode)  
        (*kdp_en_setmode)(TRUE); /* enabling link mode */

    if (pkt.input)
	kdp_panic("kdp_raise_exception");

    if (((kdp_flag & KDP_PANIC_DUMP_ENABLED) || (kdp_flag & PANIC_LOG_DUMP))
	&& (panicstr != (char *) 0)) {
	    kdp_panic_dump();
	    if (kdp_flag & REBOOT_POST_CORE)
		    kdp_machine_reboot();
      }
    else
      if ((kdp_flag & PANIC_CORE_ON_NMI) && (panicstr == (char *) 0) &&
	  !kdp.is_conn) {

	disable_debug_output = disableConsoleOutput = FALSE;
	kdp_panic_dump();

	if (!(kdp_flag & DBG_POST_CORE))
	  goto exit_raise_exception;
      }

 again:
    if (!kdp.is_conn)
	kdp_connection_wait();
    else {
	kdp_send_exception(exception, code, subcode);
	if (kdp.exception_ack_needed) {
	    kdp.exception_ack_needed = FALSE;
	    kdp_remove_all_breakpoints();
	    printf("Remote debugger disconnected.\n");
	  }
      }

    if (kdp.is_conn) {
	kdp.is_halted = TRUE;		/* XXX */
	kdp_handler(saved_state);
	if (!kdp.is_conn)
	  {
	    kdp_remove_all_breakpoints();
	    printf("Remote debugger disconnected.\n");
	  }
    }
    /* Allow triggering a panic core dump when connected to the machine
     * Continuing after setting kdp_trigger_core_dump should do the
     * trick.
     */

    if (1 == kdp_trigger_core_dump) {
	kdp_flag |= KDP_PANIC_DUMP_ENABLED;
	kdp_panic_dump();
	if (kdp_flag & REBOOT_POST_CORE)
		kdp_machine_reboot();
	kdp_trigger_core_dump = 0;
      }

/* Trigger a reboot if the user has set this flag through the
 * debugger.Ideally, this would be done through the HOSTREBOOT packet
 * in the protocol,but that will need gdb support,and when it's
 * available, it should work automatically.
 */
    if (1 == flag_kdp_trigger_reboot) {
	    kdp_machine_reboot();
	    /* If we're still around, reset the flag */
	    flag_kdp_trigger_reboot = 0;
    }

    if (kdp_reentry_deadline) {
	    kdp_schedule_debugger_reentry(kdp_reentry_deadline);
	    printf("Debugger re-entry scheduled in %d milliseconds\n", kdp_reentry_deadline);
	    kdp_reentry_deadline = 0;
    }

    kdp_sync_cache();

    if (reattach_wait == 1)
      goto again;

exit_raise_exception:
    if (kdp_en_setmode)  
        (*kdp_en_setmode)(FALSE); /* link cleanup */

    not_in_kdp = initial_not_in_kdp;

    enable_preemption();
}

void
kdp_reset(void)
{
	kdp.reply_port = kdp.exception_port = 0;
	kdp.is_halted = kdp.is_conn = FALSE;
	kdp.exception_seq = kdp.conn_seq = 0;
	kdp.session_key = 0;
	pkt.input = manual_pkt.input = FALSE;
	pkt.len = pkt.off = manual_pkt.len = 0;
}

struct corehdr *
create_panic_header(unsigned int request, const char *corename, 
    unsigned length, unsigned int block)
{
	struct udpiphdr		aligned_ui, *ui = &aligned_ui;
	struct ip		aligned_ip, *ip = &aligned_ip;
	struct ether_header	*eh;
	struct corehdr		*coreh;
	const char		*mode = "octet";
	char			modelen  = strlen(mode) + 1;

	size_t			fmask_size = sizeof(KDP_FEATURE_MASK_STRING) + sizeof(kdp_crashdump_feature_mask);

	pkt.off = sizeof (struct ether_header);
	pkt.len = (unsigned int)(length + ((request == KDP_WRQ) ? modelen + fmask_size : 0) + 
	(corename ? (strlen(corename) + 1 ): 0) + sizeof(struct corehdr));

#if DO_ALIGN
	bcopy((char *)&pkt.data[pkt.off], (char *)ui, sizeof(*ui));
#else
	ui = (struct udpiphdr *)&pkt.data[pkt.off];
#endif
	ui->ui_next = ui->ui_prev = 0;
	ui->ui_x1 = 0;
	ui->ui_pr = IPPROTO_UDP;
	ui->ui_len = htons((u_short)pkt.len + sizeof (struct udphdr));
	ui->ui_src.s_addr = (uint32_t)kdp_current_ip_address;
	/* Already in network byte order via inet_aton() */
	ui->ui_dst.s_addr = panic_server_ip;
	ui->ui_sport = htons(panicd_port);
	ui->ui_dport = ((request == KDP_WRQ) ? htons(panicd_port) : last_panic_port);
	ui->ui_ulen = ui->ui_len;
	ui->ui_sum = 0;
#if DO_ALIGN
	bcopy((char *)ui, (char *)&pkt.data[pkt.off], sizeof(*ui));
	bcopy((char *)&pkt.data[pkt.off], (char *)ip, sizeof(*ip));
#else
	ip = (struct ip *)&pkt.data[pkt.off];
#endif
	ip->ip_len = htons(sizeof (struct udpiphdr) + pkt.len);
	ip->ip_v = IPVERSION;
	ip->ip_id = htons(ip_id++);
	ip->ip_hl = sizeof (struct ip) >> 2;
	ip->ip_ttl = udp_ttl;
	ip->ip_sum = 0;
	ip->ip_sum = htons(~ip_sum((unsigned char *)ip, ip->ip_hl));
#if DO_ALIGN
	bcopy((char *)ip, (char *)&pkt.data[pkt.off], sizeof(*ip));
#endif
    
	pkt.len += (unsigned int)sizeof (struct udpiphdr);

	pkt.off += (unsigned int)sizeof (struct udpiphdr);
  
	coreh = (struct corehdr *) &pkt.data[pkt.off];
	coreh->th_opcode = htons((u_short)request);
  
	if (request == KDP_WRQ)
	{
		char *cp;

		cp = coreh->th_u.tu_rpl;
		cp += strlcpy (cp, corename, KDP_MAXPACKET);
		*cp++ = '\0';
		cp += strlcpy (cp, mode, KDP_MAXPACKET - strlen(corename));
		*cp++ = '\0';
		cp += strlcpy(cp, KDP_FEATURE_MASK_STRING, sizeof(KDP_FEATURE_MASK_STRING));
		*cp++ = '\0'; /* Redundant */
		bcopy(&kdp_crashdump_feature_mask, cp, sizeof(kdp_crashdump_feature_mask));
		kdp_crashdump_pkt_size = KDP_LARGE_CRASHDUMP_PKT_SIZE;
		PE_parse_boot_argn("kdp_crashdump_pkt_size", &kdp_crashdump_pkt_size, sizeof(kdp_crashdump_pkt_size));
		cp += sizeof(kdp_crashdump_feature_mask);
		*(uint32_t *)cp = htonl(kdp_crashdump_pkt_size);
	}
	else
	{
		coreh->th_block = htonl((unsigned int) block);
	}

	pkt.off -= (unsigned int)sizeof (struct udpiphdr);
	pkt.off -= (unsigned int)sizeof (struct ether_header);

	eh = (struct ether_header *)&pkt.data[pkt.off];
	enaddr_copy(&kdp_current_mac_address, eh->ether_shost);
	enaddr_copy(&destination_mac, eh->ether_dhost);
	eh->ether_type = htons(ETHERTYPE_IP);
    
	pkt.len += (unsigned int)sizeof (struct ether_header);
	return coreh;
}

static int kdp_send_crashdump_seek(char *corename, uint64_t seek_off)
{
	int panic_error;

	if (kdp_feature_large_crashdumps) {
		panic_error = kdp_send_crashdump_pkt(KDP_SEEK, corename, 
						     sizeof(seek_off),
						     &seek_off);
	} else {
		uint32_t off = (uint32_t) seek_off;
		panic_error = kdp_send_crashdump_pkt(KDP_SEEK, corename, 
						     sizeof(off), &off);
	}

	if (panic_error < 0) {
		printf ("kdp_send_crashdump_pkt failed with error %d\n",
			panic_error);
		return panic_error;
	}

	return 0;
}

int kdp_send_crashdump_data(unsigned int request, char *corename,
    int64_t length, caddr_t txstart)
{
	int panic_error = 0;

	while (length > 0) {
		uint64_t chunk = MIN(kdp_crashdump_pkt_size, length);

		panic_error = kdp_send_crashdump_pkt(request, corename, chunk,
							txstart);
		if (panic_error < 0) {
			printf ("kdp_send_crashdump_pkt failed with error %d\n", panic_error);
			return panic_error;
		}

		txstart += chunk;
		length  -= chunk;
	}
	return 0;
}

uint32_t kdp_crashdump_short_pkt;

int
kdp_send_crashdump_pkt(unsigned int request, char *corename, 
    uint64_t length, void *panic_data)
{
	int poll_count;
	struct corehdr *th = NULL;
	char rretries, tretries;

	if (kdp_dump_start_time == 0) {
		kdp_dump_start_time = mach_absolute_time();
		kdp_superblock_dump_start_time = kdp_dump_start_time;
	}

	tretries = rretries = 0;
	poll_count = KDP_CRASHDUMP_POLL_COUNT;
	pkt.off = pkt.len = 0;
	if (request == KDP_WRQ) /* longer timeout for initial request */
		poll_count += 1000;

TRANSMIT_RETRY:
	tretries++;

	if (tretries >=15) {
/* The crashdump server is unreachable for some reason. This could be a network
 * issue or, if we've been especially unfortunate, we've hit Radar 2760413,
 * which is a long standing problem with the IOKit polled mode network driver
 * shim which can prevent transmits/receives completely.
 */
		printf ("Cannot contact panic server, timing out.\n");
		return (-3);
	}

	if (tretries > 2)
		printf("TX retry #%d ", tretries );
  
	th = create_panic_header(request, corename, (unsigned)length, panic_block);

	if (request == KDP_DATA) {
		/* as all packets are kdp_crashdump_pkt_size in length, the last packet
		 * may end up with trailing bits. make sure that those
		 * bits aren't confusing. */
		if (length < kdp_crashdump_pkt_size) {
			kdp_crashdump_short_pkt++;
			memset(th->th_data + length, 'Y', 
                               kdp_crashdump_pkt_size - (uint32_t) length);
		}

		if (!kdp_machine_vm_read((mach_vm_address_t)(uintptr_t)panic_data, (caddr_t) th->th_data, length)) {
			uintptr_t next_page = round_page((uintptr_t)panic_data);
			memset((caddr_t) th->th_data, 'X', (size_t)length);
			if ((next_page - ((uintptr_t) panic_data)) < length) {
				uint64_t resid = length - (next_page - (intptr_t) panic_data);
				if (!kdp_machine_vm_read((mach_vm_address_t)(uintptr_t)next_page, (caddr_t) th->th_data + (length - resid), resid)) {
					memset((caddr_t) th->th_data + (length - resid), 'X', (size_t)resid);
				}
			}
		}
	}
	else if (request == KDP_SEEK) {
		if (kdp_feature_large_crashdumps)
			*(uint64_t *) th->th_data = OSSwapHostToBigInt64((*(uint64_t *) panic_data));
		else
			*(unsigned int *) th->th_data = htonl(*(unsigned int *) panic_data);
	}

	kdp_send_data(&pkt.data[pkt.off], pkt.len);

	/* Listen for the ACK */
RECEIVE_RETRY:
	while (!pkt.input && flag_panic_dump_in_progress && poll_count) {
		kdp_poll();
		poll_count--;
	}

	if (pkt.input) {
    
		pkt.input = FALSE;
    
		th = (struct corehdr *) &pkt.data[pkt.off];
		if (request == KDP_WRQ) {
			uint16_t opcode64 = ntohs(th->th_opcode);
			uint16_t features64 = (opcode64 & 0xFF00)>>8;
			if ((opcode64 & 0xFF) == KDP_ACK) {
				kdp_feature_large_crashdumps = features64 & KDP_FEATURE_LARGE_CRASHDUMPS;
				if (features64 & KDP_FEATURE_LARGE_PKT_SIZE) {
					kdp_feature_large_pkt_size = 1;
				}
				else {
					kdp_feature_large_pkt_size = 0;
					kdp_crashdump_pkt_size = 512;
				}
				printf("Protocol features: 0x%x\n", (uint32_t) features64);
				th->th_opcode = htons(KDP_ACK);
			}
		}
		if (ntohs(th->th_opcode) == KDP_ACK && ntohl(th->th_block) == panic_block) {
		}
		else
			if (ntohs(th->th_opcode) == KDP_ERROR) {
				printf("Panic server returned error %d, retrying\n", ntohl(th->th_code));
				poll_count = 1000;
				goto TRANSMIT_RETRY;
			}
			else 
				if (ntohl(th->th_block) == (panic_block - 1)) {
					printf("RX retry ");
					if (++rretries > 1)
						goto TRANSMIT_RETRY;
					else
						goto RECEIVE_RETRY;
				}
	}
	else
		if (!flag_panic_dump_in_progress) /* we received a debugging packet, bail*/
		{
			printf("Received a debugger packet,transferring control to debugger\n");
			/* Configure that if not set ..*/
			kdp_flag |= DBG_POST_CORE;
			return (-2);
		}
		else /* We timed out */
			if (0 == poll_count) {
				poll_count = 1000;
				kdp_us_spin ((tretries%4) * panic_timeout); /* capped linear backoff */
				goto TRANSMIT_RETRY;
			}

	if (!(++panic_block % SBLOCKSZ)) {
		uint64_t ctime;
		kdb_printf_unbuffered(".");
		ctime = mach_absolute_time();
		kdp_superblock_dump_time = ctime - kdp_superblock_dump_start_time;
		kdp_superblock_dump_start_time = ctime;
		if (kdp_superblock_dump_time > kdp_max_superblock_dump_time)
			kdp_max_superblock_dump_time = kdp_superblock_dump_time;
		if (kdp_superblock_dump_time < kdp_min_superblock_dump_time)
			kdp_min_superblock_dump_time = kdp_superblock_dump_time;
	}

	if (request == KDP_EOF) {
		printf("\nTotal number of packets transmitted: %d\n", panic_block);
		printf("Avg. superblock transfer abstime 0x%llx\n", ((mach_absolute_time() - kdp_dump_start_time) / panic_block) * SBLOCKSZ);
		printf("Minimum superblock transfer abstime: 0x%llx\n", kdp_min_superblock_dump_time);
		printf("Maximum superblock transfer abstime: 0x%llx\n", kdp_max_superblock_dump_time);
	}
	return 1;
}

static int 
isdigit (char c)
{
  return ((c > 47) && (c < 58));
}
/* From user mode Libc - this ought to be in a library */
static char *
strnstr(char *s, const char *find, size_t slen)
{
  char c, sc;
  size_t len;
  
  if ((c = *find++) != '\0') {
    len = strlen(find);
    do {
      do {
	if ((sc = *s++) == '\0' || slen-- < 1)
	  return (NULL);
      } while (sc != c);
      if (len > slen)
	return (NULL);
    } while (strncmp(s, find, len) != 0);
    s--;
  }
  return (s);
}

/* Horrid hack to extract xnu version if possible - a much cleaner approach
 * would be to have the integrator run a script which would copy the
 * xnu version into a string or an int somewhere at project submission
 * time - makes assumptions about sizeof(version), but will not fail if
 * it changes, but may be incorrect.
 */
/* 2006: Incorporated a change from Darwin user P. Lovell to extract
 * the minor kernel version numbers from the version string.
 */
static int 
kdp_get_xnu_version(char *versionbuf)
{
	char *versionpos;
	char vstr[20];
	int retval = -1;
	char *vptr;

	strlcpy(vstr, "custom", 10);
	if (kdp_machine_vm_read((mach_vm_address_t)(uintptr_t)version, versionbuf, 128)) {
		versionbuf[127] = '\0';
		versionpos = strnstr(versionbuf, "xnu-", 115);
		if (versionpos) {
			strncpy(vstr, versionpos, sizeof(vstr));
			vstr[sizeof(vstr)-1] = '\0';
			vptr = vstr + 4; /* Begin after "xnu-" */
			while (*vptr && (isdigit(*vptr) || *vptr == '.'))
				vptr++;
			*vptr = '\0';
			/* Remove trailing period, if any */
			if (*(--vptr) == '.')
				*vptr = '\0';
			retval = 0;
		}
	}
	strlcpy(versionbuf, vstr, KDP_MAXPACKET);
	return retval;
}

void
kdp_set_dump_info(const uint32_t flags, const char *filename, 
                  const char *destipstr, const char *routeripstr,
                  const uint32_t port)
{
	uint32_t cmd;

	if (destipstr && (destipstr[0] != '\0')) {
		strlcpy(panicd_ip_str, destipstr, sizeof(panicd_ip_str));
		panicd_specified = 1;
	}

	if (routeripstr && (routeripstr[0] != '\0')) {
		strlcpy(router_ip_str, routeripstr, sizeof(router_ip_str));
		router_specified = 1;
	}

	if (filename && (filename[0] != '\0')) {
		strlcpy(corename_str, filename, sizeof(corename_str));
		corename_specified = TRUE;
	} else {
		corename_specified = FALSE;
	}

	if (port) 
		panicd_port = port;

        /* on a disconnect, should we stay in KDP or not? */
        noresume_on_disconnect = (flags & KDP_DUMPINFO_NORESUME) ? 1 : 0;

	if ((flags & KDP_DUMPINFO_DUMP) == 0)
		return;

	/* the rest of the commands can modify kdp_flags */
	cmd = flags & KDP_DUMPINFO_MASK;
        if (cmd == KDP_DUMPINFO_DISABLE) {
		kdp_flag &= ~KDP_PANIC_DUMP_ENABLED;
		panicd_specified       = 0;
		kdp_trigger_core_dump  = 0;
		return;
        }

	kdp_flag &= ~REBOOT_POST_CORE;
	if (flags & KDP_DUMPINFO_REBOOT)
            kdp_flag |= REBOOT_POST_CORE;

	kdp_flag &= ~PANIC_LOG_DUMP;
	if (cmd == KDP_DUMPINFO_PANICLOG)
            kdp_flag |= PANIC_LOG_DUMP;
	
	kdp_flag &= ~SYSTEM_LOG_DUMP;
	if (cmd == KDP_DUMPINFO_SYSTEMLOG)
            kdp_flag |= SYSTEM_LOG_DUMP;

	/* trigger a dump */
	kdp_flag |= DBG_POST_CORE;

	flag_dont_abort_panic_dump = (flags & KDP_DUMPINFO_NOINTR) ? 
		TRUE : FALSE;

	reattach_wait          = 1;
	logPanicDataToScreen   = 1;
	disableConsoleOutput   = 0;
	disable_debug_output   = 0;
	kdp_trigger_core_dump  = 1;
}

void
kdp_get_dump_info(uint32_t *flags, char *filename, char *destipstr, 
                  char *routeripstr, uint32_t *port)
{
	if (destipstr) {
		if (panicd_specified)
			strlcpy(destipstr, panicd_ip_str, 
                                sizeof(panicd_ip_str));
		else 
			destipstr[0] = '\0';
	}

	if (routeripstr) {
		if (router_specified)
			strlcpy(routeripstr, router_ip_str,
                                sizeof(router_ip_str));
		else
			routeripstr[0] = '\0';
	}

	if (filename) {
		if (corename_specified)
			strlcpy(filename, corename_str, 
                                sizeof(corename_str));
		else 
			filename[0] = '\0';

	}

	if (port) 
		*port = panicd_port;

	if (flags) {
		*flags = 0;
                if (!panicd_specified) 
			*flags |= KDP_DUMPINFO_DISABLE;
                else if (kdp_flag & PANIC_LOG_DUMP)
			*flags |= KDP_DUMPINFO_PANICLOG;
		else
			*flags |= KDP_DUMPINFO_CORE;

		if (noresume_on_disconnect)
			*flags |= KDP_DUMPINFO_NORESUME;
	}
}


/* Primary dispatch routine for the system dump */
void 
kdp_panic_dump(void)
{
	char coreprefix[10];
	int panic_error;

	uint64_t        abstime;
	uint32_t	current_ip = ntohl((uint32_t)kdp_current_ip_address);

	if (flag_panic_dump_in_progress) {
		kdb_printf("System dump aborted.\n");
		goto panic_dump_exit;
	}
		
	printf("Entering system dump routine\n");

	if (!kdp_en_recv_pkt || !kdp_en_send_pkt) {
			kdb_printf("Error: No transport device registered for kernel crashdump\n");
			return;
	}

	if (!panicd_specified) {
		kdb_printf("A dump server was not specified in the boot-args, terminating kernel core dump.\n");
		goto panic_dump_exit;
	}

	flag_panic_dump_in_progress = TRUE;

	if (pkt.input)
		kdp_panic("kdp_panic_dump: unexpected pending input packet");

	kdp_get_xnu_version((char *) &pkt.data[0]);

        if (!corename_specified) {
            /* Panic log bit takes precedence over core dump bit */
            if ((panicstr != (char *) 0) && (kdp_flag & PANIC_LOG_DUMP))
		strlcpy(coreprefix, "paniclog", sizeof(coreprefix));
            else if (kdp_flag & SYSTEM_LOG_DUMP) 
		strlcpy(coreprefix, "systemlog", sizeof(coreprefix));
	    else
		strlcpy(coreprefix, "core", sizeof(coreprefix));
  
            abstime = mach_absolute_time();
	    pkt.data[20] = '\0';
	    snprintf (corename_str, sizeof(corename_str), "%s-%s-%d.%d.%d.%d-%x", 
		      coreprefix, &pkt.data[0],
		      (current_ip & 0xff000000) >> 24,
		      (current_ip & 0xff0000) >> 16,
		      (current_ip & 0xff00) >> 8,
		      (current_ip & 0xff),
		      (unsigned int) (abstime & 0xffffffff));
        }

	if (0 == inet_aton(panicd_ip_str, (struct in_addr *) &panic_server_ip)) {
		kdb_printf("inet_aton() failed interpreting %s as a panic server IP\n", panicd_ip_str);
	}
	else
		kdb_printf("Attempting connection to panic server configured at IP %s, port %d\n", panicd_ip_str, panicd_port);

	destination_mac = router_mac;

	if (kdp_arp_resolve(panic_server_ip, &temp_mac)) {
		kdb_printf("Resolved %s's (or proxy's) link level address\n", panicd_ip_str);
		destination_mac = temp_mac;
	}
	else {
		if (!flag_panic_dump_in_progress) goto panic_dump_exit;
		if (router_specified) {
			if (0 == inet_aton(router_ip_str, (struct in_addr *) &parsed_router_ip))
				kdb_printf("inet_aton() failed interpreting %s as an IP\n", router_ip_str);
			else {
				router_ip = parsed_router_ip;
				if (kdp_arp_resolve(router_ip, &temp_mac)) {
					destination_mac = temp_mac;
					kdb_printf("Routing through specified router IP %s (%d)\n", router_ip_str, router_ip);
				}
			}
		}
	}

	if (!flag_panic_dump_in_progress) goto panic_dump_exit;

	kdb_printf("Transmitting packets to link level address: %02x:%02x:%02x:%02x:%02x:%02x\n",
	    destination_mac.ether_addr_octet[0] & 0xff,
	    destination_mac.ether_addr_octet[1] & 0xff,
	    destination_mac.ether_addr_octet[2] & 0xff,
	    destination_mac.ether_addr_octet[3] & 0xff,
	    destination_mac.ether_addr_octet[4] & 0xff,
	    destination_mac.ether_addr_octet[5] & 0xff);

	kdb_printf("Kernel map size is %llu\n", (unsigned long long) get_vmmap_size(kernel_map));
	kdb_printf("Sending write request for %s\n", corename_str);  

	if ((panic_error = kdp_send_crashdump_pkt(KDP_WRQ, corename_str, 0 , NULL)) < 0) {
		kdb_printf ("kdp_send_crashdump_pkt failed with error %d\n", panic_error);
		goto panic_dump_exit;
	}

	/* Just the panic log requested */
	if ((panicstr != (char *) 0) && (kdp_flag & PANIC_LOG_DUMP)) {
		kdb_printf_unbuffered("Transmitting panic log, please wait: ");
		kdp_send_crashdump_data(KDP_DATA, corename_str, 
					debug_buf_ptr - debug_buf,
					debug_buf);
		kdp_send_crashdump_pkt (KDP_EOF, NULL, 0, ((void *) 0));
		printf("Please file a bug report on this panic, if possible.\n");
		goto panic_dump_exit;
	}
  
	/* maybe we wanted the systemlog */
        if (kdp_flag & SYSTEM_LOG_DUMP) {
		long start_off = msgbufp->msg_bufx;
                long len;

		kdb_printf_unbuffered("Transmitting system log, please wait: ");
		if (start_off >= msgbufp->msg_bufr) {
			len = msgbufp->msg_size - start_off;
			kdp_send_crashdump_data(KDP_DATA, corename_str, len, 
						msgbufp->msg_bufc + start_off);
			/* seek to remove trailing bytes */
			kdp_send_crashdump_seek(corename_str, len);
			start_off  = 0;
		}

		if (start_off != msgbufp->msg_bufr) {
			len = msgbufp->msg_bufr - start_off;
			kdp_send_crashdump_data(KDP_DATA, corename_str, len,
						msgbufp->msg_bufc + start_off);
		}

		kdp_send_crashdump_pkt (KDP_EOF, NULL, 0, ((void *) 0));
		goto panic_dump_exit;
        }

	/* We want a core dump if we're here */
	kern_dump();

panic_dump_exit:
	abort_panic_transfer();
	kdp_reset();
	return;
}

void 
abort_panic_transfer(void)
{
	flag_panic_dump_in_progress = FALSE;
	flag_dont_abort_panic_dump  = FALSE;
	panic_block = 0;
}

#if CONFIG_SERIAL_KDP

static boolean_t needs_serial_init = TRUE;

static void
kdp_serial_send(void *rpkt, unsigned int rpkt_len)
{
	//	printf("tx\n");
	kdp_serialize_packet((unsigned char *)rpkt, rpkt_len, pal_serial_putc);
}

static void 
kdp_serial_receive(void *rpkt, unsigned int *rpkt_len, unsigned int timeout)
{
	int readkar;
	uint64_t now, deadline;
	
	clock_interval_to_deadline(timeout, 1000 * 1000 /* milliseconds */, &deadline);

//	printf("rx\n");
	for(clock_get_uptime(&now); now < deadline; clock_get_uptime(&now))
	{
		readkar = pal_serial_getc();
		if(readkar >= 0)
		{
			unsigned char *packet;
			//			printf("got char %02x\n", readkar);
			if((packet = kdp_unserialize_packet(readkar,rpkt_len)))
			{
				memcpy(rpkt, packet, *rpkt_len);
				return;
			}
		}
	}
	*rpkt_len = 0;
}

static boolean_t
kdp_serial_setmode(boolean_t active)
{
        if (active == FALSE) /* leaving KDP */
            return TRUE;

	if (!needs_serial_init)
            return TRUE;

        pal_serial_init();
        needs_serial_init = FALSE;
        return TRUE;
}


static void kdp_serial_callout(__unused void *arg, kdp_event_t event)
{
    /* When we stop KDP, set the bit to re-initialize the console serial port
     * the next time we send/receive a KDP packet.  We don't do it on
     * KDP_EVENT_ENTER directly because it also gets called when we trap to KDP
     * for non-external debugging, i.e., stackshot or core dumps.
     *
     * Set needs_serial_init on exit (and initialization, see above) and not
     * enter because enter is sent multiple times and causes excess reinitialization.
     */
	
    switch (event)
    {
		case KDP_EVENT_PANICLOG:
		case KDP_EVENT_ENTER:
			break;
		case KDP_EVENT_EXIT:
			needs_serial_init = TRUE;
			break;
    }
}

#endif /* CONFIG_SERIAL_KDP */

void
kdp_init(void)
{
	strlcpy(kdp_kernelversion_string, version, sizeof(kdp_kernelversion_string));

	/* Relies on platform layer calling panic_init() before kdp_init() */
	if (kernel_uuid[0] != '\0') {
		/*
		 * Update kdp_kernelversion_string with our UUID
		 * generated at link time.
		 */

		strlcat(kdp_kernelversion_string, "; UUID=", sizeof(kdp_kernelversion_string));
		strlcat(kdp_kernelversion_string, kernel_uuid, sizeof(kdp_kernelversion_string));
	}

#if defined(__x86_64__) || defined(__arm__)
	debug_log_init();

	if (vm_kernel_slide) {
		char	KASLR_stext[19];
		strlcat(kdp_kernelversion_string, "; stext=", sizeof(kdp_kernelversion_string));
		snprintf(KASLR_stext, sizeof(KASLR_stext), "%p", (void *) vm_kernel_stext);
		strlcat(kdp_kernelversion_string, KASLR_stext, sizeof(kdp_kernelversion_string));
	}
#endif

	if (debug_boot_arg & DB_REBOOT_POST_CORE)
		kdp_flag |= REBOOT_POST_CORE;
#if	defined(__x86_64__)	
	kdp_machine_init();
#endif

	kdp_timer_callout_init();
	kdp_crashdump_feature_mask = htonl(kdp_crashdump_feature_mask);

#if CONFIG_SERIAL_KDP
	char kdpname[80];
	struct in_addr ipaddr;
	struct ether_addr macaddr;


#if CONFIG_EMBEDDED
	//serial will be the debugger, unless match name is explicitly provided, and it's not "serial"
	if(PE_parse_boot_argn("kdp_match_name", kdpname, sizeof(kdpname)) && strncmp(kdpname, "serial", sizeof(kdpname)) != 0)
		return;
#else
	// serial must be explicitly requested
	if(!PE_parse_boot_argn("kdp_match_name", kdpname, sizeof(kdpname)) || strncmp(kdpname, "serial", sizeof(kdpname)) != 0)
		return;
#endif
	
	kprintf("Initializing serial KDP\n");

	kdp_register_callout(kdp_serial_callout, NULL);
        kdp_register_link(NULL, kdp_serial_setmode);
	kdp_register_send_receive(kdp_serial_send, kdp_serial_receive);
	
	/* fake up an ip and mac for early serial debugging */
	macaddr.ether_addr_octet[0] = 's';
	macaddr.ether_addr_octet[1] = 'e';
	macaddr.ether_addr_octet[2] = 'r';
	macaddr.ether_addr_octet[3] = 'i';
	macaddr.ether_addr_octet[4] = 'a';
	macaddr.ether_addr_octet[5] = 'l';
	ipaddr.s_addr = KDP_SERIAL_IPADDR;
	kdp_set_ip_and_mac_addresses(&ipaddr, &macaddr);
        
#endif /* CONFIG_SERIAL_KDP */
}
