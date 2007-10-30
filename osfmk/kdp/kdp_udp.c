/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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

#include <mach_kdb.h>
#include <mach/boolean.h>
#include <mach/mach_types.h>
#include <mach/exception_types.h>
#include <kern/cpu_data.h>
#include <kern/debug.h>

#include <kdp/kdp_core.h>
#include <kdp/kdp_internal.h>
#include <kdp/kdp_en_debugger.h>
#include <kdp/kdp_udp.h>

#include <vm/vm_map.h>
#include <vm/vm_protos.h>
#include <vm/vm_kern.h> /* kernel_map */

#include <mach/memory_object_types.h>

#include <string.h>

#define DO_ALIGN	1	/* align all packet data accesses */

extern int kdp_getc(void);
extern int reattach_wait;

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

static kdp_send_t kdp_en_send_pkt;
static kdp_receive_t kdp_en_recv_pkt;


static u_long kdp_current_ip_address = 0;
static struct ether_addr kdp_current_mac_address = {{0, 0, 0, 0, 0, 0}};
static void *kdp_current_ifp;

static void kdp_handler( void *);

static uint32_t panic_server_ip = 0; 
static uint32_t parsed_router_ip = 0;
static uint32_t router_ip = 0;
static uint32_t target_ip = 0;

static volatile boolean_t panicd_specified = FALSE;
static boolean_t router_specified = FALSE;
static unsigned int panicd_port = CORE_REMOTE_PORT;

static struct ether_addr etherbroadcastaddr = {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};

static struct ether_addr router_mac = {{0, 0, 0 , 0, 0, 0}};
static struct ether_addr destination_mac = {{0, 0, 0 , 0, 0, 0}};
static struct ether_addr temp_mac = {{0, 0, 0 , 0, 0, 0}};
static struct ether_addr current_resolved_MAC = {{0, 0, 0 , 0, 0, 0}};

static boolean_t flag_panic_dump_in_progress = FALSE;
static boolean_t flag_router_mac_initialized = FALSE;

static boolean_t flag_arp_resolved = FALSE;

static unsigned int panic_timeout = 100000;
static unsigned int last_panic_port = CORE_REMOTE_PORT;

unsigned int SEGSIZE = 512;

__unused static unsigned int PANIC_PKTSIZE = 518;
static char panicd_ip_str[20];
static char router_ip_str[20];

static unsigned int panic_block = 0;
volatile unsigned int kdp_trigger_core_dump = 0;
__private_extern__ volatile unsigned int flag_kdp_trigger_reboot = 0;

extern unsigned int not_in_kdp;

extern unsigned int disableConsoleOutput;

extern int 		kdp_vm_read( caddr_t, caddr_t, unsigned int);
extern void 		kdp_call(void);
extern boolean_t 	kdp_call_kdb(void);
extern int 		kern_dump(void);

void *	kdp_get_interface(void);
void 	kdp_set_gateway_mac(void *);
void 	kdp_set_ip_and_mac_addresses(struct in_addr *, struct ether_addr *);
void 	kdp_set_interface(void *);

void 			kdp_disable_arp(void);
static void 		kdp_arp_reply(struct ether_arp *);
static void 		kdp_process_arp_reply(struct ether_arp *);
static boolean_t 	kdp_arp_resolve(uint32_t, struct ether_addr *);

static volatile unsigned	kdp_reentry_deadline;

static boolean_t	gKDPDebug = FALSE;
#define KDP_DEBUG(...) if (gKDPDebug) printf(__VA_ARGS__);

int kdp_snapshot = 0;
static int stack_snapshot_ret = 0;
static unsigned stack_snapshot_bytes_traced = 0;

static void *stack_snapshot_buf;
static uint32_t stack_snapshot_bufsize;
static int stack_snapshot_pid;
static uint32_t stack_snapshot_options;

static unsigned int old_debugger;

void
kdp_snapshot_preflight(int pid, void * tracebuf, uint32_t tracebuf_size,
    uint32_t options);

void
kdp_snapshot_postflight(void);

extern int
kdp_stackshot(int pid, void *tracebuf, uint32_t tracebuf_size,
    unsigned trace_options, uint32_t *pbytesTraced);

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


void
kdp_register_send_receive(
	kdp_send_t	send, 
	kdp_receive_t	receive)
{
	unsigned int	debug = 0;

	kdp_en_send_pkt = send;
	kdp_en_recv_pkt = receive;

	debug_log_init();

	kdp_timer_callout_init();

	PE_parse_boot_arg("debug", &debug);


	if (!debug)
		return;

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

	if (PE_parse_boot_arg ("_panicd_ip", panicd_ip_str))
		panicd_specified = TRUE;

	if (PE_parse_boot_arg ("_router_ip", router_ip_str))
		router_specified = TRUE;

	if (!PE_parse_boot_arg ("panicd_port", &panicd_port))
		panicd_port = CORE_REMOTE_PORT;

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
	kdp_en_send_pkt = NULL;
	kdp_en_recv_pkt = NULL;
}

/* Cache stack snapshot parameters in preparation for a trace */
void
kdp_snapshot_preflight(int pid, void * tracebuf, uint32_t tracebuf_size, uint32_t options)
{
	stack_snapshot_pid = pid;
	stack_snapshot_buf = tracebuf;
	stack_snapshot_bufsize = tracebuf_size;
	stack_snapshot_options = options;
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
	unsigned short		reply_port
	)
{
	struct udpiphdr		aligned_ui, *ui = &aligned_ui;
	struct ip		aligned_ip, *ip = &aligned_ip;
	struct in_addr		tmp_ipaddr;
	struct ether_addr	tmp_enaddr;
	struct ether_header	*eh = NULL;
    
	if (!pkt.input)
		kdp_panic("kdp_reply");
	
	pkt.off -= sizeof (struct udpiphdr);

#if DO_ALIGN    
	bcopy((char *)&pkt.data[pkt.off], (char *)ui, sizeof(*ui));
#else
	ui = (struct udpiphdr *)&pkt.data[pkt.off];
#endif
	ui->ui_next = ui->ui_prev = NULL;
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
    
	pkt.len += sizeof (struct udpiphdr);
    
	pkt.off -= sizeof (struct ether_header);
    
	eh = (struct ether_header *)&pkt.data[pkt.off];
	enaddr_copy(eh->ether_shost, &tmp_enaddr);
	enaddr_copy(eh->ether_dhost, eh->ether_shost);
	enaddr_copy(&tmp_enaddr, eh->ether_dhost);
	eh->ether_type = htons(ETHERTYPE_IP);
    
	pkt.len += sizeof (struct ether_header);
    
	// save reply for possible retransmission
	bcopy((char *)&pkt, (char *)&saved_reply, sizeof(pkt));

	(*kdp_en_send_pkt)(&pkt.data[pkt.off], pkt.len);

	// increment expected sequence number
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

    pkt.off -= sizeof (struct udpiphdr);

#if DO_ALIGN
    bcopy((char *)&pkt.data[pkt.off], (char *)ui, sizeof(*ui));
#else
    ui = (struct udpiphdr *)&pkt.data[pkt.off];
#endif
    ui->ui_next = ui->ui_prev = NULL;
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
    
    pkt.len += sizeof (struct udpiphdr);
    
    pkt.off -= sizeof (struct ether_header);
    
    eh = (struct ether_header *)&pkt.data[pkt.off];
    enaddr_copy(&adr.loc.ea, eh->ether_shost);
    enaddr_copy(&adr.rmt.ea, eh->ether_dhost);
    eh->ether_type = htons(ETHERTYPE_IP);
    
    pkt.len += sizeof (struct ether_header);
    (*kdp_en_send_pkt)(&pkt.data[pkt.off], pkt.len);
}

/* We don't interpret this pointer, we just give it to the
bsd stack so it can decide when to set the MAC and IP info. */
void
kdp_set_interface(void *ifp)
{
	kdp_current_ifp = ifp;
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
	kdp_current_ip_address = ipaddr->s_addr;
	kdp_current_mac_address = *macaddr;
	if ((current_debugger == KDP_CUR_DB) && halt_in_debugger) {
		kdp_call();
		halt_in_debugger=0;
	}
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
  return kdp_current_ip_address;
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

	arp_header_offset = sizeof(struct ether_header) + pkt.off;
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
	pkt.off += sizeof(struct ether_header);

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
		pkt.off -= sizeof (struct ether_header);
		/* pkt.len is still the length we want, ether_header+ether_arp */
		(*kdp_en_send_pkt)(&pkt.data[pkt.off], pkt.len);
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
	(*kdp_en_recv_pkt)(pkt.data, &pkt.len, 3/* ms */);

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

	pkt.off += sizeof (struct ether_header);
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

	pkt.off += sizeof (struct udpiphdr);
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
	 * enter the debugger.
	 */
	else
		if (flag_panic_dump_in_progress)
		{
			abort_panic_transfer();
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
	pkt.len = ntohs((u_short)ui->ui_ulen) - sizeof (struct udphdr);
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
	(*kdp_en_send_pkt)(&pkt.data[pkt.off], pkt.len);
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
	    (*kdp_en_send_pkt)(&saved_reply.data[saved_reply.off],
			    saved_reply.len);
	    goto again;
	} else if (hdr->seq != exception_seq) {
	    printf("kdp: bad sequence %d (want %d)\n",
			hdr->seq, exception_seq);
	    goto again;
	}
	
	if (kdp_packet((unsigned char*)&pkt.data[pkt.off], 
			(int *)&pkt.len, 
			(unsigned short *)&reply_port)) {
	    kdp_reply(reply_port);
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
            
	printf("\nWaiting for remote debugger connection.\n");


	if (reattach_wait == 0) {
		if((kdp_flag & KDP_GETC_ENA) && (0 != kdp_getc()))
		{
			printf("Options.....    Type\n");
			printf("------------    ----\n");
			printf("continue....    'c'\n");
			printf("reboot......    'r'\n");
#if MACH_KDB
			printf("enter kdb...    'k'\n");
#endif
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
					kdp_reboot();
					break;
#if MACH_KDB
				case 'k':
					printf("calling kdb...\n");
					if (kdp_call_kdb())
						return;
					else
						printf("not implemented...\n");
#endif
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
			kdp_reboot();
			/* should not return! */
		}
		if (((hdr->request == KDP_CONNECT) || (hdr->request == KDP_REATTACH)) &&
			!hdr->is_reply && (hdr->seq == exception_seq)) {
		    if (kdp_packet((unsigned char *)&pkt.data[pkt.off], 
				(int *)&pkt.len, 
				(unsigned short *)&reply_port))
				kdp_reply(reply_port);
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

    /* Was a system trace requested ? */
    if (kdp_snapshot && (!panic_active()) && (panic_caller == 0)) {
	    stack_snapshot_ret = kdp_stackshot(stack_snapshot_pid,
	    stack_snapshot_buf, stack_snapshot_bufsize,
	    stack_snapshot_options, &stack_snapshot_bytes_traced);
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
     
    if (pkt.input)
	kdp_panic("kdp_raise_exception");

	    
    if (((kdp_flag & KDP_PANIC_DUMP_ENABLED) || (kdp_flag & PANIC_LOG_DUMP))
	&& (panicstr != (char *) 0)) {

	    kdp_panic_dump();
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
	kdp_flag &= ~PANIC_LOG_DUMP;
	kdp_flag |= KDP_PANIC_DUMP_ENABLED;
	kdp_panic_dump();
	kdp_trigger_core_dump = 0;
      }

/* Trigger a reboot if the user has set this flag through the
 * debugger.Ideally, this would be done through the HOSTREBOOT packet
 * in the protocol,but that will need gdb support,and when it's
 * available, it should work automatically.
 */
    if (1 == flag_kdp_trigger_reboot) {
	    kdp_reboot();
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
    enable_preemption();
}

void
kdp_reset(void)
{
	kdp.reply_port = kdp.exception_port = 0;
	kdp.is_halted = kdp.is_conn = FALSE;
	kdp.exception_seq = kdp.conn_seq = 0;
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
	char			modelen  = strlen(mode);

	pkt.off = sizeof (struct ether_header);
	pkt.len = length + ((request == KDP_WRQ) ? modelen : 0) + 
	    (corename ? strlen(corename): 0) + sizeof(struct corehdr);

#if DO_ALIGN
	bcopy((char *)&pkt.data[pkt.off], (char *)ui, sizeof(*ui));
#else
	ui = (struct udpiphdr *)&pkt.data[pkt.off];
#endif
	ui->ui_next = ui->ui_prev = NULL;
	ui->ui_x1 = 0;
	ui->ui_pr = IPPROTO_UDP;
	ui->ui_len = htons((u_short)pkt.len + sizeof (struct udphdr));
	ui->ui_src.s_addr = kdp_current_ip_address;
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
    
	pkt.len += sizeof (struct udpiphdr);

	pkt.off += sizeof (struct udpiphdr);
  
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
	}
	else
	{
		coreh->th_block = htonl((unsigned int) block);
	}

	pkt.off -= sizeof (struct udpiphdr);
	pkt.off -= sizeof (struct ether_header);

	eh = (struct ether_header *)&pkt.data[pkt.off];
	enaddr_copy(&kdp_current_mac_address, eh->ether_shost);
	enaddr_copy(&destination_mac, eh->ether_dhost);
	eh->ether_type = htons(ETHERTYPE_IP);
    
	pkt.len += sizeof (struct ether_header);
	return coreh;
}

int kdp_send_crashdump_data(unsigned int request, char *corename,
    unsigned int length, caddr_t txstart)
{
	caddr_t txend = txstart + length;
	int panic_error = 0;

	if (length <= SEGSIZE) {
		if ((panic_error = kdp_send_crashdump_pkt(request, corename, length, (caddr_t) txstart)) < 0) {
			printf ("kdp_send_crashdump_pkt failed with error %d\n", panic_error);
			return panic_error ;
		}
	}
	else
	{
		while (txstart <= (txend - SEGSIZE))  {
			if ((panic_error = kdp_send_crashdump_pkt(KDP_DATA, NULL, SEGSIZE, txstart)) < 0) {
				printf ("kdp_send_crashdump_pkt failed with error %d\n", panic_error);
				return panic_error;
			}
			txstart += SEGSIZE;
			if (!(panic_block % 2000))
				printf(".");
		}
		if (txstart < txend) {
			kdp_send_crashdump_pkt(request, corename, (txend - txstart), txstart);
		}
	}
	return 0;
}

int
kdp_send_crashdump_pkt(unsigned int request, char *corename, 
    unsigned int length, void *panic_data)
{
	struct corehdr *th = NULL;
	int poll_count = 2500;
  
	char rretries = 0, tretries = 0;

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
  
	th = create_panic_header(request, corename, length, panic_block);

	if (request == KDP_DATA) {
		if (!kdp_vm_read((caddr_t) panic_data, (caddr_t) th->th_data, length)) {
			memset ((caddr_t) th->th_data, 'X', length);
		}
	}
	else if (request == KDP_SEEK) {
		*(unsigned int *) th->th_data = htonl(*(unsigned int *) panic_data);
	}

	(*kdp_en_send_pkt)(&pkt.data[pkt.off], pkt.len);

	/* Listen for the ACK */
RECEIVE_RETRY:
	while (!pkt.input && flag_panic_dump_in_progress && poll_count) {
		kdp_poll();
		poll_count--;
	}

	if (pkt.input) {
    
		pkt.input = FALSE;
    
		th = (struct corehdr *) &pkt.data[pkt.off];
    
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
  
	panic_block++;
  
	if (request == KDP_EOF)
		printf("\nTotal number of packets transmitted: %d\n", panic_block);
  
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

extern char version[];

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
	if (version) {
		if (kdp_vm_read(version, versionbuf, 95)) {
			versionbuf[94] = '\0';
			versionpos = strnstr(versionbuf, "xnu-", 90);
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
	}
	strlcpy(versionbuf, vstr, KDP_MAXPACKET);
	return retval;
}

extern char *inet_aton(const char *cp, struct in_addr *pin);
extern int snprintf(char *str, size_t size, const char *format, ...);

/* Primary dispatch routine for the system dump */
void 
kdp_panic_dump(void)
{
	char corename[50];
	char coreprefix[10];
	int panic_error;

	uint64_t 	abstime;
	uint32_t	current_ip = ntohl(kdp_current_ip_address);

	if (flag_panic_dump_in_progress) {
		printf("System dump aborted.\n");
		goto panic_dump_exit;
	}
		
	printf("Entering system dump routine\n");
  
	if (!panicd_specified) {
		printf("A dump server was not specified in the boot-args, terminating kernel core dump.\n");
		goto panic_dump_exit;
	}

	flag_panic_dump_in_progress = TRUE;
	not_in_kdp = 0;

	if (pkt.input)
		kdp_panic("kdp_panic_dump: unexpected pending input packet");

	kdp_get_xnu_version((char *) &pkt.data[0]);

	/* Panic log bit takes precedence over core dump bit */
	if ((panicstr != (char *) 0) && (kdp_flag & PANIC_LOG_DUMP))
		strncpy(coreprefix, "paniclog", sizeof(coreprefix));
	else
		strncpy(coreprefix, "core", sizeof(coreprefix));
  
	abstime = mach_absolute_time();
	pkt.data[20] = '\0';
	snprintf (corename, sizeof(corename), "%s-%s-%d.%d.%d.%d-%x", 
	    coreprefix, &pkt.data[0],
	    (current_ip & 0xff000000) >> 24,
	    (current_ip & 0xff0000) >> 16,
	    (current_ip & 0xff00) >> 8,
	    (current_ip & 0xff),
	    (unsigned int) (abstime & 0xffffffff));

	if (0 == inet_aton(panicd_ip_str, (struct in_addr *) &panic_server_ip)) {
		printf("inet_aton() failed interpreting %s as a panic server IP\n", panicd_ip_str);
	}
	else
		printf("Attempting connection to panic server configured at IP %s, port %d\n", panicd_ip_str, panicd_port);

	destination_mac = router_mac;

	if (kdp_arp_resolve(panic_server_ip, &temp_mac)) {
		printf("Resolved %s's (or proxy's) link level address\n", panicd_ip_str);
		destination_mac = temp_mac;
	}
	else {
		if (!flag_panic_dump_in_progress) goto panic_dump_exit;
		if (router_specified) {
			if (0 == inet_aton(router_ip_str, (struct in_addr *) &parsed_router_ip))
				printf("inet_aton() failed interpreting %s as an IP\n", router_ip_str);
			else {
				router_ip = parsed_router_ip;
				if (kdp_arp_resolve(router_ip, &temp_mac)) {
					destination_mac = temp_mac;
					printf("Routing through specified router IP %s (%d)\n", router_ip_str, router_ip);
				}
			}
		}
	}

	if (!flag_panic_dump_in_progress) goto panic_dump_exit;

	printf("Transmitting packets to link level address: %02x:%02x:%02x:%02x:%02x:%02x\n",
	    destination_mac.ether_addr_octet[0] & 0xff,
	    destination_mac.ether_addr_octet[1] & 0xff,
	    destination_mac.ether_addr_octet[2] & 0xff,
	    destination_mac.ether_addr_octet[3] & 0xff,
	    destination_mac.ether_addr_octet[4] & 0xff,
	    destination_mac.ether_addr_octet[5] & 0xff);

	printf("Kernel map size is %llu\n", (unsigned long long) get_vmmap_size(kernel_map));
	printf("Sending write request for %s\n", corename);  

	if ((panic_error = kdp_send_crashdump_pkt(KDP_WRQ, corename, 0 , NULL)) < 0) {
		printf ("kdp_send_crashdump_pkt failed with error %d\n", panic_error);
		goto panic_dump_exit;
	}

	/* Just the panic log requested */
	if ((panicstr != (char *) 0) && (kdp_flag & PANIC_LOG_DUMP)) {
		printf("Transmitting panic log, please wait: ");
		kdp_send_crashdump_data(KDP_DATA, corename, (debug_buf_ptr - debug_buf), debug_buf);
		kdp_send_crashdump_pkt (KDP_EOF, NULL, 0, ((void *) 0));
		printf("Please file a bug report on this panic, if possible.\n");
		goto panic_dump_exit;
	}
  
	/* We want a core dump if we're here */
	kern_dump();
panic_dump_exit:
	abort_panic_transfer();
	pkt.input = FALSE;
	pkt.len = 0;
	kdp_reset();
	return;
}

void 
abort_panic_transfer(void)
{
	flag_panic_dump_in_progress = FALSE;
	not_in_kdp = 1;
	panic_block = 0;
}
