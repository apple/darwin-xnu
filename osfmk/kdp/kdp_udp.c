/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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
#include <mach/exception_types.h>
#include <mach/mach_types.h>
#include <kern/cpu_data.h>
#include <kern/debug.h>

#include <kdp/kdp_internal.h>
#include <kdp/kdp_en_debugger.h>
#include <kdp/kdp_udp.h>

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
int		udp_ttl=UDP_TTL;
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

static char
*exception_message[] = {
    "Unknown",
    "Memory access",		/* EXC_BAD_ACCESS */
    "Failed instruction",	/* EXC_BAD_INSTRUCTION */
    "Arithmetic",		/* EXC_ARITHMETIC */
    "Emulation",		/* EXC_EMULATION */
    "Software",			/* EXC_SOFTWARE */
    "Breakpoint"		/* EXC_BREAKPOINT */
};

int kdp_flag = 0;

static kdp_send_t kdp_en_send_pkt = 0;
static kdp_receive_t kdp_en_recv_pkt = 0;


static unsigned int kdp_current_ip_address = 0;
static struct ether_addr kdp_current_mac_address = {{0, 0, 0, 0, 0, 0}};
static char kdp_arp_init = 0;

static void kdp_handler( void	*);

void
kdp_register_send_receive(
	kdp_send_t		send, 
	kdp_receive_t	receive)
{
	unsigned int	debug;

	kdp_en_send_pkt = send;
	kdp_en_recv_pkt = receive;
	debug_log_init();
	PE_parse_boot_arg("debug", &debug);
	if (debug & DB_KDP_BP_DIS)
		kdp_flag |= KDP_BP_DIS;   

	kdp_flag |= KDP_READY;
	if (current_debugger == NO_CUR_DB)
		current_debugger = KDP_CUR_DB;
	if (halt_in_debugger) {
		kdp_call(); 
		halt_in_debugger=0;
	}
}

void
kdp_unregister_send_receive(
	kdp_send_t		send, 
	kdp_receive_t	receive)
{
	if (current_debugger == KDP_CUR_DB)
		current_debugger = NO_CUR_DB;
	kdp_flag &= ~KDP_READY;
	kdp_en_send_pkt = NULL;
	kdp_en_recv_pkt = NULL;
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
    struct ip			aligned_ip, *ip = &aligned_ip;
    struct in_addr		tmp_ipaddr;
    struct ether_addr		tmp_enaddr;
    struct ether_header		*eh;
    
    if (!pkt.input)
	kdp_panic("kdp_reply");
	
    pkt.off -= sizeof (struct udpiphdr);

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
    
    pkt.len += sizeof (struct udpiphdr);
    
    pkt.off -= sizeof (struct ether_header);
    
    eh = (struct ether_header *)&pkt.data[pkt.off];
    enaddr_copy(&adr.loc.ea, eh->ether_shost);
    enaddr_copy(&adr.rmt.ea, eh->ether_dhost);
    eh->ether_type = htons(ETHERTYPE_IP);
    
    pkt.len += sizeof (struct ether_header);
    (*kdp_en_send_pkt)(&pkt.data[pkt.off], pkt.len);
}


void 
kdp_set_ip_and_mac_addresses(
	struct in_addr		*ipaddr, 
	struct ether_addr	*macaddr)
{
	unsigned int debug = 0;

	kdp_current_ip_address = ipaddr->s_addr;
	kdp_current_mac_address = *macaddr;

	/* Get the debug boot-arg to decide if ARP replies are allowed */
	if (kdp_arp_init == 0) {
		PE_parse_boot_arg("debug", &debug);
		if (debug & DB_ARP)
			kdp_flag |= KDP_ARP;
		kdp_arp_init = 1;
	}
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

/* ARP responses are enabled when the DB_ARP bit of the debug boot arg
   is set. A workaround if you don't want to reboot is to set 
   kdpDEBUGFlag &= DB_ARP when connected (but that certainly isn't a published
   interface!)
*/

static void 
kdp_arp_reply(void)
{
	struct ether_header	*eh;
	struct ether_arp		aligned_ea, *ea = &aligned_ea;

	struct in_addr 		isaddr, itaddr, myaddr;
	struct ether_addr		my_enaddr;

	eh = (struct ether_header *)&pkt.data[pkt.off];
	pkt.off += sizeof(struct ether_header);

	 memcpy((void *)ea, (void *)&pkt.data[pkt.off],sizeof(*ea));
  
	 if(ntohs(ea->arp_op) != ARPOP_REQUEST)
		return;

	myaddr.s_addr = kdp_get_ip_address();
	my_enaddr = kdp_get_mac_addr();

	if (!(myaddr.s_addr) || !(my_enaddr.ether_addr_octet[1]))
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
  struct ether_header	*eh;
  struct udpiphdr		aligned_ui, *ui = &aligned_ui;
  struct ip				aligned_ip, *ip = &aligned_ip;
  static int			msg_printed;


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
		kdp_arp_reply();
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
	return;
    }
	
    if (!kdp.is_conn) {
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
    unsigned short	reply_port;
    boolean_t kdp_call_kdb();
    struct ether_addr	kdp_mac_addr = kdp_get_mac_addr();
    unsigned int ip_addr = kdp_get_ip_address();

	printf( "ethernet MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
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
            
    printf("\nWaiting for remote debugger connection.\n");

    if (reattach_wait == 0)
      {
#ifdef MACH_PE
	if( 0 != kdp_getc())
#endif
	  {
	    printf("Options.....    Type\n");
	    printf("------------    ----\n");
	    printf("continue....    'c'\n");
	    printf("reboot......    'r'\n");
#if MACH_KDB
	    printf("enter kdb...    'k'\n");
#endif
	  }
      }
    else
      reattach_wait = 0;
    
    exception_seq = 0;
    do {
	kdp_hdr_t aligned_hdr, *hdr = &aligned_hdr;
	
	while (!pkt.input) {
	    int c;
	    c = kdp_getc();
	    switch(c) {
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
	    kdp_poll();
	}

	// check for sequence number of 0
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
	    if (hdr->request == KDP_REATTACH)
	      {
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
 again:
    if (!kdp.is_conn)
	kdp_connection_wait();
    else
      {
	kdp_send_exception(exception, code, subcode);
	if (kdp.exception_ack_needed)
	  {
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

    kdp_sync_cache();

    if (reattach_wait == 1)
      goto again;

    enable_preemption();
}

void
kdp_reset(void)
{
	kdp.reply_port = kdp.exception_port = 0;
	kdp.is_halted = kdp.is_conn = FALSE;
	kdp.exception_seq = kdp.conn_seq = 0;
}

