/*	$KAME: mip6.h,v 1.8 2000/03/18 03:05:39 itojun Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _NETINET6_MIP6_H_
#define _NETINET6_MIP6_H_

#include <netinet6/nd6.h>
#include <netinet/icmp6.h>

struct ifnet;

/*
 * Definition For Mobile Internet Protocol Version 6.
 * Draft draft-ietf-mobileip-ipv6-09.txt
 */

/* Definition of MIPv6 states for the Event-State machine */
#define MIP6_STATE_UNDEF      0x01
#define MIP6_STATE_HOME       0x02
#define MIP6_STATE_DEREG      0x03
#define MIP6_STATE_NOTREG     0x04
#define MIP6_STATE_REG        0x05
#define MIP6_STATE_REREG      0x06
#define MIP6_STATE_REGNEWCOA  0x07


/* Definition of states used by the move detection algorithm used by MIPv6. */
#define MIP6_MD_BOOT       0x01
#define MIP6_MD_UNDEFINED  0x02
#define MIP6_MD_HOME       0x03
#define MIP6_MD_FOREIGN    0x04


/* Definition of Home Address route states used by the move detection
   algorithm used by MIPv6. */
#define MIP6_ROUTE_NET     0x01
#define MIP6_ROUTE_HOST    0x02


/* Type of node calling mip6_tunnel */
#define MIP6_NODE_MN    0x01
#define MIP6_NODE_HA    0x02


/* Movement Detection default values */
#define MIP6_MAX_LOST_ADVINTS   3


/* Scope for hook activation */
#define MIP6_GENERIC_HOOKS     0x01
#define MIP6_SPECIFIC_HOOKS    0x02
#define MIP6_CONFIG_HOOKS      0x03


/* Definition of states for tunnels set up by the Home Agent and the MN. */
#define MIP6_TUNNEL_ADD   0
#define MIP6_TUNNEL_MOVE  1
#define MIP6_TUNNEL_DEL   2


/* Definition of length for different destination options */
#define IP6OPT_BULEN       8   /* Length of BU option */
#define IP6OPT_BALEN      11   /* Length of BA option */
#define IP6OPT_BRLEN       0   /* Length of BR option */
#define IP6OPT_HALEN      16   /* Length of HA option */
#define IP6OPT_UIDLEN      2   /* Length of Unique Identifier sub-option */
#define IP6OPT_HALISTLEN  16   /* Length of HA List sub-ption */
#define IP6OPT_COALEN     16   /* Length of Alternate COA sub-option */


/* Definition of minimum length of MIPv6 destination options.
   Length includes option Type and Length. */
#define IP6OPT_BAMINLEN  (IP6OPT_MINLEN + IP6OPT_BALEN)
#define IP6OPT_BRMINLEN  (IP6OPT_MINLEN + IP6OPT_BRLEN)
#define IP6OPT_BUMINLEN  (IP6OPT_MINLEN + IP6OPT_BULEN)
#define IP6OPT_HAMINLEN  (IP6OPT_MINLEN + IP6OPT_HALEN)


/* Definition of sub-options used by the Destination Options */
#define IP6SUBOPT_UNIQUEID  0x02   /* Unique Identifier (BU, BR) */
#define IP6SUBOPT_HALIST    0x03   /* Home Agents List (BA) */
#define IP6SUBOPT_ALTCOA    0x04   /* Alternate COA (BU) */


/* Definition of MIPv6 Binding Update option flags */
#define MIP6_BU_AFLAG       0x80   /* BU Acknowledgement flag present */
#define MIP6_BU_HFLAG       0x40   /* BU Home Registration flag present */
#define MIP6_BU_RFLAG       0x20   /* BU MN is Router flag present */


/* Definition of flags used for indication of options present in a
   destination header (mip6_indata->optflag) */
#define MIP6_DSTOPT_BU      0x80   /* BU Option present */
#define MIP6_DSTOPT_BA      0x40   /* BA Option present */
#define MIP6_DSTOPT_BR      0x20   /* BR Option present */
#define MIP6_DSTOPT_HA      0x10   /* HA Option present */
#define MIP6_DSTOPT_UID     0x08   /* Sub-option Unique Id present */
#define MIP6_DSTOPT_COA     0x04   /* Sub-option Alternate COA present */
#define MIP6_DSTOPT_HAL     0x02   /* Sub-option HAs List present */


#if 0
/* Definition of flags for Home Agent */
#define ND_RA_FLAG_HA         0x20  /* RA indicates that router works as HA */
#define ND_OPT_PI_FLAG_RADDR  0x20  /* Prefix Information option incl. global
                                       IP address */
#endif


/* Definition of timers for signals */
#define MIP6_BU_LIFETIME         600  /* Lifetime for BU (s) */
#define MIP6_BU_LIFETIME_DEFRTR   60  /* Lifetime for BU sent to previous def
                                         router (s) */
#define MIP6_BU_LIFETIME_DHAAD    16  /* Lifetime for BU when Dynamic Home
                                         Agent Address Discovery (s) */
#define MIP6_MAX_FAST_UPDATES      5  /* Max number of fast updates (BUs)
                                         being sent */
#define MIP6_MAX_UPDATE_RATE       1  /* Rate limiting for sending successive
                                         fast BUs (sec) */
#define MIP6_SLOW_UPDATE_RATE     10  /* Rate limiting for sending successive
                                         slow BUs (sec) */
#define MIP6_MAX_BINDACK_TIMEOUT 256  /* Max time to wait for a BA */
#define MIP6_MAX_ADVERT_REXMIT     3  /* Max retransmission of NA when retur-
                                         ning to home link */
#define MIP6_OUTQ_LIFETIME        20  /* Max number of 0.1s units that an entry
                                         is stored in the output queue */
#define MIP6_OUTQ_INTERVAL         5  /* Interval in units of 0.1s that the out
                                         queue is searched */


/* Definition of Binding Acknowledgement status field */
#define MIP6_BA_STATUS_ACCEPT         0  /* Binding Update accepted */
#define MIP6_BA_STATUS_UNSPEC       128  /* Reason unspecified */
#define MIP6_BA_STATUS_PROHIBIT     130  /* Administratively prohibited */
#define MIP6_BA_STATUS_RESOURCE     131  /* Insufficient resources */
#define MIP6_BA_STATUS_HOMEREGNOSUP 132  /* Home registration not supported */
#define MIP6_BA_STATUS_SUBNET       133  /* Not home subnet */
#define MIP6_BA_STATUS_DHAAD        135  /* Dynamic home agent address
                                            discovery response */
#define MIP6_BA_STATUS_IFLEN        136  /* Incorrect interface id length */
#define MIP6_BA_STATUS_NOTHA        137  /* Not home agent for this MN */


/* Macro for modulo 2^^16 comparison */
#define MIP6_LEQ(a,b)   ((int16_t)((a)-(b)) <= 0)


/* Macros started with MIP6_ADDR is Mobile IPv6 local */
#define MIP6_ADDR_ANYCAST_HA   0x7e

#if BYTE_ORDER == BIG_ENDIAN
#define MIP6_ADDR_INT32_ULL	0xfe800000  /* Unicast Link Local */
#define MIP6_ADDR_INT32_USL	0xfec00000  /* Unicast Site Local */
#define MIP6_ADDR_INT32_AHA1	0xfffffffe  /* Anycast Home Agent bit 97-128 */
#define MIP6_ADDR_INT32_AHA2	0xfdffffff  /* Anycast Home Agent bit 65-96  */
#elif BYTE_ORDER == LITTLE_ENDIAN
#define MIP6_ADDR_INT32_ULL	0x000080fe
#define MIP6_ADDR_INT32_USL	0x0000c0fe
#define MIP6_ADDR_INT32_AHA1	0xfeffffff
#define MIP6_ADDR_INT32_AHA2	0xfffffffd
#endif


/* Definition of some useful macros to handle IP6 addresses */
extern struct in6_addr in6addr_linklocal;
extern struct in6_addr in6addr_sitelocal;
extern struct in6_addr in6addr_aha_64;     /* 64 bits identifier */
extern struct in6_addr in6addr_aha_nn;     /* 121-nn bits identifier */


/* Definition of states for flag in queue for outgoing packets. */
enum send_state {NOT_SENT, SENT};


/* Definition of event-state machine type. */
enum esm_type {PERMANENT, TEMPORARY};


/* Configuration parameters needed for MIPv6. Controlled by the user */
struct mip6_static_addr {
    LIST_ENTRY(mip6_static_addr)	addr_entry;	/* Next IPv6 address list */
    struct ifnet      *ifp;	        /* Interface */
    u_int8_t           prefix_len;	/* Prefix length for address */
    struct in6_addr    ip6_addr;	/* Address to be used at foreign network */
};


/*
 * fna_list          List of pre-assigned care-of addresses to be used at
 *                   foreign networks that the MN might visit
 * bu_lifetime       Used by the MN when sending a BU to the CN if it wants
 *                   to use a smaller value than received in the home
 *                   registration acknowledgement
 * br_update         Indicates when the CN sends a BR to the MN. The value
 *                   should be given as percentage of the bu_lifetime
 * ha_pref           Preference for the Home Agent
 * hr_lifetime       Default life time for home registration (only sent to the
 *                   Home Agent)
 * fwd_sl_unicast    Enable forwarding of site local unicast dest addresses
 * fwd_sl_multicast  Enable forwarding of site local multicast dest addresses
 * enable_prom_mode  Enable link layer promiscus mode (used by move detection)
 * enable_bu_to_cn   Enable BU being sent to the CN (Route optimization on/off)
 * enable_rev_tunnel Enable tunneling of packets from MN to CN via Home Agent
 * enable_br         Enable sending BR to the MN
 * autoconfig        Only enable MIP6 if the mip6 deamon is running
 * eager_md          Enable eager Movement Detection
 * enable_outq       Enable reading from the MIP6 output queue for piggy
 *                   backing (Not configurable, handled internally)
 */
struct mip6_config {
    LIST_HEAD(fna_list, mip6_static_addr)  fna_list;
    u_int32_t  bu_lifetime;
    u_int8_t   br_update;
    int16_t    ha_pref;
    u_int32_t  hr_lifetime;
    u_int8_t   fwd_sl_unicast;
    u_int8_t   fwd_sl_multicast;
    u_int8_t   enable_prom_mode;
    u_int8_t   enable_bu_to_cn;
    u_int8_t   enable_rev_tunnel;
    u_int8_t   enable_br;
    u_int8_t   autoconfig;
    u_int8_t   eager_md;
    u_int8_t   enable_outq;
};


/* Generic option format */
struct mip6_bu_data {
    u_int8_t  prefix_len;  /* Prefix length for a Home Address */
    u_int8_t  ack;	       /* Acknowledgement flag */
};


/* Generic option format */
struct mip6_opt {
    u_int8_t  type;   /* Option type */
    u_int8_t  len;    /* Option length (octets) excl. type and length */
} __attribute__ ((packed));


/* List of prefixes extracted from Router Advertisments being sent by
   the Home Agent. */
struct mip6_prefix {
    struct mip6_prefix *next;	    /* Ptr to next entry in the list */
    struct ifnet       *ifp;        /* Outgoing interface */
    struct in6_addr     prefix;     /* Announced prefix (on-link) */
    u_int8_t            prefix_len; /* Prefix length for IP address */
    u_int32_t           valid_time; /* Remaining (s) until prefix expires */
} __attribute__ ((packed));


/* Binding Update destination option format */
struct mip6_opt_bu {
    u_int8_t    type;        /* Option type */
    u_int8_t    len;         /* Option length excluding Type and length */
    u_int8_t    flags;       /* Flags (A, H and R) */
    u_int8_t    prefix_len;  /* Prefix length for IP address */
    u_int16_t   seqno;       /* Sequence number */
    u_int32_t   lifetime;    /* Seconds remaining until the binding expires */
} __attribute__ ((packed));


/* Binding Acknowledgement destination option format */
struct mip6_opt_ba {
    u_int8_t   type;      /* Option type */
    u_int8_t   len;       /* Option length (octets) excl. type and length */
    u_int8_t   status;    /* Result of the BU */
    u_int16_t  seqno;     /* Sequence number */
    u_int32_t  lifetime;  /* Granted lifetime (s) for the BU in the BC */
    u_int32_t  refresh;   /* Interval for MN to send BU to refresh BC */
} __attribute__ ((packed));


/* Binding Request destination option format */
struct mip6_opt_br {
    u_int8_t   type;   /* Option type */
    u_int8_t   len;    /* Option length (octets) excl. type and length */
} __attribute__ ((packed));


/* Home Address option format */
struct mip6_opt_ha {
    u_int8_t        type;       /* Option type */
    u_int8_t        len;        /* Option length excl. type and length */
    struct in6_addr home_addr;  /* Home Addr of the MN sending the packet */
} __attribute__ ((packed));


/* Unique Identifier sub-option format */
struct mip6_subopt_id {
    u_int8_t   type;  /* Sub-option type */
    u_int8_t   len;   /* Sub-option length (octets) excl. type and length */
    u_int16_t  id;    /* Unique identifier */
} __attribute__ ((packed));


/* Home Agents list sub-option format */
struct mip6_subopt_hal {
    u_int8_t        type;      /* Sub-option type */
    u_int8_t        len;       /* Sub-option length excl. type and length */
    struct in6_addr halist[1]; /* List of HA's on the home link */
} __attribute__ ((packed));


/* Alternate Care-of Address sub-option format */
struct mip6_subopt_coa {
    u_int8_t        type; /* Sub-option type */
    u_int8_t        len;  /* Length (octets) excl. type and len fields */
    struct in6_addr coa;  /* Alternate COA */
} __attribute__ ((packed));


/* Buffer for storing a consequtive sequence of sub-options */
struct mip6_subbuf {
    u_int16_t len;          /* # of used bytes in buffer */
    char      buffer[512];
};


/* The event-state machine must be maintained for each Home Address. */
struct mip6_dad {
    struct mip6_subopt_hal  *hal;   /* Home Agents list */
    int                      index; /* Next entry in list to try */
};

struct mip6_hafn {
    time_t           time;       /* Absolute expire time */
    int16_t          pref;       /* Preference for this HA */
    u_int8_t         prefix_len; /* Prefix_len for HA Address */
    struct in6_addr  addr;       /* FN Home Agent global unicast address */
};

struct mip6_esm {
    struct mip6_esm  *next;       /* Ptr to next entry in the list */
    struct ifnet     *ifp;        /* I/f where home address is applied */
    const struct encaptab *ep;	  /* Encapsulation attach (MN -> HA) */
    int               state;      /* State for the home address */
    enum esm_type     type;       /* Type of event-state machine */
    struct in6_addr   home_addr;  /* Home address */
    u_int8_t          prefix_len; /* Prefix_len for Home Address */
    u_int16_t         lifetime;   /* if type=PERMANENT 0xFFFF, else x */
    struct in6_addr   ha_hn;      /* Home agent address (home network) */
    struct in6_addr   coa;        /* Current primary care-of address */
    struct mip6_hafn *ha_fn;      /* Home agent address (foreign network) */
    struct mip6_dad  *dad;        /* For Dynamic HA Address Discovery */
};


/* Binding Cache parameters. Bindings for other IPv6 nodes. */
/* Maintained by each node. */
struct bc_info {
    u_int32_t  br_interval;    /* % of mip6_lifetime, max 60s, min 2s */
    u_int8_t   no_of_sent_br;  /* Number of sent BR to a Mobile Node */
    u_int8_t   max_advert;     /* ? */
    u_int8_t   ra_tunneled;    /* RA being tunneled to MN */
    u_int8_t   ra_interval;    /* Interval for sending RA */
};

struct mip6_bc {
    struct mip6_bc  *next;        /* Ptr to next entry in the list */
    struct in6_addr  home_addr;	  /* Home Address of the MN for which this is
                                     the BC entry */
    struct in6_addr  coa;         /* COA for MN indicated by the HA field */
    u_int32_t        lifetime;	  /* Remaining lifetime for this BC entry */
    u_int8_t         hr_flag;     /* Flag for home registration entry (T/F) */
    u_int8_t         rtr_flag;    /* MN is a router (T/F) */
    u_int8_t         prefix_len;  /* Prefix length in last received BU */
    u_int16_t        seqno;       /* Maximum value of the sequence number */
    struct bc_info   info;        /* Usage info for cache replacement policy */
    time_t           lasttime;    /* The time at which a BR was last sent */
    const struct encaptab *ep;	  /* Encapsulation attach (HA -> MN) */
};



/* Binding Update List parameters. Information for each BU sent by this MN */
/* Each MN maintains this list. */
struct mip6_retrans {
    struct mip6_opt_bu  *bu_opt;     /* BU option in case of retransmission */
    struct mip6_subbuf  *bu_subopt;  /* BU sub-option in case of retrans. */
    u_int8_t             ba_timeout; /* Exponential back-off starting at 1 */
    u_int8_t             time_left;  /* Time left until next retransmission */
};

struct mip6_bul {
    struct mip6_bul     *next;          /* Ptr to next entry in the list */
    struct in6_addr      dst_addr;      /* Destination address for sent BU */
    struct in6_addr      bind_addr;     /* Home Address or previous COA */
    struct in6_addr      coa;           /* Care-of address sent in the BU */
    u_int32_t            lifetime;      /* Remaining binding lifetime */
    u_int32_t            refreshtime;   /* Refresh time for the BU */
    u_int16_t            seqno;         /* Last value for sent seq number */
    time_t               lasttime;      /* Time at which a BU was last sent */
    u_int32_t            no_of_sent_bu; /* Number of sent BU to a MN */
    struct mip6_retrans *state;         /* Status for BU being acknowledged */
    u_int8_t             bu_flag;       /* Flag for sending future BU (T/F) */
    u_int8_t             hr_flag;       /* Flag for home reg (True / False) */
    u_int8_t             update_rate;   /* Seconds between consequtive BUs */
};


/* Home Agent List parameters. Information about each other HA on the link
   that this node is serving as a HA. One HA list for each link it is
   serving. */
/* Each HA maintains this list. */
struct mip6_addr_list {
    struct mip6_addr_list *next;       /* Ptr to next entry in the list */
    struct in6_addr        ip6_addr;   /* IPv6 address */
    u_int8_t               prefix_len;
};

struct mip6_ha_list {
    struct mip6_ha_list   *next;       /* Ptr to next entry in the list */
    struct in6_addr        ll_addr;    /* Link-local IP-addr of a node on
                                          the home link */
    u_int16_t              lifetime;   /* Remaining lifetime of this HA
                                          list entry */
    int16_t                pref;       /* Preference for this HA */
    struct mip6_addr_list *addr_list;  /* List of global IP addresses for
                                          this HA */
};

struct mip6_link_list {
    struct mip6_link_list  *next;     /* Ptr to next entry in the list */
    struct mip6_ha_list    *ha_list;  /* List of Home Agents for the link */
    struct ifnet           *ifp;      /* Interface */
    char   ifname[IFNAMSIZ+1];        /* Link identifier */
};


/* Neighbor Advertisement information stored for retransmission when the
   Mobile Node is returning to its Home Network or the Home Agent is
   requested to act as a proxy for the Mobile Node when it is moving to a
   Foreign Network. */
struct mip6_na
{
    struct mip6_na   *next;         /* Ptr to next entry in the list */
    struct ifnet     *ifp;          /* Interface for sending the NA */
    struct in6_addr   home_addr;    /* Home address of the mobile node */
    struct in6_addr   dst_addr;     /* Destination address */
    struct in6_addr   target_addr;  /* Target address */
    u_int8_t          prefix_len;   /* Prefix length for home address */
    u_long            flags;        /* Flags for the NA message */
    int               use_link_opt; /* Include Target link layer address
                                       option or not
                                       (0 = Do not include, 1 = Include) */
    int               no;           /* Remaining no of times to send the NA */
};


/* Definition of global variable used by Mobile IPv6. All variables are
   stored in node byte order. */
struct mip6_indata {
    u_int8_t                flag;     /* How to handle tunneled packets */
    u_int8_t                optflag;  /* Dest options and sub-options flag */
    struct in6_addr         ip6_src;  /* Orig src addr from IPv6 header */
    struct in6_addr         ip6_dst;  /* Orig dst addr from IPv6 header */
    struct mip6_opt_bu     *bu_opt;   /* BU option present */
    struct mip6_opt_ba     *ba_opt;   /* BA option present */
    struct mip6_opt_br     *br_opt;   /* BR option present */
    struct mip6_opt_ha     *ha_opt;   /* HA option present */
    struct mip6_subopt_id  *uid;      /* Sub-option Unique ID present */
    struct mip6_subopt_coa *coa;      /* Sub-option alt coa present */
    struct mip6_subopt_hal *hal;      /* Sub-option HAs List present */
};


/* Queue of outgoing packets that are waiting to be sent. */
struct mip6_output {
    struct mip6_output *next;     /* Ptr to next option in chain */
    void               *opt;      /* BU, BA or BR dest option to be sent */
    struct mip6_subbuf *subopt;   /* Sub-option to be sent (if present) */
    struct in6_addr     ip6_dst;  /* Destination address for IPv6 packet */
    struct in6_addr     ip6_src;  /* Source address for IPv6 packet */
    enum send_state     flag;     /* Has packet been sent or not? */
    u_int32_t           lifetime; /* Time remaining for entry in output queue
                                     (units of 0.1s) */
};

#ifdef KERNEL

/*
 * Macro MIP6_FREEINDATA free memory allocated for the global variable
 * mip6_inp and its members. Set the variable to point at NULL when
 * the memory has been freed.
 */
#define MIP6_FREEINDATA				\
do {						\
    if (mip6_inp != NULL) {			\
	if (mip6_inp->bu_opt != NULL)		\
	    _FREE(mip6_inp->bu_opt, M_TEMP);	\
	if (mip6_inp->ba_opt != NULL)		\
	    _FREE(mip6_inp->ba_opt, M_TEMP);	\
	if (mip6_inp->br_opt != NULL)		\
	    _FREE(mip6_inp->br_opt, M_TEMP);	\
	if (mip6_inp->ha_opt != NULL)		\
	    _FREE(mip6_inp->ha_opt, M_TEMP);	\
	if (mip6_inp->uid != NULL)		\
	    _FREE(mip6_inp->uid, M_TEMP);	\
	if (mip6_inp->coa != NULL)		\
	    _FREE(mip6_inp->coa, M_TEMP);	\
	if (mip6_inp->hal != NULL)		\
	    _FREE(mip6_inp->hal, M_TEMP);	\
	_FREE(mip6_inp, M_TEMP);			\
	mip6_inp = NULL;			\
    }						\
} while (0)

#define MIP6_IS_MN_ACTIVE ((mip6_module & MIP6_MN_MODULE) == MIP6_MN_MODULE)
#define MIP6_IS_HA_ACTIVE ((mip6_module & MIP6_HA_MODULE) == MIP6_HA_MODULE)


/* External Declaration of Global variables. */
extern struct mip6_indata  *mip6_inp;     /* Input data rec in one packet */
extern struct mip6_output  *mip6_outq;    /* Ptr to output queue */
extern struct mip6_esm     *mip6_esmq;    /* Ptr to list of Home Addresses */
extern struct mip6_bc      *mip6_bcq;     /* First entry in the BC list */
extern struct mip6_prefix  *mip6_pq;      /* First entry in prefix list */
extern struct mip6_config  mip6_config;   /* Config parameters for MIP6 */
extern struct mip6_bul        *mip6_bulq;
extern struct mip6_link_list  *mip6_llq;
extern struct nd_prefix *mip6_home_prefix;
extern struct nd_prefix *mip6_primary_prefix;

extern u_int8_t mip6_module;           /* Info about loaded modules (MN/HA) */
extern int      mip6_md_state;         /* Movement Detection state */
extern int      mip6_route_state;      /* Home Address route state */
extern int      mip6_max_lost_advints; /* No. lost Adv before start of NUD */
extern int      mip6_nd6_delay;
extern int      mip6_nd6_umaxtries;


/* External declaration of function prototypes (mip6_io.c) */
extern int mip6_new_packet
	__P((struct mbuf *));
extern int mip6_store_dstopt_pre
	__P((struct mbuf *, u_int8_t *, u_int8_t, u_int8_t));
extern int mip6_store_dstopt
	__P((struct mbuf *, u_int8_t *, u_int8_t));
extern int mip6_store_dstsubopt
	__P((struct mbuf *, u_int8_t *, u_int8_t, int, int));
extern int mip6_output
	__P((struct mbuf *, struct ip6_pktopts **));
extern int mip6_add_rh
	__P((struct ip6_pktopts **, struct mip6_bc *));
extern void mip6_align
	__P((struct ip6_dest *, int *));
extern void mip6_dest_offset
	__P((struct ip6_dest *, int *));
extern int mip6_add_ha
	__P((struct ip6_dest **, int *, struct in6_addr *, struct in6_addr *));
extern int mip6_add_bu
	__P((struct ip6_dest **, int *, struct mip6_opt_bu *,
	     struct mip6_subbuf *));
extern int mip6_add_ba
	__P((struct ip6_dest **, int *, struct mip6_opt_ba *,
	     struct mip6_subbuf *));
extern int mip6_add_br
	__P((struct ip6_dest **, int *, struct mip6_opt_br *,
	     struct mip6_subbuf *));
extern int mip6_store_subopt
	__P((struct mip6_subbuf **, caddr_t));


/* External declaration of function prototypes (mip6.c) */
extern void mip6_init
	__P((void));
extern void mip6_exit
	__P((void));
extern int mip6_rec_ctrl_sig
	__P((struct mbuf *, int));
extern int mip6_icmp6_input
	__P((struct mbuf *, int));
extern int mip6_rec_bu
	__P((struct mbuf *, int));
extern void mip6_ha2srcaddr
	__P((struct mbuf *));
extern int mip6_send_ba
	__P((struct in6_addr *, struct in6_addr *, struct in6_addr *,
	     struct mip6_subbuf *, u_int8_t, u_int16_t, u_int32_t));
extern void mip6_send_na
	__P((struct mip6_na *));
extern struct mbuf *mip6_create_ip6hdr
	__P((struct in6_addr *, struct in6_addr *, u_int8_t));
extern struct ip6_rthdr  *mip6_create_rh
	__P((struct in6_addr *, u_int8_t));
extern struct mip6_opt_ba *mip6_create_ba
	__P((u_int8_t, u_int16_t, u_int32_t));
extern struct ip6_dest  *mip6_create_dh
	__P((void *, struct mip6_subbuf *, u_int8_t));
extern int mip6_opt_offset
	__P((struct mbuf *, int, int));
extern int mip6_addr_on_link
	__P((struct in6_addr *, int));
extern u_int32_t mip6_min_lifetime
	__P((struct in6_addr *, int));
extern void mip6_build_in6addr
	__P((struct in6_addr *, struct in6_addr *, const struct in6_addr *,
	     int));
extern void mip6_build_ha_anycast
	__P((struct in6_addr *, const struct in6_addr *, int));
extern int mip6_add_ifaddr
	__P((struct in6_addr *addr, struct ifnet *ifp, int plen, int flags));
extern int mip6_tunnel_output
	__P((struct mbuf **, struct mip6_bc *));
extern int mip6_tunnel_input
	__P((struct mbuf **, int *, int));
extern int mip6_tunnel
	__P((struct in6_addr *, struct in6_addr *, int, int, void *));
extern int mip6_proxy
	__P((struct in6_addr*, struct in6_addr*, int));
extern struct mip6_bc *mip6_bc_find
	__P((struct in6_addr *));
extern struct mip6_bc *mip6_bc_create
	__P((struct in6_addr *, struct in6_addr *, u_int32_t, u_int8_t,
        u_int8_t, u_int8_t, u_int16_t));
extern void mip6_bc_update
	__P((struct mip6_bc *, struct in6_addr *, u_int32_t, u_int8_t,
	     u_int8_t, u_int8_t, u_int16_t, struct bc_info, time_t));
extern int mip6_bc_delete
	__P((struct mip6_bc *, struct mip6_bc **));
extern struct mip6_na *mip6_na_create
	__P((struct in6_addr *, struct in6_addr *, struct in6_addr *,
	     u_int8_t, u_long, int));
extern struct mip6_na *mip6_na_delete
	__P((struct mip6_na *));
extern struct mip6_prefix *mip6_prefix_find
	__P((struct in6_addr *, u_int8_t));
extern struct mip6_prefix *mip6_prefix_create
	__P((struct ifnet *, struct in6_addr *, u_int8_t, u_int32_t));
extern struct mip6_prefix *mip6_prefix_delete
	__P((struct mip6_prefix *));
extern void mip6_timer_na
	__P((void *));
extern void mip6_timer_bc
	__P((void *));
extern void mip6_timer_prefix
	__P((void *));

#if !defined(__bsdi__) && !(defined(__FreeBSD__) && __FreeBSD__ < 3)
extern int mip6_ioctl __P((struct socket *, u_long, caddr_t, struct ifnet *,
			   struct proc *));
#else
extern int mip6_ioctl __P((struct socket *, u_long, caddr_t, struct ifnet *));
#endif

#if MIP6_DEBUG
void mip6_debug __P((char *, ...));
#endif

extern void mip6_enable_debug
	__P((int));
extern int mip6_write_config_data
	__P((u_long, caddr_t));
extern int mip6_clear_config_data
	__P((u_long, caddr_t));
extern int mip6_enable_func
	__P((u_long, caddr_t));


/* External declaration of function prototypes (mip6_md.c) */
extern void mip6_md_init
	__P((void));
extern void mip6_select_defrtr
	__P((void));
extern void mip6_prelist_update
	__P((struct nd_prefix *, struct nd_defrouter *));
extern void mip6_eager_md
	__P((int enable));
extern void mip6_expired_defrouter
	__P((struct nd_defrouter *dr));
extern void mip6_probe_defrouter
	__P((struct nd_defrouter *dr));
extern void mip6_probe_pfxrtrs
	__P((void));
extern void mip6_store_advint
	__P((struct nd_opt_advint *, struct nd_defrouter *));
extern int mip6_delete_ifaddr
	__P((struct in6_addr *addr, struct ifnet *ifp));
extern struct nd_prefix *mip6_get_home_prefix
	__P((void));
extern int mip6_get_md_state
	__P((void));
extern void mip6_md_exit
	__P((void));


/* External declaration of function prototypes (mip6_mn.c) */
extern void mip6_mn_init
	__P((void));
extern void mip6_mn_exit
	__P((void));
extern void mip6_new_defrtr
	__P((int, struct nd_prefix *, struct nd_prefix *,
	     struct nd_defrouter *));
extern int  mip6_rec_ba
	__P((struct mbuf *, int));
extern int  mip6_rec_br
	__P((struct mbuf *, int));
extern int mip6_rec_hal
	__P((struct in6_addr *, struct in6_addr *, struct mip6_subopt_hal *));
extern int mip6_rec_ramn
	__P((struct mbuf *, int));
extern int mip6_route_optimize
	__P((struct mbuf *));
extern int mip6_send_bu
	__P((struct mip6_bul *, struct mip6_bu_data *, struct mip6_subbuf *));
extern void mip6_send_bu2fn
	__P((struct in6_addr *, struct mip6_hafn *, struct in6_addr *,
        struct ifnet *, u_int32_t));
extern void mip6_update_cns
	__P((struct in6_addr *, struct in6_addr *, u_int8_t, u_int32_t));
extern void mip6_queue_bu
	__P((struct mip6_bul *, struct in6_addr *, struct in6_addr *,
	     u_int8_t, u_int32_t));
extern struct mip6_opt_bu *mip6_create_bu
	__P((u_int8_t, int, int, u_int16_t, u_int32_t));
extern void mip6_stop_bu
	__P((struct in6_addr *));
extern int mip6_ba_error
	__P((struct in6_addr *, struct in6_addr *, struct in6_addr *,
	     u_int8_t));
extern u_int32_t mip6_prefix_lifetime
	__P((struct in6_addr *));
extern struct mip6_retrans * mip6_create_retrans
	__P((struct mip6_bul *));
extern void mip6_clear_retrans
	__P((struct mip6_bul *));
extern struct mip6_bul *mip6_bul_find
	__P((struct in6_addr *, struct in6_addr *));
extern struct mip6_bul *mip6_bul_create
	__P((struct in6_addr *, struct in6_addr *, struct in6_addr *,
	     u_int32_t, u_int8_t));
extern struct mip6_bul *mip6_bul_delete
	__P((struct mip6_bul *));
extern struct mip6_esm *mip6_esm_find
	__P((struct in6_addr *));
extern struct mip6_esm *mip6_esm_create
	__P((struct ifnet *, struct in6_addr *, struct in6_addr *,
	     struct in6_addr *, u_int8_t, int, enum esm_type, u_int16_t));
extern struct mip6_esm *mip6_esm_delete
	__P((struct mip6_esm *));
extern int mip6_outq_create
	__P((void *, struct mip6_subbuf *, struct in6_addr *,
	     struct in6_addr *, enum send_state));
extern struct mip6_output *mip6_outq_delete
	__P((struct mip6_output *));
extern void mip6_outq_flush
	__P((void));
extern void mip6_timer_outqueue
	__P((void *));
extern void mip6_timer_bul
	__P((void *));
extern void mip6_timer_esm
	__P((void *));
extern int mip6_write_config_data_mn
	__P((u_long, void *));
extern int mip6_clear_config_data_mn
	__P((u_long, caddr_t));
extern int mip6_enable_func_mn
	__P((u_long, caddr_t));


/* External declaration of function prototypes (mip6_ha.c). */
extern void mip6_ha_init
	__P((void));
extern void mip6_ha_exit
	__P((void));
extern int mip6_rec_raha
	__P((struct mbuf *, int));
extern int mip6_ra_options
	__P((struct mip6_ha_list *, caddr_t, int));
extern struct mip6_subopt_hal * mip6_hal_dynamic
	__P((struct in6_addr *));
extern struct in6_addr *mip6_global_addr
	__P((struct in6_addr *));
extern void mip6_icmp6_output
	__P((struct mbuf *));
extern void mip6_prefix_examine
	__P((struct mip6_ha_list *, struct ifnet *, caddr_t, int));
extern struct mip6_link_list *mip6_ll_find
	__P((char *));
extern struct mip6_link_list *mip6_ll_create
	__P((char *, struct ifnet *));
extern struct mip6_link_list *mip6_ll_delete
	__P((struct mip6_link_list *));
extern struct mip6_ha_list *mip6_hal_find
	__P((struct mip6_ha_list *, struct in6_addr *));
extern struct mip6_ha_list *mip6_hal_create
	__P((struct mip6_ha_list **, struct in6_addr *, u_int32_t, int16_t));
extern void mip6_hal_sort
	__P((struct mip6_ha_list **));
extern struct mip6_ha_list *mip6_hal_delete
	__P((struct mip6_ha_list **, struct mip6_ha_list *));
extern void mip6_timer_ll
	__P((void *));
extern int mip6_write_config_data_ha
	__P((u_long, void *));
extern int mip6_clear_config_data_ha
	__P((u_long, void *));
extern int mip6_enable_func_ha
	__P((u_long, caddr_t));


/* External declaration of function prototypes (mip6_hooks.c). */
extern void mip6_minus_a_case
	__P((struct nd_prefix *));
extern struct nd_prefix *mip6_find_auto_home_addr
	__P((void));
extern void mip6_enable_hooks
	__P((int));
extern void mip6_disable_hooks
	__P((int));
extern int mip6_attach
	__P((int));
extern int mip6_release
	__P((void));


#if defined(__FreeBSD__) && __FreeBSD__ >= 3
extern struct callout_handle  mip6_timer_na_handle;
extern struct callout_handle  mip6_timer_bc_handle;
extern struct callout_handle  mip6_timer_outqueue_handle;
extern struct callout_handle  mip6_timer_bul_handle;
extern struct callout_handle  mip6_timer_esm_handle;
extern struct callout_handle  mip6_timer_prefix_handle;
extern struct callout_handle  mip6_timer_ll_handle;
#endif

#endif /* _KERNEL */

#endif /* not _NETINET6_MIP6_H_ */
