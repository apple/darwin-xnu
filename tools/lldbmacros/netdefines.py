def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    reverse = dict((value, key) for key, value in enums.iteritems())
    enums['reverse_mapping'] = reverse
    return type('Enum', (), enums)

Mbuf_Type = enum(
    'MT_FREE',
    'MT_DATA',
    'MT_HEADER',
    'MT_SOCKET',
    'MT_PCB',
    'MT_RTABLE',
    'MT_HTABLE',
    'MT_ATABLE',
    'MT_SONAME',
    'MT_SOOPTS',
    'MT_FTABLE',
    'MT_RIGHTS',
    'MT_IFADDR',
    'MT_CONTROL',
    'MT_OOBDATA',
    'MT_TAG',
    'MT_LAST')

M_EXT           = 0x0001
M_PKTHDR        = 0x0002
M_EOR           = 0x0004
M_PROTO1        = 0x0008
M_PROTO2        = 0x0010
M_PROTO3        = 0x0020
M_LOOP          = 0x0040
M_PROTO5        = 0x0080

M_BCAST         = 0x0100
M_MCAST         = 0x0200
M_FRAG          = 0x0400
M_FIRSTFRAG     = 0x0800
M_LASTFRAG      = 0x1000
M_PROMISC       = 0x2000
M_HASFCS        = 0x4000
M_TAGHDR        = 0x8000

dlil_if_flags_strings = ["DLIF_INUSE",
                         "DLIF_REUSE",
                         "DLIF_DEBUG"
                        ]

if_capenable_strings = ["RXCSUM",
                        "TXCSUM", 
                        "VLAN_MTU", 
                        "VLAN_HWTAGGING",
                        "JUMBO_MTU",
                        "TSO4",
                        "TSO6",
                        "LRO",
                        "AV",
                        "TXSTATUS",
                        "CHANNEL_IO",
                        "HW_TIMESTAMP",
                        "SW_TIMESTAMP",
                        "CSUM_PARTIAL",
                        "CSUM_ZERO_INVERT"
                       ]

if_flags_strings = ["UP",
                    "BROADCAST",
                    "DEBUG",
                    "LOOPBACK",
                    "POINTOPOINT",
                    "NOTRAILERS (deprecated)",
                    "RUNNING",
                    "NOARP",
                    "PROMISC",
                    "ALLMULTI",
                    "OACTIVE",
                    "SIMPLEX",
                    "LINK0",
                    "LINK1",
                    "LINK2-ALTPHYS",
                    "MULTICAST"
                    ]

if_refflags_strings = ["IFRF_EMBRYONIC",
                       "IFRF_ATTACHED",
                       "IFRF_DETACHING"
                      ]

if_eflags_strings = ["AUTOCONFIGURING",
                     "unused",
                     "unused",
                     "unused",
                     "unused",
                     "DVR_REENTRY_OK (deprecated)",
                     "ACCEPT_RTADV",
                     "TXSTART",
                     "RXPOLL",
                     "VLAN",
                     "BOND",
                     "ARPLL",
                     "NOWINDOWSCALE",
                     "NOAUTOIPV6LL",
                     "unused",
                     "IPV4_ROUTER",
                     "IPV6_ROUTER",
                     "LOCALNET_PRIVATE",
                     "IPV6_ND6ALT",
                     "RESTRICTED_RECV",
                     "AWDL",
                     "NOACKPRI",
                     "unused",
                     "unused",
                     "unused",
                     "unused",
                     "unused",
                     "unused",
                     "SENDLIST",
                     "REUSE (deprecated)",
                     "INUSE (deprecated)",
                     "UPDOWNCHANGE"
                     ]

AF_INET = 2
AF_INET6 = 30
AF_LINK = 18

INP_IPV4 = 0x1
INP_IPV6 = 0x2

CTRACE_STACK_SIZE = 8

IFMA_TRACE_HIST_SIZE = 32
RTD_TRACE_HIST_SIZE = 4
INIFA_TRACE_HIST_SIZE = 32
IN6IFA_TRACE_HIST_SIZE = 32
INM_TRACE_HIST_SIZE = 32
IF_REF_TRACE_HIST_SIZE = 8
NDPR_TRACE_HIST_SIZE = 32
NDDR_TRACE_HIST_SIZE = 32
IMO_TRACE_HIST_SIZE = 32
IM6O_TRACE_HIST_SIZE = 32

INP_RECVOPTS       =       0x01
INP_RECVRETOPTS    =       0x02
INP_RECVDSTADDR    =       0x04
INP_HDRINCL        =       0x08
INP_HIGHPORT       =       0x10
INP_LOWPORT        =       0x20
INP_ANONPORT       =       0x40
INP_RECVIF         =       0x80
INP_MTUDISC        =       0x100
INP_STRIPHDR       =       0x200
INP_RECV_ANYIF     =       0x400
INP_INADDR_ANY     =       0x800
INP_RECVTTL        =       0x1000
INP_UDP_NOCKSUM    =       0x2000
INP_BOUND_IF       =       0x4000
IN6P_IPV6_V6ONLY   =       0x008000
IN6P_PKTINFO       =       0x010000
IN6P_HOPLIMIT      =       0x020000
IN6P_HOPOPTS       =       0x040000
IN6P_DSTOPTS       =       0x080000
IN6P_RTHDR         =       0x100000
IN6P_RTHDRDSTOPTS  =       0x200000
IN6P_TCLASS        =       0x400000
IN6P_AUTOFLOWLABEL =       0x800000
IN6P_BINDV6ONLY    =       0x10000000
IN6P_RFC2292       =       0x02000000
IN6P_MTU           =       0x04000000
INP_PKTINFO        =       0x08000000
INP_FLOW_SUSPENDED =       0x10000000
INP_NO_IFT_CELLULAR =      0x20000000
INP_FLOW_CONTROLLED =      0x40000000
INP_FC_FEEDBACK    =       0x80000000
INPCB_STATE_INUSE  =       0x1
INPCB_STATE_CACHED =       0x2
INPCB_STATE_DEAD   =       0x3

INP2_TIMEWAIT      =       0x00000001
INP2_IN_FCTREE     =       0x00000002
INP2_WANT_APP_POLICY =    0x00000004

N_TIME_WAIT_SLOTS = 128
