if_capenable_strings = ["RXCSUM",
                        "TXCSUM", 
                        "VLAN_MTU", 
                        "VLAN_HWTAGGING",
                        "JUMBO_MTU",
                        "TSO4",
                        "TSO6",
                        "LRO",
                        "AV",
                        "TXSTATUS"
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
INP2_WANT_FLOW_DIVERT =    0x00000004

N_TIME_WAIT_SLOTS = 128
