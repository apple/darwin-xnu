/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * Copyright (C) 1993-1997 by Darren Reed.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and due credit is given
 * to the original author and the contributors.
 *
 * @(#)ip_fil.h	1.35 6/5/96
 * $Id: ip_fil.h,v 1.3 2000/11/22 01:12:12 zarzycki Exp $
 */

#ifndef	__IP_FIL_H__
#define	__IP_FIL_H__

/*
 * Pathnames for various IP Filter control devices.  Used by LKM
 * and userland, so defined here.
 */
#define	IPNAT_NAME	"/dev/ipnat"
#define	IPSTATE_NAME	"/dev/ipstate"
#define	IPAUTH_NAME	"/dev/ipauth"

#ifndef	SOLARIS
#define	SOLARIS	(defined(sun) && (defined(__svr4__) || defined(__SVR4)))
#endif

#if defined(KERNEL) && !defined(_KERNEL)
#define	_KERNEL
#endif

#ifndef	__P
# if	__STDC__
#  define	__P(x)	x
# else
#  define	__P(x)	()
# endif
#endif

#if defined(__STDC__) || defined(__GNUC__)
#define	SIOCADAFR	_IOW('r', 60, struct frentry)
#define	SIOCRMAFR	_IOW('r', 61, struct frentry)
#define	SIOCSETFF	_IOW('r', 62, u_int)
#define	SIOCGETFF	_IOR('r', 63, u_int)
#define	SIOCGETFS	_IOR('r', 64, struct friostat)
#define	SIOCIPFFL	_IOWR('r', 65, int)
#define	SIOCIPFFB	_IOR('r', 66, int)
#define	SIOCADIFR	_IOW('r', 67, struct frentry)
#define	SIOCRMIFR	_IOW('r', 68, struct frentry)
#define	SIOCSWAPA	_IOR('r', 69, u_int)
#define	SIOCINAFR	_IOW('r', 70, struct frentry)
#define	SIOCINIFR	_IOW('r', 71, struct frentry)
#define	SIOCFRENB	_IOW('r', 72, u_int)
#define	SIOCFRSYN	_IOW('r', 73, u_int)
#define	SIOCFRZST	_IOWR('r', 74, struct friostat)
#define	SIOCZRLST	_IOWR('r', 75, struct frentry)
#define	SIOCAUTHW	_IOWR('r', 76, struct fr_info)
#define	SIOCAUTHR	_IOWR('r', 77, struct fr_info)
#define	SIOCATHST	_IOWR('r', 78, struct fr_authstat)
#else
#define	SIOCADAFR	_IOW(r, 60, struct frentry)
#define	SIOCRMAFR	_IOW(r, 61, struct frentry)
#define	SIOCSETFF	_IOW(r, 62, u_int)
#define	SIOCGETFF	_IOR(r, 63, u_int)
#define	SIOCGETFS	_IOR(r, 64, struct friostat)
#define	SIOCIPFFL	_IOWR(r, 65, int)
#define	SIOCIPFFB	_IOR(r, 66, int)
#define	SIOCADIFR	_IOW(r, 67, struct frentry)
#define	SIOCRMIFR	_IOW(r, 68, struct frentry)
#define	SIOCSWAPA	_IOR(r, 69, u_int)
#define	SIOCINAFR	_IOW(r, 70, struct frentry)
#define	SIOCINIFR	_IOW(r, 71, struct frentry)
#define SIOCFRENB	_IOW(r, 72, u_int)
#define	SIOCFRSYN	_IOW(r, 73, u_int)
#define	SIOCFRZST	_IOWR(r, 74, struct friostat)
#define	SIOCZRLST	_IOWR(r, 75, struct frentry)
#define	SIOCAUTHW	_IOWR(r, 76, struct fr_info)
#define	SIOCAUTHR	_IOWR(r, 77, struct fr_info)
#define	SIOCATHST	_IOWR(r, 78, struct fr_authstat)
#endif
#define	SIOCADDFR	SIOCADAFR
#define	SIOCDELFR	SIOCRMAFR
#define	SIOCINSFR	SIOCINAFR

typedef	struct	fr_ip	{
	u_int	fi_v:4;		/* IP version */
	u_int	fi_fl:4;	/* packet flags */
	u_char	fi_tos;
	u_char	fi_ttl;
	u_char	fi_p;
	struct	in_addr	fi_src;
	struct	in_addr	fi_dst;
	u_32_t	fi_optmsk;	/* bitmask composed from IP options */
	u_short	fi_secmsk;	/* bitmask composed from IP security options */
	u_short	fi_auth;
} fr_ip_t;

#define	FI_OPTIONS	(FF_OPTIONS >> 24)
#define	FI_TCPUDP	(FF_TCPUDP >> 24)	/* TCP/UCP implied comparison*/
#define	FI_FRAG		(FF_FRAG >> 24)
#define	FI_SHORT	(FF_SHORT >> 24)

typedef	struct	fr_info	{
	struct	fr_ip	fin_fi;
	u_short	fin_data[2];
	u_short	fin_out;
	u_short	fin_hlen;
	u_char	fin_tcpf;
	u_char	fin_icode;		/* From here on is packet specific */
	u_short	fin_rule;
	u_short	fin_group;
	u_short	fin_dlen;
	u_short	fin_id;
	void	*fin_ifp;
	struct	frentry *fin_fr;
	char	*fin_dp;		/* start of data past IP header */
	void	*fin_mp;
} fr_info_t;

/*
 * Size for compares on fr_info structures
 */
#define	FI_CSIZE	(sizeof(struct fr_ip) + sizeof(u_short) * 4 + \
			 sizeof(u_char))
/*
 * Size for copying cache fr_info structure
 */
#define	FI_COPYSIZE	(sizeof(fr_info_t) - sizeof(void *) * 2)

typedef	struct	frdest	{
	void	*fd_ifp;
	struct	in_addr	fd_ip;
	char	fd_ifname[IFNAMSIZ];
} frdest_t;

typedef	struct	frentry {
	struct	frentry	*fr_next;
	u_short	fr_group;	/* group to which this rule belongs */
	u_short	fr_grhead;	/* group # which this rule starts */
	struct	frentry	*fr_grp;
	int	fr_ref;		/* reference count - for grouping */
	void	*fr_ifa;
	/*
	 * These are only incremented when a packet  matches this rule and
	 * it is the last match
	 */
	U_QUAD_T	fr_hits;
	U_QUAD_T	fr_bytes;
	/*
	 * Fields after this may not change whilst in the kernel.
	 */
	struct	fr_ip	fr_ip;
	struct	fr_ip	fr_mip;	/* mask structure */

	u_char	fr_tcpfm;	/* tcp flags mask */
	u_char	fr_tcpf;	/* tcp flags */

	u_short	fr_icmpm;	/* data for ICMP packets (mask) */
	u_short	fr_icmp;

	u_char	fr_scmp;	/* data for port comparisons */
	u_char	fr_dcmp;
	u_short	fr_dport;
	u_short	fr_sport;
	u_short	fr_stop;	/* top port for <> and >< */
	u_short	fr_dtop;	/* top port for <> and >< */
	u_32_t	fr_flags;	/* per-rule flags && options (see below) */
	int	fr_skip;	/* # of rules to skip */
	int	(*fr_func) __P((int, ip_t *, fr_info_t *));	/* call this function */
	char	fr_icode;	/* return ICMP code */
	char	fr_ifname[IFNAMSIZ];
	struct	frdest	fr_tif;	/* "to" interface */
	struct	frdest	fr_dif;	/* duplicate packet interfaces */
} frentry_t;

#define	fr_proto	fr_ip.fi_p
#define	fr_ttl		fr_ip.fi_ttl
#define	fr_tos		fr_ip.fi_tos
#define	fr_dst		fr_ip.fi_dst
#define	fr_src		fr_ip.fi_src
#define	fr_dmsk		fr_mip.fi_dst
#define	fr_smsk		fr_mip.fi_src

#ifndef	offsetof
#define	offsetof(t,m)	(int)((&((t *)0L)->m))
#endif
#define	FR_CMPSIZ	(sizeof(struct frentry) - offsetof(frentry_t, fr_ip))

/*
 * fr_flags
 */
#define	FR_BLOCK	0x00001	/* do not allow packet to pass */
#define	FR_PASS		0x00002	/* allow packet to pass */
#define	FR_OUTQUE	0x00004	/* outgoing packets */
#define	FR_INQUE	0x00008	/* ingoing packets */
#define	FR_LOG		0x00010	/* Log */
#define	FR_LOGB		0x00011	/* Log-fail */
#define	FR_LOGP		0x00012	/* Log-pass */
#define	FR_LOGBODY	0x00020	/* Log the body */
#define	FR_LOGFIRST	0x00040	/* Log the first byte if state held */
#define	FR_RETRST	0x00080	/* Return TCP RST packet - reset connection */
#define	FR_RETICMP	0x00100	/* Return ICMP unreachable packet */
#define	FR_NOMATCH	0x00200	/* no match occured */
#define	FR_ACCOUNT	0x00400	/* count packet bytes */
#define	FR_KEEPFRAG	0x00800	/* keep fragment information */
#define	FR_KEEPSTATE	0x01000	/* keep `connection' state information */
#define	FR_INACTIVE	0x02000
#define	FR_QUICK	0x04000	/* match & stop processing list */
#define	FR_FASTROUTE	0x08000	/* bypass normal routing */
#define	FR_CALLNOW	0x10000	/* call another function (fr_func) if matches */
#define	FR_DUP		0x20000	/* duplicate packet */
#define	FR_LOGORBLOCK	0x40000	/* block the packet if it can't be logged */
#define	FR_NOTSRCIP	0x80000	/* not the src IP# */
#define	FR_NOTDSTIP	0x100000	/* not the dst IP# */
#define	FR_AUTH		0x200000	/* use authentication */
#define	FR_PREAUTH	0x400000	/* require preauthentication */

#define	FR_LOGMASK	(FR_LOG|FR_LOGP|FR_LOGB)

/*
 * These correspond to #define's for FI_* and are stored in fr_flags
 */
#define	FF_OPTIONS	0x01000000
#define	FF_TCPUDP	0x02000000
#define	FF_FRAG		0x04000000
#define	FF_SHORT	0x08000000
/*
 * recognized flags for SIOCGETFF and SIOCSETFF, and get put in fr_flags
 */
#define	FF_LOGPASS	0x10000000
#define	FF_LOGBLOCK	0x20000000
#define	FF_LOGNOMATCH	0x40000000
#define	FF_LOGGING	(FF_LOGPASS|FF_LOGBLOCK|FF_LOGNOMATCH)
#define	FF_BLOCKNONIP	0x80000000	/* Solaris2 Only */

#define	FR_NONE 0
#define	FR_EQUAL 1
#define	FR_NEQUAL 2
#define FR_LESST 3
#define FR_GREATERT 4
#define FR_LESSTE 5
#define FR_GREATERTE 6
#define	FR_OUTRANGE 7
#define	FR_INRANGE 8

typedef	struct	filterstats {
	u_long	fr_pass;	/* packets allowed */
	u_long	fr_block;	/* packets denied */
	u_long	fr_nom;		/* packets which don't match any rule */
	u_long	fr_ppkl;	/* packets allowed and logged */
	u_long	fr_bpkl;	/* packets denied and logged */
	u_long	fr_npkl;	/* packets unmatched and logged */
	u_long	fr_pkl;		/* packets logged */
	u_long	fr_skip;	/* packets to be logged but buffer full */
	u_long	fr_ret;		/* packets for which a return is sent */
	u_long	fr_acct;	/* packets for which counting was performed */
	u_long	fr_bnfr;	/* bad attempts to allocate fragment state */
	u_long	fr_nfr;		/* new fragment state kept */
	u_long	fr_cfr;		/* add new fragment state but complete pkt */
	u_long	fr_bads;	/* bad attempts to allocate packet state */
	u_long	fr_ads;		/* new packet state kept */
	u_long	fr_chit;	/* cached hit */
	u_long	fr_tcpbad;	/* TCP checksum check failures */
	u_long	fr_pull[2];	/* good and bad pullup attempts */
#if SOLARIS
	u_long	fr_bad;		/* bad IP packets to the filter */
	u_long	fr_notip;	/* packets passed through no on ip queue */
	u_long	fr_drop;	/* packets dropped - no info for them! */
#endif
} filterstats_t;

/*
 * For SIOCGETFS
 */
typedef	struct	friostat	{
	struct	filterstats	f_st[2];
	struct	frentry		*f_fin[2];
	struct	frentry		*f_fout[2];
	struct	frentry		*f_acctin[2];
	struct	frentry		*f_acctout[2];
	struct	frentry		*f_auth;
	u_long	f_froute[2];
	int	f_active;
} friostat_t;

typedef struct	optlist {
	u_short ol_val;
	int	ol_bit;
} optlist_t;


/*
 * Group list structure.
 */
typedef	struct frgroup {
	u_short	fg_num;
	struct	frgroup	*fg_next;
	struct	frentry	*fg_head;
	struct	frentry	**fg_start;
} frgroup_t;


/*
 * Log structure.  Each packet header logged is prepended by one of these.
 * Following this in the log records read from the device will be an ipflog
 * structure which is then followed by any packet data.
 */
typedef	struct	iplog	{
	u_long	ipl_magic;
	u_long	ipl_sec;
	u_long	ipl_usec;
	u_int	ipl_len;
	u_int	ipl_count;
	size_t	ipl_dsize;
	struct	iplog	*ipl_next;
} iplog_t;

#define IPL_MAGIC 0x49504c4d /* 'IPLM' */

typedef	struct	ipflog	{
#if (defined(NetBSD) && (NetBSD <= 1991011) && (NetBSD >= 199603)) || \
        (defined(OpenBSD) && (OpenBSD >= 199603))
	u_char	fl_ifname[IFNAMSIZ];
#else
	u_int	fl_unit;
	u_char	fl_ifname[4];
#endif
	u_char	fl_plen;	/* extra data after hlen */
	u_char	fl_hlen;	/* length of IP headers saved */
	u_short	fl_rule;	/* assume never more than 64k rules, total */
	u_short	fl_group;
	u_32_t	fl_flags;
} ipflog_t;


#ifndef	ICMP_UNREACH_FILTER
#define	ICMP_UNREACH_FILTER	13
#endif

#ifndef	IPF_LOGGING
#define	IPF_LOGGING	0
#endif
#ifndef	IPF_DEFAULT_PASS
#define	IPF_DEFAULT_PASS	FR_PASS
#endif

#define	IPMINLEN(i, h)	((i)->ip_len >= ((i)->ip_hl * 4 + sizeof(struct h)))
#define	IPLLOGSIZE	8192

/*
 * Device filenames for reading log information.  Use ipf on Solaris2 because
 * ipl is already a name used by something else.
 */
#ifndef	IPL_NAME
# if	SOLARIS
#  define	IPL_NAME	"/dev/ipf"
# else
#  define	IPL_NAME	"/dev/ipl"
# endif
#endif
#define	IPL_NAT		IPNAT_NAME
#define	IPL_STATE	IPSTATE_NAME
#define	IPL_AUTH	IPAUTH_NAME

#define	IPL_LOGIPF	0	/* Minor device #'s for accessing logs */
#define	IPL_LOGNAT	1
#define	IPL_LOGSTATE	2
#define	IPL_LOGAUTH	3
#define	IPL_LOGMAX	3

#if !defined(CDEV_MAJOR) && defined (__FreeBSD_version) && \
    (__FreeBSD_version >= 220000)
# define	CDEV_MAJOR	79
#endif

#ifndef	_KERNEL
struct ifnet;
extern	int	fr_check __P((ip_t *, int, void *, int, mb_t **));
extern	int	(*fr_checkp) __P((ip_t *, int, void *, int, mb_t **));
extern	int	send_reset __P((ip_t *, struct ifnet *));
extern	int	icmp_error __P((ip_t *, struct ifnet *));
extern	int	ipf_log __P((void));
extern	void	ipfr_fastroute __P((ip_t *, fr_info_t *, frdest_t *));
extern	struct	ifnet *get_unit __P((char *));
# define	FR_SCANLIST(p, ip, fi, m)	fr_scanlist(p, ip, fi, m)
# if defined(__NetBSD__) || defined(__OpenBSD__) || \
     (_BSDI_VERSION >= 199701) || (__FreeBSD_version >= 300003)
extern	int	iplioctl __P((dev_t, u_long, caddr_t, int));
# else
extern	int	iplioctl __P((dev_t, int, caddr_t, int));
# endif
extern	int	iplopen __P((dev_t, int));
extern	int	iplclose __P((dev_t, int));
#else /* #ifndef _KERNEL */
# if defined(__NetBSD__) && defined(PFIL_HOOKS)
extern	int	ipfilterattach __P((int));
# endif
extern	int	iplattach __P((void));
extern	int	ipl_enable __P((void));
extern	int	ipl_disable __P((void));
extern	void	ipflog_init __P((void));
extern	int	ipflog_clear __P((int));
extern	int	ipflog_read __P((int, struct uio *));
extern	int	ipflog __P((u_int, ip_t *, fr_info_t *, mb_t *));
extern	int	ipllog __P((int, u_long, void **, size_t *, int *, int));
# if	SOLARIS
extern	int	fr_check __P((ip_t *, int, void *, int, qif_t *, mb_t **));
extern	int	(*fr_checkp) __P((ip_t *, int, void *,
				  int, qif_t *, mb_t **));
extern	int	icmp_error __P((ip_t *, int, int, qif_t *,
				struct in_addr));
extern	int	iplioctl __P((dev_t, int, int, int, cred_t *, int *));
extern	int	iplopen __P((dev_t *, int, int, cred_t *));
extern	int	iplclose __P((dev_t, int, int, cred_t *));
extern	int	ipfsync __P((void));
extern	int	send_reset __P((ip_t *, qif_t *));
extern	int	ipfr_fastroute __P((qif_t *, ip_t *, mblk_t *, mblk_t **,
				   fr_info_t *, frdest_t *));
extern	void	copyin_mblk __P((mblk_t *, int, int, char *));
extern	void	copyout_mblk __P((mblk_t *, int, int, char *));
extern	int	fr_qin __P((queue_t *, mblk_t *));
extern	int	fr_qout __P((queue_t *, mblk_t *));
#  if	IPFILTER_LOG
extern	int	iplread __P((dev_t, struct uio *, cred_t *));
#  endif
# else /* SOLARIS */
extern	int	fr_check __P((ip_t *, int, void *, int, mb_t **));
extern	int	(*fr_checkp) __P((ip_t *, int, void *, int, mb_t **));
#  if	linux
extern	int	send_reset __P((tcpiphdr_t *, struct ifnet *));
#  else
extern	int	send_reset __P((tcpiphdr_t *));
#  endif
extern	void	ipfr_fastroute __P((mb_t *, fr_info_t *, frdest_t *));
extern	size_t	mbufchainlen __P((mb_t *));
#  if	__sgi
#   include <sys/cred.h>
extern	int	iplioctl __P((dev_t, int, caddr_t, int, cred_t *, int *));
extern	int	iplopen __P((dev_t *, int, int, cred_t *));
extern	int	iplclose __P((dev_t, int, int, cred_t *));
extern	int	iplread __P((dev_t, struct uio *, cred_t *));
extern	int	ipfsync __P((void));
extern	int	ipfilter_sgi_attach __P((void));
extern	void	ipfilter_sgi_detach __P((void));
extern	void	ipfilter_sgi_intfsync __P((void));
#  else
#   if	IPFILTER_LKM
extern	int	iplidentify __P((char *));
#   endif
#   if (_BSDI_VERSION >= 199510) || (__FreeBSD_version >= 220000) || \
      (NetBSD >= 199511)
#    if defined(__NetBSD__) || (_BSDI_VERSION >= 199701) || \
        (__FreeBSD_version >= 300003)
extern	int	iplioctl __P((dev_t, u_long, caddr_t, int, struct proc *));
#    else
extern	int	iplioctl __P((dev_t, int, caddr_t, int, struct proc *));
#    endif
extern	int	iplopen __P((dev_t, int, int, struct proc *));
extern	int	iplclose __P((dev_t, int, int, struct proc *));
#   else
#    if defined(__OpenBSD__)
extern	int	iplioctl __P((dev_t, u_long, caddr_t, int));
#    else /* __OpenBSD__ */
#     ifndef	linux
extern	int	iplioctl __P((dev_t, int, caddr_t, int));
#     else
extern	int	iplioctl(struct inode *, struct file *, u_int, u_long);
#     endif
#    endif /* __OpenBSD__ */
#    ifndef linux
extern	int	iplopen __P((dev_t, int));
extern	int	iplclose __P((dev_t, int));
#    else
extern	int	iplopen __P((struct inode *, struct file *));
extern	void	iplclose __P((struct inode *, struct file *));
#    endif /* !linux */
#   endif /* (_BSDI_VERSION >= 199510) */
#   if	BSD >= 199306
extern	int	iplread __P((dev_t, struct uio *, int));
#   else
#    ifndef linux
extern	int	iplread __P((dev_t, struct uio *));
#    else
extern	int	iplread(struct inode *, struct file *, char *, int);
#    endif /* !linux */
#   endif /* BSD >= 199306 */
#  endif /* __ sgi */
# endif /* SOLARIS */
#endif /* #ifndef _KERNEL */

/*
 * Post NetBSD 1.2 has the PFIL interface for packet filters.  This turns
 * on those hooks.  We don't need any special mods in non-IP Filter code
 * with this!
 */
#if (defined(NetBSD) && (NetBSD > 199609) && (NetBSD <= 1991011)) || \
    (defined(NetBSD1_2) && NetBSD1_2 > 1)
# define NETBSD_PF
#endif

extern	int	ipldetach __P((void));
extern	u_short	fr_tcpsum __P((mb_t *, ip_t *, tcphdr_t *, int));
#define	FR_SCANLIST(p, ip, fi, m)	fr_scanlist(p, ip, fi, m)
extern	int	fr_scanlist __P((int, ip_t *, fr_info_t *, void *));
extern	u_short	ipf_cksum __P((u_short *, int));
extern	int	fr_copytolog __P((int, char *, int));
extern	void	frflush __P((int, int *));
extern	frgroup_t *fr_addgroup __P((u_short, frentry_t *, int, int));
extern	frgroup_t *fr_findgroup __P((u_short, u_32_t, int, int, frgroup_t ***));
extern	void	fr_delgroup __P((u_short, u_32_t, int, int));
extern	int	ipl_unreach;
extern	int	ipl_inited;
extern	u_long	ipl_frouteok[2];
extern	int	fr_pass;
extern	int	fr_flags;
extern	int	fr_active;
extern	fr_info_t	frcache[2];
#if	IPFILTER_LOG
extern	iplog_t	**iplh[IPL_LOGMAX+1], *iplt[IPL_LOGMAX+1];
extern	int	iplused[IPL_LOGMAX + 1];
#endif
extern	struct frentry *ipfilter[2][2], *ipacct[2][2];
extern	struct frgroup *ipfgroups[3][2];
extern	struct filterstats frstats[];

#endif	/* __IP_FIL_H__ */
