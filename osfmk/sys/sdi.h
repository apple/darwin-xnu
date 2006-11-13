/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 * 
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:48  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:59  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.7.1  1996/09/17  16:34:56  bruel
 * 	removed size_t, already defined in types.h.
 * 	[96/09/17            bruel]
 *
 * Revision 1.1.4.1  1996/04/17  17:48:54  davidp
 * 	Created for use with SVR4 drivers.
 * 	[1996/04/11  13:19:26  davidp]
 * 
 * Revision 1.1.1.2  1996/03/04  17:53:46  calvert
 * 	Created for use with SVR4 drivers.
 * 
 * $EndLog$
 */
/* In vi use ":set ts=4" to edit/view this file
 */
#ifndef _SYS_SDI_H_
#define _SYS_SDI_H_	1

#include "scsi/scsi_endian.h"

typedef u_long	paddr_t;
typedef u_int	rm_key_t;

typedef long	hba_clock_t;

typedef u_long	major_t;
typedef u_long	minor_t;

typedef u_long	hba_buf_t;	/* just to satisfy declaration */
typedef u_long	hba_uio_t;	/* just to satisfy declaration */


struct ver_no {
	uchar_t			sv_release;
	uchar_t			sv_machine;
	short			sv_modes;
};

struct hba_idata_v4 {
	int				version_num;
	char			*name;
	uchar_t			ha_id;
	ulong_t			ioaddr1;
	int				dmachan1;
	int				iov;
	int				cntlr;
	int				active;
	ulong_t			idata_memaddr;
	uchar_t			idata_ctlorder;
	uchar_t			idata_nbus;
	ushort_t		idata_ntargets;
	ushort_t		idata_nluns;
	rm_key_t		idata_rmkey;
	void			*idata_intrcookie;
	int				idata_cpubind;
};

struct hba_idata {
	int				version_num;
	char			*name;
	uchar_t			ha_id;
	ulong_t			ioaddr1;
	int				dmachan1;
	int				iov;
	int				cntlr;
	int				active;
};

#define HBA_SVR4_2		1
#define HBA_SVR4_2_2	2
#define HBA_SVR4_2MP	3

#define HBA_VMASK		0xffff

#define HBA_IDATA_EXT	0x10000
#define HBA_EXT_INFO	0x20000
#define HBA_AUTOCONF	0x40000

#define VID_LEN		8
#define PID_LEN		16
#define REV_LEN		4

#define INQ_LEN		VID_LEN+PID_LEN+1
#define INQ_EXLEN	INQ_LEN+REV_LEN

struct ident {
	BITFIELD_2( unsigned char,
					id_type : 5,
					id_pqual : 3);
	BITFIELD_2(unsigned char,
					id_qualif : 7,
					id_rmb : 1);
	uchar_t			id_ver;
	BITFIELD_2(unsigned char,
					id_form : 4,
					id_res1 : 4);
	uchar_t			id_len;
	uchar_t			id_vu [3];
	char			id_vendor [VID_LEN];
	char			id_prod [PID_LEN];
	char			id_revnum [REV_LEN];
};

#define SCSI_INQ_CON	0x0
#define SCSI_INQ_TC		0x1
#define SCSI_INQ_TNC	0x3

struct scsi_adr {
	int	scsi_ctl;
	int	scsi_target;
	int	scsi_lun;
	int	scsi_bus;
};

struct scsi_ad {
	ulong_t			sa_major;
	ulong_t			sa_minor;
	uchar_t			sa_lun;
	BITFIELD_2(unsigned char,
					sa_bus : 3,
					sa_exta : 5);
	short			sa_ct;
};

/* sa_ct */
#define SDI_SA_CT(c,t)	(((c) << 3) | ((t) & 0x07))
#define SDI_HAN(sa)		(((sa)->sa_ct >> 3) & 0x07)
#define SDI_TCN(sa)		((sa)->sa_ct & 0x07)

#define SDI_ETCN(sa)		((sa)->sa_exta)
#define SDI_EHAN(sa)		(((sa)->sa_ct >> 3) & 0x1f)

struct sdi_edt {
	struct sdi_edt	*hash_p;
	short			hba_no;
	uchar_t			scsi_id;
	uchar_t			lun;
	struct owner	*curdrv;
	struct owner	*owner_list;
	ulong_t			res1;
	int				pdtype;
	uchar_t			iotype;
	char			inquiry [INQ_EXLEN];
	struct scsi_adr	scsi_adr;
	ulong_t			memaddr;
	uchar_t			ctlorder;
	struct ident	edt_ident;
};

/* iotype */
#define F_DMA		0x001
#define F_DMA_24	F_DMA
#define F_PIO		0x002
#define F_SCGTH		0x004
#define F_RMB		0x008
#define F_DMA_32	0x010
#define F_HDWREA	0x020
#define F_RESID		0x040

struct mod_operations {
	int	(*modm_install)(void);
	int	(*modm_remove)(void);
	int	(*modm_info)(void);
	int	(*modm_bind)(void);
};

struct modlink {
	struct mod_operations	*ml_ops;
	void					*ml_type_data;
};

struct mod_type_data {
	char	*mtd_info;
	void	*mtd_pdata;
};

struct modwrapper {
	int				mw_rev;
	int				(*mw_load)(void);
	int				(*mw_unload)(void);
	void			(*mw_halt)(void);
	void			*mw_conf_data;
	struct modlink	*mw_modlink;
};

struct hbadata {
	struct xsb *sb;
};

typedef struct physreq {
	paddr_t		phys_align;
	paddr_t		phys_boundary;
	uchar_t		phys_dmasize;
	uchar_t		phys_max_scgth;
	uchar_t		phys_flags;
	void		*phys_brkup_poolp;
} physreq_t;


typedef struct bcb {
	uchar_t		bcb_addrtypes;
	uchar_t		bcb_flags;
	size_t		bcb_max_xfer;
	size_t		bcb_granularity;
	physreq_t	*bcb_physreqp;
} bcb_t;

struct hbagetinfo {
	char	*name;
	char	iotype;
	bcb_t	*bcbp;
};

struct hba_info {
	int				*hba_flag;
	ulong_t			max_xfer;
	long			(*hba_freeblk)(struct hbadata *hdp, int cntlr);
	struct hbadata	*(*hba_getblk)(int flag, int cntlr);
	long			(*hba_icmd)(struct hbadata *hdp, int flag);
	void			(*hba_getinfo)(struct scsi_ad *sap,
						struct hbagetinfo *hgip);
	long			(*hba_send)(struct hbadata *hdp, int flag);
	int				(*hba_xlat)(struct hbadata *hdp, int bflag, void *procp,
						int flag);
	int				(*hba_open)(void);
	int				(*hba_close)(void);
	int				(*hba_ioctl)(void);
};

/* hba_flag */
#define HBA_MP		0x01
#define HBA_HOT		0x02
#define HBA_TIMEOUT	0x04

#define SC_EXHAN(minor)	(((minor) >> 5) & 0x1f)
#define SC_EXTCN(minor)	((((minor) >> 2) & 0x07) | ((minor >> 7) & 0x18))
#define SC_EXLUN(minor)	(((minor) & 0x03) | ((minor>>10) & 0x1C))
#define SC_BUS(minor)	(((minor) >> 15) & 0x07)

#define SC_MKMINOR(h,t,l,b)	( \
								(((h) & 0x1f) << 5) | \
								(((t) & 0x07) << 2) | (((t) & 0x18) << 7) | \
								((l) & 0x03) | (((l) & 0x1c) << 10) | \
								(((b) & 0x07) << 15) \
							)

#define SDI_NAMESZ		49

#define SM_POOLSIZE		28
#define LG_POOLSIZE		(sizeof (struct xsb))

#define SCB_TYPE	1
#define ISCB_TYPE	2
#define SFB_TYPE	3

#define SCB_WRITE	0x00
#define SCB_READ	0x01
#define SCB_LINK	0x02
#define SCB_HAAD	0x04
#define SCB_PARTBLK	0x08

#define SDI_NOALLOC	0x00000000
#define SDI_ASW		0x00000001
#define SDI_LINKF0	0x00000002
#define SDI_LINKF1	0x00000003
#define SDI_QFLUSH	0xE0000004
#define SDI_ABORT	0xF0000005
#define SDI_RESET	0xF0000006
#define SDI_CRESET	0xD0000007
#define SDI_V2PERR	0xA0000008
#define SDI_TIME	0xD0000009
#define SDI_NOTEQ	0x8000000A
#define SDI_HAERR	0xE000000B
#define SDI_MEMERR	0xA000000C
#define SDI_SBUSER	0xA000000D
#define SDI_CKSTAT	0xD000000E
#define SDI_SCBERR	0x8000000F
#define SDI_OOS		0xA0000010
#define SDI_NOSELE	0x90000011
#define SDI_MISMAT	0x90000012
#define SDI_PROGRES	0x00000013
#define SDI_UNUSED	0x00000014
#define SDI_ONEIC	0x80000017
#define SDI_SFBERR	0x80000019
#define SDI_TCERR	0x9000001A

#define SDI_ERROR	0x80000000
#define SDI_RETRY	0x40000000
#define SDI_MESS	0x20000000
#define SDI_SUSPEND	0x10000000

#define SFB_NOPF		0x00
#define SFB_RESETM		0x01
#define SFB_ABORTM		0x02
#define SFB_FLUSHR		0x03
#define SFB_RESUME		0x04
#define SFB_SUSPEND		0x05
#define SFB_ADD_DEV		0x06
#define SFB_RM_DEV		0x07
#define SFB_PAUSE		0x08
#define SFB_CONTINUE	0x09

#define SDI_386_AT		0x06
#define SDI_386_MCA		0x07
#define SDI_386_EISA	0x08

#define SDI_RET_OK		0
#define SDI_RET_ERR		-1
#define SDI_RET_RETRY	1

#define SDI_SEND		0x0081
#define SDI_TRESET		0x0082
#define SDI_BRESET		0x0084
#define HA_VER			0x0083
#define SDI_RESERVE		0x0085
#define SDI_RELEASE		0x0086
#define SDI_RESTAT		0x0087
#define HA_GETPARMS		0x008a
#define IHA_GETPARMS	0x008b
#define HA_SETPARMS		0x008c
#define IHA_SETPARMS	0x008d
#define HA_GETPPARMS	0x008e

struct sense {
	uchar_t			sd_pad0;
	BITFIELD_2(unsigned char,
					sd_errc : 7,
					sd_valid : 1);
	uchar_t			sd_res1;
	BITFIELD_5(unsigned char,
					sd_key : 4,
					sd_res2 : 1,
					sd_ili : 1,
					sd_eom : 1,
					sd_fm : 1);
	uint_t			sd_ba;
	uchar_t			sd_len;
	uchar_t			sd_res3 [4];
	uchar_t			sd_sencode;
	uchar_t			sd_qualifier;
	uchar_t			sd_fru;
	BITFIELD_5(unsigned char,
					sd_bitpt : 3,
					sd_bpv : 1,
					sd_res4 : 2,
					sd_cd : 1,
					sd_res5 : 1);
	uchar_t			sd_field [2];
	uchar_t			sd_res6;
	uchar_t			sd_buffer;
	uchar_t			sd_res7 [2];
};


struct sb_extra {
	struct sense	sb_sense;
};

#define sc_priv		sc_extra

struct sb;

struct scb {
	ulong_t			sc_comp_code;
	void			*sc_extra;
	void			(*sc_int)(struct sb *sbp);
	caddr_t			sc_cmdpt;
	caddr_t			sc_datapt;
	long			sc_wd;
	time_t			sc_time;
	struct scsi_ad	sc_dev;
	ushort_t		sc_mode;
	uchar_t			sc_status;
	char			sc_fill;
	struct sb		*sc_link;
	long			sc_cmdsz;
	long			sc_datasz;
	long			sc_resid;
	hba_clock_t		sc_start;
};

struct sfb {
	ulong_t			sf_comp_code;
	char			*sf_priv;
	void			(*sf_int)(struct sb *sbp);
	struct scsi_ad	sf_dev;
	ulong_t			sf_func;
	int				sf_wd;
};

struct sb {
	ulong_t			sb_type;
	union {
		struct scb	b_scb;
		struct sfb	b_sfb;
	} sb_b;
};

#define SCB		sb_b.b_scb
#define SFB		sb_b.b_sfb

struct xsb {
	struct sb		sb;
	struct hbadata	*hbadata_p;
	struct owner	*owner_p;
	struct sb_extra	extra;
};

#define S_GOOD		0X00
#define S_CKCON		0X02
#define S_METGD		0X04
#define S_BUSY		0X08
#define S_INGD		0X10
#define S_INMET		0X12
#define S_RESER		0X18
#define S_CTERM		0x22
#define S_QFULL		0x28

#define SLEEP			0
#define NOSLEEP			1

#define KM_SLEEP		SLEEP
#define KM_NOSLEEP		NOSLEEP
#define KM_DMA			2
#define KM_REQ_DMA		4
#define KM_PHYSCONTIG	8

struct mod_drvintr {
	ushort_t	di_magic;
	ushort_t	di_version;
	char		*di_modname;
	int			*di_devflagp;
	void		(*di_handler)(int vect);
	void		*di_hook;
};

#define MOD_INTR_MAGIC	0xEB13
#define MOD_INTR_VER	1

struct o_mod_drvintr {
	struct intr_info	*drv_intrinfo;
	void				(*ihndler)(int vect);
};

#define MOD_INTRVER_MASK	0xff000000
#define MOD_INTRVER_42		0x01000000

#define INTRVER(infop)	((unsigned int)((infop)->ivect_no & MOD_INTRVER_MASK))
#define INTRNO(infop)	((infop)->ivect_no & ~MOD_INTRVER_MASK)

struct intr_info0 {
	int	ivect_no;
	int	int_pri;
	int	itype;
};

struct intr_info {
	int	ivect_no;
	int	int_pri;
	int	itype;
	int	int_cpu;
	int	int_mp;
};

#endif	/* _SYS_SDI_H_ */
