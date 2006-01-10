/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
 * Definition of remote debugger protocol.
 */

#include	<mach/vm_prot.h>

/*
 * Retransmit parameters
 */
#if	DDEBUG_DEBUG || DEBUG_DEBUG
#define	KDP_REXMIT_SECS		20	/* rexmit if no ack in 3 secs */
#else	/* DDEBUG_DEBUG || DEBUG_DEBUG */
#define	KDP_REXMIT_SECS		3	/* rexmit if no ack in 3 secs */
#endif	/* DDEBUG_DEBUG || DEBUG_DEBUG */
#define	KDP_REXMIT_TRIES	8	/* xmit 8 times, then give up */

/*
 * (NMI) Attention Max Wait Time
 * Remote will resume unless KDP requests is received within this
 * many seconds after an attention (nmi) packet is sent.
 */
#define	KDP_MAX_ATTN_WAIT	30	/* wait max of 30 seconds */

/*
 * Well-known UDP port, debugger side.
 * FIXME: This is what the 68K guys use, but beats me how they chose it...
 */
#define	KDP_REMOTE_PORT		41139	/* pick one and register it */

/*
 * UDP ports, KDB side. 5 port numbers are reserved for each port (request
 * and exception). This allows multiple KDBs to run on one host.
 */
#define UDP_HOST_COMM_BASE	41140
#define UDP_HOST_EXCEP_BASE	41145
#define NUM_UDP_HOST_PORTS	5

/*
 * Requests
 */
typedef enum {
	/* connection oriented requests */
	KDP_CONNECT,	KDP_DISCONNECT,

	/* obtaining client info */
	KDP_HOSTINFO,	KDP_VERSION,	KDP_MAXBYTES,
	
	/* memory access */
	KDP_READMEM,	KDP_WRITEMEM,
	
	/* register access */
	KDP_READREGS,	KDP_WRITEREGS,
	
	/* executable image info */
	KDP_LOAD,	KDP_IMAGEPATH,
	
	/* execution control */
	KDP_SUSPEND,	KDP_RESUMECPUS,
	
	/* exception and termination notification, NOT true requests */
	KDP_EXCEPTION,	KDP_TERMINATION,

	/* breakpoint control */
	KDP_BREAKPOINT_SET, KDP_BREAKPOINT_REMOVE,
	
	/* vm regions */
	KDP_REGIONS,

	/* reattach to a connected host */
	KDP_REATTACH,

	/* remote reboot request */
	KDP_HOSTREBOOT
} kdp_req_t;

/*
 * Common KDP packet header
 */
typedef struct {
	kdp_req_t	request:7;	/* request type */
	unsigned	is_reply:1;	/* 0 => request, 1 => reply */
	unsigned	seq:8;		/* sequence number within session */
	unsigned	len:16;		/* length of entire pkt including hdr */
	unsigned	key;		/* session key */
} kdp_hdr_t;

/*
 * KDP errors
 */
typedef enum {
	KDPERR_NO_ERROR = 0,
	KDPERR_ALREADY_CONNECTED,
	KDPERR_BAD_NBYTES,
	KDPERR_BADFLAVOR		/* bad flavor in w/r regs */
} kdp_error_t;

/*
 * KDP requests and reply packet formats
 */

/*
 * KDP_CONNECT
 */
typedef struct {			/* KDP_CONNECT request */
	kdp_hdr_t	hdr;
	unsigned short	req_reply_port;	/* udp port which to send replies */
	unsigned short	exc_note_port;	/* udp port which to send exc notes */
	char		greeting[0];	/* "greetings", null-terminated */
} kdp_connect_req_t;

typedef struct {			/* KDP_CONNECT reply */
	kdp_hdr_t	hdr;
	kdp_error_t	error;
} kdp_connect_reply_t;

/*
 * KDP_DISCONNECT
 */
typedef struct {			/* KDP_DISCONNECT request */
	kdp_hdr_t	hdr;
} kdp_disconnect_req_t;

typedef struct {			/* KDP_DISCONNECT reply */
	kdp_hdr_t	hdr;
} kdp_disconnect_reply_t;

/*
 * KDP_REATTACH
 */
typedef struct {
  kdp_hdr_t hdr;
  unsigned short req_reply_port; /* udp port which to send replies */
} kdp_reattach_req_t;

/*
 * KDP_HOSTINFO
 */
typedef struct {			/* KDP_HOSTINFO request */
	kdp_hdr_t	hdr;
} kdp_hostinfo_req_t;

typedef struct {
	unsigned	cpus_mask;	/* bit is 1 if cpu present */
	int		cpu_type;
	int		cpu_subtype;
} kdp_hostinfo_t;

typedef struct {			/* KDP_HOSTINFO reply */
	kdp_hdr_t	hdr;
	kdp_hostinfo_t	hostinfo;
} kdp_hostinfo_reply_t;

/*
 * KDP_VERSION
 */
typedef struct {			/* KDP_VERSION request */
	kdp_hdr_t	hdr;
} kdp_version_req_t;

#define	KDP_FEATURE_BP	0x1	/* local breakpoint support */

typedef struct {			/* KDP_REGIONS reply */
	kdp_hdr_t	hdr;
	unsigned	version;
	unsigned	feature;
	unsigned	pad0;
	unsigned	pad1;
} kdp_version_reply_t;

/*
 * KDP_REGIONS
 */
typedef struct {			/* KDP_REGIONS request */
	kdp_hdr_t	hdr;
} kdp_regions_req_t;

#define	VM_PROT_VOLATILE	((vm_prot_t) 0x08)	/* not cacheable */
#define	VM_PROT_SPARSE		((vm_prot_t) 0x10)	/* sparse addr space */

typedef struct {
	void		*address;
	unsigned	nbytes;
	vm_prot_t	protection;
} kdp_region_t;

typedef struct {			/* KDP_REGIONS reply */
	kdp_hdr_t	hdr;
	unsigned	nregions;
	kdp_region_t	regions[0];
} kdp_regions_reply_t;

/*
 * KDP_MAXBYTES
 */
typedef struct {			/* KDP_MAXBYTES request */
	kdp_hdr_t	hdr;
} kdp_maxbytes_req_t;

typedef struct {			/* KDP_MAXBYTES reply */
	kdp_hdr_t	hdr;
	unsigned	max_bytes;
} kdp_maxbytes_reply_t;

/*
 * KDP_READMEM
 */
typedef struct {			/* KDP_READMEM request */
	kdp_hdr_t	hdr;
	void		*address;
	unsigned	nbytes;
} kdp_readmem_req_t;

typedef struct {			/* KDP_READMEM reply */
	kdp_hdr_t	hdr;
	kdp_error_t	error;
	char		data[0];
} kdp_readmem_reply_t;

/*
 * KDP_WRITEMEM
 */
typedef struct {			/* KDP_WRITEMEM request */
	kdp_hdr_t	hdr;
	void		*address;
	unsigned	nbytes;
	char		data[0];
} kdp_writemem_req_t;

typedef struct {			/* KDP_WRITEMEM reply */
	kdp_hdr_t	hdr;
	kdp_error_t	error;
} kdp_writemem_reply_t;

/*
 * KDP_READREGS
 */
typedef struct {			/* KDP_READREGS request */
	kdp_hdr_t	hdr;
	unsigned	cpu;
	unsigned	flavor;
} kdp_readregs_req_t;

typedef struct {			/* KDP_READREGS reply */
	kdp_hdr_t	hdr;
	kdp_error_t	error;		/* could be KDPERR_BADFLAVOR */
	char		data[0];
} kdp_readregs_reply_t;

/*
 * KDP_WRITEREGS
 */
typedef struct {			/* KDP_WRITEREGS request */
	kdp_hdr_t	hdr;
	unsigned	cpu;
	unsigned	flavor;
	char		data[0];
} kdp_writeregs_req_t;

typedef struct {			/* KDP_WRITEREGS reply */
	kdp_hdr_t	hdr;
	kdp_error_t	error;
} kdp_writeregs_reply_t;

/*
 * KDP_LOAD
 */
typedef struct {			/* KDP_LOAD request */
	kdp_hdr_t	hdr;
	char		file_args[0];
} kdp_load_req_t;

typedef struct {			/* KDP_LOAD reply */
	kdp_hdr_t	hdr;
	kdp_error_t	error;
} kdp_load_reply_t;

/*
 * KDP_IMAGEPATH
 */
typedef struct {			/* KDP_IMAGEPATH request */
	kdp_hdr_t	hdr;
} kdp_imagepath_req_t;

typedef struct {			/* KDP_IMAGEPATH reply */
	kdp_hdr_t	hdr;
	char		path[0];
} kdp_imagepath_reply_t;

/*
 * KDP_SUSPEND
 */
typedef struct {			/* KDP_SUSPEND request */
	kdp_hdr_t	hdr;
} kdp_suspend_req_t;

typedef struct {			/* KDP_SUSPEND reply */
	kdp_hdr_t	hdr;
} kdp_suspend_reply_t;

/*
 * KDP_RESUMECPUS
 */
typedef struct {			/* KDP_RESUMECPUS request */
	kdp_hdr_t	hdr;
	unsigned	cpu_mask;
} kdp_resumecpus_req_t;

typedef struct {			/* KDP_RESUMECPUS reply */
	kdp_hdr_t	hdr;
} kdp_resumecpus_reply_t;

typedef struct {
  kdp_hdr_t hdr;
  unsigned long address;
} kdp_breakpoint_req_t;

typedef struct {
  kdp_hdr_t hdr;
  kdp_error_t error;
} kdp_breakpoint_reply_t;

/*
 * Exception notifications
 * (Exception notifications are not requests, and in fact travel from
 * the remote debugger to the gdb agent KDB.)
 */
typedef struct {			/* exc. info for one cpu */
	unsigned	cpu;
	/*
	 * Following info is defined as
	 * per <mach/exception.h>
	 */
	unsigned	exception;
	unsigned	code;
	unsigned	subcode;
} kdp_exc_info_t;

typedef struct {			/* KDP_EXCEPTION notification */
	kdp_hdr_t	hdr;
	unsigned	n_exc_info;
	kdp_exc_info_t	exc_info[0];
} kdp_exception_t;

typedef struct {			/* KDP_EXCEPTION acknowledgement */
	kdp_hdr_t	hdr;
} kdp_exception_ack_t;

/*
 * Child termination messages
 */
typedef enum {
	KDP_FAULT = 0,		/* child took fault (internal use) */
	KDP_EXIT,		/* child exited */
	KDP_POWEROFF,		/* child power-off */
	KDP_REBOOT,		/* child reboot */
	KDP_COMMAND_MODE	/* child exit to mon command_mode */
} kdp_termination_code_t;

typedef struct {			/* KDP_TERMINATION notification */
	kdp_hdr_t		hdr;
	kdp_termination_code_t	term_code;
	unsigned		exit_code;
} kdp_termination_t;

typedef struct {
	kdp_hdr_t	hdr;
} kdp_termination_ack_t;

typedef union {
	kdp_hdr_t		hdr;
	kdp_connect_req_t	connect_req;
	kdp_connect_reply_t	connect_reply;
	kdp_disconnect_req_t	disconnect_req;
	kdp_disconnect_reply_t	disconnect_reply;
	kdp_hostinfo_req_t	hostinfo_req;
	kdp_hostinfo_reply_t	hostinfo_reply;
	kdp_version_req_t	version_req;
	kdp_version_reply_t	version_reply;
	kdp_maxbytes_req_t	maxbytes_req;
	kdp_maxbytes_reply_t	maxbytes_reply;
	kdp_readmem_req_t	readmem_req;
	kdp_readmem_reply_t	readmem_reply;
	kdp_writemem_req_t	writemem_req;
	kdp_writemem_reply_t	writemem_reply;
	kdp_readregs_req_t	readregs_req;
	kdp_readregs_reply_t	readregs_reply;
	kdp_writeregs_req_t	writeregs_req;
	kdp_writeregs_reply_t	writeregs_reply;
	kdp_load_req_t		load_req;
	kdp_load_reply_t	load_reply;
	kdp_imagepath_req_t	imagepath_req;
	kdp_imagepath_reply_t	imagepath_reply;
	kdp_suspend_req_t	suspend_req;
	kdp_suspend_reply_t	suspend_reply;
	kdp_resumecpus_req_t	resumecpus_req;
	kdp_resumecpus_reply_t	resumecpus_reply;
	kdp_exception_t		exception;
	kdp_exception_ack_t	exception_ack;
	kdp_termination_t	termination;
	kdp_termination_ack_t	termination_ack;
	kdp_breakpoint_req_t	breakpoint_req;
	kdp_breakpoint_reply_t	breakpoint_reply;
	kdp_reattach_req_t	reattach_req;
	kdp_regions_req_t	regions_req;
	kdp_regions_reply_t	regions_reply;
} kdp_pkt_t;

#define MAX_KDP_PKT_SIZE	1200	/* max packet size */
#define MAX_KDP_DATA_SIZE	1024	/* max r/w data per packet */
