/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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

/* HISTORY
 * 8 Aug. 2003 - Created (Derek Kumar)
 */

/* Various protocol definitions 
 * for the core transfer protocol, which is a variant of TFTP 
 */

/*
 * Packet types.
 */
#define	KDP_RRQ	  1			/* read request */
#define	KDP_WRQ	  2			/* write request */
#define	KDP_DATA  3			/* data packet */
#define	KDP_ACK	  4			/* acknowledgement */
#define	KDP_ERROR 5			/* error code */
#define KDP_SEEK  6                     /* Seek to specified offset */
#define KDP_EOF   7                     /* signal end of file */

#if	defined(__LP64__)
#define KDP_FEATURE_MASK_STRING		"features"
enum	{KDP_FEATURE_LARGE_CRASHDUMPS = 1};
extern	uint32_t	kdp_crashdump_feature_mask;
#endif
struct	corehdr {
	short	th_opcode;		/* packet type */
	union {
		unsigned int	tu_block;	/* block # */
		unsigned int	tu_code;	/* error code */
		char	tu_rpl[1];	/* request packet payload */
	} th_u;
	char	th_data[1];		/* data or error string */
}__attribute__((packed));

#define	th_block	th_u.tu_block
#define	th_code		th_u.tu_code
#define	th_stuff	th_u.tu_rpl
#define	th_msg		th_data

/*
 * Error codes.
 */
#define	EUNDEF		0		/* not defined */
#define	ENOTFOUND	1		/* file not found */
#define	EACCESS		2		/* access violation */
#define	ENOSPACE	3		/* disk full or allocation exceeded */
#define	EBADOP		4		/* illegal TFTP operation */
#define	EBADID		5		/* unknown transfer ID */
#define	EEXISTS		6		/* file already exists */
#define	ENOUSER		7		/* no such user */

#define CORE_REMOTE_PORT 1069 /* hardwired, we can't really query the services file */

void kdp_panic_dump (void);

void abort_panic_transfer (void);

struct corehdr *create_panic_header(unsigned int request, const char *corename, unsigned length, unsigned block);

int 	kdp_send_crashdump_pkt(unsigned int request, char *corename,
				uint64_t length, void *panic_data);

int	kdp_send_crashdump_data(unsigned int request, char *corename,
				uint64_t length, caddr_t txstart);
