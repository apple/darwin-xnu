/*
 * Copyright (c) 1988 University of Utah.
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * the Systems Programming Group of the University of Utah Computer
 * Science Department.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * from: Utah $Hdr: fdioctl.h 1.1 90/07/09$
 *
 *	@(#)vnioctl.h	8.1 (Berkeley) 6/10/93
 *
 * $FreeBSD: src/sys/sys/vnioctl.h,v 1.4 1999/09/17 05:33:58 dillon Exp $
 */

#ifndef _SYS_VNIOCTL_H_
#define _SYS_VNIOCTL_H_

#include <sys/appleapiopts.h>

#ifdef KERNEL_PRIVATE

#ifdef __APPLE_API_PRIVATE
/*
 * Ioctl definitions for file (vnode) disk pseudo-device.
 */

#define _PATH_VNTAB	"/etc/vntab"	/* default config file */

typedef enum {
	vncontrol_readwrite_io_e = 0,
} vncontrol_t;

struct vn_ioctl {
	char *		vn_file;	/* pathname of file to mount */
	int		vn_size;	/* (returned) size of disk */
	vncontrol_t	vn_control;
};

/*
 * Before you can use a unit, it must be configured with VNIOCSET.
 * The configuration persists across opens and closes of the device;
 * an VNIOCCLR must be used to reset a configuration.  An attempt to
 * VNIOCSET an already active unit will return EBUSY.
 */
#define VNIOCATTACH	_IOWR('F', 0, struct vn_ioctl)	/* attach file */
#define VNIOCDETACH	_IOWR('F', 1, struct vn_ioctl)	/* detach disk */
#define VNIOCGSET	_IOWR('F', 2, u_long )		/* set global option */
#define VNIOCGCLEAR	_IOWR('F', 3, u_long )		/* reset --//-- */
#define VNIOCUSET	_IOWR('F', 4, u_long )		/* set unit option */
#define VNIOCUCLEAR	_IOWR('F', 5, u_long )		/* reset --//-- */
#define VNIOCSHADOW	_IOWR('F', 6, struct vn_ioctl)	/* attach shadow */

#define VN_LABELS	0x1	/* Use disk(/slice) labels */
#define VN_FOLLOW	0x2	/* Debug flow in vn driver */
#define VN_DEBUG	0x4	/* Debug data in vn driver */
#define VN_IO		0x8	/* Debug I/O in vn driver */
#define VN_DONTCLUSTER	0x10	/* Don't cluster */
#define VN_RESERVE	0x20	/* Pre-reserve swap */

#endif /* __APPLE_API_PRIVATE */

#endif KERNEL_PRIVATE

#endif	/* _SYS_VNIOCTL_H_*/
