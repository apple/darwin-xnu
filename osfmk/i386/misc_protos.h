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
 * @OSF_COPYRIGHT@
 */

#include <i386/thread.h>

extern void		get_root_device(void);
extern void		picinit(void);
extern void		slave_clock(void);
extern void		interrupt_processor(
				int		cpu);
extern void		mp_probe_cpus(void);
extern void		remote_kdb(void);
extern void		clear_kdb_intr(void);
extern void		set_cpu_model(void);
extern void		cpu_shutdown(void);
extern void		fix_desc(
				void		* desc,
				int		num_desc);
extern void		cnpollc(
				boolean_t	on);
extern void		form_pic_mask(void);
extern void		intnull(
				int		unit);
extern char *		i386_boot_info(
				char		*buf,
				vm_size_t	buf_len);

extern void		blkclr(
			       const char	*from,
			       int		nbytes);

extern void		kdb_kintr(void);
extern void		kdb_console(void);

extern unsigned	long  	ntohl(unsigned long);

extern unsigned int	div_scale(
				unsigned int	dividend,
				unsigned int	divisor,
				unsigned int	*scale);

extern unsigned int	mul_scale(
				unsigned int	multiplicand,
				unsigned int	multiplier,
				unsigned int	*scale);

/* Move arbitrarily-aligned data from one physical address to another */
extern void bcopy_phys(
		       const char *from,
		       char       *to,
		       vm_size_t  nbytes);
