/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
/*
 * @OSF_COPYRIGHT@
 */
/*
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#ifndef	_MISC_PROTOS_H_
#define	_MISC_PROTOS_H_

#include <stdarg.h>
#include <string.h>
#include <machine/setjmp.h>
#include <mach/boolean.h>
#include <mach/message.h>
#include <mach/machine/vm_types.h>
#include <ipc/ipc_types.h>
#include <kern/debug.h>

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif /* MIN */
#ifndef MAX
#define MAX(a,b) (((a)>(b))?(a):(b))
#endif  /* MAX */

/* Set a bit in a bit array */
extern void setbit(
	int		which,
	int		*bitmap);

/* Clear a bit in a bit array */
extern void clrbit(
	int		which,
	int		*bitmap);

/* Find the first set bit in a bit array */
extern int ffsbit(
	int		*bitmap);
extern int ffs(
	unsigned int	mask);

/*
 * Test if indicated bit is set in bit string.
 */
extern int testbit(
	int		which,
	int		*bitmap);

/* Move arbitrarily-aligned data from a user space to kernel space */
extern int copyin(
	const user_addr_t   user_addr,
	char                *kernel_addr,
	vm_size_t           nbytes);

/* Move a NUL-terminated string from a user space to kernel space */
extern int copyinstr(
	const user_addr_t   user_addr,
	char                *kernel_addr,
	vm_size_t           max,
	vm_size_t           *actual);

/* Move arbitrarily-aligned data from a user space to kernel space */
extern int copyinmsg(
	const user_addr_t   user_addr,
	char                *kernel_addr,
	mach_msg_size_t     nbytes);

/* Move arbitrarily-aligned data from a kernel space to user space */
extern int copyout(
	const void      *kernel_addr,
	user_addr_t     user_addr,
	vm_size_t       nbytes);

/* Move arbitrarily-aligned data from a kernel space to user space */
extern int copyoutmsg(
	const char      *kernel_addr,
	user_addr_t     user_addr,
	mach_msg_size_t nbytes);

/* Invalidate copy window(s) cache */
extern void    inval_copy_windows(thread_t);

extern int sscanf(const char *input, const char *fmt, ...) __scanflike(2,3);

/* sprintf() is being deprecated. Please use snprintf() instead. */ 
extern integer_t sprintf(char *buf, const char *fmt, ...) __deprecated;

extern int printf(const char *format, ...) __printflike(1,2);

extern void dbugprintf(const char *format, ...) __printflike(1,2);

extern int kdb_printf(const char *format, ...) __printflike(1,2);

extern int kdb_log(const char *format, ...) __printflike(1,2);

extern void printf_init(void);

extern int snprintf(char *, size_t, const char *, ...) __printflike(3,4);

extern void log(int level, char *fmt, ...);

void 
_doprnt(
	register const char	*fmt,
	va_list			*argp,
	void			(*putc)(char),
	int			radix);
int
__doprnt(
	register const char	*fmt,
	va_list			*argp,
	void			(*putc)(int, void *),
	void                    *arg,
	int			radix);

extern void safe_gets(
	char	*str,
	int	maxlen);

extern void cnputcusr(char);

extern void conslog_putc(char);

extern void consdebug_putc(char);

extern void consdebug_log(char);

extern void cnputc(char);

extern int cngetc(void);

extern int cnmaygetc(void);

extern int _setjmp(
	jmp_buf_t	*jmp_buf);

extern int _longjmp(
	jmp_buf_t	*jmp_buf,
	int		value);

extern void bootstrap_create(void);

extern void Debugger(
		const char	* message);

extern void delay(
		int		n);


extern void norma_bootstrap(void);

#if	DIPC
extern boolean_t	no_bootstrap_task(void);
extern ipc_port_t	get_root_master_device_port(void);
#endif	/* DIPC */

extern kern_return_t	kernel_set_special_port(
		host_priv_t	host_priv,
		int 		which,
		ipc_port_t	port);

user_addr_t get_useraddr(void);

/* symbol lookup */
struct kmod_info_t;

extern int syms_formataddr(
		vm_offset_t	addr,
		char		*out,
		vm_offset_t	outsize);

extern const char *syms_nameforaddr(
		vm_offset_t	addr,
		vm_offset_t	*ofs,
		kmod_info_t	**kmod);

#endif	/* _MISC_PROTOS_H_ */
