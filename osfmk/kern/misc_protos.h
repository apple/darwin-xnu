/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
	const char      *kernel_addr,
	user_addr_t     user_addr,
	vm_size_t       nbytes);

/* Move arbitrarily-aligned data from a kernel space to user space */
extern int copyoutmsg(
	const char      *kernel_addr,
	user_addr_t     user_addr,
	mach_msg_size_t nbytes);

/* Invalidate copy window(s) cache */
extern void	inval_copy_windows(thread_t);


extern int sscanf(const char *input, const char *fmt, ...);

extern integer_t sprintf(char *buf, const char *fmt, ...);

extern void printf(const char *format, ...);

extern void dbugprintf(const char *format, ...);

extern void kdb_printf(const char *format, ...);

extern void printf_init(void);

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

#endif	/* _MISC_PROTOS_H_ */
