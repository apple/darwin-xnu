/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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

/* Move arbitrarily-aligned data from one array to another */
extern void bcopy(
	const char	*from,
	char		*to,
	vm_size_t	nbytes);

/* Move overlapping, arbitrarily aligned data from one array to another */
/* Not present on all ports */
extern void ovbcopy(
	const char	*from,
	char		*to,
	vm_size_t	nbytes);

extern int bcmp(
		const char *a,
		const char *b,
		vm_size_t len);

/* Zero an arbitrarily aligned array */
extern void bzero(
	char	*from,
	vm_size_t	nbytes);

/* Move arbitrarily-aligned data from a user space to kernel space */
extern boolean_t copyin(
	const char	*user_addr,
	char		*kernel_addr,
	vm_size_t	nbytes);

/* Move a NUL-terminated string from a user space to kernel space */
extern boolean_t copyinstr(
	const char	*user_addr,
	char		*kernel_addr,
	vm_size_t	max,
	vm_size_t	*actual);

/* Move arbitrarily-aligned data from a user space to kernel space */
extern boolean_t copyinmsg(
	const char	*user_addr,
	char		*kernel_addr,
	mach_msg_size_t nbytes);

/* Move arbitrarily-aligned data from a kernel space to user space */
extern boolean_t copyout(
	const char	*kernel_addr,
	char		*user_addr,
	vm_size_t	 nbytes);

/* Move arbitrarily-aligned data from a kernel space to user space */
extern boolean_t copyoutmsg(
	const char	*kernel_addr,
	char		*user_addr,
	mach_msg_size_t nbytes);

extern int sscanf(const char *input, const char *fmt, ...);

extern integer_t sprintf(char *buf, const char *fmt, ...);

extern void printf(const char *format, ...);

extern void dbugprintf(const char *format, ...);

extern void kdp_printf(const char *format, ...);

extern void printf_init(void);

extern void panic(const char *string, ...);

extern void panic_init(void);

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

extern void halt_cpu(void);

extern void halt_all_cpus(
		boolean_t	reboot);

extern void Debugger(
		const char	* message);

extern void delay(
		int		n);

extern char *machine_boot_info(
		char		*buf,
		vm_size_t	buf_len);

/*
 * Machine-dependent routine to fill in an array with up to callstack_max
 * levels of return pc information.
 */
extern void machine_callstack(
		natural_t	*buf,
		vm_size_t	callstack_max);

extern void consider_machine_collect(void);

extern void norma_bootstrap(void);

#if	DIPC
extern boolean_t	no_bootstrap_task(void);
extern ipc_port_t	get_root_master_device_port(void);
#endif	/* DIPC */

#endif	/* _MISC_PROTOS_H_ */
