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
 */
/*
 * @APPLE_FREE_COPYRIGHT@
 */


#include <device/device_types.h>
#include <mach_kdp.h>

/*
 *	Console is on the Printer Port (chip channel 0)
 *	Debugger is on the Modem Port (chip channel 1)
 */

#define	CONSOLE_PORT	1

struct scc_tty {
	char *		t_addr;		/* device pointer */
	int		t_dev;		/* device number */
	int		t_ispeed;	/* input speed */
	int		t_ospeed;	/* output speed */
	char		t_breakc;	/* character to deliver when 'break'
					   condition received */
	int		t_flags;	/* mode flags */
	int		t_state;	/* current state */
	int		t_line;		/* fake line discipline number,
					   for old drivers - always 0 */
	int		t_outofband;	/* current out-of-band events */
	int		t_outofbandarg;	/* arg to first out-of-band event */
	int		t_nquoted;	/* number of quoted chars in inq */
	int		t_hiwater;	/* baud-rate limited high water mark */
	int		t_lowater;	/* baud-rate limited low water mark */
};
typedef struct scc_tty	*scc_tty_t;

/*
 * function declarations for performing serial i/o
 * other functions below are declared in kern/misc_protos.h
 *    cnputc, cngetc, cnmaygetc
 */

void initialize_serial(caddr_t scc_phys_base, int32_t serial_baud);

extern int		scc_probe(int32_t serial_baud);

#if 0
extern int		scc_open(
				dev_t		dev,
				dev_mode_t	flag,
				io_req_t	ior);

extern void		scc_close(
				dev_t		dev);

extern int		scc_read(
				dev_t		dev,
				io_req_t	ior);

extern io_return_t	scc_write(
				dev_t		dev,
				io_req_t	ior);

extern io_return_t	scc_get_status(
				dev_t			dev,
				dev_flavor_t		flavor,
				dev_status_t		data,
				mach_msg_type_number_t	*status_count);

extern io_return_t	scc_set_status(
				dev_t			dev,
				dev_flavor_t		flavor,
				dev_status_t		data,
				mach_msg_type_number_t	status_count);

extern boolean_t	scc_portdeath(
				dev_t		dev,
				ipc_port_t	port);

#endif /* 0 */

extern int	 	scc_putc(
				int			unit,
				int			line,
				int			c);

extern int		scc_getc(
				int			unit,
				int			line,
				boolean_t		wait,
				boolean_t		raw);

/* Functions in serial_console.c for switching between serial and video
   consoles.  */
extern boolean_t	console_is_serial(void);
extern int		switch_to_serial_console(
				void);

extern int		switch_to_video_console(
				void);

extern void		switch_to_old_console(
				int			old_console);

void serial_keyboard_init(void);
void serial_keyboard_start(void);
void serial_keyboard_poll(void);


/*
 * JMM - We are not really going to support this driver in SMP (barely
 * support it now - so just pick up the stubbed out versions.
 */
#define DECL_FUNNEL(class,f)
#define DECL_FUNNEL_VARS
#define FUNNEL_INIT(f,p)
#define FUNNEL_ENTER(f)
#define FUNNEL_EXIT(f)
#define FUNNEL_ESCAPE(f)		(1)
#define FUNNEL_REENTER(f,count)
#define FUNNEL_IN_USE(f)		(TRUE)

/*
 * Flags
 */
#define	TF_ODDP		0x00000002	/* get/send odd parity */
#define	TF_EVENP	0x00000004	/* get/send even parity */
#define	TF_ANYP		(TF_ODDP|TF_EVENP)
					/* get any parity/send none */
#define	TF_LITOUT	0x00000008	/* output all 8 bits
					   otherwise, characters >= 0x80
					   are time delays	XXX */
#define	TF_ECHO		0x00000080	/* device wants user to echo input */
#define	TS_MIN		0x00004000	/* buffer input chars, if possible */
