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
/*
  Copyright 1988, 1989 by Intel Corporation, Santa Clara, California.

		All Rights Reserved

Permission to use, copy, modify, and distribute this software and
its documentation for any purpose and without fee is hereby
granted, provided that the above copyright notice appears in all
copies and that both the copyright notice and this permission notice
appear in supporting documentation, and that the name of Intel
not be used in advertising or publicity pertaining to distribution
of the software without specific, written prior permission.

INTEL DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS,
IN NO EVENT SHALL INTEL BE LIABLE FOR ANY SPECIAL, INDIRECT, OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN ACTION OF CONTRACT,
NEGLIGENCE, OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#include <types.h>
#include <mach/message.h>
#include <kern/thread.h>
#include <kern/clock.h>
#include <kern/spl.h>
#include <kern/processor.h>
#include <kern/misc_protos.h>
#include <i386/pio.h>
#include <i386/AT386/rtc.h>
#include <i386/AT386/bbclock_entries.h>

/* local data */
static	int	month[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

extern	char	dectohexdec(
			int			n);
extern int	hexdectodec(
			char			c);
extern int	yeartoday(
			int			yr);
extern void	rtcput(
			struct rtc_st		* regs);
extern int	rtcget(
			struct rtc_st		* regs);

#define	LOCK_BBC()	splclock()
#define	UNLOCK_BBC(s)	splx(s)

/*
 * Configure battery-backed clock.
 */
int
bbc_config(void)
{
	int		BbcFlag;
	struct rtc_st	rtclk;

#if	NCPUS > 1 && AT386
	mp_disable_preemption();
	if (cpu_number() != master_cpu) {
		mp_enable_preemption();
		return(1);
	}
#endif
	/*
	 * Setup device.
	 */
	outb(RTC_ADDR, RTC_A);
	outb(RTC_DATA, RTC_DIV2 | RTC_RATE6);
	outb(RTC_ADDR, RTC_B);
	outb(RTC_DATA, RTC_HM);

	/*
	 * Probe the device by trying to read it.
	 */
	BbcFlag = (rtcget(&rtclk) ? 0 : 1);
	if (BbcFlag)
		printf("battery clock configured\n");
	else
		printf("WARNING: Battery Clock Failure!\n");
#if	NCPUS > 1 && AT386
	mp_enable_preemption();
#endif
	return (BbcFlag);
}

/*
 * Get the current clock time.
 */
kern_return_t
bbc_gettime(
	mach_timespec_t	*cur_time)	/* OUT */
{
	struct rtc_st	rtclk;
	time_t		n;
	int		sec, min, hr, dom, mon, yr;
	int		i, days = 0;
	spl_t		s;
	thread_t	thread;

#if 	NCPUS > 1 && AT386
	if ((thread = current_thread()) != THREAD_NULL) {
		thread_bind(thread, master_processor);
		mp_disable_preemption();
		if (current_processor() != master_processor) {
			mp_enable_preemption();
			thread_block((void (*)) 0);
		} else {
			mp_enable_preemption();
		}
	}
#endif
	s = LOCK_BBC();
	rtcget(&rtclk);
	sec = hexdectodec(rtclk.rtc_sec);
	min = hexdectodec(rtclk.rtc_min);
	hr = hexdectodec(rtclk.rtc_hr);
	dom = hexdectodec(rtclk.rtc_dom);
	mon = hexdectodec(rtclk.rtc_mon);
	yr = hexdectodec(rtclk.rtc_yr);
	yr = (yr < 70) ? yr+100 : yr;
	n = sec + 60 * min + 3600 * hr;
	n += (dom - 1) * 3600 * 24;
	if (yeartoday(yr) == 366)
		month[1] = 29;
	for (i = mon - 2; i >= 0; i--)
		days += month[i];
	month[1] = 28;
	for (i = 70; i < yr; i++)
		days += yeartoday(i);
	n += days * 3600 * 24;
	cur_time->tv_sec  = n;
	cur_time->tv_nsec = 0;
	UNLOCK_BBC(s);

#if	NCPUS > 1 && AT386
	if (thread != THREAD_NULL)
		thread_bind(thread, PROCESSOR_NULL);
#endif
	return (KERN_SUCCESS);
}

/*
 * Set the current clock time.
 */
kern_return_t
bbc_settime(
	mach_timespec_t	*new_time)
{
	struct rtc_st	rtclk;
	time_t		n;
	int		diff, i, j;
	spl_t		s;
	thread_t	thread;

#if	NCPUS > 1 && AT386
	if ((thread = current_thread()) != THREAD_NULL) {
		thread_bind(thread, master_processor);
		mp_disable_preemption();
		if (current_processor() != master_processor) {
			mp_enable_preemption();
			thread_block((void (*)) 0);
		} else { 
			mp_enable_preemption();
		}
	}
#endif
	s = LOCK_BBC();
	rtcget(&rtclk);
	diff = 0;
	n = (new_time->tv_sec - diff) % (3600 * 24);   /* hrs+mins+secs */
	rtclk.rtc_sec = dectohexdec(n%60);
	n /= 60;
	rtclk.rtc_min = dectohexdec(n%60);
	rtclk.rtc_hr = dectohexdec(n/60);
	n = (new_time->tv_sec - diff) / (3600 * 24);	/* days */
	rtclk.rtc_dow = (n + 4) % 7;  /* 1/1/70 is Thursday */
	for (j = 1970; n >= (i = yeartoday(j)); j++)
		n -= i;
	rtclk.rtc_yr = dectohexdec(j % 100);
	if (yeartoday(j) == 366)
		month[1] = 29;
	for (i = 0; n >= month[i]; i++)
		n -= month[i];
	month[1] = 28;
	rtclk.rtc_mon = dectohexdec(++i);
	rtclk.rtc_dom = dectohexdec(++n);
	rtcput(&rtclk);
	UNLOCK_BBC(s);

#if	NCPUS > 1 && AT386
	if (thread != THREAD_NULL)
		thread_bind(current_thread(), PROCESSOR_NULL);
#endif
	return (KERN_SUCCESS);
}

/*
 * Get clock device attributes.
 */
kern_return_t
bbc_getattr(
	clock_flavor_t		flavor,
	clock_attr_t		attr,		/* OUT */
	mach_msg_type_number_t	*count)		/* IN/OUT */
{
	if (*count != 1)
		return (KERN_FAILURE);
	switch (flavor) {

	case CLOCK_GET_TIME_RES:	/* >0 res */
		*(clock_res_t *) attr = NSEC_PER_SEC;
		break;

	case CLOCK_ALARM_CURRES:	/* =0 no alarm */
	case CLOCK_ALARM_MINRES:
	case CLOCK_ALARM_MAXRES:
		*(clock_res_t *) attr = 0;
		break;

	default:
		return (KERN_INVALID_VALUE);
	}
	return (KERN_SUCCESS);
}


/* DEVICE SPECIFIC ROUTINES */

int
rtcget(
	struct rtc_st	* regs)
{
	outb(RTC_ADDR, RTC_D); 
	if (inb(RTC_DATA) & RTC_VRT == 0)
		return (-1);
	outb(RTC_ADDR, RTC_A);	
	while (inb(RTC_DATA) & RTC_UIP)		/* busy wait */
		outb(RTC_ADDR, RTC_A);	
	load_rtc((unsigned char *)regs);
	return (0);
}	

void
rtcput(
	struct rtc_st	* regs)
{
	register unsigned char	x;

	outb(RTC_ADDR, RTC_B);
	x = inb(RTC_DATA);
	outb(RTC_ADDR, RTC_B);
	outb(RTC_DATA, x | RTC_SET); 	
	save_rtc((unsigned char *)regs);
	outb(RTC_ADDR, RTC_B);
	outb(RTC_DATA, x & ~RTC_SET); 
}

int
yeartoday(
	int	year)
{
  year += 1900;
	return((year % 4) ? 365 :
	       ((year % 100) ? 366 : ((year % 400) ? 365: 366)));
}

int
hexdectodec(
	char	n)
{
	return ((((n >> 4) & 0x0F) * 10) + (n & 0x0F));
}

char
dectohexdec(
	int	n)
{
	return ((char)(((n / 10) << 4) & 0xF0) | ((n % 10) & 0x0F));
}
