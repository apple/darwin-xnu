/*
 * Copyright (c) 1997-2012 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1993 NeXT Computer, Inc.
 *
 * UNIX Device switch tables.
 *
 * HISTORY
 *
 * 30 July 1997 Umesh Vaishampayan (umeshv@apple.com)
 * 	enabled file descriptor pseudo-device.
 * 18 June 1993 ? at NeXT
 *	Cleaned up a lot of stuff in this file.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ioctl.h>
#include <sys/tty.h>
#include <sys/conf.h>

/* Prototypes that should be elsewhere: */
extern dev_t	chrtoblk(dev_t dev);
extern int	chrtoblk_set(int cdev, int bdev);
extern int	iskmemdev(dev_t dev);

struct bdevsw	bdevsw[] =
{
	/*
	 *	For block devices, every other block of 8 slots is 
	 *	reserved for Apple.  The other slots are available for
	 *	the user.  This way we can both add new entries without
	 *	running into each other.  Be sure to fill in Apple's
	 *	8 reserved slots when you jump over us -- we'll do the
	 *	same for you.
	 */

	/* 0 - 7 are reserved for Apple */

	NO_BDEVICE,							/* 0*/
	NO_BDEVICE,							/* 1*/
	NO_BDEVICE,							/* 2*/
	NO_BDEVICE,							/* 3*/
	NO_BDEVICE,							/* 4*/
	NO_BDEVICE,							/* 5*/
	NO_BDEVICE,							/* 6*/
	NO_BDEVICE,							/* 7*/

	/* 8 - 15 are reserved to the user */
	NO_BDEVICE,							/* 8*/
	NO_BDEVICE,							/* 9*/
	NO_BDEVICE,							/*10*/
	NO_BDEVICE,							/*11*/
	NO_BDEVICE,							/*12*/
	NO_BDEVICE,							/*13*/
	NO_BDEVICE,							/*14*/
	NO_BDEVICE,							/*15*/

	/* 16 - 23 are reserved for Apple */
	NO_BDEVICE,							/*16*/
	NO_BDEVICE,							/*17*/
	NO_BDEVICE,							/*18*/
	NO_BDEVICE,							/*18*/
	NO_BDEVICE,							/*20*/
	NO_BDEVICE,							/*21*/
	NO_BDEVICE,							/*22*/
	NO_BDEVICE,							/*23*/
};

int	nblkdev = sizeof (bdevsw) / sizeof (bdevsw[0]);

extern struct tty *km_tty[];
extern d_open_t		cnopen;
extern d_close_t	cnclose;
extern d_read_t		cnread;
extern d_write_t	cnwrite;
extern d_ioctl_t	cnioctl;
extern d_select_t	cnselect;
extern d_open_t		kmopen;
extern d_close_t	kmclose;
extern d_read_t		kmread;
extern d_write_t	kmwrite;
extern d_ioctl_t	kmioctl;
extern d_open_t		sgopen;
extern d_close_t	sgclose;
extern d_ioctl_t	sgioctl;

#if NVOL > 0
extern d_open_t		volopen;
extern d_close_t	volclose;
extern d_ioctl_t	volioctl;
#else
#define	volopen		eno_opcl
#define	volclose	eno_opcl
#define	volioctl	eno_ioctl
#endif

extern d_open_t		cttyopen;
extern d_read_t		cttyread;
extern d_write_t	cttywrite;
extern d_ioctl_t	cttyioctl;
extern d_select_t	cttyselect;

extern d_read_t		mmread;
extern d_write_t	mmwrite;
extern d_ioctl_t	mmioctl;
#define	mmselect	(select_fcn_t *)seltrue
#define mmmmap		eno_mmap

#include <pty.h>
#if NPTY > 0
extern struct tty *pt_tty[];
extern d_open_t		ptsopen;
extern d_close_t	ptsclose;
extern d_read_t		ptsread;
extern d_write_t	ptswrite;
extern d_stop_t		ptsstop;
extern d_open_t		ptcopen;
extern d_close_t	ptcclose;
extern d_read_t		ptcread;
extern d_write_t	ptcwrite;
extern d_select_t	ptcselect;
extern d_ioctl_t	ptyioctl;
#else
#define ptsopen		eno_opcl
#define ptsclose	eno_opcl
#define ptsread		eno_rdwrt
#define ptswrite	eno_rdwrt
#define	ptsstop		nulldev

#define ptcopen		eno_opcl
#define ptcclose	eno_opcl
#define ptcread		eno_rdwrt
#define ptcwrite	eno_rdwrt
#define	ptcselect	eno_select
#define ptyioctl	eno_ioctl
#endif

extern d_open_t		logopen;
extern d_close_t	logclose;
extern d_read_t		logread;
extern d_ioctl_t	logioctl;
extern d_select_t	logselect;
extern d_open_t		fdesc_open;
extern d_read_t		fdesc_read;
extern d_write_t	fdesc_write;
extern d_ioctl_t	fdesc_ioctl;
extern d_select_t	fdesc_select;

#define nullopen	(d_open_t *)&nulldev
#define nullclose	(d_close_t *)&nulldev
#define nullread	(d_read_t *)&nulldev
#define nullwrite	(d_write_t *)&nulldev
#define nullioctl	(d_ioctl_t *)&nulldev
#define nullselect	(d_select_t *)&nulldev
#define nullstop	(d_stop_t *)&nulldev
#define nullreset	(d_reset_t *)&nulldev

struct cdevsw	cdevsw[] =
{
	/*
	 *	For character devices, every other block of 16 slots is
	 *	reserved for Apple.  The other slots are available for
	 *	the user.  This way we can both add new entries without
	 *	running into each other.  Be sure to fill in Apple's
	 *	16 reserved slots when you jump over us -- we'll do the
	 *	same for you.
	 */

	/* 0 - 15 are reserved for Apple */

    {
	cnopen,		cnclose,	cnread,		cnwrite,	/* 0*/
	cnioctl,	nullstop,	nullreset,	0,		cnselect,
	eno_mmap,	eno_strat,	eno_getc,	eno_putc, 	D_TTY
    },
    NO_CDEVICE,								/* 1*/
    {
	cttyopen,	nullclose,	cttyread,	cttywrite,	/* 2*/
	cttyioctl,	nullstop,	nullreset,	0,		cttyselect,
	eno_mmap,	eno_strat,	eno_getc,	eno_putc,	D_TTY
    },
    {
	nullopen,	nullclose,	mmread,		mmwrite,	/* 3*/
	mmioctl,	nullstop,	nullreset,	0,		mmselect,
	mmmmap,		eno_strat,	eno_getc,	eno_putc,	D_DISK
    },
    {
	ptsopen,	ptsclose,	ptsread,	ptswrite,	/* 4*/
	ptyioctl,	ptsstop,	nullreset,	pt_tty,		ttselect,
	eno_mmap,	eno_strat,	eno_getc,	eno_putc,	D_TTY
    },
    {
	ptcopen,	ptcclose,	ptcread,	ptcwrite,	/* 5*/
	ptyioctl,	nullstop,	nullreset,	0,		ptcselect,
	eno_mmap,	eno_strat,	eno_getc,	eno_putc,	D_TTY
    },
    {
	logopen,	logclose,	logread,	eno_rdwrt,	/* 6*/
	logioctl,	eno_stop,	nullreset,	0,		logselect,
	eno_mmap,	eno_strat,	eno_getc,	eno_putc,	0
    },
    NO_CDEVICE,								/* 7*/
    NO_CDEVICE,								/* 8*/
    NO_CDEVICE,								/* 9*/
    NO_CDEVICE,								/*10*/
    NO_CDEVICE,								/*11*/
    {
	kmopen,		kmclose,	kmread,		kmwrite,	/*12*/
	kmioctl,	nullstop,	nullreset,	km_tty,		ttselect,
	eno_mmap,	eno_strat,	eno_getc,	eno_putc,	0
    },
    NO_CDEVICE,								/*13*/
    NO_CDEVICE,								/*14*/
    NO_CDEVICE,								/*15*/

	/* 16 - 31 are reserved to the user */
    NO_CDEVICE,								/*16*/
    NO_CDEVICE,								/*17*/
    NO_CDEVICE,								/*18*/
    NO_CDEVICE,								/*19*/
    NO_CDEVICE,								/*20*/
    NO_CDEVICE,								/*21*/
    NO_CDEVICE,								/*22*/
    NO_CDEVICE,								/*23*/
    NO_CDEVICE,								/*24*/
    NO_CDEVICE,								/*25*/
    NO_CDEVICE,								/*26*/
    NO_CDEVICE,								/*27*/
    NO_CDEVICE,								/*28*/
    NO_CDEVICE,								/*29*/
    NO_CDEVICE,								/*30*/
    NO_CDEVICE,								/*31*/

	/* 32 - 47 are reserved to NeXT */
    {
	fdesc_open,	eno_opcl,	fdesc_read,	fdesc_write,	/*32*/
	fdesc_ioctl,	eno_stop,	eno_reset,	0,		fdesc_select,
	eno_mmap,	eno_strat,	eno_getc,	eno_putc,	0
    },
#if 1
   NO_CDEVICE,
#else
    {
	sgopen,		sgclose,	eno_rdwrt,	eno_rdwrt,	/*33*/
	sgioctl,	eno_stop,	eno_reset,	0,		eno_select,
	eno_mmap,	eno_strat,	eno_getc,	eno_putc,	D_TAPE
    },
#endif
    NO_CDEVICE,								/*34*/
    NO_CDEVICE,								/*35*/
    NO_CDEVICE,								/*36*/
    NO_CDEVICE,								/*37*/
    NO_CDEVICE,								/*38*/
    NO_CDEVICE,								/*39*/
    NO_CDEVICE,								/*40*/
    NO_CDEVICE,								/*41*/
    {
	volopen,	volclose,	eno_rdwrt,	eno_rdwrt,	/*42*/
	volioctl,	eno_stop,	eno_reset,	0,		(select_fcn_t *)seltrue,
	eno_mmap,	eno_strat,	eno_getc,	eno_putc,	0
    },
};
int	nchrdev = sizeof (cdevsw) / sizeof (cdevsw[0]);

uint64_t cdevsw_flags[sizeof (cdevsw) / sizeof (cdevsw[0])];

#include	<sys/vnode.h> /* for VCHR and VBLK */
/*
 * return true if a disk
 */
int
isdisk(dev_t dev, int type)
{
	dev_t	maj = major(dev);

	switch (type) {
	case VCHR:
		maj = chrtoblk(maj);
		if (maj == NODEV) {
			break;
		}
		/* FALL THROUGH */
	case VBLK:
		if (bdevsw[maj].d_type == D_DISK) {
			return (1);
		}
		break;
	}
	return(0);
}

static int chrtoblktab[] = {
	/* CHR*/	/* BLK*/	/* CHR*/	/* BLK*/
	/*  0 */	NODEV,		/*  1 */	NODEV,
	/*  2 */	NODEV,		/*  3 */	NODEV,
	/*  4 */	NODEV,		/*  5 */	NODEV,
	/*  6 */	NODEV,		/*  7 */	NODEV,
	/*  8 */	NODEV,		/*  9 */	NODEV,
	/* 10 */	NODEV,		/* 11 */	NODEV,
	/* 12 */	NODEV,		/* 13 */	NODEV,
	/* 14 */	NODEV,		/* 15 */	NODEV,
	/* 16 */	NODEV,		/* 17 */	NODEV,
	/* 18 */	NODEV,		/* 19 */	NODEV,
	/* 20 */	NODEV,		/* 21 */	NODEV,
	/* 22 */	NODEV,		/* 23 */	NODEV,
	/* 24 */	NODEV,		/* 25 */	NODEV,
	/* 26 */	NODEV,		/* 27 */	NODEV,
	/* 28 */	NODEV,		/* 29 */	NODEV,
	/* 30 */	NODEV,		/* 31 */	NODEV,
	/* 32 */	NODEV,		/* 33 */	NODEV,
	/* 34 */	NODEV,		/* 35 */	NODEV,
	/* 36 */	NODEV,		/* 37 */	NODEV,
	/* 38 */	NODEV,		/* 39 */	NODEV,
	/* 40 */	NODEV,		/* 41 */	NODEV,
	/* 42 */	NODEV,		/* 43 */	NODEV,
	/* 44 */	NODEV,
};

/*
 * convert chr dev to blk dev
 */
dev_t
chrtoblk(dev_t dev)
{
	int blkmaj;

	if (major(dev) >= nchrdev)
		return(NODEV);
	blkmaj = chrtoblktab[major(dev)];
	if (blkmaj == NODEV)
		return(NODEV);
	return(makedev(blkmaj, minor(dev)));
}

int
chrtoblk_set(int cdev, int bdev)
{
	if (cdev >= nchrdev)
		return (-1);
	if (bdev != NODEV && bdev >= nblkdev)
		return (-1);
	chrtoblktab[cdev] = bdev;
	return 0;
}

/*
 * Returns true if dev is /dev/mem or /dev/kmem.
 */
int iskmemdev(dev_t dev)
{
	return (major(dev) == 3 && minor(dev) < 2);
}
