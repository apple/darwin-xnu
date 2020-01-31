/*
 * Copyright (c) 2000-2017 Apple Inc. All rights reserved.
 */
/*
 * Copyright (c) 1997 by Apple Computer, Inc., all rights reserved
 * Copyright (c) 1993 NeXT Computer, Inc.
 *
 * UNIX Device switch tables.
 *
 * HISTORY
 *
 * 30 July 1997 Umesh Vaishampayan (umeshv@apple.com)
 *	enabled file descriptor pseudo-device.
 * 18 June 1993 ? at NeXT
 *	Cleaned up a lot of stuff in this file.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ioctl.h>
#include <sys/tty.h>
#include <sys/conf.h>

/* Prototypes that should be elsewhere: */
extern dev_t    chrtoblk(dev_t dev);
extern int      chrtoblk_set(int cdev, int bdev);

struct bdevsw   bdevsw[] =
{
	/*
	 * For block devices, every other block of 8 slots is reserved to Apple.
	 * The other slots are available for the user.  This way we can both
	 * add new entries without running into each other.  Be sure to fill in
	 * Apple's 8 reserved slots when you jump over us -- we'll do the same
	 * for you.
	 */

	/* 0 - 7 are reserved to Apple */

	NO_BDEVICE,             /* 0 */
	NO_BDEVICE,             /* 1 */
	NO_BDEVICE,             /* 2 */
	NO_BDEVICE,             /* 3 */
	NO_BDEVICE,             /* 4 */
	NO_BDEVICE,             /* 5 */
	NO_BDEVICE,             /* 6 */
	NO_BDEVICE,             /* 7 */

	/* 8 - 15 are reserved to the user */
	NO_BDEVICE,             /* 8 */
	NO_BDEVICE,             /* 9 */
	NO_BDEVICE,             /* 10 */
	NO_BDEVICE,             /* 11 */
	NO_BDEVICE,             /* 12 */
	NO_BDEVICE,             /* 13 */
	NO_BDEVICE,             /* 14 */
	NO_BDEVICE,             /* 15 */

	/* 16 - 23 are reserved to Apple */
	NO_BDEVICE,             /* 16 */
	NO_BDEVICE,             /* 17 */
	NO_BDEVICE,             /* 18 */
	NO_BDEVICE,             /* 18 */
	NO_BDEVICE,             /* 20 */
	NO_BDEVICE,             /* 21 */
	NO_BDEVICE,             /* 22 */
	NO_BDEVICE,             /* 23 */
};

const int nblkdev = sizeof(bdevsw) / sizeof(bdevsw[0]);

extern struct tty *km_tty[];
extern d_open_t cnopen;
extern d_close_t cnclose;
extern d_read_t cnread;
extern d_write_t cnwrite;
extern d_ioctl_t cnioctl;
extern d_select_t cnselect;
extern d_open_t kmopen;
extern d_close_t kmclose;
extern d_read_t kmread;
extern d_write_t kmwrite;
extern d_ioctl_t kmioctl;
extern d_open_t sgopen;
extern d_close_t sgclose;
extern d_ioctl_t sgioctl;

#if NVOL > 0
extern d_open_t volopen;
extern d_close_t volclose;
extern d_ioctl_t volioctl;
#else
#define volopen         eno_opcl
#define volclose        eno_opcl
#define volioctl        eno_ioctl
#endif

extern d_open_t cttyopen;
extern d_read_t cttyread;
extern d_write_t cttywrite;
extern d_ioctl_t cttyioctl;
extern d_select_t cttyselect;

extern d_read_t mmread;
extern d_write_t mmwrite;
extern d_ioctl_t mmioctl;
#define mmselect        (select_fcn_t *)seltrue
#define mmmmap          eno_mmap

#include <pty.h>
#if NPTY > 0
extern d_open_t ptsopen;
extern d_close_t ptsclose;
extern d_read_t ptsread;
extern d_write_t ptswrite;
extern d_select_t ptsselect;
extern d_stop_t ptsstop;
extern d_open_t ptcopen;
extern d_close_t ptcclose;
extern d_read_t ptcread;
extern d_write_t ptcwrite;
extern d_select_t ptcselect;
extern d_ioctl_t ptyioctl;
#else
#define ptsopen         eno_opcl
#define ptsclose        eno_opcl
#define ptsread         eno_rdwrt
#define ptswrite        eno_rdwrt
#define ptsstop         nulldev

#define ptcopen         eno_opcl
#define ptcclose        eno_opcl
#define ptcread         eno_rdwrt
#define ptcwrite        eno_rdwrt
#define ptcselect       eno_select
#define ptyioctl        eno_ioctl
#endif

extern d_open_t logopen;
extern d_close_t logclose;
extern d_read_t logread;
extern d_ioctl_t logioctl;
extern d_select_t logselect;

extern d_open_t oslog_streamopen;
extern d_close_t oslog_streamclose;
extern d_read_t oslog_streamread;
extern d_ioctl_t oslog_streamioctl;
extern d_select_t oslog_streamselect;


extern d_open_t oslogopen;
extern d_close_t oslogclose;
extern d_ioctl_t oslogioctl;
extern d_select_t oslogselect;

#define nullopen        (d_open_t *)&nulldev
#define nullclose       (d_close_t *)&nulldev
#define nullread        (d_read_t *)&nulldev
#define nullwrite       (d_write_t *)&nulldev
#define nullioctl       (d_ioctl_t *)&nulldev
#define nullselect      (d_select_t *)&nulldev
#define nullstop        (d_stop_t *)&nulldev
#define nullreset       (d_reset_t *)&nulldev

struct cdevsw cdevsw[] = {
	/*
	 * To add character devices to this table dynamically, use cdevsw_add.
	 */

	[0] = {
		cnopen, cnclose, cnread, cnwrite,
		cnioctl, nullstop, nullreset, 0, cnselect,
		eno_mmap, eno_strat, eno_getc, eno_putc, D_TTY
	},
	[1] = NO_CDEVICE,
	[2] = {
		cttyopen, nullclose, cttyread, cttywrite,
		cttyioctl, nullstop, nullreset, 0, cttyselect,
		eno_mmap, eno_strat, eno_getc, eno_putc, D_TTY
	},
	[3] = {
		nullopen, nullclose, mmread, mmwrite,
		mmioctl, nullstop, nullreset, 0, mmselect,
		mmmmap, eno_strat, eno_getc, eno_putc, D_DISK
	},
	[PTC_MAJOR] = {
		ptsopen, ptsclose, ptsread, ptswrite,
		ptyioctl, ptsstop, nullreset, 0, ptsselect,
		eno_mmap, eno_strat, eno_getc, eno_putc, D_TTY
	},
	[PTS_MAJOR] = {
		ptcopen, ptcclose, ptcread, ptcwrite,
		ptyioctl, nullstop, nullreset, 0, ptcselect,
		eno_mmap, eno_strat, eno_getc, eno_putc, D_TTY
	},
	[6] = {
		logopen, logclose, logread, eno_rdwrt,
		logioctl, eno_stop, nullreset, 0, logselect,
		eno_mmap, eno_strat, eno_getc, eno_putc, 0
	},
	[7] = {
		oslogopen, oslogclose, eno_rdwrt, eno_rdwrt,
		oslogioctl, eno_stop, nullreset, 0, oslogselect,
		eno_mmap, eno_strat, eno_getc, eno_putc, 0
	},
	[8] = {
		oslog_streamopen, oslog_streamclose, oslog_streamread, eno_rdwrt,
		oslog_streamioctl, eno_stop, nullreset, 0, oslog_streamselect,
		eno_mmap, eno_strat, eno_getc, eno_putc, 0
	},
	[9 ... 11] = NO_CDEVICE,
	[12] = {
		kmopen, kmclose, kmread, kmwrite,
		kmioctl, nullstop, nullreset, km_tty, ttselect,
		eno_mmap, eno_strat, eno_getc, eno_putc, 0
	},
	[13 ... 41] = NO_CDEVICE,
	[42] = {
		volopen, volclose, eno_rdwrt, eno_rdwrt,
		volioctl, eno_stop, eno_reset, 0, (select_fcn_t *) seltrue,
		eno_mmap, eno_strat, eno_getc, eno_putc, 0
	}
};
const int nchrdev = sizeof(cdevsw) / sizeof(cdevsw[0]);

uint64_t cdevsw_flags[sizeof(cdevsw) / sizeof(cdevsw[0])];

#include        <sys/vnode.h>   /* for VCHR and VBLK */
/*
 * return true if a disk
 */
int
isdisk(dev_t dev, int type)
{
	dev_t           maj = major(dev);

	switch (type) {
	case VCHR:
		maj = chrtoblk(maj);
		if (maj == NODEV) {
			break;
		}
	/* FALL THROUGH */
	case VBLK:
		if (bdevsw[maj].d_type == D_DISK) {
			return 1;
		}
		break;
	}
	return 0;
}

static int      chrtoblktab[] = {
	/* CHR *//* BLK *//* CHR *//* BLK */
	/* 0 */ NODEV, /* 1 */ NODEV,
	/* 2 */ NODEV, /* 3 */ NODEV,
	/* 4 */ NODEV, /* 5 */ NODEV,
	/* 6 */ NODEV, /* 7 */ NODEV,
	/* 8 */ NODEV, /* 9 */ NODEV,
	/* 10 */ NODEV, /* 11 */ NODEV,
	/* 12 */ NODEV, /* 13 */ NODEV,
	/* 14 */ NODEV, /* 15 */ NODEV,
	/* 16 */ NODEV, /* 17 */ NODEV,
	/* 18 */ NODEV, /* 19 */ NODEV,
	/* 20 */ NODEV, /* 21 */ NODEV,
	/* 22 */ NODEV, /* 23 */ NODEV,
	/* 24 */ NODEV, /* 25 */ NODEV,
	/* 26 */ NODEV, /* 27 */ NODEV,
	/* 28 */ NODEV, /* 29 */ NODEV,
	/* 30 */ NODEV, /* 31 */ NODEV,
	/* 32 */ NODEV, /* 33 */ NODEV,
	/* 34 */ NODEV, /* 35 */ NODEV,
	/* 36 */ NODEV, /* 37 */ NODEV,
	/* 38 */ NODEV, /* 39 */ NODEV,
	/* 40 */ NODEV, /* 41 */ NODEV,
	/* 42 */ NODEV, /* 43 */ NODEV,
	/* 44 */ NODEV,
};

/*
 * convert chr dev to blk dev
 */
dev_t
chrtoblk(dev_t dev)
{
	int             blkmaj;

	if (major(dev) >= nchrdev) {
		return NODEV;
	}
	blkmaj = chrtoblktab[major(dev)];
	if (blkmaj == NODEV) {
		return NODEV;
	}
	return makedev(blkmaj, minor(dev));
}

int
chrtoblk_set(int cdev, int bdev)
{
	if (cdev >= nchrdev) {
		return -1;
	}
	if (bdev != NODEV && bdev >= nblkdev) {
		return -1;
	}
	chrtoblktab[cdev] = bdev;
	return 0;
}
