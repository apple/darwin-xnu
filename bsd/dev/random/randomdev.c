/*
 * Copyright (c) 1999, 2000-2003 Apple Computer, Inc. All rights reserved.
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <miscfs/devfs/devfs.h>
#include <kern/lock.h>
#include <sys/time.h>
#include <sys/malloc.h>

#include <dev/random/randomdev.h>
#include <dev/random/YarrowCoreLib/include/yarrow.h>

#define RANDOM_MAJOR  -1 /* let the kernel pick the device number */

d_ioctl_t       random_ioctl;

/*
 * A struct describing which functions will get invoked for certain
 * actions.
 */
static struct cdevsw random_cdevsw =
{
	random_open,		/* open */
	random_close,		/* close */
	random_read,		/* read */
	random_write,		/* write */
	random_ioctl,			/* ioctl */
	nulldev,			/* stop */
	nulldev,			/* reset */
	NULL,				/* tty's */
	eno_select,			/* select */
	eno_mmap,			/* mmap */
	eno_strat,			/* strategy */
	eno_getc,			/* getc */
	eno_putc,			/* putc */
	0					/* type */
};

/* Used to detect whether we've already been initialized */
static int gRandomInstalled = 0;
static PrngRef gPrngRef;
static int gRandomError = 1;
static mutex_t *gYarrowMutex = 0;

#define RESEED_TICKS 50 /* how long a reseed operation can take */

/*
 *Initialize ONLY the Yarrow generator.
 */
void PreliminarySetup ()
{
    prng_error_status perr;
    struct timeval tt;
    char buffer [16];

    /* create a Yarrow object */
    perr = prngInitialize(&gPrngRef);
    if (perr != 0) {
        printf ("Couldn't initialize Yarrow, /dev/random will not work.\n");
        return;
    }

	/* clear the error flag, reads and write should then work */
    gRandomError = 0;

    /* get a little non-deterministic data as an initial seed. */
    microtime(&tt);

    /*
	 * So how much of the system clock is entropic?
	 * It's hard to say, but assume that at least the
	 * least significant byte of a 64 bit structure
	 * is entropic.  It's probably more, how can you figure
	 * the exact time the user turned the computer on, for example.
    */
    perr = prngInput(gPrngRef, (BYTE*) &tt, sizeof (tt), SYSTEM_SOURCE, 8);
    if (perr != 0) {
        /* an error, complain */
        printf ("Couldn't seed Yarrow.\n");
        return;
    }
    
    /* turn the data around */
    perr = prngOutput(gPrngRef, (BYTE*) buffer, sizeof (buffer));
    
    /* and scramble it some more */
    perr = prngForceReseed(gPrngRef, RESEED_TICKS);
    
    /* make a mutex to control access */
    gYarrowMutex = mutex_alloc(0);
}

/*
 * Called to initialize our device,
 * and to register ourselves with devfs
 */
void
random_init()
{
	int ret;

	if (gRandomInstalled)
		return;

	/* install us in the file system */
	gRandomInstalled = 1;

	/* setup yarrow and the mutex */
	PreliminarySetup();

	ret = cdevsw_add(RANDOM_MAJOR, &random_cdevsw);
	if (ret < 0) {
		printf("random_init: failed to allocate a major number!\n");
		gRandomInstalled = 0;
		return;
	}

	devfs_make_node(makedev (ret, 0), DEVFS_CHAR,
		UID_ROOT, GID_WHEEL, 0666, "random", 0);

	/*
	 * also make urandom 
	 * (which is exactly the same thing in our context)
	 */
	devfs_make_node(makedev (ret, 1), DEVFS_CHAR,
		UID_ROOT, GID_WHEEL, 0666, "urandom", 0);
}

int
random_ioctl(dev, cmd, data, flag, p)
        dev_t dev;
        u_long cmd;
        caddr_t data;
        int flag;
        struct proc *p;
{
	switch (cmd) {
	case FIONBIO:
	case FIOASYNC:
		break;
	default:
		return ENODEV;
	}

	return (0);
}

/*
 * Open the device.  Make sure init happened, and make sure the caller is
 * authorized.
 */
 
int
random_open(dev_t dev, int flags, int devtype, struct proc *p)
{
	if (gRandomError != 0) {
		/* forget it, yarrow didn't come up */
		return (ENOTSUP);
	}

	/*
	 * if we are being opened for write,
	 * make sure that we have privledges do so
	 */
	if (flags & FWRITE) {
		if (securelevel >= 2)
			return (EPERM);
#ifndef __APPLE__
		if ((securelevel >= 1) && suser(p->p_ucred, &p->p_acflag))
			return (EPERM);
#endif	/* !__APPLE__ */
	}

	return (0);
}


/*
 * close the device.
 */
 
int
random_close(dev_t dev, int flags, int mode, struct proc *p)
{
	return (0);
}


/*
 * Get entropic data from the Security Server, and use it to reseed the
 * prng.
 */
int
random_write (dev_t dev, struct uio *uio, int ioflag)
{
    int retCode = 0;
    char rdBuffer[256];

    if (gRandomError != 0) {
        return (ENOTSUP);
    }
    
    /* get control of the Yarrow instance, Yarrow is NOT thread safe */
    mutex_lock(gYarrowMutex);
    
    /* Security server is sending us entropy */

    while (uio->uio_resid > 0 && retCode == 0) {
        /* get the user's data */
        int bytesToInput = min(uio->uio_resid, sizeof (rdBuffer));
        retCode = uiomove(rdBuffer, bytesToInput, uio);
        if (retCode != 0)
            goto /*ugh*/ error_exit;
        
        /* put it in Yarrow */
        if (prngInput(gPrngRef, (BYTE*) rdBuffer,
			sizeof (rdBuffer), SYSTEM_SOURCE,
        	sizeof (rdBuffer) * 8) != 0) {
            retCode = EIO;
            goto error_exit;
        }
    }
    
    /* force a reseed */
    if (prngForceReseed(gPrngRef, RESEED_TICKS) != 0) {
        retCode = EIO;
        goto error_exit;
    }
    
    /* retCode should be 0 at this point */
    
error_exit: /* do this to make sure the mutex unlocks. */
    mutex_unlock(gYarrowMutex);
    return (retCode);
}

/*
 * return data to the caller.  Results unpredictable.
 */ 
int
random_read(dev_t dev, struct uio *uio, int ioflag)
{
    int retCode = 0;
    char wrBuffer[512];

    if (gRandomError != 0)
        return (ENOTSUP);

   /* lock down the mutex */
    mutex_lock(gYarrowMutex);

    while (uio->uio_resid > 0 && retCode == 0) {
        /* get the user's data */
        int bytesToRead = min(uio->uio_resid, sizeof (wrBuffer));
        
        /* get the data from Yarrow */
        if (prngOutput(gPrngRef, (BYTE *) wrBuffer, sizeof (wrBuffer)) != 0) {
            printf ("Couldn't read data from Yarrow.\n");
            
            /* something's really weird */
            retCode = EIO;
            goto error_exit;
        }
        
        retCode = uiomove(wrBuffer, bytesToRead, uio);
        
        if (retCode != 0)
            goto error_exit;
    }
    
    retCode = 0;
    
error_exit:
    mutex_unlock(gYarrowMutex);
    return retCode;
}

/* export good random numbers to the rest of the kernel */
void
read_random(void* buffer, u_int numbytes)
{
    if (gYarrowMutex == 0) { /* are we initialized? */
        PreliminarySetup ();
    }
    
    mutex_lock(gYarrowMutex);
    prngOutput(gPrngRef, (BYTE *) buffer, numbytes);
    mutex_unlock(gYarrowMutex);
}

/*
 * Return an unsigned long pseudo-random number.
 */
u_long
RandomULong()
{
	u_long buf;
	read_random(&buf, sizeof (buf));
	return (buf);
}

