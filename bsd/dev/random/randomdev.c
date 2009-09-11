/*
 * Copyright (c) 1999-2009 Apple, Inc. All rights reserved.
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
	WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! WARNING!
	
	THIS FILE IS NEEDED TO PASS FIPS ACCEPTANCE FOR THE RANDOM NUMBER GENERATOR.
	IF YOU ALTER IT IN ANY WAY, WE WILL NEED TO GO THOUGH FIPS ACCEPTANCE AGAIN,
	AN OPERATION THAT IS VERY EXPENSIVE AND TIME CONSUMING.  IN OTHER WORDS,
	DON'T MESS WITH THIS FILE.

	WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! WARNING! WARNING!
*/

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <string.h>
#include <miscfs/devfs/devfs.h>
#include <kern/lock.h>
#include <kern/clock.h>
#include <sys/time.h>
#include <sys/malloc.h>
#include <sys/uio_internal.h>

#include <dev/random/randomdev.h>
#include <dev/random/YarrowCoreLib/include/yarrow.h>

#include <libkern/OSByteOrder.h>

#include <mach/mach_time.h>
#include <machine/machine_routines.h>

#include "fips_sha1.h"

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
	random_ioctl,		/* ioctl */
	(stop_fcn_t *)nulldev, /* stop */
	(reset_fcn_t *)nulldev, /* reset */
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
static lck_grp_t *gYarrowGrp;
static lck_attr_t *gYarrowAttr;
static lck_grp_attr_t *gYarrowGrpAttr;
static lck_mtx_t *gYarrowMutex = 0;

#define RESEED_TICKS 50 /* how long a reseed operation can take */


typedef u_int8_t BlockWord;
enum {kBSize = 20};
typedef BlockWord Block[kBSize];
enum {kBlockSize = sizeof(Block)};

/* define prototypes to keep the compiler happy... */

void add_blocks(Block a, Block b, BlockWord carry);
void fips_initialize(void);
void random_block(Block b, int addOptional);
u_int32_t CalculateCRC(u_int8_t* buffer, size_t length);

/*
 * Get 120 bits from yarrow
 */

/*
 * add block b to block a
 */
void
add_blocks(Block a, Block b, BlockWord carry)
{
	int i = kBlockSize - 1;
	while (i >= 0)
	{
		u_int32_t c = (u_int32_t)carry +
					  (u_int32_t)a[i] +
					  (u_int32_t)b[i];
		a[i] = c & 0xff;
		carry = c >> 8;
		i -= 1;
	}
}



static char zeros[(512 - kBSize * 8) / 8];
static Block g_xkey;
static Block g_random_data;
static int g_bytes_used;
static unsigned char g_SelfTestInitialized = 0;
static u_int32_t gLastBlockChecksum;

static const u_int32_t g_crc_table[] =
{
	0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
	0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
	0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
	0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
	0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
	0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
	0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
	0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
	0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
	0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
	0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
	0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
	0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
	0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
	0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
	0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
	0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
	0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
	0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
	0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
	0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
	0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
	0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
	0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
	0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
	0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
	0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
	0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
	0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
	0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
	0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
	0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D,
};

/*
 * Setup for fips compliance
 */

/*
 * calculate a crc-32 checksum
 */
u_int32_t CalculateCRC(u_int8_t* buffer, size_t length)
{
	u_int32_t crc = 0;
	
	size_t i;
	for (i = 0; i < length; ++i)
	{
		u_int32_t temp = (crc ^ ((u_int32_t) buffer[i])) & 0xFF;
		crc = (crc >> 8) ^ g_crc_table[temp];
	}
	
	return crc;
}

/*
 * get a random block of data per fips 186-2
 */
void
random_block(Block b, int addOptional)
{
	SHA1_CTX sha1_ctx;
	
	int repeatCount = 0;
	do
	{
		// do one iteration
		
		if (addOptional)
		{
			// create an xSeed to add.
			Block xSeed;
			prngOutput (gPrngRef, (BYTE*) &xSeed, sizeof (xSeed));
			
			// add the seed to the previous value of g_xkey
			add_blocks (g_xkey, xSeed, 0);
		}
		
		// initialize the value of H
		FIPS_SHA1Init(&sha1_ctx);
		
		// to stay compatible with the FIPS specification, we need to flip the bytes in
		// g_xkey to little endian byte order.  In our case, this makes exactly no difference
		// (random is random), but we need to do it anyway to keep FIPS happy
		
		// compute "G"
		FIPS_SHA1Update(&sha1_ctx, g_xkey, kBlockSize);
		
		// add zeros to fill the internal SHA-1 buffer
		FIPS_SHA1Update (&sha1_ctx, (const u_int8_t *)zeros, sizeof (zeros));
		
		// we have to do a byte order correction here because the sha1 math is being done internally
		// as u_int32_t, not a stream of bytes.  Since we maintain our data as a byte stream, we need
		// to convert
		
		u_int32_t* finger = (u_int32_t*) b;
		
		unsigned j;
		for (j = 0; j < kBlockSize / sizeof (u_int32_t); ++j)
		{
			*finger++ = OSSwapHostToBigInt32(sha1_ctx.h.b32[j]);
		}		
		
		// calculate the CRC-32 of the block
		u_int32_t new_crc = CalculateCRC(sha1_ctx.h.b8, sizeof (Block));
		
		// make sure we don't repeat
		int cmp = new_crc == gLastBlockChecksum;
		gLastBlockChecksum = new_crc;
		if (!g_SelfTestInitialized)
		{
			g_SelfTestInitialized = 1;
			return;
		}
		else if (!cmp)
		{
			return;
		}
		
		repeatCount += 1;
		
		// fix up the next value of g_xkey
		add_blocks (g_xkey, b, 1);
	} while (repeatCount < 2);
	
	/*
	 * If we got here, three sucessive checksums of the random number
	 * generator have been the same.  Since the odds of this happening are
	 * 1 in 18,446,744,073,709,551,616, (1 in 18 quintillion) one of the following has
	 * most likely happened:
	 *
	 * 1: There is a significant bug in this code.
	 * 2: There has been a massive system failure.
	 * 3: The universe has ceased to exist.
	 *
	 * There is no good way to recover from any of these cases. We
	 * therefore panic.
	 */
	 
	 panic("FIPS random self-test failed.");
}

/*
 *Initialize ONLY the Yarrow generator.
 */
void
PreliminarySetup(void)
{
    prng_error_status perr;

    /* create a Yarrow object */
    perr = prngInitialize(&gPrngRef);
    if (perr != 0) {
        printf ("Couldn't initialize Yarrow, /dev/random will not work.\n");
        return;
    }

	/* clear the error flag, reads and write should then work */
    gRandomError = 0;

    struct timeval tt;
    char buffer [16];

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
    gYarrowGrpAttr = lck_grp_attr_alloc_init();
    gYarrowGrp     = lck_grp_alloc_init("random", gYarrowGrpAttr);
    gYarrowAttr    = lck_attr_alloc_init();
    gYarrowMutex   = lck_mtx_alloc_init(gYarrowGrp, gYarrowAttr);
	
	fips_initialize ();
}

const Block kKnownAnswer = {0x92, 0xb4, 0x04, 0xe5, 0x56, 0x58, 0x8c, 0xed, 0x6c, 0x1a, 0xcd, 0x4e, 0xbf, 0x05, 0x3f, 0x68, 0x09, 0xf7, 0x3a, 0x93};

void
fips_initialize(void)
{
	/* So that we can do the self test, set the seed to zero */
	memset(&g_xkey, 0, sizeof(g_xkey));
	
	/* other initializations */
	memset (zeros, 0, sizeof (zeros));
	g_bytes_used = 0;
	random_block(g_random_data, FALSE);
	
	// check here to see if we got the initial data we were expecting
	if (memcmp(kKnownAnswer, g_random_data, kBlockSize) != 0)
	{
		panic("FIPS random self test failed");
	}
	
	// now do the random block again to make sure that userland doesn't get predicatable data
	random_block(g_random_data, TRUE);
}

/*
 * Called to initialize our device,
 * and to register ourselves with devfs
 */
void
random_init(void)
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
random_ioctl(	__unused dev_t dev, u_long cmd, __unused caddr_t data, 
				__unused int flag, __unused struct proc *p  )
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
random_open(__unused dev_t dev, int flags, __unused int devtype, __unused struct proc *p)
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
		if ((securelevel >= 1) && proc_suser(p))
			return (EPERM);
#endif	/* !__APPLE__ */
	}

	return (0);
}


/*
 * close the device.
 */
 
int
random_close(__unused dev_t dev, __unused int flags, __unused int mode, __unused struct proc *p)
{
	return (0);
}


/*
 * Get entropic data from the Security Server, and use it to reseed the
 * prng.
 */
int
random_write (__unused dev_t dev, struct uio *uio, __unused int ioflag)
{
    int retCode = 0;
    char rdBuffer[256];

    if (gRandomError != 0) {
        return (ENOTSUP);
    }
    
    /* get control of the Yarrow instance, Yarrow is NOT thread safe */
    lck_mtx_lock(gYarrowMutex);
    
    /* Security server is sending us entropy */

    while (uio_resid(uio) > 0 && retCode == 0) {
        /* get the user's data */
        int bytesToInput = min(uio_resid(uio), sizeof (rdBuffer));
        retCode = uiomove(rdBuffer, bytesToInput, uio);
        if (retCode != 0)
            goto /*ugh*/ error_exit;
        
        /* put it in Yarrow */
        if (prngInput(gPrngRef, (BYTE*) rdBuffer,
			bytesToInput, SYSTEM_SOURCE,
        	bytesToInput * 8) != 0) {
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
    lck_mtx_unlock(gYarrowMutex);
    return (retCode);
}

/*
 * return data to the caller.  Results unpredictable.
 */ 
int
random_read(__unused dev_t dev, struct uio *uio, __unused int ioflag)
{
    int retCode = 0;
	
    if (gRandomError != 0)
        return (ENOTSUP);

   /* lock down the mutex */
    lck_mtx_lock(gYarrowMutex);

	int bytes_remaining = uio_resid(uio);
    while (bytes_remaining > 0 && retCode == 0) {
        /* get the user's data */
		int bytes_to_read = 0;
		
		int bytes_available = kBlockSize - g_bytes_used;
        if (bytes_available == 0)
		{
			random_block(g_random_data, TRUE);
			g_bytes_used = 0;
			bytes_available = kBlockSize;
		}
		
		bytes_to_read = min (bytes_remaining, bytes_available);
		
        retCode = uiomove(((caddr_t)g_random_data)+ g_bytes_used, bytes_to_read, uio);
        g_bytes_used += bytes_to_read;

        if (retCode != 0)
            goto error_exit;
		
		bytes_remaining = uio_resid(uio);
    }
    
    retCode = 0;
    
error_exit:
    lck_mtx_unlock(gYarrowMutex);
    return retCode;
}

/* export good random numbers to the rest of the kernel */
void
read_random(void* buffer, u_int numbytes)
{
    if (gYarrowMutex == 0) { /* are we initialized? */
        PreliminarySetup ();
    }
    
    lck_mtx_lock(gYarrowMutex);

	int bytes_read = 0;

	int bytes_remaining = numbytes;
    while (bytes_remaining > 0) {
        int bytes_to_read = min(bytes_remaining, kBlockSize - g_bytes_used);
        if (bytes_to_read == 0)
		{
			random_block(g_random_data, TRUE);
			g_bytes_used = 0;
			bytes_to_read = min(bytes_remaining, kBlockSize);
		}
		
		memmove ((u_int8_t*) buffer + bytes_read, ((u_int8_t*)g_random_data)+ g_bytes_used, bytes_to_read);
		g_bytes_used += bytes_to_read;
		bytes_read += bytes_to_read;
		bytes_remaining -= bytes_to_read;
    }

    lck_mtx_unlock(gYarrowMutex);
}

/*
 * Return an u_int32_t pseudo-random number.
 */
u_int32_t
RandomULong(void)
{
	u_int32_t buf;
	read_random(&buf, sizeof (buf));
	return (buf);
}
