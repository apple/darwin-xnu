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
 * BSD driver for Non-volatile RAM.
 * Stub functions call the real thing in the Platform Expert.
 *
 * Suurballe 11 Feb 1999
 */

#include <sys/types.h>
#include <sys/param.h>

extern int PEnvopen ( dev_t, int, int, struct proc * );
extern int PEnvclose ( dev_t, int, int, struct proc * );
extern int PEnvread ( long, int, unsigned char *);
extern int PEnvwrite ( long, int, unsigned char * );


nvopen(dev, flag, devtype, pp)
	dev_t dev;
	int flag, devtype;
	struct proc *pp;
{
    return PEnvopen(dev,flag,devtype,pp);
}



nvclose(dev, flag, mode, pp)
	dev_t dev;
	int flag, mode;
	struct proc *pp;
{
    return PEnvclose(dev,flag,mode,pp);
}



nvread(dev, uio, ioflag)
	dev_t dev;
	struct uio *uio;
	int ioflag;
{
    long offset;
    long size;
    int c;
    unsigned char cc;
    long	read = 0;
    int error = 0;

    offset = uio->uio_offset;
    size = uio_resid(uio);

    for (read = 0; read < size; read++, offset++)  {
        error = PEnvread(offset, 1, &cc);
        if ( error ) {
            return error;
        }
        c = (int)cc;
        error = ureadc(c, uio);
        if (error) {
            return error;
        }
    }
    return error;
}



nvwrite(dev_t dev,  struct uio *uio, int ioflag)
{
        long offset;
        long size;
        int c;
        unsigned char cc;
        long	wrote = 0;
        int error = 0;

        offset = uio->uio_offset;
        size = uio_resid(uio);

        for (wrote = 0; wrote < size; wrote++, offset++) {
            c = uwritec(uio);
            if (c < 0) {
                return 0;
            }
            cc = (unsigned char)c;
            error = PEnvwrite(offset, 1, &cc);
        }
        return error;
}
