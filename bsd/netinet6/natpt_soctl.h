/*	$KAME: natpt_soctl.h,v 1.8 2000/03/25 07:23:56 sumikawa Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* cmd for use with ioctl at the socket						*/
/*	_IO()		no parameters						*/
/*	_IOR()		copy out parameters					*/
/*	_IOW()		copy in	 parameters					*/
/*	_IOWR()		copy in/out parameters					*/

#define	SIOCSETIF	_IOW ('n',   0, struct natpt_msgBox)	/* Set interface side	*/
#define SIOCGETIF	_IOWR('n',   1, struct natpt_msgBox)	/* Get interface sidde	*/
#define	SIOCENBTRANS	_IOW ('n',   2, struct natpt_msgBox)	/* Enable  translation	*/
#define SIOCDSBTRANS	_IOW ('n',   3, struct natpt_msgBox)	/* Disable translation	*/
#define	SIOCSETRULE	_IOW ('n',   4, struct natpt_msgBox)	/* Set rule		*/
#define	SIOCGETRULE	_IOWR('n',   5, struct natpt_msgBox)	/* Get rule		*/
#define SIOCFLUSHRULE	_IOW ('n',   6, struct natpt_msgBox)	/* Flush rule		*/
#define	SIOCSETPREFIX	_IOW ('n',   8, struct natpt_msgBox)	/* Set prefix		*/
#define	SIOCGETPREFIX	_IOWR('n',   9, struct natpt_msgBox)	/* Get prefix		*/
#define	SIOCSETVALUE	_IOW ('n',  10, struct natpt_msgBox)	/* Set value		*/
#define	SIOCGETVALUE	_IOW ('n',  11, struct natpt_msgBox)	/* Get value		*/

#define	SIOCTESTLOG	_IOW ('n',  12, struct natpt_msgBox)	/* Test log		*/

#define SIOCBREAK	_IO  ('n', 255)				/* stop			*/


typedef	struct natpt_msgBox				/* sizeof():  44[byte]	*/
{
    int		 flags;
/* in case SIOC(GET|SET)IF		*/
#define	IF_EXTERNAL		(0x01)
#define	IF_INTERNAL		(0x02)

/* in case SIOT(SET|GET)RULE		*/
#ifndef NATPT_STATIC
#define	NATPT_STATIC		(0x01)
#define	NATPT_DYNAMIC		(0x02)
#define NATPT_FAITH		(0x03)
#endif

/* in case SIOCFLUSHRULE ... bitwise	*/
#define	FLUSH_STATIC		(0x01)
#define	FLUSH_DYNAMIC		(0x02)

/* in case SIOC(GET|SET)PREFIX		*/
#define	PREFIX_FAITH		(0x01)
#define	PREFIX_NATPT		(0x02)

/* in case SIOC(GET|SET)VALUE		*/
#define	NATPT_DEBUG		(0x01)		/* natpt_debug := <value>	*/
#define	NATPT_DUMP		(0x02)		/* natpt_dump  := <value>	*/

    int		 size;				/* sizeof(*freight)		*/
    char	*freight;
    union
    {
	char	 M_ifName[IFNAMSIZ];
	char	 M_aux[32];
    }		 M_dat;
}   natpt_msgBox;

#define	m_ifName	M_dat.M_ifName
#define	m_aux		M_dat.M_aux
