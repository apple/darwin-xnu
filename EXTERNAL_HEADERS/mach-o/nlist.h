/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
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
#ifndef _MACHO_NLIST_H_
#define _MACHO_NLIST_H_
/*	$NetBSD: nlist.h,v 1.5 1994/10/26 00:56:11 cgd Exp $	*/

/*-
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)nlist.h	8.2 (Berkeley) 1/21/94
 */

/*
 * Format of a symbol table entry of a Mach-O file.  Modified from the BSD
 * format.  The modifications from the original format were changing n_other
 * (an unused field) to n_sect and the addition of the N_SECT type.  These
 * modifications are required to support symbols in an arbitrary number of
 * sections not just the three sections (text, data and bss) in a BSD file.
 */
struct nlist {
	union {
		char *n_name;	/* for use when in-core */
		long  n_strx;	/* index into the string table */
	} n_un;
	unsigned char n_type;	/* type flag, see below */
	unsigned char n_sect;	/* section number or NO_SECT */
	short	      n_desc;	/* see <mach-o/stab.h> */
	unsigned long n_value;	/* value of this symbol (or stab offset) */
};

/*
 * This is the symbol table entry structure for 64-bit architectures.
 */
struct nlist_64 {
	union {
		uint32_t n_strx;	/* index into the string table */
	} n_un;
	uint8_t n_type;		/* type flag, see below */
	uint8_t n_sect;		/* section number or NO_SECT */
	uint16_t n_desc;	/* see <mach-o/stab.h> */
	uint64_t n_value;	/* value of this symbol (or stab offset) */
};


/*
 * Symbols with a index into the string table of zero (n_un.n_strx == 0) are
 * defined to have a null, "", name.  Therefore all string indexes to non null
 * names must not have a zero string index.  This is bit historical information
 * that has never been well documented.
 */

/*
 * The n_type field really contains three fields:
 *	unsigned char N_STAB:3,
 *		      N_PEXT:1,
 *		      N_TYPE:3,
 *		      N_EXT:1;
 * which are used via the following masks.
 */
#define	N_STAB	0xe0  /* if any of these bits set, a symbolic debugging entry */
#define	N_PEXT	0x10  /* private external symbol bit */
#define	N_TYPE	0x0e  /* mask for the type bits */
#define	N_EXT	0x01  /* external symbol bit, set for external symbols */

/*
 * Only symbolic debugging entries have some of the N_STAB bits set and if any
 * of these bits are set then it is a symbolic debugging entry (a stab).  In
 * which case then the values of the n_type field (the entire field) are given
 * in <mach-o/stab.h>
 */

/*
 * Values for N_TYPE bits of the n_type field.
 */
#define	N_UNDF	0x0		/* undefined, n_sect == NO_SECT */
#define	N_ABS	0x2		/* absolute, n_sect == NO_SECT */
#define	N_SECT	0xe		/* defined in section number n_sect */
#define	N_PBUD	0xc		/* prebound undefined (defined in a dylib) */
#define N_INDR	0xa		/* indirect */

/* 
 * If the type is N_INDR then the symbol is defined to be the same as another
 * symbol.  In this case the n_value field is an index into the string table
 * of the other symbol's name.  When the other symbol is defined then they both
 * take on the defined type and value.
 */

/*
 * If the type is N_SECT then the n_sect field contains an ordinal of the
 * section the symbol is defined in.  The sections are numbered from 1 and 
 * refer to sections in order they appear in the load commands for the file
 * they are in.  This means the same ordinal may very well refer to different
 * sections in different files.
 *
 * The n_value field for all symbol table entries (including N_STAB's) gets
 * updated by the link editor based on the value of it's n_sect field and where
 * the section n_sect references gets relocated.  If the value of the n_sect 
 * field is NO_SECT then it's n_value field is not changed by the link editor.
 */
#define	NO_SECT		0	/* symbol is not in any section */
#define MAX_SECT	255	/* 1 thru 255 inclusive */

/*
 * Common symbols are represented by undefined (N_UNDF) external (N_EXT) types
 * who's values (n_value) are non-zero.  In which case the value of the n_value
 * field is the size (in bytes) of the common symbol.  The n_sect field is set
 * to NO_SECT.
 */

/*
 * To support the lazy binding of undefined symbols in the dynamic link-editor,
 * the undefined symbols in the symbol table (the nlist structures) are marked
 * with the indication if the undefined reference is a lazy reference or
 * non-lazy reference.  If both a non-lazy reference and a lazy reference is
 * made to the same symbol the non-lazy reference takes precedence.  A reference
 * is lazy only when all references to that symbol are made through a symbol
 * pointer in a lazy symbol pointer section.
 *
 * The implementation of marking nlist structures in the symbol table for
 * undefined symbols will be to use some of the bits of the n_desc field as a
 * reference type.  The mask REFERENCE_TYPE will be applied to the n_desc field
 * of an nlist structure for an undefined symbol to determine the type of
 * undefined reference (lazy or non-lazy).
 *
 * The constants for the REFERENCE FLAGS are propagated to the reference table
 * in a shared library file.  In that case the constant for a defined symbol,
 * REFERENCE_FLAG_DEFINED, is also used.
 */
/* Reference type bits of the n_desc field of undefined symbols */
#define REFERENCE_TYPE				0xf
/* types of references */
#define REFERENCE_FLAG_UNDEFINED_NON_LAZY		0
#define REFERENCE_FLAG_UNDEFINED_LAZY			1
#define REFERENCE_FLAG_DEFINED				2
#define REFERENCE_FLAG_PRIVATE_DEFINED			3
#define REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY	4
#define REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY		5

/*
 * To simplify stripping of objects that use are used with the dynamic link
 * editor, the static link editor marks the symbols defined an object that are
 * referenced by a dynamicly bound object (dynamic shared libraries, bundles).
 * With this marking strip knows not to strip these symbols.
 */
#define REFERENCED_DYNAMICALLY	0x0010

/*
 * The non-reference type bits of the n_desc field for global symbols are
 * reserved for the dynamic link editor.  All of these bits must start out
 * zero in the object file.
 */
#define N_DESC_DISCARDED 0x8000	/* symbol is discarded */

#endif
