/*
 ---------------------------------------------------------------------------
 Copyright (c) 2003, Dr Brian Gladman, Worcester, UK.   All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software in both source and binary
 form is allowed (with or without changes) provided that:

   1. distributions of this source code include the above copyright
      notice, this list of conditions and the following disclaimer;

   2. distributions in binary form include the above copyright
      notice, this list of conditions and the following disclaimer
      in the documentation and/or other associated materials;

   3. the copyright holder's name is not used to endorse products
      built using this software without specific written permission.

 ALTERNATIVELY, provided that this notice is retained in full, this product
 may be distributed under the terms of the GNU General Public License (GPL),
 in which case the provisions of the GPL apply INSTEAD OF those given above.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue 31/01/2006
*/

#ifndef EDEFS_H
#define EDEFS_H
#if defined(__cplusplus)
extern "C"
{
#endif

#define IS_LITTLE_ENDIAN   1234 /* byte 0 is least significant (i386) */
#define IS_BIG_ENDIAN      4321 /* byte 0 is most significant (mc68k) */

#if defined(__GNUC__) || defined(__GNU_LIBRARY__)
#  if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#    include <sys/endian.h>
#  elif defined( BSD ) && ( BSD >= 199103 ) || defined( __DJGPP__ ) || defined( __CYGWIN32__ ) 
#      include <machine/endian.h>
#  elif defined(__APPLE__)
#    if defined(__BIG_ENDIAN__) && !defined( BIG_ENDIAN )
#      define BIG_ENDIAN
#    elif defined(__LITTLE_ENDIAN__) && !defined( LITTLE_ENDIAN )
#      define LITTLE_ENDIAN
#    endif
#  elif !defined( __MINGW32__ )
#    include <endian.h>
#    if !defined(__BEOS__)
#      include <byteswap.h>
#    endif
#  endif
#endif

#if !defined(PLATFORM_BYTE_ORDER)
#  if defined(LITTLE_ENDIAN) || defined(BIG_ENDIAN)
#    if    defined(LITTLE_ENDIAN) && !defined(BIG_ENDIAN)
#      define PLATFORM_BYTE_ORDER IS_LITTLE_ENDIAN
#    elif !defined(LITTLE_ENDIAN) &&  defined(BIG_ENDIAN)
#      define PLATFORM_BYTE_ORDER IS_BIG_ENDIAN
#    elif defined(BYTE_ORDER) && (BYTE_ORDER == LITTLE_ENDIAN)
#      define PLATFORM_BYTE_ORDER IS_LITTLE_ENDIAN
#    elif defined(BYTE_ORDER) && (BYTE_ORDER == BIG_ENDIAN)
#      define PLATFORM_BYTE_ORDER IS_BIG_ENDIAN
#    endif
#  elif defined(_LITTLE_ENDIAN) || defined(_BIG_ENDIAN)
#    if    defined(_LITTLE_ENDIAN) && !defined(_BIG_ENDIAN)
#      define PLATFORM_BYTE_ORDER IS_LITTLE_ENDIAN
#    elif !defined(_LITTLE_ENDIAN) &&  defined(_BIG_ENDIAN)
#      define PLATFORM_BYTE_ORDER IS_BIG_ENDIAN
#    elif defined(_BYTE_ORDER) && (_BYTE_ORDER == _LITTLE_ENDIAN)
#      define PLATFORM_BYTE_ORDER IS_LITTLE_ENDIAN
#    elif defined(_BYTE_ORDER) && (_BYTE_ORDER == _BIG_ENDIAN)
#      define PLATFORM_BYTE_ORDER IS_BIG_ENDIAN
#   endif
#  elif defined(__LITTLE_ENDIAN__) || defined(__BIG_ENDIAN__)
#    if    defined(__LITTLE_ENDIAN__) && !defined(__BIG_ENDIAN__)
#      define PLATFORM_BYTE_ORDER IS_LITTLE_ENDIAN
#    elif !defined(__LITTLE_ENDIAN__) &&  defined(__BIG_ENDIAN__)
#      define PLATFORM_BYTE_ORDER IS_BIG_ENDIAN
#    elif defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __LITTLE_ENDIAN__)
#      define PLATFORM_BYTE_ORDER IS_LITTLE_ENDIAN
#    elif defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __BIG_ENDIAN__)
#      define PLATFORM_BYTE_ORDER IS_BIG_ENDIAN
#    endif
#  endif
#endif

/*  if the platform is still unknown, try to find its byte order    */
/*  from commonly used machine defines                              */

#if !defined(PLATFORM_BYTE_ORDER)

#if   defined( __alpha__ ) || defined( __alpha ) || defined( i386 )       || \
      defined( __i386__ )  || defined( _M_I86 )  || defined( _M_IX86 )    || \
      defined( __OS2__ )   || defined( sun386 )  || defined( __TURBOC__ ) || \
      defined( vax )       || defined( vms )     || defined( VMS )        || \
      defined( __VMS )     || defined( _M_X64 )
#  define PLATFORM_BYTE_ORDER IS_LITTLE_ENDIAN

#elif defined( AMIGA )    || defined( applec )  || defined( __AS400__ )  || \
      defined( _CRAY )    || defined( __hppa )  || defined( __hp9000 )   || \
      defined( ibm370 )   || defined( mc68000 ) || defined( m68k )       || \
      defined( __MRC__ )  || defined( __MVS__ ) || defined( __MWERKS__ ) || \
      defined( sparc )    || defined( __sparc)  || defined( SYMANTEC_C ) || \
      defined( __TANDEM ) || defined( THINK_C ) || defined( __VMCMS__ )  || \
	  defined( __VOS__ )
#  define PLATFORM_BYTE_ORDER IS_BIG_ENDIAN

#elif 0     /* **** EDIT HERE IF NECESSARY **** */
#  define PLATFORM_BYTE_ORDER IS_LITTLE_ENDIAN
#elif 0     /* **** EDIT HERE IF NECESSARY **** */
#  define PLATFORM_BYTE_ORDER IS_BIG_ENDIAN
#else
#  error Please edit edefs.h (lines 117 or 119) to set the platform byte order
#endif

#endif

#if defined(__cplusplus)
}
#endif
#endif
