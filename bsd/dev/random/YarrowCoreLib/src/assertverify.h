/*
 * Copyright (c) 1999, 2000-2001 Apple Computer, Inc. All rights reserved.
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

#ifndef ASSERT_VERIFY_H
#define ASSERT_VERIFY_H

/******************************************************************************
Written by: Jeffrey Richter
Notices: Copyright (c) 1995-1997 Jeffrey Richter
Purpose: Common header file containing handy macros and definitions used
         throughout all the applications in the book.
******************************************************************************/

/* These header functions were copied from the cmnhdr.h file that accompanies 
   Advanced Windows 3rd Edition by Jeffrey Richter */

//////////////////////////// Assert/Verify Macros /////////////////////////////

#if		defined(macintosh) || defined(__APPLE__)
/* TBD */
#define chFAIL(szMSG)                                          
#define chASSERTFAIL(file,line,expr) 
#else
#define chFAIL(szMSG) {                                                   \
      MessageBox(GetActiveWindow(), szMSG,                                \
         __TEXT("Assertion Failed"), MB_OK | MB_ICONERROR);               \
      DebugBreak();                                                       \
   }

/* Put up an assertion failure message box. */
#define chASSERTFAIL(file,line,expr) {                                    \
      TCHAR sz[128];                                                      \
      wsprintf(sz, __TEXT("File %hs, line %d : %hs"), file, line, expr);  \
      chFAIL(sz);                                                         \
   }

#endif	/* macintosh */

/* Put up a message box if an assertion fails in a debug build. */
#ifdef _DEBUG
#define chASSERT(x) if (!(x)) chASSERTFAIL(__FILE__, __LINE__, #x)
#else
#define chASSERT(x)
#endif

/* Assert in debug builds, but don't remove the code in retail builds. */
#ifdef _DEBUG
#define chVERIFY(x) chASSERT(x)
#else
#define chVERIFY(x) (x)
#endif

#endif	/* ASSERT_VERIFY_H */
