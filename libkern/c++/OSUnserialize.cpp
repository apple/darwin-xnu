/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */

/*  OSUnserialize.y created by rsulack on Nov 21 1998 */

// 		"classic" parser for unserializing OSContainer objects
//
//  XXX - this code should really be removed!
//	- the XML format is now prefered
//	- this code leaks on syntax errors, the XML doesn't
//	- "classic" looks, reads, ... much better than XML :-(
//	- well except the XML is more efficent on OSData
//
//
// to build :
//	bison -p OSUnserialize OSUnserialize.y
//	head -50 OSUnserialize.y > OSUnserialize.cpp
//	sed -e "s/stdio.h/stddef.h/" < OSUnserialize.tab.c >> OSUnserialize.cpp
//
//	when changing code check in both OSUnserialize.y and OSUnserialize.cpp
//
//
//
//
//		 DO NOT EDIT OSUnserialize.tab.cpp!
//
//			this means you!
//
//
//
//

/*  A Bison parser, made from OSUnserialize.y
    by GNU Bison version 1.28  */

#define YYBISON 1  /* Identify Bison output.  */

#define yyparse OSUnserializeparse
#define yylex OSUnserializelex
#define yyerror OSUnserializeerror
#define yylval OSUnserializelval
#define yychar OSUnserializechar
#define yydebug OSUnserializedebug
#define yynerrs OSUnserializenerrs
#define	NUMBER	257
#define	STRING	258
#define	DATA	259
#define	BOOLEAN	260
#define	SYNTAX_ERROR	261

#line 54 "OSUnserialize.y"

#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSContainers.h>
#include <libkern/c++/OSLib.h>

typedef	struct object {
	struct object	*next;
	struct object	*prev;
	void		*object;
	int		size;		// for data
	union {
		void	*key;		// for dictionary
		long long offset;	// for offset
	} u;

} object_t;

static int yyparse();
static int yyerror(char *s);
static int yylex();

static object_t * newObject();
static void freeObject(object_t *o);

static OSObject *buildOSDictionary(object_t *);
static OSObject *buildOSArray(object_t *);
static OSObject *buildOSSet(object_t *);
static OSObject *buildOSString(object_t *);
static OSObject *buildOSData(object_t *);
static OSObject *buildOSOffset(object_t *);
static OSObject *buildOSBoolean(object_t *o);

static void rememberObject(int, object_t *);
static OSObject *retrieveObject(int);

// temp variable to use during parsing
static object_t *o;

// resultant object of parsed text
static OSObject	*parsedObject;

#define YYSTYPE object_t *

extern "C" {
extern void *kern_os_malloc(size_t size);
extern void *kern_os_realloc(void * addr, size_t size);
extern void kern_os_free(void * addr);
} /* extern "C" */

#define malloc(s) kern_os_malloc(s)
#define realloc(a, s) kern_os_realloc(a, s)
#define free(a) kern_os_free(a)

#ifndef YYSTYPE
#define YYSTYPE int
#endif

#ifndef __cplusplus
#ifndef __STDC__
#define const
#endif
#endif



#define	YYFINAL		43
#define	YYFLAG		-32768
#define	YYNTBASE	19

#define YYTRANSLATE(x) ((unsigned)(x) <= 261 ? yytranslate[x] : 31)

static const char yytranslate[] = {     0,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,    13,
    14,     2,     2,    17,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,    18,    12,     2,
    11,     2,     2,     8,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
    15,     2,    16,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     9,     2,    10,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     1,     3,     4,     5,     6,
     7
};

#if YYDEBUG != 0
static const short yyprhs[] = {     0,
     0,     1,     3,     5,     7,     9,    11,    13,    15,    17,
    19,    22,    26,    29,    33,    35,    38,    43,    46,    50,
    53,    57,    59,    63,    67,    69,    71
};

static const short yyrhs[] = {    -1,
    20,     0,     7,     0,    21,     0,    24,     0,    25,     0,
    29,     0,    28,     0,    27,     0,    30,     0,     8,     3,
     0,    20,     8,     3,     0,     9,    10,     0,     9,    22,
    10,     0,    23,     0,    22,    23,     0,    20,    11,    20,
    12,     0,    13,    14,     0,    13,    26,    14,     0,    15,
    16,     0,    15,    26,    16,     0,    20,     0,    26,    17,
    20,     0,     3,    18,     3,     0,     5,     0,     4,     0,
     6,     0
};

#endif

#if YYDEBUG != 0
static const short yyrline[] = { 0,
   116,   117,   118,   121,   122,   123,   124,   125,   126,   127,
   128,   137,   145,   146,   149,   150,   153,   163,   164,   167,
   168,   171,   176,   187,   195,   200,   205
};
#endif


#if YYDEBUG != 0 || defined (YYERROR_VERBOSE)

static const char * const yytname[] = {   "$","error","$undefined.","NUMBER",
"STRING","DATA","BOOLEAN","SYNTAX_ERROR","'@'","'{'","'}'","'='","';'","'('",
"')'","'['","']'","','","':'","input","object","dict","pairs","pair","array",
"set","elements","offset","data","string","boolean", NULL
};
#endif

static const short yyr1[] = {     0,
    19,    19,    19,    20,    20,    20,    20,    20,    20,    20,
    20,    20,    21,    21,    22,    22,    23,    24,    24,    25,
    25,    26,    26,    27,    28,    29,    30
};

static const short yyr2[] = {     0,
     0,     1,     1,     1,     1,     1,     1,     1,     1,     1,
     2,     3,     2,     3,     1,     2,     4,     2,     3,     2,
     3,     1,     3,     3,     1,     1,     1
};

static const short yydefact[] = {     1,
     0,    26,    25,    27,     3,     0,     0,     0,     0,     2,
     4,     5,     6,     9,     8,     7,    10,     0,    11,    13,
     0,     0,    15,    18,    22,     0,    20,     0,     0,    24,
     0,    14,    16,    19,     0,    21,    12,     0,    23,    17,
     0,     0,     0
};

static const short yydefgoto[] = {    41,
    21,    11,    22,    23,    12,    13,    26,    14,    15,    16,
    17
};

static const short yypact[] = {    12,
   -13,-32768,-32768,-32768,-32768,     9,    33,    46,    -2,     2,
-32768,-32768,-32768,-32768,-32768,-32768,-32768,    25,-32768,-32768,
    21,    59,-32768,-32768,     2,    16,-32768,     7,    31,-32768,
    72,-32768,-32768,-32768,    72,-32768,-32768,    14,     2,-32768,
    40,    44,-32768
};

static const short yypgoto[] = {-32768,
     0,-32768,-32768,    23,-32768,-32768,    38,-32768,-32768,-32768,
-32768
};


#define	YYLAST		87


static const short yytable[] = {    10,
     1,     2,     3,     4,    18,     6,     7,    25,    25,    29,
     8,    19,     9,    27,     1,     2,     3,     4,     5,     6,
     7,    29,    36,    35,     8,    40,     9,    30,    29,    34,
    38,    31,    35,    37,    39,     1,     2,     3,     4,    42,
     6,     7,    20,    43,    33,     8,    28,     9,     1,     2,
     3,     4,     0,     6,     7,     0,     0,     0,     8,    24,
     9,     1,     2,     3,     4,     0,     6,     7,    32,     0,
     0,     8,     0,     9,     1,     2,     3,     4,     0,     6,
     7,     0,     0,     0,     8,     0,     9
};

static const short yycheck[] = {     0,
     3,     4,     5,     6,    18,     8,     9,     8,     9,     8,
    13,     3,    15,    16,     3,     4,     5,     6,     7,     8,
     9,     8,    16,    17,    13,    12,    15,     3,     8,    14,
    31,    11,    17,     3,    35,     3,     4,     5,     6,     0,
     8,     9,    10,     0,    22,    13,     9,    15,     3,     4,
     5,     6,    -1,     8,     9,    -1,    -1,    -1,    13,    14,
    15,     3,     4,     5,     6,    -1,     8,     9,    10,    -1,
    -1,    13,    -1,    15,     3,     4,     5,     6,    -1,     8,
     9,    -1,    -1,    -1,    13,    -1,    15
};
/* -*-C-*-  Note some compilers choke on comments on `#line' lines.  */
#line 3 "/usr/share/bison.simple"
/* This file comes from bison-1.28.  */

/* Skeleton output parser for bison,
   Copyright (C) 1984, 1989, 1990 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* This is the parser code that is written into each bison parser
  when the %semantic_parser declaration is not specified in the grammar.
  It was written by Richard Stallman by simplifying the hairy parser
  used when %semantic_parser is specified.  */

#ifndef YYSTACK_USE_ALLOCA
#ifdef alloca
#define YYSTACK_USE_ALLOCA
#else /* alloca not defined */
#ifdef __GNUC__
#define YYSTACK_USE_ALLOCA
#define alloca __builtin_alloca
#else /* not GNU C.  */
#if (!defined (__STDC__) && defined (sparc)) || defined (__sparc__) || defined (__sparc) || defined (__sgi) || (defined (__sun) && defined (__i386))
#define YYSTACK_USE_ALLOCA
#include <alloca.h>
#else /* not sparc */
/* We think this test detects Watcom and Microsoft C.  */
/* This used to test MSDOS, but that is a bad idea
   since that symbol is in the user namespace.  */
#if (defined (_MSDOS) || defined (_MSDOS_)) && !defined (__TURBOC__)
#if 0 /* No need for malloc.h, which pollutes the namespace;
	 instead, just don't use alloca.  */
#include <malloc.h>
#endif
#else /* not MSDOS, or __TURBOC__ */
#if defined(_AIX)
/* I don't know what this was needed for, but it pollutes the namespace.
   So I turned it off.   rms, 2 May 1997.  */
/* #include <malloc.h>  */
 #pragma alloca
#define YYSTACK_USE_ALLOCA
#else /* not MSDOS, or __TURBOC__, or _AIX */
#if 0
#ifdef __hpux /* haible@ilog.fr says this works for HPUX 9.05 and up,
		 and on HPUX 10.  Eventually we can turn this on.  */
#define YYSTACK_USE_ALLOCA
#define alloca __builtin_alloca
#endif /* __hpux */
#endif
#endif /* not _AIX */
#endif /* not MSDOS, or __TURBOC__ */
#endif /* not sparc */
#endif /* not GNU C */
#endif /* alloca not defined */
#endif /* YYSTACK_USE_ALLOCA not defined */

#ifdef YYSTACK_USE_ALLOCA
#define YYSTACK_ALLOC alloca
#else
#define YYSTACK_ALLOC malloc
#endif

/* Note: there must be only one dollar sign in this file.
   It is replaced by the list of actions, each action
   as one case of the switch.  */

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		-2
#define YYEOF		0
#define YYACCEPT	goto yyacceptlab
#define YYABORT 	goto yyabortlab
#define YYERROR		goto yyerrlab1
/* Like YYERROR except do call yyerror.
   This remains here temporarily to ease the
   transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */
#define YYFAIL		goto yyerrlab
#define YYRECOVERING()  (!!yyerrstatus)
#define YYBACKUP(token, value) \
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    { yychar = (token), yylval = (value);			\
      yychar1 = YYTRANSLATE (yychar);				\
      YYPOPSTACK;						\
      goto yybackup;						\
    }								\
  else								\
    { yyerror ("syntax error: cannot back up"); YYERROR; }	\
while (0)

#define YYTERROR	1
#define YYERRCODE	256

#ifndef YYPURE
#define YYLEX		yylex()
#endif

#ifdef YYPURE
#ifdef YYLSP_NEEDED
#ifdef YYLEX_PARAM
#define YYLEX		yylex(&yylval, &yylloc, YYLEX_PARAM)
#else
#define YYLEX		yylex(&yylval, &yylloc)
#endif
#else /* not YYLSP_NEEDED */
#ifdef YYLEX_PARAM
#define YYLEX		yylex(&yylval, YYLEX_PARAM)
#else
#define YYLEX		yylex(&yylval)
#endif
#endif /* not YYLSP_NEEDED */
#endif

/* If nonreentrant, generate the variables here */

#ifndef YYPURE

int	yychar;			/*  the lookahead symbol		*/
YYSTYPE	yylval;			/*  the semantic value of the		*/
				/*  lookahead symbol			*/

#ifdef YYLSP_NEEDED
YYLTYPE yylloc;			/*  location data for the lookahead	*/
				/*  symbol				*/
#endif

int yynerrs;			/*  number of parse errors so far       */
#endif  /* not YYPURE */

#if YYDEBUG != 0
int yydebug;			/*  nonzero means print parse trace	*/
/* Since this is uninitialized, it does not stop multiple parsers
   from coexisting.  */
#endif

/*  YYINITDEPTH indicates the initial size of the parser's stacks	*/

#ifndef	YYINITDEPTH
#define YYINITDEPTH 200
#endif

/*  YYMAXDEPTH is the maximum size the stacks can grow to
    (effective only if the built-in stack extension method is used).  */

#if YYMAXDEPTH == 0
#undef YYMAXDEPTH
#endif

#ifndef YYMAXDEPTH
#define YYMAXDEPTH 10000
#endif

/* Define __yy_memcpy.  Note that the size argument
   should be passed with type unsigned int, because that is what the non-GCC
   definitions require.  With GCC, __builtin_memcpy takes an arg
   of type size_t, but it can handle unsigned int.  */

#if __GNUC__ > 1		/* GNU C and GNU C++ define this.  */
#define __yy_memcpy(TO,FROM,COUNT)	__builtin_memcpy(TO,FROM,COUNT)
#else				/* not GNU C or C++ */
#ifndef __cplusplus

/* This is the most reliable way to avoid incompatibilities
   in available built-in functions on various systems.  */
static void
__yy_memcpy (to, from, count)
     char *to;
     char *from;
     unsigned int count;
{
  register char *f = from;
  register char *t = to;
  register int i = count;

  while (i-- > 0)
    *t++ = *f++;
}

#else /* __cplusplus */

/* This is the most reliable way to avoid incompatibilities
   in available built-in functions on various systems.  */
static void
__yy_memcpy (char *to, char *from, unsigned int count)
{
  register char *t = to;
  register char *f = from;
  register int i = count;

  while (i-- > 0)
    *t++ = *f++;
}

#endif
#endif

#line 217 "/usr/share/bison.simple"

/* The user can define YYPARSE_PARAM as the name of an argument to be passed
   into yyparse.  The argument should have type void *.
   It should actually point to an object.
   Grammar actions can access the variable by casting it
   to the proper pointer type.  */

#ifdef YYPARSE_PARAM
#ifdef __cplusplus
#define YYPARSE_PARAM_ARG void *YYPARSE_PARAM
#define YYPARSE_PARAM_DECL
#else /* not __cplusplus */
#define YYPARSE_PARAM_ARG YYPARSE_PARAM
#define YYPARSE_PARAM_DECL void *YYPARSE_PARAM;
#endif /* not __cplusplus */
#else /* not YYPARSE_PARAM */
#define YYPARSE_PARAM_ARG
#define YYPARSE_PARAM_DECL
#endif /* not YYPARSE_PARAM */

/* Prevent warning if -Wstrict-prototypes.  */
#ifdef __GNUC__
#ifdef YYPARSE_PARAM
int yyparse (void *);
#else
int yyparse (void);
#endif
#endif

int
yyparse(YYPARSE_PARAM_ARG)
     YYPARSE_PARAM_DECL
{
  register int yystate;
  register int yyn;
  register short *yyssp;
  register YYSTYPE *yyvsp;
  int yyerrstatus;	/*  number of tokens to shift before error messages enabled */
  int yychar1 = 0;		/*  lookahead token as an internal (translated) token number */

  short	yyssa[YYINITDEPTH];	/*  the state stack			*/
  YYSTYPE yyvsa[YYINITDEPTH];	/*  the semantic value stack		*/

  short *yyss = yyssa;		/*  refer to the stacks thru separate pointers */
  YYSTYPE *yyvs = yyvsa;	/*  to allow yyoverflow to reallocate them elsewhere */

#ifdef YYLSP_NEEDED
  YYLTYPE yylsa[YYINITDEPTH];	/*  the location stack			*/
  YYLTYPE *yyls = yylsa;
  YYLTYPE *yylsp;

#define YYPOPSTACK   (yyvsp--, yyssp--, yylsp--)
#else
#define YYPOPSTACK   (yyvsp--, yyssp--)
#endif

  int yystacksize = YYINITDEPTH;
  int yyfree_stacks = 0;

#ifdef YYPURE
  int yychar;
  YYSTYPE yylval;
  int yynerrs;
#ifdef YYLSP_NEEDED
  YYLTYPE yylloc;
#endif
#endif

  YYSTYPE yyval;		/*  the variable used to return		*/
				/*  semantic values from the action	*/
				/*  routines				*/

  int yylen;

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Starting parse\n");
#endif

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss - 1;
  yyvsp = yyvs;
#ifdef YYLSP_NEEDED
  yylsp = yyls;
#endif

/* Push a new state, which is found in  yystate  .  */
/* In all cases, when you get here, the value and location stacks
   have just been pushed. so pushing a state here evens the stacks.  */
yynewstate:

  *++yyssp = yystate;

  if (yyssp >= yyss + yystacksize - 1)
    {
      /* Give user a chance to reallocate the stack */
      /* Use copies of these so that the &'s don't force the real ones into memory. */
      YYSTYPE *yyvs1 = yyvs;
      short *yyss1 = yyss;
#ifdef YYLSP_NEEDED
      YYLTYPE *yyls1 = yyls;
#endif

      /* Get the current used size of the three stacks, in elements.  */
      int size = yyssp - yyss + 1;

#ifdef yyoverflow
      /* Each stack pointer address is followed by the size of
	 the data in use in that stack, in bytes.  */
#ifdef YYLSP_NEEDED
      /* This used to be a conditional around just the two extra args,
	 but that might be undefined if yyoverflow is a macro.  */
      yyoverflow("parser stack overflow",
		 &yyss1, size * sizeof (*yyssp),
		 &yyvs1, size * sizeof (*yyvsp),
		 &yyls1, size * sizeof (*yylsp),
		 &yystacksize);
#else
      yyoverflow("parser stack overflow",
		 &yyss1, size * sizeof (*yyssp),
		 &yyvs1, size * sizeof (*yyvsp),
		 &yystacksize);
#endif

      yyss = yyss1; yyvs = yyvs1;
#ifdef YYLSP_NEEDED
      yyls = yyls1;
#endif
#else /* no yyoverflow */
      /* Extend the stack our own way.  */
      if (yystacksize >= YYMAXDEPTH)
	{
	  yyerror("parser stack overflow");
	  if (yyfree_stacks)
	    {
	      free (yyss);
	      free (yyvs);
#ifdef YYLSP_NEEDED
	      free (yyls);
#endif
	    }
	  return 2;
	}
      yystacksize *= 2;
      if (yystacksize > YYMAXDEPTH)
	yystacksize = YYMAXDEPTH;
#ifndef YYSTACK_USE_ALLOCA
      yyfree_stacks = 1;
#endif
      yyss = (short *) YYSTACK_ALLOC (yystacksize * sizeof (*yyssp));
      __yy_memcpy ((char *)yyss, (char *)yyss1,
		   size * (unsigned int) sizeof (*yyssp));
      yyvs = (YYSTYPE *) YYSTACK_ALLOC (yystacksize * sizeof (*yyvsp));
      __yy_memcpy ((char *)yyvs, (char *)yyvs1,
		   size * (unsigned int) sizeof (*yyvsp));
#ifdef YYLSP_NEEDED
      yyls = (YYLTYPE *) YYSTACK_ALLOC (yystacksize * sizeof (*yylsp));
      __yy_memcpy ((char *)yyls, (char *)yyls1,
		   size * (unsigned int) sizeof (*yylsp));
#endif
#endif /* no yyoverflow */

      yyssp = yyss + size - 1;
      yyvsp = yyvs + size - 1;
#ifdef YYLSP_NEEDED
      yylsp = yyls + size - 1;
#endif

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Stack size increased to %d\n", yystacksize);
#endif

      if (yyssp >= yyss + yystacksize - 1)
	YYABORT;
    }

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Entering state %d\n", yystate);
#endif

  goto yybackup;
 yybackup:

/* Do appropriate processing given the current state.  */
/* Read a lookahead token if we need one and don't already have one.  */
/* yyresume: */

  /* First try to decide what to do without reference to lookahead token.  */

  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* yychar is either YYEMPTY or YYEOF
     or a valid token in external form.  */

  if (yychar == YYEMPTY)
    {
#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Reading a token: ");
#endif
      yychar = YYLEX;
    }

  /* Convert token to internal form (in yychar1) for indexing tables with */

  if (yychar <= 0)		/* This means end of input. */
    {
      yychar1 = 0;
      yychar = YYEOF;		/* Don't call YYLEX any more */

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Now at end of input.\n");
#endif
    }
  else
    {
      yychar1 = YYTRANSLATE(yychar);

#if YYDEBUG != 0
      if (yydebug)
	{
	  fprintf (stderr, "Next token is %d (%s", yychar, yytname[yychar1]);
	  /* Give the individual parser a way to print the precise meaning
	     of a token, for further debugging info.  */
#ifdef YYPRINT
	  YYPRINT (stderr, yychar, yylval);
#endif
	  fprintf (stderr, ")\n");
	}
#endif
    }

  yyn += yychar1;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != yychar1)
    goto yydefault;

  yyn = yytable[yyn];

  /* yyn is what to do for this token type in this state.
     Negative => reduce, -yyn is rule number.
     Positive => shift, yyn is new state.
       New state is final state => don't bother to shift,
       just return success.
     0, or most negative number => error.  */

  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrlab;

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Shift the lookahead token.  */

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Shifting token %d (%s), ", yychar, yytname[yychar1]);
#endif

  /* Discard the token being shifted unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  *++yyvsp = yylval;
#ifdef YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  /* count tokens shifted since error; after three, turn off error status.  */
  if (yyerrstatus) yyerrstatus--;

  yystate = yyn;
  goto yynewstate;

/* Do the default action for the current state.  */
yydefault:

  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;

/* Do a reduction.  yyn is the number of a rule to reduce with.  */
yyreduce:
  yylen = yyr2[yyn];
  if (yylen > 0)
    yyval = yyvsp[1-yylen]; /* implement default value of the action */

#if YYDEBUG != 0
  if (yydebug)
    {
      int i;

      fprintf (stderr, "Reducing via rule %d (line %d), ",
	       yyn, yyrline[yyn]);

      /* Print the symbols being reduced, and their result.  */
      for (i = yyprhs[yyn]; yyrhs[i] > 0; i++)
	fprintf (stderr, "%s ", yytname[yyrhs[i]]);
      fprintf (stderr, " -> %s\n", yytname[yyr1[yyn]]);
    }
#endif


  switch (yyn) {

case 1:
#line 116 "OSUnserialize.y"
{ parsedObject = (OSObject *)NULL; YYACCEPT; ;
    break;}
case 2:
#line 117 "OSUnserialize.y"
{ parsedObject = (OSObject *)yyvsp[0];   YYACCEPT; ;
    break;}
case 3:
#line 118 "OSUnserialize.y"
{ yyerror("syntax error");	   YYERROR; ;
    break;}
case 4:
#line 121 "OSUnserialize.y"
{ yyval = (object_t *)buildOSDictionary(yyvsp[0]); ;
    break;}
case 5:
#line 122 "OSUnserialize.y"
{ yyval = (object_t *)buildOSArray(yyvsp[0]); ;
    break;}
case 6:
#line 123 "OSUnserialize.y"
{ yyval = (object_t *)buildOSSet(yyvsp[0]); ;
    break;}
case 7:
#line 124 "OSUnserialize.y"
{ yyval = (object_t *)buildOSString(yyvsp[0]); ;
    break;}
case 8:
#line 125 "OSUnserialize.y"
{ yyval = (object_t *)buildOSData(yyvsp[0]); ;
    break;}
case 9:
#line 126 "OSUnserialize.y"
{ yyval = (object_t *)buildOSOffset(yyvsp[0]); ;
    break;}
case 10:
#line 127 "OSUnserialize.y"
{ yyval = (object_t *)buildOSBoolean(yyvsp[0]); ;
    break;}
case 11:
#line 128 "OSUnserialize.y"
{ yyval = (object_t *)retrieveObject(yyvsp[0]->u.offset);
				  if (yyval) {
				    ((OSObject *)yyval)->retain();
				  } else { 
				    yyerror("forward reference detected");
				    YYERROR;
				  }
				  freeObject(yyvsp[0]); 
				;
    break;}
case 12:
#line 137 "OSUnserialize.y"
{ yyval = yyvsp[-2]; 
				  rememberObject(yyvsp[0]->u.offset, yyvsp[-2]);
				  freeObject(yyvsp[0]); 
				;
    break;}
case 13:
#line 145 "OSUnserialize.y"
{ yyval = NULL; ;
    break;}
case 14:
#line 146 "OSUnserialize.y"
{ yyval = yyvsp[-1]; ;
    break;}
case 16:
#line 150 "OSUnserialize.y"
{ yyvsp[0]->next = yyvsp[-1]; yyvsp[-1]->prev = yyvsp[0]; yyval = yyvsp[0]; ;
    break;}
case 17:
#line 153 "OSUnserialize.y"
{ yyval = newObject();
				  yyval->next = NULL; 
				  yyval->prev = NULL;
				  yyval->u.key = yyvsp[-3];
				  yyval->object = yyvsp[-1]; 
				;
    break;}
case 18:
#line 163 "OSUnserialize.y"
{ yyval = NULL; ;
    break;}
case 19:
#line 164 "OSUnserialize.y"
{ yyval = yyvsp[-1]; ;
    break;}
case 20:
#line 167 "OSUnserialize.y"
{ yyval = NULL; ;
    break;}
case 21:
#line 168 "OSUnserialize.y"
{ yyval = yyvsp[-1]; ;
    break;}
case 22:
#line 171 "OSUnserialize.y"
{ yyval = newObject(); 
				  yyval->object = yyvsp[0]; 
				  yyval->next = NULL; 
				  yyval->prev = NULL; 
				;
    break;}
case 23:
#line 176 "OSUnserialize.y"
{ o = newObject();
				  o->object = yyvsp[0];
				  o->next = yyvsp[-2];
				  o->prev = NULL; 
				  yyvsp[-2]->prev = o;
				  yyval = o; 
				;
    break;}
case 24:
#line 187 "OSUnserialize.y"
{ yyval = yyvsp[-2];
				  yyval->size = yyvsp[0]->u.offset;
				  freeObject(yyvsp[0]); 
				;
    break;}
}
   /* the action file gets copied in in place of this dollarsign */
#line 543 "/usr/share/bison.simple"

  yyvsp -= yylen;
  yyssp -= yylen;
#ifdef YYLSP_NEEDED
  yylsp -= yylen;
#endif

#if YYDEBUG != 0
  if (yydebug)
    {
      short *ssp1 = yyss - 1;
      fprintf (stderr, "state stack now");
      while (ssp1 != yyssp)
	fprintf (stderr, " %d", *++ssp1);
      fprintf (stderr, "\n");
    }
#endif

  *++yyvsp = yyval;

#ifdef YYLSP_NEEDED
  yylsp++;
  if (yylen == 0)
    {
      yylsp->first_line = yylloc.first_line;
      yylsp->first_column = yylloc.first_column;
      yylsp->last_line = (yylsp-1)->last_line;
      yylsp->last_column = (yylsp-1)->last_column;
      yylsp->text = 0;
    }
  else
    {
      yylsp->last_line = (yylsp+yylen-1)->last_line;
      yylsp->last_column = (yylsp+yylen-1)->last_column;
    }
#endif

  /* Now "shift" the result of the reduction.
     Determine what state that goes to,
     based on the state we popped back to
     and the rule number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTBASE] + *yyssp;
  if (yystate >= 0 && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTBASE];

  goto yynewstate;

yyerrlab:   /* here on detecting error */

  if (! yyerrstatus)
    /* If not already recovering from an error, report this error.  */
    {
      ++yynerrs;

#ifdef YYERROR_VERBOSE
      yyn = yypact[yystate];

      if (yyn > YYFLAG && yyn < YYLAST)
	{
	  int size = 0;
	  char *msg;
	  int x, count;

	  count = 0;
	  /* Start X at -yyn if nec to avoid negative indexes in yycheck.  */
	  for (x = (yyn < 0 ? -yyn : 0);
	       x < (sizeof(yytname) / sizeof(char *)); x++)
	    if (yycheck[x + yyn] == x)
	      size += strlen(yytname[x]) + 15, count++;
	  msg = (char *) malloc(size + 15);
	  if (msg != 0)
	    {
	      strcpy(msg, "parse error");

	      if (count < 5)
		{
		  count = 0;
		  for (x = (yyn < 0 ? -yyn : 0);
		       x < (sizeof(yytname) / sizeof(char *)); x++)
		    if (yycheck[x + yyn] == x)
		      {
			strcat(msg, count == 0 ? ", expecting `" : " or `");
			strcat(msg, yytname[x]);
			strcat(msg, "'");
			count++;
		      }
		}
	      yyerror(msg);
	      free(msg);
	    }
	  else
	    yyerror ("parse error; also virtual memory exceeded");
	}
      else
#endif /* YYERROR_VERBOSE */
	yyerror("parse error");
    }

  goto yyerrlab1;
yyerrlab1:   /* here on error raised explicitly by an action */

  if (yyerrstatus == 3)
    {
      /* if just tried and failed to reuse lookahead token after an error, discard it.  */

      /* return failure if at end of input */
      if (yychar == YYEOF)
	YYABORT;

#if YYDEBUG != 0
      if (yydebug)
	fprintf(stderr, "Discarding token %d (%s).\n", yychar, yytname[yychar1]);
#endif

      yychar = YYEMPTY;
    }

  /* Else will try to reuse lookahead token
     after shifting the error token.  */

  yyerrstatus = 3;		/* Each real token shifted decrements this */

  goto yyerrhandle;

yyerrdefault:  /* current state does not do anything special for the error token. */

#if 0
  /* This is wrong; only states that explicitly want error tokens
     should shift them.  */
  yyn = yydefact[yystate];  /* If its default is to accept any token, ok.  Otherwise pop it.*/
  if (yyn) goto yydefault;
#endif

yyerrpop:   /* pop the current state because it cannot handle the error token */

  if (yyssp == yyss) YYABORT;
  yyvsp--;
  yystate = *--yyssp;
#ifdef YYLSP_NEEDED
  yylsp--;
#endif

#if YYDEBUG != 0
  if (yydebug)
    {
      short *ssp1 = yyss - 1;
      fprintf (stderr, "Error: state stack now");
      while (ssp1 != yyssp)
	fprintf (stderr, " %d", *++ssp1);
      fprintf (stderr, "\n");
    }
#endif

yyerrhandle:

  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yyerrdefault;

  yyn += YYTERROR;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != YYTERROR)
    goto yyerrdefault;

  yyn = yytable[yyn];
  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrpop;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrpop;

  if (yyn == YYFINAL)
    YYACCEPT;

#if YYDEBUG != 0
  if (yydebug)
    fprintf(stderr, "Shifting error token, ");
#endif

  *++yyvsp = yylval;
#ifdef YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  yystate = yyn;
  goto yynewstate;

 yyacceptlab:
  /* YYACCEPT comes here.  */
  if (yyfree_stacks)
    {
      free (yyss);
      free (yyvs);
#ifdef YYLSP_NEEDED
      free (yyls);
#endif
    }
  return 0;

 yyabortlab:
  /* YYABORT comes here.  */
  if (yyfree_stacks)
    {
      free (yyss);
      free (yyvs);
#ifdef YYLSP_NEEDED
      free (yyls);
#endif
    }
  return 1;
}
#line 208 "OSUnserialize.y"

     
static int		lineNumber = 0;
static const char	*parseBuffer;
static int		parseBufferIndex;

#define currentChar()	(parseBuffer[parseBufferIndex])
#define nextChar()	(parseBuffer[++parseBufferIndex])
#define prevChar()	(parseBuffer[parseBufferIndex - 1])

#define isSpace(c)	((c) == ' ' || (c) == '\t')
#define isAlpha(c)	(((c) >= 'A' && (c) <= 'Z') || ((c) >= 'a' && (c) <= 'z'))
#define isDigit(c)	((c) >= '0' && (c) <= '9')
#define isAlphaDigit(c)	((c) >= 'a' && (c) <= 'f')
#define isHexDigit(c)	(isDigit(c) || isAlphaDigit(c))
#define isAlphaNumeric(c) (isAlpha(c) || isDigit(c) || ((c) == '-')) 

static char yyerror_message[128];

int
yyerror(char *s)  /* Called by yyparse on error */
{
	sprintf(yyerror_message, "OSUnserialize: %s near line %d\n", s, lineNumber);
	return 0;
}

int
yylex()
{
	int c;

	if (parseBufferIndex == 0) lineNumber = 1;

 top:
	c = currentChar();

	/* skip white space  */
	if (isSpace(c)) while ((c = nextChar()) != 0 && isSpace(c)) {};

	/* skip over comments */
	if (c == '#') while ((c = nextChar()) != 0 && c != '\n') {};

	/* keep track of line number, don't return \n's */
	if (c == '\n') {
		lineNumber++;
		(void)nextChar();
		goto top;
	}

	/* parse boolean */
	if (c == '.') {
		bool boolean = false;
		if (nextChar() == 't') {
			if (nextChar() != 'r') return SYNTAX_ERROR;
			if (nextChar() != 'u') return SYNTAX_ERROR;
			if (nextChar() != 'e') return SYNTAX_ERROR;
			boolean = true;
		} else {
			if (currentChar() != 'f') return SYNTAX_ERROR;
			if (nextChar() != 'a') return SYNTAX_ERROR;
			if (nextChar() != 'l') return SYNTAX_ERROR;
			if (nextChar() != 's') return SYNTAX_ERROR;
			if (nextChar() != 'e') return SYNTAX_ERROR;
		}
		if (nextChar() != '.') return SYNTAX_ERROR;
		/* skip over dot */
		(void)nextChar();

		yylval = (object_t *)boolean;
		return BOOLEAN;
	}

	/* parse unquoted string */
	if (isAlpha(c)) {
		int start, length;
		char * tempString;

		start = parseBufferIndex;
		/* find end of string */
		while (isAlphaNumeric(c)) { 
			c = nextChar();
		}
		length = parseBufferIndex - start;

		/* copy to null terminated buffer */
		tempString = (char *)malloc(length + 1);
		if (tempString == 0) {
			printf("OSUnserialize: can't alloc temp memory\n");
			return 0;
		}
		bcopy(&parseBuffer[start], tempString, length);
		tempString[length] = 0;
		yylval = (object_t *)tempString;
		return STRING;
	}

	/* parse quoted string */
	if (c == '"' || c == '\'') {
		int start, length;
		char * tempString;
		char quoteChar = c;

		start = parseBufferIndex + 1;		// skip quote
		/* find end of string, line, buffer */
		while ((c = nextChar()) != quoteChar) {
			if (c == '\\') c = nextChar();
			if (c == '\n') lineNumber++;
			if (c == 0) return SYNTAX_ERROR;
		}
		length = parseBufferIndex - start;
		/* skip over trailing quote */
		(void)nextChar();
		/* copy to null terminated buffer */
		tempString = (char *)malloc(length + 1);
		if (tempString == 0) {
			printf("OSUnserialize: can't alloc temp memory\n");
			return 0;
		}

		int to = 0;
		for (int from=start; from < parseBufferIndex; from++) {
			// hack - skip over backslashes
			if (parseBuffer[from] == '\\') {
				length--;
				continue;
			}
			tempString[to] = parseBuffer[from]; 
			to++;
		}
		tempString[length] = 0;
		yylval = (object_t *)tempString;
		return STRING;
	}

	/* process numbers */
	if (isDigit (c))
	{
		unsigned long long n = 0;
		int base = 10;

		if (c == '0') {
			c = nextChar();
			if (c == 'x') {
				base = 16;
				c = nextChar();
			}
		}
		if (base == 10) {
			while(isDigit(c)) {
				n = (n * base + c - '0');
				c = nextChar();
			}
		} else {
			while(isHexDigit(c)) {
				if (isDigit(c)) {
					n = (n * base + c - '0');
				} else {
					n = (n * base + 0xa + c - 'a');
				}
				c = nextChar();
			}
		}

		yylval = newObject();
		yylval->u.offset = n;
			
		return NUMBER;
	}

#define OSDATA_ALLOC_SIZE 4096
	
	/* process data */
	if (c == '<') {
		unsigned char *d, *start, *lastStart;

		start = lastStart = d = (unsigned char *)malloc(OSDATA_ALLOC_SIZE);
		c = nextChar();	// skip over '<'
		while (c != 0 && c != '>') {

			if (isSpace(c)) while ((c = nextChar()) != 0 && isSpace(c)) {};
			if (c == '#') while ((c = nextChar()) != 0 && c != '\n') {};
			if (c == '\n') {
				lineNumber++;
				c = nextChar();
				continue;
			}

			// get high nibble
			if (!isHexDigit(c)) break;
			if (isDigit(c)) {
				*d = (c - '0') << 4;
			} else {
				*d =  (0xa + (c - 'a')) << 4;
			}

			// get low nibble
			c = nextChar();
			if (!isHexDigit(c)) break;
			if (isDigit(c)) {
				*d |= c - '0';
			} else {
				*d |= 0xa + (c - 'a');
			}
	
			d++;
			if ((d - lastStart) >= OSDATA_ALLOC_SIZE) {
				int oldsize = d - start;
				start = (unsigned char *)realloc(start, oldsize + OSDATA_ALLOC_SIZE);
				d = lastStart = start + oldsize;
			}
			c = nextChar();
		}
		if (c != '>' ) {
			free(start);
			return SYNTAX_ERROR;
		}

		// got it!
		yylval = newObject();
		yylval->object = start;
		yylval->size = d - start;

		(void)nextChar();	// skip over '>'
		return DATA;
	}


	/* return single chars, move pointer to next char */
	(void)nextChar();
	return c;
}

// !@$&)(^Q$&*^!$(*!@$_(^%_(*Q#$(_*&!$_(*&!$_(*&!#$(*!@&^!@#%!_!#
// !@$&)(^Q$&*^!$(*!@$_(^%_(*Q#$(_*&!$_(*&!$_(*&!#$(*!@&^!@#%!_!#
// !@$&)(^Q$&*^!$(*!@$_(^%_(*Q#$(_*&!$_(*&!$_(*&!#$(*!@&^!@#%!_!#

#ifdef DEBUG
int debugUnserializeAllocCount = 0;
#endif

object_t *
newObject()
{
#ifdef DEBUG
	debugUnserializeAllocCount++;
#endif
	return (object_t *)malloc(sizeof(object_t));
}

void
freeObject(object_t *o)
{
#ifdef DEBUG
	debugUnserializeAllocCount--;
#endif
	free(o);
}

static OSDictionary *tags;

static void 
rememberObject(int tag, object_t *o)
{
	char key[16];
	sprintf(key, "%u", tag);

	tags->setObject(key, (OSObject *)o);
}

static OSObject *
retrieveObject(int tag)
{
	char key[16];
	sprintf(key, "%u", tag);

	return tags->getObject(key);
}

OSObject *
buildOSDictionary(object_t *o)
{
	object_t *temp, *last = o;
	int count = 0;

	// get count and last object
	while (o) {
		count++;
		last = o;
		o = o->next;
	}
	o = last;

	OSDictionary *d = OSDictionary::withCapacity(count);

	while (o) {
#ifdef metaclass_stuff_worksXXX
		if (((OSObject *)o->u.key)->metaCast("OSSymbol")) {
			// XXX the evil frontdoor
			d->setObject((OSSymbol *)o->u.key, (OSObject *)o->object);
		} else {
                        // If it isn't a symbol, I hope it's a string!
			d->setObject((OSString *)o->u.key, (OSObject *)o->object);
		}
#else
		d->setObject((OSString *)o->u.key, (OSObject *)o->object);
#endif
		((OSObject *)o->object)->release();
		((OSObject *)o->u.key)->release();
		temp = o;
		o = o->prev;
		freeObject(temp);
	}
	return d;
};

OSObject *
buildOSArray(object_t *o)
{
	object_t *temp, *last = o;
	int count = 0;

	// get count and last object
	while (o) {
		count++;
		last = o;
		o = o->next;
	}
	o = last;

	OSArray *a = OSArray::withCapacity(count);

	while (o) {
		a->setObject((OSObject *)o->object);
		((OSObject *)o->object)->release();
		temp = o;
		o = o->prev;
		freeObject(temp);
	}
	return a;
};

OSObject *
buildOSSet(object_t *o)
{
	OSArray *a = (OSArray *)buildOSArray(o);
	OSSet *s = OSSet::withArray(a, a->getCapacity());

	a->release();
	return s;
};

OSObject *
buildOSString(object_t *o)
{
	OSString *s = OSString::withCString((char *)o);

	free(o);

	return s;
};

OSObject *
buildOSData(object_t *o)
{
	OSData *d;

	if (o->size) {
		d = OSData::withBytes(o->object, o->size);
	} else {
		d = OSData::withCapacity(0);
	}
	free(o->object);
	freeObject(o);
	return d;
};

OSObject *
buildOSOffset(object_t *o)
{
	OSNumber *off = OSNumber::withNumber(o->u.offset, o->size);
	freeObject(o);
	return off;
};

OSObject *
buildOSBoolean(object_t *o)
{
	OSBoolean *b = OSBoolean::withBoolean((bool)o);
	return b;
};

__BEGIN_DECLS
#include <kern/lock.h>
__END_DECLS

static mutex_t *lock = 0;

OSObject*
OSUnserialize(const char *buffer, OSString **errorString)
{
	OSObject *object;

	if (!lock) {
		lock = mutex_alloc(0);
		mutex_lock(lock);
	} else {
		mutex_lock(lock);

	}

#ifdef DEBUG
	debugUnserializeAllocCount = 0;
#endif
	yyerror_message[0] = 0;	//just in case
	parseBuffer = buffer;
	parseBufferIndex = 0;
	tags = OSDictionary::withCapacity(128);
	if (yyparse() == 0) {
		object = parsedObject;
		if (errorString) *errorString = 0;
	} else {
		object = 0;
		if (errorString)
			*errorString = OSString::withCString(yyerror_message);
	}

	tags->release();
#ifdef DEBUG
	if (debugUnserializeAllocCount) {
		printf("OSUnserialize: allocation check failed, count = %d.\n", 
		       debugUnserializeAllocCount);
	}
#endif
	mutex_unlock(lock);

	return object;
}


//
//
//
//
//
//		 DO NOT EDIT OSUnserialize.cpp!
//
//			this means you!
//
//
//
//
//
