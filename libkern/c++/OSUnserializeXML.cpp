/*
 * Copyright (c) 1999-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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

/*
 * HISTORY
 *
 * OSUnserializeXML.y created by rsulack on Tue Oct 12 1999
 */

// parser for unserializing OSContainer objects serialized to XML
//
// to build :
//	bison -p OSUnserializeXML OSUnserializeXML.y
//	head -50 OSUnserializeXML.y > OSUnserializeXML.cpp
//	sed -e "s/#include <stdio.h>//" < OSUnserializeXML.tab.c >> OSUnserializeXML.cpp
//
//	when changing code check in both OSUnserializeXML.y and OSUnserializeXML.cpp
//
//
//
//
//
//		 DO NOT EDIT OSUnserializeXML.cpp!
//
//			this means you!
//
//
//
//
//
//

/*  A Bison parser, made from OSUnserializeXML.y
    by GNU Bison version 1.28  */

#define YYBISON 1  /* Identify Bison output.  */

#define yyparse OSUnserializeXMLparse
#define yylex OSUnserializeXMLlex
#define yyerror OSUnserializeXMLerror
#define yylval OSUnserializeXMLlval
#define yychar OSUnserializeXMLchar
#define yydebug OSUnserializeXMLdebug
#define yynerrs OSUnserializeXMLnerrs
#define	ARRAY	257
#define	BOOLEAN	258
#define	DATA	259
#define	DICTIONARY	260
#define	IDREF	261
#define	KEY	262
#define	NUMBER	263
#define	SET	264
#define	STRING	265
#define	SYNTAX_ERROR	266

#line 55 "OSUnserializeXML.y"

#include <string.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSContainers.h>
#include <libkern/c++/OSLib.h>

#define YYSTYPE object_t *
#define YYPARSE_PARAM	state
#define YYLEX_PARAM	state

// this is the internal struct used to hold objects on parser stack
// it represents objects both before and after they have been created
typedef	struct object {
	struct object	*next;
	struct object	*free;
	struct object	*elements;
	OSObject	*object;
	OSString	*key;			// for dictionary
	int		size;
	void		*data;			// for data
	char		*string;		// for string & symbol
	long long 	number;			// for number
	int		idref;
} object_t;

// this code is reentrant, this structure contains all
// state information for the parsing of a single buffer
typedef struct parser_state {
	const char	*parseBuffer;		// start of text to be parsed
	int		parseBufferIndex;	// current index into text
	int		lineNumber;		// current line number
	object_t	*objects;		// internal objects in use
	object_t	*freeObjects;		// internal objects that are free
	OSDictionary	*tags;			// used to remember "ID" tags
	OSString	**errorString;		// parse error with line
	OSObject	*parsedObject;		// resultant object of parsed text
} parser_state_t;

#define STATE		((parser_state_t *)state)

#undef yyerror 	
#define yyerror(s)	OSUnserializeerror(STATE, (s))
static int		OSUnserializeerror(parser_state_t *state, char *s);

static int		yylex(YYSTYPE *lvalp, parser_state_t *state);
static int		yyparse(void * state);

static object_t 	*newObject(parser_state_t *state);
static void 		freeObject(parser_state_t *state, object_t *o);
static void		rememberObject(parser_state_t *state, int tag, OSObject *o);
static object_t		*retrieveObject(parser_state_t *state, int tag);
static void		cleanupObjects(parser_state_t *state);

static object_t		*buildDictionary(parser_state_t *state, object_t *o);
static object_t		*buildArray(parser_state_t *state, object_t *o);
static object_t		*buildSet(parser_state_t *state, object_t *o);
static object_t		*buildString(parser_state_t *state, object_t *o);
static object_t		*buildData(parser_state_t *state, object_t *o);
static object_t		*buildNumber(parser_state_t *state, object_t *o);
static object_t		*buildBoolean(parser_state_t *state, object_t *o);

extern "C" {
extern void		*kern_os_malloc(size_t size);
extern void		*kern_os_realloc(void * addr, size_t size);
extern void		kern_os_free(void * addr);

//XXX shouldn't have to define these
extern long		strtol(const char *, char **, int);
extern unsigned long	strtoul(const char *, char **, int);

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



#define	YYFINAL		40
#define	YYFLAG		-32768
#define	YYNTBASE	19

#define YYTRANSLATE(x) ((unsigned)(x) <= 266 ? yytranslate[x] : 33)

static const char yytranslate[] = {     0,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,    15,
    16,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
    17,     2,    18,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
     2,     2,    13,     2,    14,     2,     2,     2,     2,     2,
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
     7,     8,     9,    10,    11,    12
};

#if YYDEBUG != 0
static const short yyprhs[] = {     0,
     0,     1,     3,     5,     7,     9,    11,    13,    15,    17,
    19,    21,    24,    28,    30,    32,    35,    38,    40,    43,
    47,    49,    52,    56,    58,    60,    63,    65,    67,    69,
    71
};

static const short yyrhs[] = {    -1,
    20,     0,    12,     0,    21,     0,    25,     0,    26,     0,
    32,     0,    29,     0,    31,     0,    28,     0,    30,     0,
    13,    14,     0,    13,    22,    14,     0,     6,     0,    23,
     0,    22,    23,     0,    24,    20,     0,     8,     0,    15,
    16,     0,    15,    27,    16,     0,     3,     0,    17,    18,
     0,    17,    27,    18,     0,    10,     0,    20,     0,    27,
    20,     0,     4,     0,     5,     0,     7,     0,     9,     0,
    11,     0
};

#endif

#if YYDEBUG != 0
static const short yyrline[] = { 0,
   144,   147,   152,   157,   158,   159,   160,   161,   162,   163,
   164,   177,   180,   183,   186,   187,   192,   201,   206,   209,
   212,   215,   218,   221,   224,   227,   234,   237,   240,   243,
   246
};
#endif


#if YYDEBUG != 0 || defined (YYERROR_VERBOSE)

static const char * const yytname[] = {   "$","error","$undefined.","ARRAY",
"BOOLEAN","DATA","DICTIONARY","IDREF","KEY","NUMBER","SET","STRING","SYNTAX_ERROR",
"'{'","'}'","'('","')'","'['","']'","input","object","dict","pairs","pair","key",
"array","set","elements","boolean","data","idref","number","string", NULL
};
#endif

static const short yyr1[] = {     0,
    19,    19,    19,    20,    20,    20,    20,    20,    20,    20,
    20,    21,    21,    21,    22,    22,    23,    24,    25,    25,
    25,    26,    26,    26,    27,    27,    28,    29,    30,    31,
    32
};

static const short yyr2[] = {     0,
     0,     1,     1,     1,     1,     1,     1,     1,     1,     1,
     1,     2,     3,     1,     1,     2,     2,     1,     2,     3,
     1,     2,     3,     1,     1,     2,     1,     1,     1,     1,
     1
};

static const short yydefact[] = {     1,
    21,    27,    28,    14,    29,    30,    24,    31,     3,     0,
     0,     0,     2,     4,     5,     6,    10,     8,    11,     9,
     7,    18,    12,     0,    15,     0,    19,    25,     0,    22,
     0,    13,    16,    17,    20,    26,    23,     0,     0,     0
};

static const short yydefgoto[] = {    38,
    28,    14,    24,    25,    26,    15,    16,    29,    17,    18,
    19,    20,    21
};

static const short yypact[] = {    45,
-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,     4,
    60,    -2,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
-32768,-32768,-32768,     6,-32768,    90,-32768,-32768,    75,-32768,
    29,-32768,-32768,-32768,-32768,-32768,-32768,    10,    17,-32768
};

static const short yypgoto[] = {-32768,
     0,-32768,-32768,   -18,-32768,-32768,-32768,     7,-32768,-32768,
-32768,-32768,-32768
};


#define	YYLAST		107


static const short yytable[] = {    13,
     1,     2,     3,     4,     5,    33,     6,     7,     8,    39,
    10,    22,    11,    22,    12,    30,    40,    23,    31,    32,
     0,     0,     0,     0,     0,    34,     0,     0,    36,     0,
    36,     1,     2,     3,     4,     5,     0,     6,     7,     8,
     0,    10,     0,    11,     0,    12,    37,     1,     2,     3,
     4,     5,     0,     6,     7,     8,     9,    10,     0,    11,
     0,    12,     1,     2,     3,     4,     5,     0,     6,     7,
     8,     0,    10,     0,    11,    27,    12,     1,     2,     3,
     4,     5,     0,     6,     7,     8,     0,    10,     0,    11,
    35,    12,     1,     2,     3,     4,     5,     0,     6,     7,
     8,     0,    10,     0,    11,     0,    12
};

static const short yycheck[] = {     0,
     3,     4,     5,     6,     7,    24,     9,    10,    11,     0,
    13,     8,    15,     8,    17,    18,     0,    14,    12,    14,
    -1,    -1,    -1,    -1,    -1,    26,    -1,    -1,    29,    -1,
    31,     3,     4,     5,     6,     7,    -1,     9,    10,    11,
    -1,    13,    -1,    15,    -1,    17,    18,     3,     4,     5,
     6,     7,    -1,     9,    10,    11,    12,    13,    -1,    15,
    -1,    17,     3,     4,     5,     6,     7,    -1,     9,    10,
    11,    -1,    13,    -1,    15,    16,    17,     3,     4,     5,
     6,     7,    -1,     9,    10,    11,    -1,    13,    -1,    15,
    16,    17,     3,     4,     5,     6,     7,    -1,     9,    10,
    11,    -1,    13,    -1,    15,    -1,    17
};
#define YYPURE 1

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
#line 144 "OSUnserializeXML.y"
{ yyerror("unexpected end of buffer");
				  YYERROR;
				;
    break;}
case 2:
#line 147 "OSUnserializeXML.y"
{ STATE->parsedObject = yyvsp[0]->object;
				  yyvsp[0]->object = 0;
				  freeObject(STATE, yyvsp[0]);
				  YYACCEPT;
				;
    break;}
case 3:
#line 152 "OSUnserializeXML.y"
{ yyerror("syntax error");
				  YYERROR;
				;
    break;}
case 4:
#line 157 "OSUnserializeXML.y"
{ yyval = buildDictionary(STATE, yyvsp[0]); ;
    break;}
case 5:
#line 158 "OSUnserializeXML.y"
{ yyval = buildArray(STATE, yyvsp[0]); ;
    break;}
case 6:
#line 159 "OSUnserializeXML.y"
{ yyval = buildSet(STATE, yyvsp[0]); ;
    break;}
case 7:
#line 160 "OSUnserializeXML.y"
{ yyval = buildString(STATE, yyvsp[0]); ;
    break;}
case 8:
#line 161 "OSUnserializeXML.y"
{ yyval = buildData(STATE, yyvsp[0]); ;
    break;}
case 9:
#line 162 "OSUnserializeXML.y"
{ yyval = buildNumber(STATE, yyvsp[0]); ;
    break;}
case 10:
#line 163 "OSUnserializeXML.y"
{ yyval = buildBoolean(STATE, yyvsp[0]); ;
    break;}
case 11:
#line 164 "OSUnserializeXML.y"
{ yyval = retrieveObject(STATE, yyvsp[0]->idref);
				  if (yyval) {
				    yyval->object->retain();
				  } else { 
				    yyerror("forward reference detected");
				    YYERROR;
				  }
				  freeObject(STATE, yyvsp[0]);
				;
    break;}
case 12:
#line 177 "OSUnserializeXML.y"
{ yyval = yyvsp[-1];
				  yyval->elements = NULL;
				;
    break;}
case 13:
#line 180 "OSUnserializeXML.y"
{ yyval = yyvsp[-2];
				  yyval->elements = yyvsp[-1];
				;
    break;}
case 16:
#line 187 "OSUnserializeXML.y"
{ yyval = yyvsp[0];
				  yyval->next = yyvsp[-1];
				;
    break;}
case 17:
#line 192 "OSUnserializeXML.y"
{ yyval = yyvsp[-1];
				  yyval->key = yyval->object;
				  yyval->object = yyvsp[0]->object;
				  yyval->next = NULL; 
				  yyvsp[0]->object = 0;
				  freeObject(STATE, yyvsp[0]);
				;
    break;}
case 18:
#line 201 "OSUnserializeXML.y"
{ yyval = buildString(STATE, yyvsp[0]); ;
    break;}
case 19:
#line 206 "OSUnserializeXML.y"
{ yyval = yyvsp[-1];
				  yyval->elements = NULL;
				;
    break;}
case 20:
#line 209 "OSUnserializeXML.y"
{ yyval = yyvsp[-2];
				  yyval->elements = yyvsp[-1];
				;
    break;}
case 22:
#line 215 "OSUnserializeXML.y"
{ yyval = yyvsp[-1];
				  yyval->elements = NULL;
				;
    break;}
case 23:
#line 218 "OSUnserializeXML.y"
{ yyval = yyvsp[-2];
				  yyval->elements = yyvsp[-1];
				;
    break;}
case 25:
#line 224 "OSUnserializeXML.y"
{ yyval = yyvsp[0]; 
				  yyval->next = NULL; 
				;
    break;}
case 26:
#line 227 "OSUnserializeXML.y"
{ yyval = yyvsp[0];
				  yyval->next = yyvsp[-1];
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
#line 249 "OSUnserializeXML.y"


int
OSUnserializeerror(parser_state_t * state, char *s)  /* Called by yyparse on errors */
{
    char tempString[128];

    if (state->errorString) {
	snprintf(tempString, 128, "OSUnserializeXML: %s near line %d\n", s, state->lineNumber);
	*(state->errorString) = OSString::withCString(tempString);
    }

    return 0;
}

#define TAG_MAX_LENGTH		32
#define TAG_MAX_ATTRIBUTES	32
#define TAG_BAD			0
#define TAG_START		1
#define TAG_END			2
#define TAG_EMPTY		3
#define TAG_COMMENT		4

#define currentChar()	(state->parseBuffer[state->parseBufferIndex])
#define nextChar()	(state->parseBuffer[++state->parseBufferIndex])
#define prevChar()	(state->parseBuffer[state->parseBufferIndex - 1])

#define isSpace(c)	((c) == ' ' || (c) == '\t')
#define isAlpha(c)	(((c) >= 'A' && (c) <= 'Z') || ((c) >= 'a' && (c) <= 'z'))
#define isDigit(c)	((c) >= '0' && (c) <= '9')
#define isAlphaDigit(c)	((c) >= 'a' && (c) <= 'f')
#define isHexDigit(c)	(isDigit(c) || isAlphaDigit(c))
#define isAlphaNumeric(c) (isAlpha(c) || isDigit(c) || ((c) == '-')) 

static int
getTag(parser_state_t *state,
       char tag[TAG_MAX_LENGTH],
       int *attributeCount, 
       char attributes[TAG_MAX_ATTRIBUTES][TAG_MAX_LENGTH],
       char values[TAG_MAX_ATTRIBUTES][TAG_MAX_LENGTH] )
{
	int length = 0;
	int c = currentChar();
	int tagType = TAG_START;

	*attributeCount = 0;

	if (c != '<') return TAG_BAD;
        c = nextChar();		// skip '<'

        if (c == '?' || c == '!') {
                while ((c = nextChar()) != 0) {
                        if (c == '\n') state->lineNumber++;
                        if (c == '>') {
                                (void)nextChar();
                                return TAG_COMMENT;
                        }
                }
        }

	if (c == '/') {
		c = nextChar();		// skip '/'
		tagType = TAG_END;
	}
        if (!isAlpha(c)) return TAG_BAD;

	/* find end of tag while copying it */
	while (isAlphaNumeric(c)) {
		tag[length++] = c;
		c = nextChar();
		if (length >= (TAG_MAX_LENGTH - 1)) return TAG_BAD;
	}

	tag[length] = 0;

//	printf("tag %s, type %d\n", tag, tagType);
	
	// look for attributes of the form attribute = "value" ...
	while ((c != '>') && (c != '/')) {
		while (isSpace(c)) c = nextChar();

		length = 0;
		while (isAlphaNumeric(c)) {
			attributes[*attributeCount][length++] = c;
			if (length >= (TAG_MAX_LENGTH - 1)) return TAG_BAD;
			c = nextChar();
		}
		attributes[*attributeCount][length] = 0;

		while (isSpace(c)) c = nextChar();
		
		if (c != '=') return TAG_BAD;
		c = nextChar();
		
		while (isSpace(c)) c = nextChar();

		if (c != '"') return TAG_BAD;
		c = nextChar();
		length = 0;
		while (c != '"') {
			values[*attributeCount][length++] = c;
			if (length >= (TAG_MAX_LENGTH - 1)) return TAG_BAD;
			c = nextChar();
		}
		values[*attributeCount][length] = 0;

		c = nextChar(); // skip closing quote

//		printf("	attribute '%s' = '%s', nextchar = '%c'\n", 
//		       attributes[*attributeCount], values[*attributeCount], c);

		(*attributeCount)++;
		if (*attributeCount >= TAG_MAX_ATTRIBUTES) return TAG_BAD;
	}

	if (c == '/') {
		c = nextChar();		// skip '/'
		tagType = TAG_EMPTY;
	}
	if (c != '>') return TAG_BAD;
	c = nextChar();		// skip '>'

	return tagType;
}

static char *
getString(parser_state_t *state)
{
	int c = currentChar();
	int start, length, i, j;
	char * tempString;

	start = state->parseBufferIndex;
	/* find end of string */

	while (c != 0) {
		if (c == '\n') state->lineNumber++;
		if (c == '<') {
			break;
		}
		c = nextChar();
	}

	if (c != '<') return 0;

	length = state->parseBufferIndex - start;

	/* copy to null terminated buffer */
	tempString = (char *)malloc(length + 1);
	if (tempString == 0) {
		printf("OSUnserializeXML: can't alloc temp memory\n");
		goto error;
	}

	// copy out string in tempString
	// "&amp;" -> '&', "&lt;" -> '<', "&gt;" -> '>'

	i = j = 0;
	while (i < length) {
		c = state->parseBuffer[start + i++];
		if (c != '&') {
			tempString[j++] = c;
		} else {
			if ((i+3) > length) goto error;
			c = state->parseBuffer[start + i++];
			if (c == 'l') {
				if (state->parseBuffer[start + i++] != 't') goto error;
				if (state->parseBuffer[start + i++] != ';') goto error;
				tempString[j++] = '<';
				continue;
			}	
			if (c == 'g') {
				if (state->parseBuffer[start + i++] != 't') goto error;
				if (state->parseBuffer[start + i++] != ';') goto error;
				tempString[j++] = '>';
				continue;
			}	
			if ((i+3) > length) goto error;
			if (c == 'a') {
				if (state->parseBuffer[start + i++] != 'm') goto error;
				if (state->parseBuffer[start + i++] != 'p') goto error;
				if (state->parseBuffer[start + i++] != ';') goto error;
				tempString[j++] = '&';
				continue;
			}
			goto error;
		}	
	}
	tempString[j] = 0;

//	printf("string %s\n", tempString);

	return tempString;

error:
	if (tempString) free(tempString);
	return 0;
}

static long long
getNumber(parser_state_t *state)
{
	unsigned long long n = 0;
	int base = 10;
	bool negate = false;
	int c = currentChar();

	if (c == '0') {
		c = nextChar();
		if (c == 'x') {
			base = 16;
			c = nextChar();
		}
	}
	if (base == 10) {
		if (c == '-') {
			negate = true;
			c = nextChar();
		}
		while(isDigit(c)) {
			n = (n * base + c - '0');
			c = nextChar();
		}
		if (negate) {
			n = (unsigned long long)((long long)n * (long long)-1);
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
//	printf("number 0x%x\n", (unsigned long)n);
	return n;
}

// taken from CFXMLParsing/CFPropertyList.c

static const signed char __CFPLDataDecodeTable[128] = {
    /* 000 */ -1, -1, -1, -1, -1, -1, -1, -1,
    /* 010 */ -1, -1, -1, -1, -1, -1, -1, -1,
    /* 020 */ -1, -1, -1, -1, -1, -1, -1, -1,
    /* 030 */ -1, -1, -1, -1, -1, -1, -1, -1,
    /* ' ' */ -1, -1, -1, -1, -1, -1, -1, -1,
    /* '(' */ -1, -1, -1, 62, -1, -1, -1, 63,
    /* '0' */ 52, 53, 54, 55, 56, 57, 58, 59,
    /* '8' */ 60, 61, -1, -1, -1,  0, -1, -1,
    /* '@' */ -1,  0,  1,  2,  3,  4,  5,  6,
    /* 'H' */  7,  8,  9, 10, 11, 12, 13, 14,
    /* 'P' */ 15, 16, 17, 18, 19, 20, 21, 22,
    /* 'X' */ 23, 24, 25, -1, -1, -1, -1, -1,
    /* '`' */ -1, 26, 27, 28, 29, 30, 31, 32,
    /* 'h' */ 33, 34, 35, 36, 37, 38, 39, 40,
    /* 'p' */ 41, 42, 43, 44, 45, 46, 47, 48,
    /* 'x' */ 49, 50, 51, -1, -1, -1, -1, -1
};

#define DATA_ALLOC_SIZE 4096

static void *
getCFEncodedData(parser_state_t *state, unsigned int *size)
{
    int numeq = 0, acc = 0, cntr = 0;
    int tmpbufpos = 0, tmpbuflen = 0;
    unsigned char *tmpbuf = (unsigned char *)malloc(DATA_ALLOC_SIZE);

    int c = currentChar();
    *size = 0;
	
    while (c != '<') {
        c &= 0x7f;
	if (c == 0) {
		free(tmpbuf);
		return 0;
	}
	if (c == '=') numeq++; else numeq = 0;
	if (c == '\n') state->lineNumber++;
        if (__CFPLDataDecodeTable[c] < 0) {
	    c = nextChar();
            continue;
	}
        cntr++;
        acc <<= 6;
        acc += __CFPLDataDecodeTable[c];
        if (0 == (cntr & 0x3)) {
            if (tmpbuflen <= tmpbufpos + 2) {
                tmpbuflen += DATA_ALLOC_SIZE;
		tmpbuf = (unsigned char *)realloc(tmpbuf, tmpbuflen);
            }
            tmpbuf[tmpbufpos++] = (acc >> 16) & 0xff;
            if (numeq < 2)
                tmpbuf[tmpbufpos++] = (acc >> 8) & 0xff;
            if (numeq < 1)
                tmpbuf[tmpbufpos++] = acc & 0xff;
        }
	c = nextChar();
    }
    *size = tmpbufpos;
    if (*size == 0) {
	free(tmpbuf);
	return 0;
    }
    return tmpbuf;
}

static void *
getHexData(parser_state_t *state, unsigned int *size)
{
    int c;
    unsigned char *d, *start, *lastStart;

    start = lastStart = d = (unsigned char *)malloc(DATA_ALLOC_SIZE);
    c = currentChar();

    while (c != '<') {

	if (isSpace(c)) while ((c = nextChar()) != 0 && isSpace(c)) {};
	if (c == '\n') {
	    state->lineNumber++;
	    c = nextChar();
	    continue;
	}

	// get high nibble
	if (isDigit(c)) {
	    *d = (c - '0') << 4;
	} else if (isAlphaDigit(c)) {
	    *d =  (0xa + (c - 'a')) << 4;
	} else {
	    goto error;
	}

	// get low nibble
	c = nextChar();
	if (isDigit(c)) {
	    *d |= c - '0';
	} else if (isAlphaDigit(c)) {
	    *d |= 0xa + (c - 'a');
	} else {
	    goto error;
	}
	
	d++;
	if ((d - lastStart) >= DATA_ALLOC_SIZE) {
	    int oldsize = d - start;
	    start = (unsigned char *)realloc(start, oldsize + DATA_ALLOC_SIZE);
	    d = lastStart = start + oldsize;
	}
	c = nextChar();
    }

    *size = d - start;
    return start;

 error:

    *size = 0;
    free(start);
    return 0;
}

static int
yylex(YYSTYPE *lvalp, parser_state_t *state)
{
	int c, i;
	int tagType;
	char tag[TAG_MAX_LENGTH];
	int attributeCount;
	char attributes[TAG_MAX_ATTRIBUTES][TAG_MAX_LENGTH];
	char values[TAG_MAX_ATTRIBUTES][TAG_MAX_LENGTH];
	object_t *object;

 top:
	c = currentChar();

	/* skip white space  */
	if (isSpace(c)) while ((c = nextChar()) != 0 && isSpace(c)) {};

	/* keep track of line number, don't return \n's */
	if (c == '\n') {
		STATE->lineNumber++;
		(void)nextChar();
		goto top;
	}

	// end of the buffer?
	if (!c)	return 0;

	tagType = getTag(STATE, tag, &attributeCount, attributes, values);
	if (tagType == TAG_BAD) return SYNTAX_ERROR;
	if (tagType == TAG_COMMENT) goto top;

	// handle allocation and check for "ID" and "IDREF" tags up front
	*lvalp = object = newObject(STATE);
	object->idref = -1;
	for (i=0; i < attributeCount; i++) {
	    if (attributes[i][0] == 'I' && attributes[i][1] == 'D') {
		// check for idref's, note: we ignore the tag, for
		// this to work correctly, all idrefs must be unique
		// across the whole serialization
		if (attributes[i][2] == 'R' && attributes[i][3] == 'E' &&
		    attributes[i][4] == 'F' && !attributes[i][5]) {
		    if (tagType != TAG_EMPTY) return SYNTAX_ERROR;
		    object->idref = strtol(values[i], NULL, 0);
		    return IDREF;
		}
		// check for id's
		if (!attributes[i][2]) {
		    object->idref = strtol(values[i], NULL, 0);
		} else {
		    return SYNTAX_ERROR;
		}
	    }
	}

	switch (*tag) {
	case 'a':
		if (!strcmp(tag, "array")) {
			if (tagType == TAG_EMPTY) {
				object->elements = NULL;
				return ARRAY;
			}
			return (tagType == TAG_START) ? '(' : ')';
		}
		break;
	case 'd':
		if (!strcmp(tag, "dict")) {
			if (tagType == TAG_EMPTY) {
				object->elements = NULL;
				return DICTIONARY;
			}
			return (tagType == TAG_START) ? '{' : '}';
		}
		if (!strcmp(tag, "data")) {
			unsigned int size;
			if (tagType == TAG_EMPTY) {
				object->data = NULL;
				object->size = 0;
				return DATA;
			}

			bool isHexFormat = false;
			for (int i=0; i < attributeCount; i++) {
				if (!strcmp(attributes[i], "format") && !strcmp(values[i], "hex")) {
					isHexFormat = true;
					break;
				}
			}
			// CF encoded is the default form
			if (isHexFormat) {
			    object->data = getHexData(STATE, &size);
			} else {
			    object->data = getCFEncodedData(STATE, &size);
			}
			object->size = size;
			if ((getTag(STATE, tag, &attributeCount, attributes, values) != TAG_END) || strcmp(tag, "data")) {
				return SYNTAX_ERROR;
			}
			return DATA;
		}
		break;
	case 'f':
		if (!strcmp(tag, "false")) {
			if (tagType == TAG_EMPTY) {
				object->number = 0;
				return BOOLEAN;
			}
		}
		break;
	case 'i':
		if (!strcmp(tag, "integer")) {
			object->size = 64;	// default
			for (i=0; i < attributeCount; i++) {
				if (!strcmp(attributes[i], "size")) {
					object->size = strtoul(values[i], NULL, 0);
				}
			}
			if (tagType == TAG_EMPTY) {
				object->number = 0;
				return NUMBER;
			}
			object->number = getNumber(STATE);
			if ((getTag(STATE, tag, &attributeCount, attributes, values) != TAG_END) || strcmp(tag, "integer")) {
				return SYNTAX_ERROR;
			}
			return NUMBER;
		}
		break;
	case 'k':
		if (!strcmp(tag, "key")) {
			if (tagType == TAG_EMPTY) return SYNTAX_ERROR;
			object->string = getString(STATE);
			if (!object->string) {
				return SYNTAX_ERROR;
			}
			if ((getTag(STATE, tag, &attributeCount, attributes, values) != TAG_END)
			   || strcmp(tag, "key")) {
				return SYNTAX_ERROR;
			}
			return KEY;
		}
		break;
	case 'p':
		if (!strcmp(tag, "plist")) {
			freeObject(STATE, object);
			goto top;
		}
		break;
	case 's':
		if (!strcmp(tag, "string")) {
			if (tagType == TAG_EMPTY) {
			    	object->string = (char *)malloc(1);
			    	object->string[0] = 0;
				return STRING;
			}
			object->string = getString(STATE);
			if (!object->string) {
				return SYNTAX_ERROR;
			}
			if ((getTag(STATE, tag, &attributeCount, attributes, values) != TAG_END)
			   || strcmp(tag, "string")) {
				return SYNTAX_ERROR;
			}
			return STRING;
		}
		if (!strcmp(tag, "set")) {
			if (tagType == TAG_EMPTY) {
				object->elements = NULL;
				return SET;;
			}
			if (tagType == TAG_START) {
				return '[';
			} else {
				return ']';
			}
		}
		break;
	case 't':
		if (!strcmp(tag, "true")) {
			if (tagType == TAG_EMPTY) {
				object->number = 1;
				return BOOLEAN;
			}
		}
		break;
	}

	return SYNTAX_ERROR;
}

// !@$&)(^Q$&*^!$(*!@$_(^%_(*Q#$(_*&!$_(*&!$_(*&!#$(*!@&^!@#%!_!#
// !@$&)(^Q$&*^!$(*!@$_(^%_(*Q#$(_*&!$_(*&!$_(*&!#$(*!@&^!@#%!_!#
// !@$&)(^Q$&*^!$(*!@$_(^%_(*Q#$(_*&!$_(*&!$_(*&!#$(*!@&^!@#%!_!#

// "java" like allocation, if this code hits a syntax error in the
// the middle of the parsed string we just bail with pointers hanging
// all over place, this code helps keeps it all together

//static int object_count = 0;

object_t *
newObject(parser_state_t *state)
{
	object_t *o;

	if (state->freeObjects) {
		o = state->freeObjects;
		state->freeObjects = state->freeObjects->next;
	} else {
		o = (object_t *)malloc(sizeof(object_t));
//		object_count++;
		bzero(o, sizeof(object_t));
		o->free = state->objects;
		state->objects = o;
	}
	
	return o;
}

void
freeObject(parser_state_t * state, object_t *o)
{
	o->next = state->freeObjects;
	state->freeObjects = o;	
}

void
cleanupObjects(parser_state_t *state)
{
	object_t *t, *o = state->objects;

	while (o) {
		if (o->object) {
//			printf("OSUnserializeXML: releasing object o=%x object=%x\n", (int)o, (int)o->object);
			o->object->release();
		}
		if (o->data) {
//			printf("OSUnserializeXML: freeing   object o=%x data=%x\n", (int)o, (int)o->data);
			free(o->data);
		}
		if (o->key) {
//			printf("OSUnserializeXML: releasing object o=%x key=%x\n", (int)o, (int)o->key);
			o->key->release();
		}
		if (o->string) {
//			printf("OSUnserializeXML: freeing   object o=%x string=%x\n", (int)o, (int)o->string);
			free(o->string);
		}

		t = o;
		o = o->free;
		free(t);
//		object_count--;
	}
//	printf("object_count = %d\n", object_count);
}

// !@$&)(^Q$&*^!$(*!@$_(^%_(*Q#$(_*&!$_(*&!$_(*&!#$(*!@&^!@#%!_!#
// !@$&)(^Q$&*^!$(*!@$_(^%_(*Q#$(_*&!$_(*&!$_(*&!#$(*!@&^!@#%!_!#
// !@$&)(^Q$&*^!$(*!@$_(^%_(*Q#$(_*&!$_(*&!$_(*&!#$(*!@&^!@#%!_!#

static void 
rememberObject(parser_state_t *state, int tag, OSObject *o)
{
	char key[16];
	snprintf(key, 16, "%u", tag);

//	printf("remember key %s\n", key);

	state->tags->setObject(key, o);
}

static object_t *
retrieveObject(parser_state_t *state, int tag)
{
	OSObject *ref;
	object_t *o;
	char key[16];
	snprintf(key, 16, "%u", tag);

//	printf("retrieve key '%s'\n", key);

	ref = state->tags->getObject(key);
	if (!ref) return 0;

	o = newObject(state);
	o->object = ref;
	return o;
}

// !@$&)(^Q$&*^!$(*!@$_(^%_(*Q#$(_*&!$_(*&!$_(*&!#$(*!@&^!@#%!_!#
// !@$&)(^Q$&*^!$(*!@$_(^%_(*Q#$(_*&!$_(*&!$_(*&!#$(*!@&^!@#%!_!#
// !@$&)(^Q$&*^!$(*!@$_(^%_(*Q#$(_*&!$_(*&!$_(*&!#$(*!@&^!@#%!_!#

object_t *
buildDictionary(parser_state_t *state, object_t * header)
{
	object_t *o, *t;
	int count = 0;
	OSDictionary *dict;

	// get count and reverse order
	o = header->elements;
	header->elements = 0;
	while (o) {
		count++;
		t = o;
		o = o->next;

		t->next = header->elements;
		header->elements = t;
	}

	dict = OSDictionary::withCapacity(count);
	if (header->idref >= 0) rememberObject(state, header->idref, dict);

	o = header->elements;
	while (o) {
		dict->setObject(o->key, o->object);

		o->key->release();
		o->object->release();
		o->key = 0;
		o->object = 0;

		t = o;
		o = o->next;
		freeObject(state, t);
	}
	o = header;
	o->object = dict;
	return o;
};

object_t *
buildArray(parser_state_t *state, object_t * header)
{
	object_t *o, *t;
	int count = 0;
	OSArray *array;

	// get count and reverse order
	o = header->elements;
	header->elements = 0;
	while (o) {
		count++;
		t = o;
		o = o->next;

		t->next = header->elements;
		header->elements = t;
	}

	array = OSArray::withCapacity(count);
	if (header->idref >= 0) rememberObject(state, header->idref, array);

	o = header->elements;
	while (o) {
		array->setObject(o->object);

		o->object->release();
		o->object = 0;

		t = o;
		o = o->next;
		freeObject(state, t);
	}
	o = header;
	o->object = array;
	return o;
};

object_t *
buildSet(parser_state_t *state, object_t *header)
{
	object_t *o = buildArray(state, header);

	OSArray *array = (OSArray *)o->object;
	OSSet *set = OSSet::withArray(array, array->getCapacity());

	// write over the reference created in buildArray
	if (header->idref >= 0) rememberObject(state, header->idref, set);

	array->release();
	o->object = set;
	return o;
};

object_t *
buildString(parser_state_t *state, object_t *o)
{
	OSString *string;

	string = OSString::withCString(o->string);
	if (o->idref >= 0) rememberObject(state, o->idref, string);

	free(o->string);
	o->string = 0;
	o->object = string;

	return o;
};

object_t *
buildData(parser_state_t *state, object_t *o)
{
	OSData *data;

	if (o->size) {
		data = OSData::withBytes(o->data, o->size);
	} else {
		data = OSData::withCapacity(0);
	}
	if (o->idref >= 0) rememberObject(state, o->idref, data);

	if (o->size) free(o->data);
	o->data = 0;
	o->object = data;
	return o;
};

object_t *
buildNumber(parser_state_t *state, object_t *o)
{
	OSNumber *number = OSNumber::withNumber(o->number, o->size);

	if (o->idref >= 0) rememberObject(state, o->idref, number);

	o->object = number;
	return o;
};

object_t *
buildBoolean(parser_state_t *state, object_t *o)
{
	o->object = ((o->number == 0) ? kOSBooleanFalse : kOSBooleanTrue);
	o->object->retain();
	return o;
};

OSObject*
OSUnserializeXML(const char *buffer, OSString **errorString)
{
	OSObject *object;
	parser_state_t *state = (parser_state_t *)malloc(sizeof(parser_state_t));

	if ((!state) || (!buffer)) return 0;

	// just in case
	if (errorString) *errorString = NULL;

	state->parseBuffer = buffer;
	state->parseBufferIndex = 0;
	state->lineNumber = 1;
	state->objects = 0;
	state->freeObjects = 0;
	state->tags = OSDictionary::withCapacity(128);
	state->errorString = errorString;
	state->parsedObject = 0;

	(void)yyparse((void *)state);

	object = state->parsedObject;

	cleanupObjects(state);
	state->tags->release();
	free(state);

	return object;
}


//
//
//
//
//
//		 DO NOT EDIT OSUnserializeXML.cpp!
//
//			this means you!
//
//
//
//
//
