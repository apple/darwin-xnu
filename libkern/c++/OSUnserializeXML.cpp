/*
 * Copyright (c) 1999-2013 Apple Inc. All rights reserved.
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
/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton implementation for Bison's Yacc-like parsers in C
 *
 *  Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
 *  Free Software Foundation, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *  Boston, MA 02110-1301, USA.  */

/* As a special exception, you may create a larger work that contains
 *  part or all of the Bison parser skeleton and distribute that work
 *  under terms of your choice, so long as that work isn't itself a
 *  parser generator using the skeleton or a modified version thereof
 *  as a parser skeleton.  Alternatively, if you modify or redistribute
 *  the parser skeleton itself, you may (at your option) remove this
 *  special exception, which will cause the skeleton and the resulting
 *  Bison output files to be licensed under the GNU General Public
 *  License without this special exception.
 *
 *  This special exception was added by the Free Software Foundation in
 *  version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
*  simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
 *  infringing on user name space.  This should be done even for local
 *  variables, as they might otherwise be expanded by user macros.
 *  There are some unavoidable exceptions within include files to
 *  define necessary library symbols; they are noted "INFRINGES ON
 *  USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "2.3"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 1

/* Using locations.  */
#define YYLSP_NEEDED 0

/* Substitute the variable and function names.  */
#define yyparse OSUnserializeXMLparse
#define yylex   OSUnserializeXMLlex
#define yyerror OSUnserializeXMLerror
#define yylval  OSUnserializeXMLlval
#define yychar  OSUnserializeXMLchar
#define yydebug OSUnserializeXMLdebug
#define yynerrs OSUnserializeXMLnerrs


/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
/* Put the tokens into the symbol table, so that GDB and other debuggers
 *  know about them.  */
enum yytokentype {
	ARRAY = 258,
	BOOLEAN = 259,
	DATA = 260,
	DICTIONARY = 261,
	IDREF = 262,
	KEY = 263,
	NUMBER = 264,
	SET = 265,
	STRING = 266,
	SYNTAX_ERROR = 267
};
#endif
/* Tokens.  */
#define ARRAY 258
#define BOOLEAN 259
#define DATA 260
#define DICTIONARY 261
#define IDREF 262
#define KEY 263
#define NUMBER 264
#define SET 265
#define STRING 266
#define SYNTAX_ERROR 267




/* Copy the first part of user declarations.  */
#line 61 "OSUnserializeXML.y"

#include <string.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSContainers.h>
#include <libkern/c++/OSLib.h>

#define MAX_OBJECTS              131071
#define MAX_REFED_OBJECTS        65535

#define YYSTYPE object_t *
#define YYPARSE_PARAM   state
#define YYLEX_PARAM     (parser_state_t *)state

// this is the internal struct used to hold objects on parser stack
// it represents objects both before and after they have been created
typedef struct object {
	struct object   *next;
	struct object   *free;
	struct object   *elements;
	OSObject        *object;
	OSSymbol        *key;                   // for dictionary
	int             size;
	void            *data;                  // for data
	char            *string;                // for string & symbol
	long long       number;                 // for number
	int             idref;
} object_t;

// this code is reentrant, this structure contains all
// state information for the parsing of a single buffer
typedef struct parser_state {
	const char      *parseBuffer;           // start of text to be parsed
	int             parseBufferIndex;       // current index into text
	int             lineNumber;             // current line number
	object_t        *objects;               // internal objects in use
	object_t        *freeObjects;           // internal objects that are free
	OSDictionary    *tags;                  // used to remember "ID" tags
	OSString        **errorString;          // parse error with line
	OSObject        *parsedObject;          // resultant object of parsed text
	int             parsedObjectCount;
	int             retrievedObjectCount;
} parser_state_t;

#define STATE           ((parser_state_t *)state)

#undef yyerror
#define yyerror(s)      OSUnserializeerror(STATE, (s))
static int              OSUnserializeerror(parser_state_t *state, const char *s);

static int              yylex(YYSTYPE *lvalp, parser_state_t *state);

static object_t         *newObject(parser_state_t *state);
static void             freeObject(parser_state_t *state, object_t *o);
static void             rememberObject(parser_state_t *state, int tag, OSObject *o);
static object_t         *retrieveObject(parser_state_t *state, int tag);
static void             cleanupObjects(parser_state_t *state);

static object_t         *buildDictionary(parser_state_t *state, object_t *o);
static object_t         *buildArray(parser_state_t *state, object_t *o);
static object_t         *buildSet(parser_state_t *state, object_t *o);
static object_t         *buildString(parser_state_t *state, object_t *o);
static object_t         *buildSymbol(parser_state_t *state, object_t *o);
static object_t         *buildData(parser_state_t *state, object_t *o);
static object_t         *buildNumber(parser_state_t *state, object_t *o);
static object_t         *buildBoolean(parser_state_t *state, object_t *o);

#include <libkern/OSRuntime.h>

#define malloc(s) kern_os_malloc(s)
#define realloc(a, s) kern_os_realloc(a, s)
#define free(a) kern_os_free((void *)a)



/* Enabling traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 0
#endif

/* Enabling the token table.  */
#ifndef YYTOKEN_TABLE
# define YYTOKEN_TABLE 0
#endif

#if !defined YYSTYPE && !defined YYSTYPE_IS_DECLARED
typedef int YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif



/* Copy the second part of user declarations.  */


/* Line 216 of yacc.c.  */
#line 212 "OSUnserializeXML.tab.c"

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#elif (defined __STDC__ || defined __C99__FUNC__ \
        || defined __cplusplus || defined _MSC_VER)
typedef signed char yytype_int8;
#else
typedef short int yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif !defined YYSIZE_T && (defined __STDC__ || defined __C99__FUNC__ \
        || defined __cplusplus || defined _MSC_VER)
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(msgid) dgettext ("bison-runtime", msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(msgid) msgid
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if !defined lint || defined __GNUC__
# define YYUSE(e) ((void) (e))
#else
# define YYUSE(e) /* empty */
#endif

/* Identity function, used to suppress warnings about constant conditions.  */
#ifndef lint
# define YYID(n) (n)
#else
#if (defined __STDC__ || defined __C99__FUNC__ \
        || defined __cplusplus || defined _MSC_VER)
static int
YYID(int i)
#else
static int
    YYID(i)
int i;
#endif
{
	return i;
}
#endif

#if !defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if !defined _ALLOCA_H && !defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
        || defined __cplusplus || defined _MSC_VER)
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#     ifndef _STDLIB_H
#      define _STDLIB_H 1
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
/* Pacify GCC's `empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */ ; } while (YYID (0))
#  ifndef YYSTACK_ALLOC_MAXIMUM
/* The OS might guarantee only one guard page at the bottom of the stack,
 *  and a page size can be as small as 4096 bytes.  So we cannot safely
 *  invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
 *  to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && !defined _STDLIB_H \
        && !((defined YYMALLOC || defined malloc) \
        && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef _STDLIB_H
#    define _STDLIB_H 1
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if !defined malloc && !defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
        || defined __cplusplus || defined _MSC_VER)
void *malloc(YYSIZE_T);  /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if !defined free && !defined _STDLIB_H && (defined __STDC__ || defined __C99__FUNC__ \
        || defined __cplusplus || defined _MSC_VER)
void free(void *);  /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (!defined yyoverflow \
        && (!defined __cplusplus \
        || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc {
	yytype_int16 yyss;
	YYSTYPE yyvs;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
 *  N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

/* Copy COUNT objects from FROM to TO.  The source and destination do
 *  not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(To, From, Count) \
      __builtin_memcpy (To, From, (Count) * sizeof (*(From)))
#  else
#   define YYCOPY(To, From, Count)              \
      do                                        \
	{                                       \
	  YYSIZE_T yyi;                         \
	  for (yyi = 0; yyi < (Count); yyi++)   \
	    (To)[yyi] = (From)[yyi];            \
	}                                       \
      while (YYID (0))
#  endif
# endif

/* Relocate STACK from its old location to the new one.  The
 *  local variables YYSIZE and YYSTACKSIZE give the old and new number of
 *  elements in the stack, and YYPTR gives the new location of the
 *  stack.  Advance YYPTR to a properly aligned location for the next
 *  stack.  */
# define YYSTACK_RELOCATE(Stack)                                        \
    do                                                                  \
      {                                                                 \
	YYSIZE_T yynewbytes;                                            \
	YYCOPY (&yyptr->Stack, Stack, yysize);                          \
	Stack = &yyptr->Stack;                                          \
	yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
	yyptr += yynewbytes / sizeof (*yyptr);                          \
      }                                                                 \
    while (YYID (0))

#endif

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  33
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   108

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  19
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  15
/* YYNRULES -- Number of rules.  */
#define YYNRULES  32
/* YYNRULES -- Number of states.  */
#define YYNSTATES  40

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   267

#define YYTRANSLATE(YYX)                                                \
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint8 yytranslate[] =
{
	0, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	15, 16, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 17, 2, 18, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 13, 2, 14, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 1, 2, 3, 4,
	5, 6, 7, 8, 9, 10, 11, 12
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
 *  YYRHS.  */
static const yytype_uint8 yyprhs[] =
{
	0, 0, 3, 4, 6, 8, 10, 12, 14, 16,
	18, 20, 22, 24, 27, 31, 33, 35, 38, 41,
	43, 46, 50, 52, 55, 59, 61, 63, 66, 68,
	70, 72, 74
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int8 yyrhs[] =
{
	20, 0, -1, -1, 21, -1, 12, -1, 22, -1,
	26, -1, 27, -1, 33, -1, 30, -1, 32, -1,
	29, -1, 31, -1, 13, 14, -1, 13, 23, 14,
	-1, 6, -1, 24, -1, 23, 24, -1, 25, 21,
	-1, 8, -1, 15, 16, -1, 15, 28, 16, -1,
	3, -1, 17, 18, -1, 17, 28, 18, -1, 10,
	-1, 21, -1, 28, 21, -1, 4, -1, 5, -1,
	7, -1, 9, -1, 11, -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
	0, 146, 146, 149, 154, 159, 171, 183, 195, 207,
	219, 231, 243, 267, 270, 273, 276, 277, 292, 301,
	313, 316, 319, 322, 325, 328, 331, 334, 341, 344,
	347, 350, 353
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || YYTOKEN_TABLE
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
 *  First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
	"$end", "error", "$undefined", "ARRAY", "BOOLEAN", "DATA", "DICTIONARY",
	"IDREF", "KEY", "NUMBER", "SET", "STRING", "SYNTAX_ERROR", "'{'", "'}'",
	"'('", "')'", "'['", "']'", "$accept", "input", "object", "dict",
	"pairs", "pair", "key", "array", "set", "elements", "boolean", "data",
	"idref", "number", "string", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
 *  token YYLEX-NUM.  */
static const yytype_uint16 yytoknum[] =
{
	0, 256, 257, 258, 259, 260, 261, 262, 263, 264,
	265, 266, 267, 123, 125, 40, 41, 91, 93
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
	0, 19, 20, 20, 20, 21, 21, 21, 21, 21,
	21, 21, 21, 22, 22, 22, 23, 23, 24, 25,
	26, 26, 26, 27, 27, 27, 28, 28, 29, 30,
	31, 32, 33
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
	0, 2, 0, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 2, 3, 1, 1, 2, 2, 1,
	2, 3, 1, 2, 3, 1, 1, 2, 1, 1,
	1, 1, 1
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
 *  STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
 *  means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
	2, 22, 28, 29, 15, 30, 31, 25, 32, 4,
	0, 0, 0, 0, 3, 5, 6, 7, 11, 9,
	12, 10, 8, 19, 13, 0, 16, 0, 20, 26,
	0, 23, 0, 1, 14, 17, 18, 21, 27, 24
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int8 yydefgoto[] =
{
	-1, 13, 29, 15, 25, 26, 27, 16, 17, 30,
	18, 19, 20, 21, 22
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
 *  STATE-NUM.  */
#define YYPACT_NINF -20
static const yytype_int8 yypact[] =
{
	46, -20, -20, -20, -20, -20, -20, -20, -20, -20,
	4, 61, -2, 10, -20, -20, -20, -20, -20, -20,
	-20, -20, -20, -20, -20, 6, -20, 91, -20, -20,
	76, -20, 30, -20, -20, -20, -20, -20, -20, -20
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
	-20, -20, 0, -20, -20, -19, -20, -20, -20, 5,
	-20, -20, -20, -20, -20
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
 *  positive, shift that token.  If negative, reduce the rule which
 *  number is the opposite.  If zero, do what YYDEFACT says.
 *  If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -1
static const yytype_uint8 yytable[] =
{
	14, 1, 2, 3, 4, 5, 35, 6, 7, 8,
	33, 10, 23, 11, 23, 12, 31, 32, 24, 0,
	34, 0, 0, 0, 0, 0, 0, 36, 0, 0,
	38, 0, 38, 1, 2, 3, 4, 5, 0, 6,
	7, 8, 0, 10, 0, 11, 0, 12, 39, 1,
	2, 3, 4, 5, 0, 6, 7, 8, 9, 10,
	0, 11, 0, 12, 1, 2, 3, 4, 5, 0,
	6, 7, 8, 0, 10, 0, 11, 28, 12, 1,
	2, 3, 4, 5, 0, 6, 7, 8, 0, 10,
	0, 11, 37, 12, 1, 2, 3, 4, 5, 0,
	6, 7, 8, 0, 10, 0, 11, 0, 12
};

static const yytype_int8 yycheck[] =
{
	0, 3, 4, 5, 6, 7, 25, 9, 10, 11,
	0, 13, 8, 15, 8, 17, 18, 12, 14, -1,
	14, -1, -1, -1, -1, -1, -1, 27, -1, -1,
	30, -1, 32, 3, 4, 5, 6, 7, -1, 9,
	10, 11, -1, 13, -1, 15, -1, 17, 18, 3,
	4, 5, 6, 7, -1, 9, 10, 11, 12, 13,
	-1, 15, -1, 17, 3, 4, 5, 6, 7, -1,
	9, 10, 11, -1, 13, -1, 15, 16, 17, 3,
	4, 5, 6, 7, -1, 9, 10, 11, -1, 13,
	-1, 15, 16, 17, 3, 4, 5, 6, 7, -1,
	9, 10, 11, -1, 13, -1, 15, -1, 17
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
 *  symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
	0, 3, 4, 5, 6, 7, 9, 10, 11, 12,
	13, 15, 17, 20, 21, 22, 26, 27, 29, 30,
	31, 32, 33, 8, 14, 23, 24, 25, 16, 21,
	28, 18, 28, 0, 14, 24, 21, 16, 21, 18
};

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


/* Like YYERROR except do call yyerror.  This remains here temporarily
 *  to ease the transition to the new meaning of YYERROR, for GCC.
 *  Once GCC version 2 has supplanted version 1, this can go.  */

#define YYFAIL          goto yyerrlab

#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                  \
do                                                              \
  if (yychar == YYEMPTY && yylen == 1)                          \
    {                                                           \
      yychar = (Token);                                         \
      yylval = (Value);                                         \
      yytoken = YYTRANSLATE (yychar);                           \
      YYPOPSTACK (1);                                           \
      goto yybackup;                                            \
    }                                                           \
  else                                                          \
    {                                                           \
      yyerror (YY_("syntax error: cannot back up")); \
      YYERROR;                                                  \
    }                                                           \
while (YYID (0))


#define YYTERROR        1
#define YYERRCODE       256


/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
 *  If N is 0, then set CURRENT to the empty location which ends
 *  the previous symbol: RHS[0] (always defined).  */

#define YYRHSLOC(Rhs, K) ((Rhs)[K])
#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)                                \
    do                                                                  \
      if (YYID (N))                                                    \
	{                                                               \
	  (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;        \
	  (Current).first_column = YYRHSLOC (Rhs, 1).first_column;      \
	  (Current).last_line    = YYRHSLOC (Rhs, N).last_line;         \
	  (Current).last_column  = YYRHSLOC (Rhs, N).last_column;       \
	}                                                               \
      else                                                              \
	{                                                               \
	  (Current).first_line   = (Current).last_line   =              \
	    YYRHSLOC (Rhs, 0).last_line;                                \
	  (Current).first_column = (Current).last_column =              \
	    YYRHSLOC (Rhs, 0).last_column;                              \
	}                                                               \
    while (YYID (0))
#endif


/* YY_LOCATION_PRINT -- Print the location on the stream.
 *  This macro was not mandated originally: define only if we know
 *  we won't break user code: when these are the locations we know.  */

#ifndef YY_LOCATION_PRINT
# if defined YYLTYPE_IS_TRIVIAL && YYLTYPE_IS_TRIVIAL
#  define YY_LOCATION_PRINT(File, Loc)                  \
     fprintf (File, "%d.%d-%d.%d",                      \
	      (Loc).first_line, (Loc).first_column,     \
	      (Loc).last_line,  (Loc).last_column)
# else
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */

#ifdef YYLEX_PARAM
# define YYLEX yylex (&yylval, YYLEX_PARAM)
#else
# define YYLEX yylex (&yylval)
#endif

/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (YYID (0))

# define YY_SYMBOL_PRINT(Title, Type, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
	          Type, Value); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (YYID (0))


/*--------------------------------.
 | Print this symbol on YYOUTPUT.  |
 |   `--------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
        || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_value_print(FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
    yy_symbol_value_print(yyoutput, yytype, yyvaluep)
FILE *yyoutput;
int yytype;
YYSTYPE const * const yyvaluep;
#endif
{
	if (!yyvaluep) {
		return;
	}
# ifdef YYPRINT
	if (yytype < YYNTOKENS) {
		YYPRINT(yyoutput, yytoknum[yytype], *yyvaluep);
	}
# else
	YYUSE(yyoutput);
# endif
	switch (yytype) {
	default:
		break;
	}
}


/*--------------------------------.
 | Print this symbol on YYOUTPUT.  |
 |   `--------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
        || defined __cplusplus || defined _MSC_VER)
static void
yy_symbol_print(FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep)
#else
static void
    yy_symbol_print(yyoutput, yytype, yyvaluep)
FILE *yyoutput;
int yytype;
YYSTYPE const * const yyvaluep;
#endif
{
	if (yytype < YYNTOKENS) {
		YYFPRINTF(yyoutput, "token %s (", yytname[yytype]);
	} else {
		YYFPRINTF(yyoutput, "nterm %s (", yytname[yytype]);
	}

	yy_symbol_value_print(yyoutput, yytype, yyvaluep);
	YYFPRINTF(yyoutput, ")");
}

/*------------------------------------------------------------------.
 | yy_stack_print -- Print the state stack from its BOTTOM up to its |
 | TOP (included).                                                   |
 |   `------------------------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
        || defined __cplusplus || defined _MSC_VER)
static void
yy_stack_print(yytype_int16 *bottom, yytype_int16 *top)
#else
static void
    yy_stack_print(bottom, top)
yytype_int16 *bottom;
yytype_int16 *top;
#endif
{
	YYFPRINTF(stderr, "Stack now");
	for (; bottom <= top; ++bottom) {
		YYFPRINTF(stderr, " %d", *bottom);
	}
	YYFPRINTF(stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (YYID (0))


/*------------------------------------------------.
 | Report that the YYRULE is going to be reduced.  |
 |   `------------------------------------------------*/

#if (defined __STDC__ || defined __C99__FUNC__ \
        || defined __cplusplus || defined _MSC_VER)
static void
yy_reduce_print(YYSTYPE *yyvsp, int yyrule)
#else
static void
    yy_reduce_print(yyvsp, yyrule)
YYSTYPE *yyvsp;
int yyrule;
#endif
{
	int yynrhs = yyr2[yyrule];
	int yyi;
	unsigned long int yylno = yyrline[yyrule];
	YYFPRINTF(stderr, "Reducing stack by rule %d (line %lu):\n",
	    yyrule - 1, yylno);
	/* The symbols being reduced.  */
	for (yyi = 0; yyi < yynrhs; yyi++) {
		fprintf(stderr, "   $%d = ", yyi + 1);
		yy_symbol_print(stderr, yyrhs[yyprhs[yyrule] + yyi],
		    &(yyvsp[(yyi + 1) - (yynrhs)])
		    );
		fprintf(stderr, "\n");
	}
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyvsp, Rule); \
} while (YYID (0))

/* Nonzero means print parse trace.  It is left uninitialized so that
 *  multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
 *  if the built-in stack extension method is used).
 *
 *  Do not make this value too large; the results are undefined if
 *  YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
 *  evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif



#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
        || defined __cplusplus || defined _MSC_VER)
static YYSIZE_T
yystrlen(const char *yystr)
#else
static YYSIZE_T
    yystrlen(yystr)
const char *yystr;
#endif
{
	YYSIZE_T yylen;
	for (yylen = 0; yystr[yylen]; yylen++) {
		continue;
	}
	return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
 *  YYDEST.  */
#if (defined __STDC__ || defined __C99__FUNC__ \
        || defined __cplusplus || defined _MSC_VER)
static char *
yystpcpy(char *yydest, const char *yysrc)
#else
static char *
yystpcpy(yydest, yysrc)
char *yydest;
const char *yysrc;
#endif
{
	char *yyd = yydest;
	const char *yys = yysrc;

	while ((*yyd++ = *yys++) != '\0') {
		continue;
	}

	return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
 *  quotes and backslashes, so that it's suitable for yyerror.  The
 *  heuristic is that double-quoting is unnecessary unless the string
 *  contains an apostrophe, a comma, or backslash (other than
 *  backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
 *  null, do not copy; instead, return the length of what the result
 *  would have been.  */
static YYSIZE_T
yytnamerr(char *yyres, const char *yystr)
{
	if (*yystr == '"') {
		YYSIZE_T yyn = 0;
		char const *yyp = yystr;

		for (;;) {
			switch (*++yyp) {
			case '\'':
			case ',':
				goto do_not_strip_quotes;

			case '\\':
				if (*++yyp != '\\') {
					goto do_not_strip_quotes;
				}
			/* Fall through.  */
			default:
				if (yyres) {
					yyres[yyn] = *yyp;
				}
				yyn++;
				break;

			case '"':
				if (yyres) {
					yyres[yyn] = '\0';
				}
				return yyn;
			}
		}
do_not_strip_quotes:;
	}

	if (!yyres) {
		return yystrlen(yystr);
	}

	return yystpcpy(yyres, yystr) - yyres;
}
# endif

/* Copy into YYRESULT an error message about the unexpected token
 *  YYCHAR while in state YYSTATE.  Return the number of bytes copied,
 *  including the terminating null byte.  If YYRESULT is null, do not
 *  copy anything; just return the number of bytes that would be
 *  copied.  As a special case, return 0 if an ordinary "syntax error"
 *  message will do.  Return YYSIZE_MAXIMUM if overflow occurs during
 *  size calculation.  */
static YYSIZE_T
yysyntax_error(char *yyresult, int yystate, int yychar)
{
	int yyn = yypact[yystate];

	if (!(YYPACT_NINF < yyn && yyn <= YYLAST)) {
		return 0;
	} else {
		int yytype = YYTRANSLATE(yychar);
		YYSIZE_T yysize0 = yytnamerr(0, yytname[yytype]);
		YYSIZE_T yysize = yysize0;
		YYSIZE_T yysize1;
		int yysize_overflow = 0;
		enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
		char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
		int yyx;

# if 0
		/* This is so xgettext sees the translatable formats that are
		 *  constructed on the fly.  */
		YY_("syntax error, unexpected %s");
		YY_("syntax error, unexpected %s, expecting %s");
		YY_("syntax error, unexpected %s, expecting %s or %s");
		YY_("syntax error, unexpected %s, expecting %s or %s or %s");
		YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s");
# endif
		char *yyfmt;
		char const *yyf;
		static char const yyunexpected[] = "syntax error, unexpected %s";
		static char const yyexpecting[] = ", expecting %s";
		static char const yyor[] = " or %s";
		char yyformat[sizeof yyunexpected
		+ sizeof yyexpecting - 1
		+ ((YYERROR_VERBOSE_ARGS_MAXIMUM - 2)
		* (sizeof yyor - 1))];
		char const *yyprefix = yyexpecting;

		/* Start YYX at -YYN if negative to avoid negative indexes in
		 *  YYCHECK.  */
		int yyxbegin = yyn < 0 ? -yyn : 0;

		/* Stay within bounds of both yycheck and yytname.  */
		int yychecklim = YYLAST - yyn + 1;
		int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
		int yycount = 1;

		yyarg[0] = yytname[yytype];
		yyfmt = yystpcpy(yyformat, yyunexpected);

		for (yyx = yyxbegin; yyx < yyxend; ++yyx) {
			if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR) {
				if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM) {
					yycount = 1;
					yysize = yysize0;
					yyformat[sizeof yyunexpected - 1] = '\0';
					break;
				}
				yyarg[yycount++] = yytname[yyx];
				yysize1 = yysize + yytnamerr(0, yytname[yyx]);
				yysize_overflow |= (yysize1 < yysize);
				yysize = yysize1;
				yyfmt = yystpcpy(yyfmt, yyprefix);
				yyprefix = yyor;
			}
		}

		yyf = YY_(yyformat);
		yysize1 = yysize + yystrlen(yyf);
		yysize_overflow |= (yysize1 < yysize);
		yysize = yysize1;

		if (yysize_overflow) {
			return YYSIZE_MAXIMUM;
		}

		if (yyresult) {
			/* Avoid sprintf, as that infringes on the user's name space.
			 *  Don't have undefined behavior even if the translation
			 *  produced a string with the wrong number of "%s"s.  */
			char *yyp = yyresult;
			int yyi = 0;
			while ((*yyp = *yyf) != '\0') {
				if (*yyp == '%' && yyf[1] == 's' && yyi < yycount) {
					yyp += yytnamerr(yyp, yyarg[yyi++]);
					yyf += 2;
				} else {
					yyp++;
					yyf++;
				}
			}
		}
		return yysize;
	}
}
#endif /* YYERROR_VERBOSE */


/*-----------------------------------------------.
 | Release the memory associated to this symbol.  |
 |   `-----------------------------------------------*/

/*ARGSUSED*/
#if (defined __STDC__ || defined __C99__FUNC__ \
        || defined __cplusplus || defined _MSC_VER)
static void
yydestruct(const char *yymsg, int yytype, YYSTYPE *yyvaluep)
#else
static void
    yydestruct(yymsg, yytype, yyvaluep)
const char *yymsg;
int yytype;
YYSTYPE *yyvaluep;
#endif
{
	YYUSE(yyvaluep);

	if (!yymsg) {
		yymsg = "Deleting";
	}
	YY_SYMBOL_PRINT(yymsg, yytype, yyvaluep, yylocationp);

	switch (yytype) {
	default:
		break;
	}
}


/* Prevent warnings from -Wmissing-prototypes.  */

#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int yyparse(void *YYPARSE_PARAM);
#else
int yyparse();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int yyparse(void);
#else
int yyparse();
#endif
#endif /* ! YYPARSE_PARAM */






/*----------.
 | yyparse.  |
 |   `----------*/

#ifdef YYPARSE_PARAM
#if (defined __STDC__ || defined __C99__FUNC__ \
        || defined __cplusplus || defined _MSC_VER)
int
yyparse(void *YYPARSE_PARAM)
#else
int
    yyparse(YYPARSE_PARAM)
void *YYPARSE_PARAM;
#endif
#else /* ! YYPARSE_PARAM */
#if (defined __STDC__ || defined __C99__FUNC__ \
        || defined __cplusplus || defined _MSC_VER)
int
yyparse(void)
#else
int
yyparse()

#endif
#endif
{
	/* The look-ahead symbol.  */
	int yychar;

/* The semantic value of the look-ahead symbol.  */
	YYSTYPE yylval;

/* Number of syntax errors so far.  */
	int yynerrs;

	int yystate;
	int yyn;
	int yyresult;
	/* Number of tokens to shift before error messages enabled.  */
	int yyerrstatus;
	/* Look-ahead token as an internal (translated) token number.  */
	int yytoken = 0;
#if YYERROR_VERBOSE
	/* Buffer for error messages, and its allocated size.  */
	char yymsgbuf[128];
	char *yymsg = yymsgbuf;
	YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

	/* Three stacks and their tools:
	 *  `yyss': related to states,
	 *  `yyvs': related to semantic values,
	 *  `yyls': related to locations.
	 *
	 *  Refer to the stacks thru separate pointers, to allow yyoverflow
	 *  to reallocate them elsewhere.  */

	/* The state stack.  */
	yytype_int16 yyssa[YYINITDEPTH];
	yytype_int16 *yyss = yyssa;
	yytype_int16 *yyssp;

	/* The semantic value stack.  */
	YYSTYPE yyvsa[YYINITDEPTH];
	YYSTYPE *yyvs = yyvsa;
	YYSTYPE *yyvsp;



#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

	YYSIZE_T yystacksize = YYINITDEPTH;

	/* The variables used to return semantic value and location from the
	 *  action routines.  */
	YYSTYPE yyval;


	/* The number of symbols on the RHS of the reduced rule.
	 *  Keep to zero when no symbol should be popped.  */
	int yylen = 0;

	YYDPRINTF((stderr, "Starting parse\n"));

	yystate = 0;
	yyerrstatus = 0;
	yynerrs = 0;
	yychar = YYEMPTY;       /* Cause a token to be read.  */

	/* Initialize stack pointers.
	 *  Waste one element of value and location stack
	 *  so that they stay on the same level as the state stack.
	 *  The wasted elements are never initialized.  */

	yyssp = yyss;
	yyvsp = yyvs;

	goto yysetstate;

/*------------------------------------------------------------.
 | yynewstate -- Push a new state, which is found in yystate.  |
 |   `------------------------------------------------------------*/
yynewstate:
	/* In all cases, when you get here, the value and location stacks
	 *  have just been pushed.  So pushing a state here evens the stacks.  */
	yyssp++;

yysetstate:
	*yyssp = yystate;

	if (yyss + yystacksize - 1 <= yyssp) {
		/* Get the current used size of the three stacks, in elements.  */
		YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
		{
			/* Give user a chance to reallocate the stack.  Use copies of
			 *  these so that the &'s don't force the real ones into
			 *  memory.  */
			YYSTYPE *yyvs1 = yyvs;
			yytype_int16 *yyss1 = yyss;


			/* Each stack pointer address is followed by the size of the
			 *  data in use in that stack, in bytes.  This used to be a
			 *  conditional around just the two extra args, but that might
			 *  be undefined if yyoverflow is a macro.  */
			yyoverflow(YY_("memory exhausted"),
			    &yyss1, yysize * sizeof(*yyssp),
			    &yyvs1, yysize * sizeof(*yyvsp),

			    &yystacksize);

			yyss = yyss1;
			yyvs = yyvs1;
		}
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
		goto yyexhaustedlab;
# else
		/* Extend the stack our own way.  */
		if (YYMAXDEPTH <= yystacksize) {
			goto yyexhaustedlab;
		}
		yystacksize *= 2;
		if (YYMAXDEPTH < yystacksize) {
			yystacksize = YYMAXDEPTH;
		}

		{
			yytype_int16 *yyss1 = yyss;
			union yyalloc *yyptr =
			    (union yyalloc *) YYSTACK_ALLOC(YYSTACK_BYTES(yystacksize));
			if (!yyptr) {
				goto yyexhaustedlab;
			}
			YYSTACK_RELOCATE(yyss);
			YYSTACK_RELOCATE(yyvs);

#  undef YYSTACK_RELOCATE
			if (yyss1 != yyssa) {
				YYSTACK_FREE(yyss1);
			}
		}
# endif
#endif /* no yyoverflow */

		yyssp = yyss + yysize - 1;
		yyvsp = yyvs + yysize - 1;


		YYDPRINTF((stderr, "Stack size increased to %lu\n",
		    (unsigned long int) yystacksize));

		if (yyss + yystacksize - 1 <= yyssp) {
			YYABORT;
		}
	}

	YYDPRINTF((stderr, "Entering state %d\n", yystate));

	goto yybackup;

/*-----------.
 | yybackup.  |
 |   `-----------*/
yybackup:

	/* Do appropriate processing given the current state.  Read a
	 *  look-ahead token if we need one and don't already have one.  */

	/* First try to decide what to do without reference to look-ahead token.  */
	yyn = yypact[yystate];
	if (yyn == YYPACT_NINF) {
		goto yydefault;
	}

	/* Not known => get a look-ahead token if don't already have one.  */

	/* YYCHAR is either YYEMPTY or YYEOF or a valid look-ahead symbol.  */
	if (yychar == YYEMPTY) {
		YYDPRINTF((stderr, "Reading a token: "));
		yychar = YYLEX;
	}

	if (yychar <= YYEOF) {
		yychar = yytoken = YYEOF;
		YYDPRINTF((stderr, "Now at end of input.\n"));
	} else {
		yytoken = YYTRANSLATE(yychar);
		YY_SYMBOL_PRINT("Next token is", yytoken, &yylval, &yylloc);
	}

	/* If the proper action on seeing token YYTOKEN is to reduce or to
	 *  detect an error, take that action.  */
	yyn += yytoken;
	if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken) {
		goto yydefault;
	}
	yyn = yytable[yyn];
	if (yyn <= 0) {
		if (yyn == 0 || yyn == YYTABLE_NINF) {
			goto yyerrlab;
		}
		yyn = -yyn;
		goto yyreduce;
	}

	if (yyn == YYFINAL) {
		YYACCEPT;
	}

	/* Count tokens shifted since error; after three, turn off error
	 *  status.  */
	if (yyerrstatus) {
		yyerrstatus--;
	}

	/* Shift the look-ahead token.  */
	YY_SYMBOL_PRINT("Shifting", yytoken, &yylval, &yylloc);

	/* Discard the shifted token unless it is eof.  */
	if (yychar != YYEOF) {
		yychar = YYEMPTY;
	}

	yystate = yyn;
	*++yyvsp = yylval;

	goto yynewstate;


/*-----------------------------------------------------------.
 | yydefault -- do the default action for the current state.  |
 |   `-----------------------------------------------------------*/
yydefault:
	yyn = yydefact[yystate];
	if (yyn == 0) {
		goto yyerrlab;
	}
	goto yyreduce;


/*-----------------------------.
 | yyreduce -- Do a reduction.  |
 |   `-----------------------------*/
yyreduce:
	/* yyn is the number of a rule to reduce with.  */
	yylen = yyr2[yyn];

	/* If YYLEN is nonzero, implement the default value of the action:
	 *  `$$ = $1'.
	 *
	 *  Otherwise, the following line sets YYVAL to garbage.
	 *  This behavior is undocumented and Bison
	 *  users should not rely upon it.  Assigning to YYVAL
	 *  unconditionally makes the parser a bit smaller, and it avoids a
	 *  GCC warning that YYVAL may be used uninitialized.  */
	yyval = yyvsp[1 - yylen];


	YY_REDUCE_PRINT(yyn);
	switch (yyn) {
	case 2:
#line 146 "OSUnserializeXML.y"
		{ yyerror("unexpected end of buffer");
		  YYERROR;
		  ;}
		break;

	case 3:
#line 149 "OSUnserializeXML.y"
		{ STATE->parsedObject = (yyvsp[(1) - (1)])->object;
		  (yyvsp[(1) - (1)])->object = 0;
		  freeObject(STATE, (yyvsp[(1) - (1)]));
		  YYACCEPT;
		  ;}
		break;

	case 4:
#line 154 "OSUnserializeXML.y"
		{ yyerror("syntax error");
		  YYERROR;
		  ;}
		break;

	case 5:
#line 159 "OSUnserializeXML.y"
		{ (yyval) = buildDictionary(STATE, (yyvsp[(1) - (1)]));

		  if (!yyval->object) {
			  yyerror("buildDictionary");
			  YYERROR;
		  }
		  STATE->parsedObjectCount++;
		  if (STATE->parsedObjectCount > MAX_OBJECTS) {
			  yyerror("maximum object count");
			  YYERROR;
		  }
		  ;}
		break;

	case 6:
#line 171 "OSUnserializeXML.y"
		{ (yyval) = buildArray(STATE, (yyvsp[(1) - (1)]));

		  if (!yyval->object) {
			  yyerror("buildArray");
			  YYERROR;
		  }
		  STATE->parsedObjectCount++;
		  if (STATE->parsedObjectCount > MAX_OBJECTS) {
			  yyerror("maximum object count");
			  YYERROR;
		  }
		  ;}
		break;

	case 7:
#line 183 "OSUnserializeXML.y"
		{ (yyval) = buildSet(STATE, (yyvsp[(1) - (1)]));

		  if (!yyval->object) {
			  yyerror("buildSet");
			  YYERROR;
		  }
		  STATE->parsedObjectCount++;
		  if (STATE->parsedObjectCount > MAX_OBJECTS) {
			  yyerror("maximum object count");
			  YYERROR;
		  }
		  ;}
		break;

	case 8:
#line 195 "OSUnserializeXML.y"
		{ (yyval) = buildString(STATE, (yyvsp[(1) - (1)]));

		  if (!yyval->object) {
			  yyerror("buildString");
			  YYERROR;
		  }
		  STATE->parsedObjectCount++;
		  if (STATE->parsedObjectCount > MAX_OBJECTS) {
			  yyerror("maximum object count");
			  YYERROR;
		  }
		  ;}
		break;

	case 9:
#line 207 "OSUnserializeXML.y"
		{ (yyval) = buildData(STATE, (yyvsp[(1) - (1)]));

		  if (!yyval->object) {
			  yyerror("buildData");
			  YYERROR;
		  }
		  STATE->parsedObjectCount++;
		  if (STATE->parsedObjectCount > MAX_OBJECTS) {
			  yyerror("maximum object count");
			  YYERROR;
		  }
		  ;}
		break;

	case 10:
#line 219 "OSUnserializeXML.y"
		{ (yyval) = buildNumber(STATE, (yyvsp[(1) - (1)]));

		  if (!yyval->object) {
			  yyerror("buildNumber");
			  YYERROR;
		  }
		  STATE->parsedObjectCount++;
		  if (STATE->parsedObjectCount > MAX_OBJECTS) {
			  yyerror("maximum object count");
			  YYERROR;
		  }
		  ;}
		break;

	case 11:
#line 231 "OSUnserializeXML.y"
		{ (yyval) = buildBoolean(STATE, (yyvsp[(1) - (1)]));

		  if (!yyval->object) {
			  yyerror("buildBoolean");
			  YYERROR;
		  }
		  STATE->parsedObjectCount++;
		  if (STATE->parsedObjectCount > MAX_OBJECTS) {
			  yyerror("maximum object count");
			  YYERROR;
		  }
		  ;}
		break;

	case 12:
#line 243 "OSUnserializeXML.y"
		{ (yyval) = retrieveObject(STATE, (yyvsp[(1) - (1)])->idref);
		  if ((yyval)) {
			  STATE->retrievedObjectCount++;
			  (yyval)->object->retain();
			  if (STATE->retrievedObjectCount > MAX_REFED_OBJECTS) {
				  yyerror("maximum object reference count");
				  YYERROR;
			  }
		  } else {
			  yyerror("forward reference detected");
			  YYERROR;
		  }
		  freeObject(STATE, (yyvsp[(1) - (1)]));

		  STATE->parsedObjectCount++;
		  if (STATE->parsedObjectCount > MAX_OBJECTS) {
			  yyerror("maximum object count");
			  YYERROR;
		  }
		  ;}
		break;

	case 13:
#line 267 "OSUnserializeXML.y"
		{ (yyval) = (yyvsp[(1) - (2)]);
		  (yyval)->elements = NULL;
		  ;}
		break;

	case 14:
#line 270 "OSUnserializeXML.y"
		{ (yyval) = (yyvsp[(1) - (3)]);
		  (yyval)->elements = (yyvsp[(2) - (3)]);
		  ;}
		break;

	case 17:
#line 277 "OSUnserializeXML.y"
		{ (yyval) = (yyvsp[(2) - (2)]);
		  (yyval)->next = (yyvsp[(1) - (2)]);

		  object_t *o;
		  o = (yyval)->next;
		  while (o) {
			  if (o->key == (yyval)->key) {
				  yyerror("duplicate dictionary key");
				  YYERROR;
			  }
			  o = o->next;
		  }
		  ;}
		break;

	case 18:
#line 292 "OSUnserializeXML.y"
		{ (yyval) = (yyvsp[(1) - (2)]);
		  (yyval)->key = (OSSymbol *)(yyval)->object;
		  (yyval)->object = (yyvsp[(2) - (2)])->object;
		  (yyval)->next = NULL;
		  (yyvsp[(2) - (2)])->object = 0;
		  freeObject(STATE, (yyvsp[(2) - (2)]));
		  ;}
		break;

	case 19:
#line 301 "OSUnserializeXML.y"
		{ (yyval) = buildSymbol(STATE, (yyvsp[(1) - (1)]));

//				  STATE->parsedObjectCount++;
//				  if (STATE->parsedObjectCount > MAX_OBJECTS) {
//				    yyerror("maximum object count");
//				    YYERROR;
//				  }
		  ;}
		break;

	case 20:
#line 313 "OSUnserializeXML.y"
		{ (yyval) = (yyvsp[(1) - (2)]);
		  (yyval)->elements = NULL;
		  ;}
		break;

	case 21:
#line 316 "OSUnserializeXML.y"
		{ (yyval) = (yyvsp[(1) - (3)]);
		  (yyval)->elements = (yyvsp[(2) - (3)]);
		  ;}
		break;

	case 23:
#line 322 "OSUnserializeXML.y"
		{ (yyval) = (yyvsp[(1) - (2)]);
		  (yyval)->elements = NULL;
		  ;}
		break;

	case 24:
#line 325 "OSUnserializeXML.y"
		{ (yyval) = (yyvsp[(1) - (3)]);
		  (yyval)->elements = (yyvsp[(2) - (3)]);
		  ;}
		break;

	case 26:
#line 331 "OSUnserializeXML.y"
		{ (yyval) = (yyvsp[(1) - (1)]);
		  (yyval)->next = NULL;
		  ;}
		break;

	case 27:
#line 334 "OSUnserializeXML.y"
		{ (yyval) = (yyvsp[(2) - (2)]);
		  (yyval)->next = (yyvsp[(1) - (2)]);
		  ;}
		break;


/* Line 1267 of yacc.c.  */
#line 1701 "OSUnserializeXML.tab.c"
	default: break;
	}
	YY_SYMBOL_PRINT("-> $$ =", yyr1[yyn], &yyval, &yyloc);

	YYPOPSTACK(yylen);
	yylen = 0;
	YY_STACK_PRINT(yyss, yyssp);

	*++yyvsp = yyval;


	/* Now `shift' the result of the reduction.  Determine what state
	 *  that goes to, based on the state we popped back to and the rule
	 *  number reduced by.  */

	yyn = yyr1[yyn];

	yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
	if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp) {
		yystate = yytable[yystate];
	} else {
		yystate = yydefgoto[yyn - YYNTOKENS];
	}

	goto yynewstate;


/*------------------------------------.
 | yyerrlab -- here on detecting error |
 |   `------------------------------------*/
yyerrlab:
	/* If not already recovering from an error, report this error.  */
	if (!yyerrstatus) {
		++yynerrs;
#if !YYERROR_VERBOSE
		yyerror(YY_("syntax error"));
#else
		{
			YYSIZE_T yysize = yysyntax_error(0, yystate, yychar);
			if (yymsg_alloc < yysize && yymsg_alloc < YYSTACK_ALLOC_MAXIMUM) {
				YYSIZE_T yyalloc = 2 * yysize;
				if (!(yysize <= yyalloc && yyalloc <= YYSTACK_ALLOC_MAXIMUM)) {
					yyalloc = YYSTACK_ALLOC_MAXIMUM;
				}
				if (yymsg != yymsgbuf) {
					YYSTACK_FREE(yymsg);
				}
				yymsg = (char *) YYSTACK_ALLOC(yyalloc);
				if (yymsg) {
					yymsg_alloc = yyalloc;
				} else {
					yymsg = yymsgbuf;
					yymsg_alloc = sizeof yymsgbuf;
				}
			}

			if (0 < yysize && yysize <= yymsg_alloc) {
				(void) yysyntax_error(yymsg, yystate, yychar);
				yyerror(yymsg);
			} else {
				yyerror(YY_("syntax error"));
				if (yysize != 0) {
					goto yyexhaustedlab;
				}
			}
		}
#endif
	}



	if (yyerrstatus == 3) {
		/* If just tried and failed to reuse look-ahead token after an
		 *  error, discard it.  */

		if (yychar <= YYEOF) {
			/* Return failure if at end of input.  */
			if (yychar == YYEOF) {
				YYABORT;
			}
		} else {
			yydestruct("Error: discarding",
			    yytoken, &yylval);
			yychar = YYEMPTY;
		}
	}

	/* Else will try to reuse look-ahead token after shifting the error
	 *  token.  */
	goto yyerrlab1;


/*---------------------------------------------------.
 | yyerrorlab -- error raised explicitly by YYERROR.  |
 |   `---------------------------------------------------*/
yyerrorlab:

	/* Pacify compilers like GCC when the user code never invokes
	 *  YYERROR and the label yyerrorlab therefore never appears in user
	 *  code.  */
	if (/*CONSTCOND*/ 0) {
		goto yyerrorlab;
	}

	/* Do not reclaim the symbols of the rule which action triggered
	 *  this YYERROR.  */
	YYPOPSTACK(yylen);
	yylen = 0;
	YY_STACK_PRINT(yyss, yyssp);
	yystate = *yyssp;
	goto yyerrlab1;


/*-------------------------------------------------------------.
 | yyerrlab1 -- common code for both syntax error and YYERROR.  |
 |   `-------------------------------------------------------------*/
yyerrlab1:
	yyerrstatus = 3; /* Each real token shifted decrements this.  */

	for (;;) {
		yyn = yypact[yystate];
		if (yyn != YYPACT_NINF) {
			yyn += YYTERROR;
			if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR) {
				yyn = yytable[yyn];
				if (0 < yyn) {
					break;
				}
			}
		}

		/* Pop the current state because it cannot handle the error token.  */
		if (yyssp == yyss) {
			YYABORT;
		}


		yydestruct("Error: popping",
		    yystos[yystate], yyvsp);
		YYPOPSTACK(1);
		yystate = *yyssp;
		YY_STACK_PRINT(yyss, yyssp);
	}

	if (yyn == YYFINAL) {
		YYACCEPT;
	}

	*++yyvsp = yylval;


	/* Shift the error token.  */
	YY_SYMBOL_PRINT("Shifting", yystos[yyn], yyvsp, yylsp);

	yystate = yyn;
	goto yynewstate;


/*-------------------------------------.
 | yyacceptlab -- YYACCEPT comes here.  |
 |   `-------------------------------------*/
yyacceptlab:
	yyresult = 0;
	goto yyreturn;

/*-----------------------------------.
 | yyabortlab -- YYABORT comes here.  |
 |   `-----------------------------------*/
yyabortlab:
	yyresult = 1;
	goto yyreturn;

#ifndef yyoverflow
/*-------------------------------------------------.
 | yyexhaustedlab -- memory exhaustion comes here.  |
 |   `-------------------------------------------------*/
yyexhaustedlab:
	yyerror(YY_("memory exhausted"));
	yyresult = 2;
	/* Fall through.  */
#endif

yyreturn:
	if (yychar != YYEOF && yychar != YYEMPTY) {
		yydestruct("Cleanup: discarding lookahead",
		    yytoken, &yylval);
	}
	/* Do not reclaim the symbols of the rule which action triggered
	 *  this YYABORT or YYACCEPT.  */
	YYPOPSTACK(yylen);
	YY_STACK_PRINT(yyss, yyssp);
	while (yyssp != yyss) {
		yydestruct("Cleanup: popping",
		    yystos[*yyssp], yyvsp);
		YYPOPSTACK(1);
	}
#ifndef yyoverflow
	if (yyss != yyssa) {
		YYSTACK_FREE(yyss);
	}
#endif
#if YYERROR_VERBOSE
	if (yymsg != yymsgbuf) {
		YYSTACK_FREE(yymsg);
	}
#endif
	/* Make sure YYID is used.  */
	return YYID(yyresult);
}


#line 356 "OSUnserializeXML.y"


int
OSUnserializeerror(parser_state_t * state, const char *s)  /* Called by yyparse on errors */
{
	if (state->errorString) {
		char tempString[128];
		snprintf(tempString, 128, "OSUnserializeXML: %s near line %d\n", s, state->lineNumber);
		*(state->errorString) = OSString::withCString(tempString);
	}

	return 0;
}

#define TAG_MAX_LENGTH          32
#define TAG_MAX_ATTRIBUTES      32
#define TAG_BAD                 0
#define TAG_START               1
#define TAG_END                 2
#define TAG_EMPTY               3
#define TAG_IGNORE              4

#define currentChar()   (state->parseBuffer[state->parseBufferIndex])
#define nextChar()      (state->parseBuffer[++state->parseBufferIndex])
#define prevChar()      (state->parseBuffer[state->parseBufferIndex - 1])

#define isSpace(c)      ((c) == ' ' || (c) == '\t')
#define isAlpha(c)      (((c) >= 'A' && (c) <= 'Z') || ((c) >= 'a' && (c) <= 'z'))
#define isDigit(c)      ((c) >= '0' && (c) <= '9')
#define isAlphaDigit(c) ((c) >= 'a' && (c) <= 'f')
#define isHexDigit(c)   (isDigit(c) || isAlphaDigit(c))
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

	if (c != '<') {
		return TAG_BAD;
	}
	c = nextChar();         // skip '<'


	// <!TAG   declarations     >
	// <!--     comments      -->
	if (c == '!') {
		c = nextChar();
		bool isComment = (c == '-') && ((c = nextChar()) != 0) && (c == '-');
		if (!isComment && !isAlpha(c)) {
			return TAG_BAD;                      // <!1, <!-A, <!eos
		}
		while (c && (c = nextChar()) != 0) {
			if (c == '\n') {
				state->lineNumber++;
			}
			if (isComment) {
				if (c != '-') {
					continue;
				}
				c = nextChar();
				if (c != '-') {
					continue;
				}
				c = nextChar();
			}
			if (c == '>') {
				(void)nextChar();
				return TAG_IGNORE;
			}
			if (isComment) {
				break;
			}
		}
		return TAG_BAD;
	} else
	// <? Processing Instructions  ?>
	if (c == '?') {
		while ((c = nextChar()) != 0) {
			if (c == '\n') {
				state->lineNumber++;
			}
			if (c != '?') {
				continue;
			}
			c = nextChar();
			if (!c) {
				return TAG_IGNORE;
			}
			if (c == '>') {
				(void)nextChar();
				return TAG_IGNORE;
			}
		}
		return TAG_BAD;
	} else
	// </ end tag >
	if (c == '/') {
		c = nextChar();         // skip '/'
		tagType = TAG_END;
	}
	if (!isAlpha(c)) {
		return TAG_BAD;
	}

	/* find end of tag while copying it */
	while (isAlphaNumeric(c)) {
		tag[length++] = c;
		c = nextChar();
		if (length >= (TAG_MAX_LENGTH - 1)) {
			return TAG_BAD;
		}
	}

	tag[length] = 0;

//	printf("tag %s, type %d\n", tag, tagType);

	// look for attributes of the form attribute = "value" ...
	while ((c != '>') && (c != '/')) {
		while (isSpace(c)) {
			c = nextChar();
		}

		length = 0;
		while (isAlphaNumeric(c)) {
			attributes[*attributeCount][length++] = c;
			if (length >= (TAG_MAX_LENGTH - 1)) {
				return TAG_BAD;
			}
			c = nextChar();
		}
		attributes[*attributeCount][length] = 0;

		while (isSpace(c)) {
			c = nextChar();
		}

		if (c != '=') {
			return TAG_BAD;
		}
		c = nextChar();

		while (isSpace(c)) {
			c = nextChar();
		}

		if (c != '"') {
			return TAG_BAD;
		}
		c = nextChar();
		length = 0;
		while (c != '"') {
			values[*attributeCount][length++] = c;
			if (length >= (TAG_MAX_LENGTH - 1)) {
				return TAG_BAD;
			}
			c = nextChar();
			if (!c) {
				return TAG_BAD;
			}
		}
		values[*attributeCount][length] = 0;

		c = nextChar(); // skip closing quote

//		printf("	attribute '%s' = '%s', nextchar = '%c'\n",
//		       attributes[*attributeCount], values[*attributeCount], c);

		(*attributeCount)++;
		if (*attributeCount >= TAG_MAX_ATTRIBUTES) {
			return TAG_BAD;
		}
	}

	if (c == '/') {
		c = nextChar();         // skip '/'
		tagType = TAG_EMPTY;
	}
	if (c != '>') {
		return TAG_BAD;
	}
	c = nextChar();         // skip '>'

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
		if (c == '\n') {
			state->lineNumber++;
		}
		if (c == '<') {
			break;
		}
		c = nextChar();
	}

	if (c != '<') {
		return 0;
	}

	length = state->parseBufferIndex - start;

	/* copy to null terminated buffer */
	tempString = (char *)malloc(length + 1);
	if (tempString == NULL) {
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
			if ((i + 3) > length) {
				goto error;
			}
			c = state->parseBuffer[start + i++];
			if (c == 'l') {
				if (state->parseBuffer[start + i++] != 't') {
					goto error;
				}
				if (state->parseBuffer[start + i++] != ';') {
					goto error;
				}
				tempString[j++] = '<';
				continue;
			}
			if (c == 'g') {
				if (state->parseBuffer[start + i++] != 't') {
					goto error;
				}
				if (state->parseBuffer[start + i++] != ';') {
					goto error;
				}
				tempString[j++] = '>';
				continue;
			}
			if ((i + 3) > length) {
				goto error;
			}
			if (c == 'a') {
				if (state->parseBuffer[start + i++] != 'm') {
					goto error;
				}
				if (state->parseBuffer[start + i++] != 'p') {
					goto error;
				}
				if (state->parseBuffer[start + i++] != ';') {
					goto error;
				}
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
	if (tempString) {
		free(tempString);
	}
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
		while (isDigit(c)) {
			n = (n * base + c - '0');
			c = nextChar();
		}
		if (negate) {
			n = (unsigned long long)((long long)n * (long long)-1);
		}
	} else {
		while (isHexDigit(c)) {
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
	/* '8' */ 60, 61, -1, -1, -1, 0, -1, -1,
	/* '@' */ -1, 0, 1, 2, 3, 4, 5, 6,
	/* 'H' */ 7, 8, 9, 10, 11, 12, 13, 14,
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
	int numeq = 0, cntr = 0;
	unsigned int acc = 0;
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
		if (c == '=') {
			numeq++;
		} else {
			numeq = 0;
		}
		if (c == '\n') {
			state->lineNumber++;
		}
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
			if (numeq < 2) {
				tmpbuf[tmpbufpos++] = (acc >> 8) & 0xff;
			}
			if (numeq < 1) {
				tmpbuf[tmpbufpos++] = acc & 0xff;
			}
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
		if (isSpace(c)) {
			while ((c = nextChar()) != 0 && isSpace(c)) {
			}
		}
		;
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
	if (isSpace(c)) {
		while ((c = nextChar()) != 0 && isSpace(c)) {
		}
	}
	;

	/* keep track of line number, don't return \n's */
	if (c == '\n') {
		STATE->lineNumber++;
		(void)nextChar();
		goto top;
	}

	// end of the buffer?
	if (!c) {
		return 0;
	}

	tagType = getTag(STATE, tag, &attributeCount, attributes, values);
	if (tagType == TAG_BAD) {
		return SYNTAX_ERROR;
	}
	if (tagType == TAG_IGNORE) {
		goto top;
	}

	// handle allocation and check for "ID" and "IDREF" tags up front
	*lvalp = object = newObject(STATE);
	object->idref = -1;
	for (i = 0; i < attributeCount; i++) {
		if (attributes[i][0] == 'I' && attributes[i][1] == 'D') {
			// check for idref's, note: we ignore the tag, for
			// this to work correctly, all idrefs must be unique
			// across the whole serialization
			if (attributes[i][2] == 'R' && attributes[i][3] == 'E' &&
			    attributes[i][4] == 'F' && !attributes[i][5]) {
				if (tagType != TAG_EMPTY) {
					return SYNTAX_ERROR;
				}
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
			for (i = 0; i < attributeCount; i++) {
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
			object->size = 64;      // default
			for (i = 0; i < attributeCount; i++) {
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
			if (tagType == TAG_EMPTY) {
				return SYNTAX_ERROR;
			}
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
	if (!ref) {
		return 0;
	}

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
	if (header->idref >= 0) {
		rememberObject(state, header->idref, dict);
	}

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
	if (header->idref >= 0) {
		rememberObject(state, header->idref, array);
	}

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
	if (header->idref >= 0) {
		rememberObject(state, header->idref, set);
	}

	array->release();
	o->object = set;
	return o;
};

object_t *
buildString(parser_state_t *state, object_t *o)
{
	OSString *string;

	string = OSString::withCString(o->string);
	if (o->idref >= 0) {
		rememberObject(state, o->idref, string);
	}

	free(o->string);
	o->string = 0;
	o->object = string;

	return o;
};

object_t *
buildSymbol(parser_state_t *state, object_t *o)
{
	OSSymbol *symbol;

	symbol = const_cast < OSSymbol * > (OSSymbol::withCString(o->string));
	if (o->idref >= 0) {
		rememberObject(state, o->idref, symbol);
	}

	free(o->string);
	o->string = 0;
	o->object = symbol;

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
	if (o->idref >= 0) {
		rememberObject(state, o->idref, data);
	}

	if (o->size) {
		free(o->data);
	}
	o->data = 0;
	o->object = data;
	return o;
};

object_t *
buildNumber(parser_state_t *state, object_t *o)
{
	OSNumber *number = OSNumber::withNumber(o->number, o->size);

	if (o->idref >= 0) {
		rememberObject(state, o->idref, number);
	}

	o->object = number;
	return o;
};

object_t *
buildBoolean(parser_state_t *state __unused, object_t *o)
{
	o->object = ((o->number == 0) ? kOSBooleanFalse : kOSBooleanTrue);
	o->object->retain();
	return o;
};

OSObject*
OSUnserializeXML(const char *buffer, OSString **errorString)
{
	OSObject *object;

	if (!buffer) {
		return 0;
	}
	parser_state_t *state = (parser_state_t *)malloc(sizeof(parser_state_t));
	if (!state) {
		return 0;
	}

	// just in case
	if (errorString) {
		*errorString = NULL;
	}

	state->parseBuffer = buffer;
	state->parseBufferIndex = 0;
	state->lineNumber = 1;
	state->objects = 0;
	state->freeObjects = 0;
	state->tags = OSDictionary::withCapacity(128);
	state->errorString = errorString;
	state->parsedObject = 0;
	state->parsedObjectCount = 0;
	state->retrievedObjectCount = 0;

	(void)yyparse((void *)state);

	object = state->parsedObject;

	cleanupObjects(state);
	state->tags->release();
	free(state);

	return object;
}

#include <libkern/OSSerializeBinary.h>

OSObject*
OSUnserializeXML(const char *buffer, size_t bufferSize, OSString **errorString)
{
	if (!buffer) {
		return 0;
	}
	if (bufferSize < sizeof(kOSSerializeBinarySignature)) {
		return 0;
	}

	if (!strcmp(kOSSerializeBinarySignature, buffer)
	    || (kOSSerializeIndexedBinarySignature == (uint8_t)buffer[0])) {
		return OSUnserializeBinary(buffer, bufferSize, errorString);
	}

	// XML must be null terminated
	if (buffer[bufferSize - 1]) {
		return 0;
	}

	return OSUnserializeXML(buffer, errorString);
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
