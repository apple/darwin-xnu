/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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

/*  OSUnserialize.y created by rsulack on Nov 21 1998 */

//              "classic" parser for unserializing OSContainer objects
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
#define YYPURE 0

/* Using locations.  */
#define YYLSP_NEEDED 0

/* Substitute the variable and function names.  */
#define yyparse OSUnserializeparse
#define yylex   OSUnserializelex
#define yyerror OSUnserializeerror
#define yylval  OSUnserializelval
#define yychar  OSUnserializechar
#define yydebug OSUnserializedebug
#define yynerrs OSUnserializenerrs


/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
/* Put the tokens into the symbol table, so that GDB and other debuggers
 *  know about them.  */
enum yytokentype {
	NUMBER = 258,
	STRING = 259,
	DATA = 260,
	BOOLEAN = 261,
	SYNTAX_ERROR = 262
};
#endif
/* Tokens.  */
#define NUMBER 258
#define STRING 259
#define DATA 260
#define BOOLEAN 261
#define SYNTAX_ERROR 262




/* Copy the first part of user declarations.  */
#line 60 "OSUnserialize.y"

#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSContainers.h>
#include <libkern/c++/OSLib.h>

typedef struct object {
	struct object   *next;
	struct object   *prev;
	void            *object;
	int             size;           // for data
	union {
		void    *key;           // for dictionary
		long long offset;       // for offset
	} u;
} object_t;

static int yyerror(const char *s);
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
static object_t *oo;

// resultant object of parsed text
static OSObject *parsedObject;

#define YYSTYPE object_t *

__BEGIN_DECLS
#include <kern/kalloc.h>
__END_DECLS

#define malloc(size) malloc_impl(size)
static inline void *
malloc_impl(size_t size)
{
	if (size == 0) {
		return NULL;
	}
	return kheap_alloc_tag_bt(KHEAP_DEFAULT, size,
	           (zalloc_flags_t) (Z_WAITOK | Z_ZERO),
	           VM_KERN_MEMORY_LIBKERN);
}

#define free(addr) free_impl(addr)
static inline void
free_impl(void *addr)
{
	kheap_free_addr(KHEAP_DEFAULT, addr);
}
static inline void
safe_free(void *addr, size_t size)
{
	if (addr) {
		assert(size != 0);
		kheap_free(KHEAP_DEFAULT, addr, size);
	}
}

#define realloc(addr, osize, nsize) realloc_impl(addr, osize, nsize)
static inline void *
realloc_impl(void *addr, size_t osize, size_t nsize)
{
	if (!addr) {
		return malloc(nsize);
	}
	if (nsize == osize) {
		return addr;
	}
	void *nmem = malloc(nsize);
	if (!nmem) {
		safe_free(addr, osize);
		return NULL;
	}
	(void)memcpy(nmem, addr, (nsize > osize) ? osize : nsize);
	safe_free(addr, osize);

	return nmem;
}



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
#line 224 "OSUnserialize.tab.c"

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
#define YYFINAL  30
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   80

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  19
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  13
/* YYNRULES -- Number of rules.  */
#define YYNRULES  28
/* YYNRULES -- Number of states.  */
#define YYNSTATES  43

/* YYTRANSLATE(YYLEX) -- Bison symbol number corresponding to YYLEX.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   262

#define YYTRANSLATE(YYX)                                                \
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[YYLEX] -- Bison symbol number corresponding to YYLEX.  */
static const yytype_uint8 yytranslate[] =
{
	0, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	13, 14, 2, 2, 17, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 18, 12,
	2, 11, 2, 2, 8, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 15, 2, 16, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 2, 2, 9, 2, 10, 2, 2, 2, 2,
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
	5, 6, 7
};

#if YYDEBUG
/* YYPRHS[YYN] -- Index of the first RHS symbol of rule number YYN in
 *  YYRHS.  */
static const yytype_uint8 yyprhs[] =
{
	0, 0, 3, 4, 6, 8, 10, 12, 14, 16,
	18, 20, 22, 25, 29, 32, 36, 38, 41, 46,
	49, 53, 56, 60, 62, 66, 70, 72, 74
};

/* YYRHS -- A `-1'-separated list of the rules' RHS.  */
static const yytype_int8 yyrhs[] =
{
	20, 0, -1, -1, 21, -1, 7, -1, 22, -1,
	25, -1, 26, -1, 30, -1, 29, -1, 28, -1,
	31, -1, 8, 3, -1, 21, 8, 3, -1, 9,
	10, -1, 9, 23, 10, -1, 24, -1, 23, 24,
	-1, 21, 11, 21, 12, -1, 13, 14, -1, 13,
	27, 14, -1, 15, 16, -1, 15, 27, 16, -1,
	21, -1, 27, 17, 21, -1, 3, 18, 3, -1,
	5, -1, 4, -1, 6, -1
};

/* YYRLINE[YYN] -- source line where rule number YYN was defined.  */
static const yytype_uint8 yyrline[] =
{
	0, 163, 163, 164, 165, 168, 169, 170, 171, 172,
	173, 174, 175, 184, 192, 193, 196, 197, 200, 210,
	211, 214, 215, 218, 223, 234, 242, 247, 252
};
#endif

#if YYDEBUG || YYERROR_VERBOSE || YYTOKEN_TABLE
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
 *  First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
	"$end", "error", "$undefined", "NUMBER", "STRING", "DATA", "BOOLEAN",
	"SYNTAX_ERROR", "'@'", "'{'", "'}'", "'='", "';'", "'('", "')'", "'['",
	"']'", "','", "':'", "$accept", "input", "object", "dict", "pairs",
	"pair", "array", "set", "elements", "offset", "data", "string",
	"boolean", 0
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[YYLEX-NUM] -- Internal token number corresponding to
 *  token YYLEX-NUM.  */
static const yytype_uint16 yytoknum[] =
{
	0, 256, 257, 258, 259, 260, 261, 262, 64, 123,
	125, 61, 59, 40, 41, 91, 93, 44, 58
};
# endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
	0, 19, 20, 20, 20, 21, 21, 21, 21, 21,
	21, 21, 21, 21, 22, 22, 23, 23, 24, 25,
	25, 26, 26, 27, 27, 28, 29, 30, 31
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
	0, 2, 0, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 2, 3, 2, 3, 1, 2, 4, 2,
	3, 2, 3, 1, 3, 3, 1, 1, 1
};

/* YYDEFACT[STATE-NAME] -- Default rule to reduce with in state
 *  STATE-NUM when YYTABLE doesn't specify something else to do.  Zero
 *  means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
	2, 0, 27, 26, 28, 4, 0, 0, 0, 0,
	0, 3, 5, 6, 7, 10, 9, 8, 11, 0,
	12, 14, 0, 0, 16, 19, 23, 0, 21, 0,
	1, 0, 25, 0, 15, 17, 20, 0, 22, 13,
	0, 24, 18
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int8 yydefgoto[] =
{
	-1, 10, 22, 12, 23, 24, 13, 14, 27, 15,
	16, 17, 18
};

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
 *  STATE-NUM.  */
#define YYPACT_NINF -14
static const yytype_int8 yypact[] =
{
	12, -13, -14, -14, -14, -14, 9, 26, 39, -2,
	10, 20, -14, -14, -14, -14, -14, -14, -14, 35,
	-14, -14, 38, 52, -14, -14, 20, 49, -14, 7,
	-14, 37, -14, 65, -14, -14, -14, 65, -14, -14,
	14, 20, -14
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
	-14, -14, 0, -14, -14, 27, -14, -14, 42, -14,
	-14, -14, -14
};

/* YYTABLE[YYPACT[STATE-NUM]].  What to do in state STATE-NUM.  If
 *  positive, shift that token.  If negative, reduce the rule which
 *  number is the opposite.  If zero, do what YYDEFACT says.
 *  If YYTABLE_NINF, syntax error.  */
#define YYTABLE_NINF -1
static const yytype_uint8 yytable[] =
{
	11, 1, 2, 3, 4, 19, 6, 7, 26, 26,
	30, 8, 20, 9, 28, 1, 2, 3, 4, 5,
	6, 7, 31, 38, 37, 8, 42, 9, 31, 1,
	2, 3, 4, 40, 6, 7, 21, 41, 32, 8,
	39, 9, 1, 2, 3, 4, 31, 6, 7, 33,
	35, 29, 8, 25, 9, 1, 2, 3, 4, 0,
	6, 7, 34, 36, 0, 8, 37, 9, 1, 2,
	3, 4, 0, 6, 7, 0, 0, 0, 8, 0,
	9
};

static const yytype_int8 yycheck[] =
{
	0, 3, 4, 5, 6, 18, 8, 9, 8, 9,
	0, 13, 3, 15, 16, 3, 4, 5, 6, 7,
	8, 9, 8, 16, 17, 13, 12, 15, 8, 3,
	4, 5, 6, 33, 8, 9, 10, 37, 3, 13,
	3, 15, 3, 4, 5, 6, 8, 8, 9, 11,
	23, 9, 13, 14, 15, 3, 4, 5, 6, -1,
	8, 9, 10, 14, -1, 13, 17, 15, 3, 4,
	5, 6, -1, 8, 9, -1, -1, -1, 13, -1,
	15
};

/* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
 *  symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
	0, 3, 4, 5, 6, 7, 8, 9, 13, 15,
	20, 21, 22, 25, 26, 28, 29, 30, 31, 18,
	3, 10, 21, 23, 24, 14, 21, 27, 16, 27,
	0, 8, 3, 11, 10, 24, 14, 17, 16, 3,
	21, 21, 12
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
# define YYLEX yylex (YYLEX_PARAM)
#else
# define YYLEX yylex ()
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



/* The look-ahead symbol.  */
int yychar;

/* The semantic value of the look-ahead symbol.  */
YYSTYPE yylval;

/* Number of syntax errors so far.  */
int yynerrs;



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
#line 163 "OSUnserialize.y"
		{ parsedObject = (OSObject *)NULL; YYACCEPT;;}
		break;

	case 3:
#line 164 "OSUnserialize.y"
		{ parsedObject = (OSObject *)(yyvsp[(1) - (1)]); YYACCEPT;;}
		break;

	case 4:
#line 165 "OSUnserialize.y"
		{ yyerror("syntax error"); YYERROR;;}
		break;

	case 5:
#line 168 "OSUnserialize.y"
		{ (yyval) = (object_t *)buildOSDictionary((yyvsp[(1) - (1)]));;}
		break;

	case 6:
#line 169 "OSUnserialize.y"
		{ (yyval) = (object_t *)buildOSArray((yyvsp[(1) - (1)]));;}
		break;

	case 7:
#line 170 "OSUnserialize.y"
		{ (yyval) = (object_t *)buildOSSet((yyvsp[(1) - (1)]));;}
		break;

	case 8:
#line 171 "OSUnserialize.y"
		{ (yyval) = (object_t *)buildOSString((yyvsp[(1) - (1)]));;}
		break;

	case 9:
#line 172 "OSUnserialize.y"
		{ (yyval) = (object_t *)buildOSData((yyvsp[(1) - (1)]));;}
		break;

	case 10:
#line 173 "OSUnserialize.y"
		{ (yyval) = (object_t *)buildOSOffset((yyvsp[(1) - (1)]));;}
		break;

	case 11:
#line 174 "OSUnserialize.y"
		{ (yyval) = (object_t *)buildOSBoolean((yyvsp[(1) - (1)]));;}
		break;

	case 12:
#line 175 "OSUnserialize.y"
		{ (yyval) = (object_t *)retrieveObject((yyvsp[(2) - (2)])->u.offset);
		  if ((yyval)) {
			  ((OSObject *)(yyval))->retain();
		  } else {
			  yyerror("forward reference detected");
			  YYERROR;
		  }
		  freeObject((yyvsp[(2) - (2)]));
		  ;}
		break;

	case 13:
#line 184 "OSUnserialize.y"
		{ (yyval) = (yyvsp[(1) - (3)]);
		  rememberObject((yyvsp[(3) - (3)])->u.offset, (yyvsp[(1) - (3)]));
		  freeObject((yyvsp[(3) - (3)]));
		  ;}
		break;

	case 14:
#line 192 "OSUnserialize.y"
		{ (yyval) = NULL;;}
		break;

	case 15:
#line 193 "OSUnserialize.y"
		{ (yyval) = (yyvsp[(2) - (3)]);;}
		break;

	case 17:
#line 197 "OSUnserialize.y"
		{ (yyvsp[(2) - (2)])->next = (yyvsp[(1) - (2)]); (yyvsp[(1) - (2)])->prev = (yyvsp[(2) - (2)]); (yyval) = (yyvsp[(2) - (2)]);;}
		break;

	case 18:
#line 200 "OSUnserialize.y"
		{ (yyval) = newObject();
		  (yyval)->next = NULL;
		  (yyval)->prev = NULL;
		  (yyval)->u.key = (yyvsp[(1) - (4)]);
		  (yyval)->object = (yyvsp[(3) - (4)]);
		  ;}
		break;

	case 19:
#line 210 "OSUnserialize.y"
		{ (yyval) = NULL;;}
		break;

	case 20:
#line 211 "OSUnserialize.y"
		{ (yyval) = (yyvsp[(2) - (3)]);;}
		break;

	case 21:
#line 214 "OSUnserialize.y"
		{ (yyval) = NULL;;}
		break;

	case 22:
#line 215 "OSUnserialize.y"
		{ (yyval) = (yyvsp[(2) - (3)]);;}
		break;

	case 23:
#line 218 "OSUnserialize.y"
		{ (yyval) = newObject();
		  (yyval)->object = (yyvsp[(1) - (1)]);
		  (yyval)->next = NULL;
		  (yyval)->prev = NULL;
		  ;}
		break;

	case 24:
#line 223 "OSUnserialize.y"
		{ oo = newObject();
		  oo->object = (yyvsp[(3) - (3)]);
		  oo->next = (yyvsp[(1) - (3)]);
		  oo->prev = NULL;
		  (yyvsp[(1) - (3)])->prev = oo;
		  (yyval) = oo;
		  ;}
		break;

	case 25:
#line 234 "OSUnserialize.y"
		{ (yyval) = (yyvsp[(1) - (3)]);
		  (yyval)->size = (yyvsp[(3) - (3)])->u.offset;
		  freeObject((yyvsp[(3) - (3)]));
		  ;}
		break;


/* Line 1267 of yacc.c.  */
#line 1597 "OSUnserialize.tab.c"
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


#line 255 "OSUnserialize.y"


static int              lineNumber = 0;
static const char       *parseBuffer;
static int              parseBufferIndex;

#define currentChar()   (parseBuffer[parseBufferIndex])
#define nextChar()      (parseBuffer[++parseBufferIndex])
#define prevChar()      (parseBuffer[parseBufferIndex - 1])

#define isSpace(c)      ((c) == ' ' || (c) == '\t')
#define isAlpha(c)      (((c) >= 'A' && (c) <= 'Z') || ((c) >= 'a' && (c) <= 'z'))
#define isDigit(c)      ((c) >= '0' && (c) <= '9')
#define isAlphaDigit(c) ((c) >= 'a' && (c) <= 'f')
#define isHexDigit(c)   (isDigit(c) || isAlphaDigit(c))
#define isAlphaNumeric(c) (isAlpha(c) || isDigit(c) || ((c) == '-'))

static char yyerror_message[128];

int
yyerror(const char *s)  /* Called by yyparse on error */
{
	snprintf(yyerror_message, sizeof(yyerror_message), "OSUnserialize: %s near line %d\n", s, lineNumber);
	return 0;
}

int
yylex()
{
	int c;

	if (parseBufferIndex == 0) {
		lineNumber = 1;
	}

top:
	c = currentChar();

	/* skip white space  */
	if (isSpace(c)) {
		while ((c = nextChar()) != 0 && isSpace(c)) {
		}
	}
	;

	/* skip over comments */
	if (c == '#') {
		while ((c = nextChar()) != 0 && c != '\n') {
		}
	}
	;

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
			if (nextChar() != 'r') {
				return SYNTAX_ERROR;
			}
			if (nextChar() != 'u') {
				return SYNTAX_ERROR;
			}
			if (nextChar() != 'e') {
				return SYNTAX_ERROR;
			}
			boolean = true;
		} else {
			if (currentChar() != 'f') {
				return SYNTAX_ERROR;
			}
			if (nextChar() != 'a') {
				return SYNTAX_ERROR;
			}
			if (nextChar() != 'l') {
				return SYNTAX_ERROR;
			}
			if (nextChar() != 's') {
				return SYNTAX_ERROR;
			}
			if (nextChar() != 'e') {
				return SYNTAX_ERROR;
			}
		}
		if (nextChar() != '.') {
			return SYNTAX_ERROR;
		}
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
		if (tempString == NULL) {
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

		start = parseBufferIndex + 1;           // skip quote
		/* find end of string, line, buffer */
		while ((c = nextChar()) != quoteChar) {
			if (c == '\\') {
				c = nextChar();
			}
			if (c == '\n') {
				lineNumber++;
			}
			if (c == 0) {
				return SYNTAX_ERROR;
			}
		}
		length = parseBufferIndex - start;
		/* skip over trailing quote */
		(void)nextChar();
		/* copy to null terminated buffer */
		tempString = (char *)malloc(length + 1);
		if (tempString == NULL) {
			printf("OSUnserialize: can't alloc temp memory\n");
			return 0;
		}

		int to = 0;
		for (int from = start; from < parseBufferIndex; from++) {
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
	if (isDigit(c)) {
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
			while (isDigit(c)) {
				n = (n * base + c - '0');
				c = nextChar();
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

		yylval = newObject();
		yylval->u.offset = n;

		return NUMBER;
	}

#define OSDATA_ALLOC_SIZE 4096

	/* process data */
	if (c == '<') {
		unsigned char *d, *start, *lastStart;

		size_t buflen = OSDATA_ALLOC_SIZE;
		start = lastStart = d = (unsigned char *)malloc(buflen);
		c = nextChar(); // skip over '<'
		while (c != 0 && c != '>') {
			if (isSpace(c)) {
				while ((c = nextChar()) != 0 && isSpace(c)) {
				}
			}
			;
			if (c == '#') {
				while ((c = nextChar()) != 0 && c != '\n') {
				}
			}
			;
			if (c == '\n') {
				lineNumber++;
				c = nextChar();
				continue;
			}

			// get high nibble
			if (!isHexDigit(c)) {
				break;
			}
			if (isDigit(c)) {
				*d = (c - '0') << 4;
			} else {
				*d =  (0xa + (c - 'a')) << 4;
			}

			// get low nibble
			c = nextChar();
			if (!isHexDigit(c)) {
				break;
			}
			if (isDigit(c)) {
				*d |= c - '0';
			} else {
				*d |= 0xa + (c - 'a');
			}

			d++;
			if ((d - lastStart) >= OSDATA_ALLOC_SIZE) {
				int oldsize = d - start;
				assert(buflen == oldsize);
				start = (unsigned char *)realloc(start, oldsize, buflen);
				d = lastStart = start + oldsize;
			}
			c = nextChar();
		}
		if (c != '>') {
			safe_free(start, buflen);
			return SYNTAX_ERROR;
		}

		// got it!
		yylval = newObject();
		yylval->object = start;
		yylval->size = d - start;

		(void)nextChar();       // skip over '>'
		return DATA;
	}


	/* return single chars, move pointer to next char */
	(void)nextChar();
	return c;
}

// !@$&)(^Q$&*^!$(*!@$_(^%_(*Q#$(_*&!$_(*&!$_(*&!#$(*!@&^!@#%!_!#
// !@$&)(^Q$&*^!$(*!@$_(^%_(*Q#$(_*&!$_(*&!$_(*&!#$(*!@&^!@#%!_!#
// !@$&)(^Q$&*^!$(*!@$_(^%_(*Q#$(_*&!$_(*&!$_(*&!#$(*!@&^!@#%!_!#

#if DEBUG
int debugUnserializeAllocCount = 0;
#endif

object_t *
newObject()
{
#if DEBUG
	debugUnserializeAllocCount++;
#endif
	return (object_t *)malloc(sizeof(object_t));
}

void
freeObject(object_t *o)
{
#if DEBUG
	debugUnserializeAllocCount--;
#endif
	safe_free(o, sizeof(object_t));
}

static OSDictionary *tags;

static void
rememberObject(int tag, object_t *o)
{
	char key[16];
	snprintf(key, sizeof(key), "%u", tag);

	tags->setObject(key, (OSObject *)o);
}

static OSObject *
retrieveObject(int tag)
{
	char key[16];
	snprintf(key, sizeof(key), "%u", tag);

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

	safe_free(o, strlen((char *)o) + 1);

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
	safe_free(o->object, o->size);
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
#include <kern/locks.h>
__END_DECLS

static lck_mtx_t * lock = 0;
extern lck_grp_t *IOLockGroup;

OSObject*
OSUnserialize(const char *buffer, OSString **errorString)
{
	OSObject *object;

	if (!lock) {
		lock = lck_mtx_alloc_init(IOLockGroup, LCK_ATTR_NULL);
		lck_mtx_lock(lock);
	} else {
		lck_mtx_lock(lock);
	}

#if DEBUG
	debugUnserializeAllocCount = 0;
#endif
	yyerror_message[0] = 0; //just in case
	parseBuffer = buffer;
	parseBufferIndex = 0;
	tags = OSDictionary::withCapacity(128);
	if (yyparse() == 0) {
		object = parsedObject;
		if (errorString) {
			*errorString = NULL;
		}
	} else {
		object = NULL;
		if (errorString) {
			*errorString = OSString::withCString(yyerror_message);
		}
	}

	tags->release();
#if DEBUG
	if (debugUnserializeAllocCount) {
		printf("OSUnserialize: allocation check failed, count = %d.\n",
		    debugUnserializeAllocCount);
	}
#endif
	lck_mtx_unlock(lock);

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
