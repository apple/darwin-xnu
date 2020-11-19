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
//

     
%{
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
static OSObject	*parsedObject;

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
  if(addr) {
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

%}
%token NUMBER
%token STRING
%token DATA
%token BOOLEAN
%token SYNTAX_ERROR
     
%% /* Grammar rules and actions follow */

input:	  /* empty */		{ parsedObject = (OSObject *)NULL; YYACCEPT; }
	| object		{ parsedObject = (OSObject *)$1;   YYACCEPT; }
	| SYNTAX_ERROR		{ yyerror("syntax error");	   YYERROR; }
	;

object:	  dict			{ $$ = (object_t *)buildOSDictionary($1); }
	| array			{ $$ = (object_t *)buildOSArray($1); }
	| set			{ $$ = (object_t *)buildOSSet($1); }
	| string		{ $$ = (object_t *)buildOSString($1); }
	| data			{ $$ = (object_t *)buildOSData($1); }
	| offset		{ $$ = (object_t *)buildOSOffset($1); }
	| boolean		{ $$ = (object_t *)buildOSBoolean($1); }
	| '@' NUMBER		{ $$ = (object_t *)retrieveObject($2->u.offset);
				  if ($$) {
				    ((OSObject *)$$)->retain();
				  } else { 
				    yyerror("forward reference detected");
				    YYERROR;
				  }
				  freeObject($2); 
				}
	| object '@' NUMBER	{ $$ = $1; 
				  rememberObject($3->u.offset, $1);
				  freeObject($3); 
				}
	;

//------------------------------------------------------------------------------

dict:	  '{' '}'		{ $$ = NULL; }
	| '{' pairs '}'		{ $$ = $2; }
	;

pairs:	  pair
	| pairs pair		{ $2->next = $1; $1->prev = $2; $$ = $2; }
	;

pair:	  object '=' object ';'	{ $$ = newObject();
				  $$->next = NULL; 
				  $$->prev = NULL;
				  $$->u.key = $1;
				  $$->object = $3; 
				}
	;

//------------------------------------------------------------------------------

array:	  '(' ')'		{ $$ = NULL; }
	| '(' elements ')'	{ $$ = $2; }
	;

set:	  '[' ']'		{ $$ = NULL; }
	| '[' elements ']'	{ $$ = $2; }
	;

elements: object		{ $$ = newObject(); 
				  $$->object = $1; 
				  $$->next = NULL; 
				  $$->prev = NULL; 
				}
	| elements ',' object	{ oo = newObject();
				  oo->object = $3;
				  oo->next = $1;
				  oo->prev = NULL; 
				  $1->prev = oo;
				  $$ = oo; 
				}
	;

//------------------------------------------------------------------------------

offset:	  NUMBER ':' NUMBER	{ $$ = $1;
				  $$->size = $3->u.offset;
				  freeObject($3); 
				}
	;

//------------------------------------------------------------------------------

data:	  DATA
	;

//------------------------------------------------------------------------------

string:	  STRING
	;

//------------------------------------------------------------------------------

boolean:  BOOLEAN
	;

%%
     
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
yyerror(const char *s)  /* Called by yyparse on error */
{
	snprintf(yyerror_message, sizeof(yyerror_message), "OSUnserialize: %s near line %d\n", s, lineNumber);
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
		if (tempString == NULL) {
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

		size_t buflen = OSDATA_ALLOC_SIZE;
		start = lastStart = d = (unsigned char *)malloc(buflen);
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
				assert(buflen == oldsize);
				start = (unsigned char *)realloc(start, oldsize, buflen);
				d = lastStart = start + oldsize;
			}
			c = nextChar();
		}
		if (c != '>' ) {
			safe_free(start, buflen);
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

static lck_mtx_t *lock = 0;
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
	yyerror_message[0] = 0;	//just in case
	parseBuffer = buffer;
	parseBufferIndex = 0;
	tags = OSDictionary::withCapacity(128);
	if (yyparse() == 0) {
		object = parsedObject;
		if (errorString) *errorString = NULL;
	} else {
		object = NULL;
		if (errorString)
			*errorString = OSString::withCString(yyerror_message);
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
