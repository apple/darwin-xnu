/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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

/*  OSUnserializeXML.y created by rsulack on Tue Oct 12 1999 */

// 		XML parser for unserializing OSContainer objects
//
// to build :
//	bison -p OSUnserializeXML OSUnserializeXML.y
//	head -50 OSUnserializeXML.y > OSUnserializeXML.cpp
//	sed -e "s/stdio.h/stddef.h/" < OSUnserializeXML.tab.c >> OSUnserializeXML.cpp
//
//	when changing code check in both OSUnserializeXML.y and OSUnserializeXML.cpp
//
//
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
//

     
%{
#include <string.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSContainers.h>
#include <libkern/c++/OSLib.h>

typedef	struct object {
	struct object	*next;
	struct object	*free;
	struct object	*elements;
	OSObject	*object;
	const OSSymbol	*key;		// for dictionary
	int		size;
	void		*data;		// for data
	char		*string;	// for string & symbol
	long long 	number;		// for number
	int		idref;
} object_t;

static int yyparse();
static int yyerror(char *s);
static int yylex();

static object_t * newObject();
static void freeObject(object_t *o);

static object_t *buildOSDictionary(object_t *);
static object_t *buildOSArray(object_t *);
static object_t *buildOSSet(object_t *);
static object_t *buildOSString(object_t *);
static object_t *buildKey(object_t *);
static object_t *buildOSData(object_t *);
static object_t *buildOSNumber(object_t *);
static object_t *buildOSBoolean(object_t *o);

static void rememberObject(int, OSObject *);
static object_t *retrieveObject(int);

// resultant object of parsed text
static OSObject	*parsedObject;

#define YYSTYPE object_t *

extern "C" {
extern void *kern_os_malloc(size_t size);
extern void *kern_os_realloc(void * addr, size_t size);
extern void kern_os_free(void * addr);

//XXX shouldn't have to define these
extern long strtol(const char *, char **, int);
extern unsigned long strtoul(const char *, char **, int);

} /* extern "C" */

#define malloc(s) kern_os_malloc(s)
#define realloc(a, s) kern_os_realloc(a, s)
#define free(a) kern_os_free(a)

%}
%token ARRAY
%token BOOLEAN
%token DATA
%token DICTIONARY
%token IDREF
%token KEY
%token NUMBER
%token SET
%token STRING
%token SYNTAX_ERROR     
%% /* Grammar rules and actions follow */

input:	  /* empty */		{ parsedObject = (OSObject *)NULL; YYACCEPT; }
	| object		{ parsedObject = $1->object;
				  $1->object = 0;
				  freeObject($1);
				  YYACCEPT;
				}
	| SYNTAX_ERROR		{
				  yyerror("syntax error");
				  YYERROR;
				}
	;

object:	  dict			{ $$ = buildOSDictionary($1); }
	| array			{ $$ = buildOSArray($1); }
	| set			{ $$ = buildOSSet($1); }
	| string		{ $$ = buildOSString($1); }
	| data			{ $$ = buildOSData($1); }
	| number		{ $$ = buildOSNumber($1); }
	| boolean		{ $$ = buildOSBoolean($1); }
	| idref			{ $$ = retrieveObject($1->idref);
				  if ($$) {
				    $$->object->retain();
				  } else { 
				    yyerror("forward reference detected");
				    YYERROR;
				  }
				  freeObject($1);
				}
	;

//------------------------------------------------------------------------------

dict:	  '{' '}'		{ $$ = $1;
				  $$->elements = NULL;
				}
	| '{' pairs '}'		{ $$ = $1;
				  $$->elements = $2;
				}
	| DICTIONARY
	;

pairs:	  pair
	| pairs pair		{ $$ = $2;
				  $$->next = $1;
				}
	;

pair:	  key object		{ $$ = $1;
				  $$->next = NULL; 
				  $$->object = $2->object;
				  $2->object = 0;
				  freeObject($2);
				}
	;

key:	  KEY			{ $$ = buildKey($1); }
	;

//------------------------------------------------------------------------------

array:	  '(' ')'		{ $$ = $1;
				  $$->elements = NULL;
				}
	| '(' elements ')'	{ $$ = $1;
				  $$->elements = $2;
				}
	| ARRAY
	;

set:	  '[' ']'		{ $$ = $1;
				  $$->elements = NULL;
				}
	| '[' elements ']'	{ $$ = $1;
				  $$->elements = $2;
				}
	| SET
	;

elements: object		{ $$ = $1; 
				  $$->next = NULL; 
				}
	| elements object	{ $$ = $2;
				  $$->next = $1;
				}
	;

//------------------------------------------------------------------------------

boolean:  BOOLEAN
	;

data:	  DATA
	;

idref:	  IDREF
	;

number:	  NUMBER
	;

string:	  STRING
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
yyerror(char *s)  /* Called by yyparse on error */
{
	sprintf(yyerror_message, "OSUnserializeXML: %s near line %d\n", s, lineNumber);
	return 0;
}

#define TAG_MAX_LENGTH		32
#define TAG_MAX_ATTRIBUTES	32
#define TAG_BAD			0
#define TAG_START		1
#define TAG_END			2
#define TAG_EMPTY		3
#define TAG_COMMENT		4

static int
getTag(char tag[TAG_MAX_LENGTH],
       int *attributeCount, 
       char attributes[TAG_MAX_ATTRIBUTES][TAG_MAX_LENGTH],
       char values[TAG_MAX_ATTRIBUTES][TAG_MAX_LENGTH] )
{
	int length = 0;;
	int c = currentChar();
	int tagType = TAG_START;

	*attributeCount = 0;

	if (c != '<') return TAG_BAD;
        c = nextChar();		// skip '<'

        if (c == '?' || c == '!') {
                while ((c = nextChar()) != 0) {
                        if (c == '\n') lineNumber++;
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

//printf("tag %s, type %d\n", tag, tagType);
	
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

//printf("	attribute '%s' = '%s', nextchar = '%c'\n", attributes[*attributeCount], values[*attributeCount], c);

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
getString()
{
	int c = currentChar();

	int start, length, i, j;;
	char * tempString;

	start = parseBufferIndex;
	/* find end of string */

	while (c != 0) {
		if (c == '\n') lineNumber++;
		if (c == '<') {
			break;
		}
		c = nextChar();
	}

	if (c != '<') return 0;

	length = parseBufferIndex - start;

	/* copy to null terminated buffer */
	tempString = (char *)malloc(length + 1);
	if (tempString == 0) {
		printf("OSUnserializeXML: can't alloc temp memory\n");
		return 0;
	}

	// copy out string in tempString
	// "&amp;" -> '&', "&lt;" -> '<', "&gt;" -> '>'

	i = j = 0;
	while (i < length) {
		c = parseBuffer[start + i++];
		if (c != '&') {
			tempString[j++] = c;
		} else {
			if ((i+3) > length) goto error;
			c = parseBuffer[start + i++];
			if (c == 'l') {
				if (parseBuffer[start + i++] != 't') goto error;
				if (parseBuffer[start + i++] != ';') goto error;
				tempString[j++] = '<';
				continue;
			}	
			if (c == 'g') {
				if (parseBuffer[start + i++] != 't') goto error;
				if (parseBuffer[start + i++] != ';') goto error;
				tempString[j++] = '>';
				continue;
			}	
			if ((i+3) > length) goto error;
			if (c == 'a') {
				if (parseBuffer[start + i++] != 'm') goto error;
				if (parseBuffer[start + i++] != 'p') goto error;
				if (parseBuffer[start + i++] != ';') goto error;
				tempString[j++] = '&';
				continue;
			}
			goto error;
		}	
	}
	tempString[j] = 0;

//printf("string %s\n", tempString);

	return tempString;

error:
	if (tempString) free(tempString);
	return 0;
}

static long long
getNumber()
{
	unsigned long long n = 0;
	int base = 10;
	int c = currentChar();

	if (!isDigit (c)) return 0;

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
//printf("number 0x%x\n", (unsigned long)n);
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

#define OSDATA_ALLOC_SIZE 4096

static void *
getCFEncodedData(unsigned int *size)
{
    int numeq = 0, acc = 0, cntr = 0;
    int tmpbufpos = 0, tmpbuflen = 0;
    unsigned char *tmpbuf = (unsigned char *)malloc(OSDATA_ALLOC_SIZE);

    int c = currentChar();
    *size = 0;
	
    while (c != '<') {
        c &= 0x7f;
	if (c == 0) {
		free(tmpbuf);
		return 0;
	}
	if (c == '=') numeq++; else numeq = 0;
	if (c == '\n') lineNumber++;
        if (__CFPLDataDecodeTable[c] < 0) {
	    c = nextChar();
            continue;
	}
        cntr++;
        acc <<= 6;
        acc += __CFPLDataDecodeTable[c];
        if (0 == (cntr & 0x3)) {
            if (tmpbuflen <= tmpbufpos + 2) {
                tmpbuflen += OSDATA_ALLOC_SIZE;
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
    return tmpbuf;
}

static void *
getHexData(unsigned int *size)
{
    int c;
    unsigned char *d, *start, *lastStart;

    start = lastStart = d = (unsigned char *)malloc(OSDATA_ALLOC_SIZE);
    c = currentChar();

    while (c != '<') {

	if (isSpace(c)) while ((c = nextChar()) != 0 && isSpace(c)) {};
	if (c == '\n') {
	    lineNumber++;
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
	if ((d - lastStart) >= OSDATA_ALLOC_SIZE) {
	    int oldsize = d - start;
	    start = (unsigned char *)realloc(start, oldsize + OSDATA_ALLOC_SIZE);
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
yylex()
{
	int c;
	int tagType;
	char tag[TAG_MAX_LENGTH];
	int attributeCount;
	char attributes[TAG_MAX_ATTRIBUTES][TAG_MAX_LENGTH];
	char values[TAG_MAX_ATTRIBUTES][TAG_MAX_LENGTH];

	if (parseBufferIndex == 0) lineNumber = 1;

 top:
	c = currentChar();

	/* skip white space  */
	if (isSpace(c)) while ((c = nextChar()) != 0 && isSpace(c)) {};

	/* keep track of line number, don't return \n's */
	if (c == '\n') {
		lineNumber++;
		(void)nextChar();
		goto top;
	}
	
	if (!c)	return c;

	tagType = getTag(tag, &attributeCount, attributes, values);
	if (tagType == TAG_BAD) return SYNTAX_ERROR;
	if (tagType == TAG_COMMENT) goto top;

	// handle allocation and check for "ID" and "IDREF" tags up front
	yylval = newObject();
	yylval->idref = -1;
	for (int i=0; i < attributeCount; i++) {
	    if (attributes[i][0] == 'I' && attributes[i][1] == 'D') {
		// check for idref's, note: we ignore the tag, for
		// this to work correctly, all idrefs must be unique
		// across the whole serialization
		if (attributes[i][2] == 'R' && attributes[i][3] == 'E' &&
		    attributes[i][4] == 'F' && !attributes[i][5]) {
		    if (tagType != TAG_EMPTY) return SYNTAX_ERROR;
		    yylval->idref = strtol(values[i], NULL, 0);
		    return IDREF;
		}
		// check for id's
		if (!attributes[i][2]) {
		    yylval->idref = strtol(values[i], NULL, 0);
		} else {
		    return SYNTAX_ERROR;
		}
	    }
	}

	switch (*tag) {
	case 'a':
		if (!strcmp(tag, "array")) {
			if (tagType == TAG_EMPTY) {
				yylval->elements = NULL;
				return ARRAY;
			}
			return (tagType == TAG_START) ? '(' : ')';
		}
		break;
	case 'd':
		if (!strcmp(tag, "dict")) {
			if (tagType == TAG_EMPTY) {
				yylval->elements = NULL;
				return DICTIONARY;
			}
			return (tagType == TAG_START) ? '{' : '}';
		}
		if (!strcmp(tag, "data")) {
			unsigned int size;
			int readable = 0;
			if (tagType == TAG_EMPTY) {
				yylval->data = NULL;
				yylval->size = 0;
				return DATA;
			}
			for (int i=0; i < attributeCount; i++) {
				if (!strcmp(attributes[i], "format") && !strcmp(values[i], "hex")) {
					readable++;
					break;
				}
			}
			// CF encoded is the default form
			if (readable) {
			    yylval->data = getHexData(&size);
			} else {
			    yylval->data = getCFEncodedData(&size);
			}
			yylval->size = size;
			if ((getTag(tag, &attributeCount, attributes, values) != TAG_END) || strcmp(tag, "data")) {
				return SYNTAX_ERROR;
			}
			return DATA;
		}
		break;
	case 'f':
		if (!strcmp(tag, "false")) {
			if (tagType == TAG_EMPTY) {
				yylval->number = 0;
				return BOOLEAN;
			}
		}
		break;
	case 'i':
		if (!strcmp(tag, "integer")) {
			yylval->size = 64;	// default
			for (int i=0; i < attributeCount; i++) {
				if (!strcmp(attributes[i], "size")) {
					yylval->size = strtoul(values[i], NULL, 0);
				}
			}
			if (tagType == TAG_EMPTY) {
				yylval->number = 0;
				return NUMBER;
			}
			yylval->number = getNumber();
			if ((getTag(tag, &attributeCount, attributes, values) != TAG_END) || strcmp(tag, "integer")) {
				return SYNTAX_ERROR;
			}
			return NUMBER;
		}
		break;
	case 'k':
		if (!strcmp(tag, "key")) {
			if (tagType == TAG_EMPTY) return SYNTAX_ERROR;
			yylval->string = getString();
			if (!yylval->string) {
				return SYNTAX_ERROR;
			}
			if ((getTag(tag, &attributeCount, attributes, values) != TAG_END)
			   || strcmp(tag, "key")) {
				return SYNTAX_ERROR;
			}
			return KEY;
		}
		break;
	case 'p':
		if (!strcmp(tag, "plist")) {
			freeObject(yylval);
			goto top;
		}
		break;
	case 's':
		if (!strcmp(tag, "string")) {
			if (tagType == TAG_EMPTY) {
			    	yylval->string = (char *)malloc(1);
			    	*yylval->string = 0;
				return STRING;
			}
			yylval->string = getString();
			if (!yylval->string) {
				return SYNTAX_ERROR;
			}
			if ((getTag(tag, &attributeCount, attributes, values) != TAG_END)
			   || strcmp(tag, "string")) {
				return SYNTAX_ERROR;
			}
			return STRING;
		}
		if (!strcmp(tag, "set")) {
			if (tagType == TAG_EMPTY) {
				yylval->elements = NULL;
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
				yylval->number = 1;
				return BOOLEAN;
			}
		}
		break;

	default:
		// XXX should we ignore invalid tags?
		return SYNTAX_ERROR;
		break;
	}

	return 0;
}

// !@$&)(^Q$&*^!$(*!@$_(^%_(*Q#$(_*&!$_(*&!$_(*&!#$(*!@&^!@#%!_!#
// !@$&)(^Q$&*^!$(*!@$_(^%_(*Q#$(_*&!$_(*&!$_(*&!#$(*!@&^!@#%!_!#
// !@$&)(^Q$&*^!$(*!@$_(^%_(*Q#$(_*&!$_(*&!$_(*&!#$(*!@&^!@#%!_!#

// "java" like allocation, if this code hits a syntax error in the
// the middle of the parsed string we just bail with pointers hanging
// all over place, so this code helps keeps all together

static object_t *objects = 0;
static object_t *freeObjects = 0;

object_t *
newObject()
{
	object_t *o;

	if (freeObjects) {
		o = freeObjects;
		freeObjects = freeObjects->next;
	} else {
		o = (object_t *)malloc(sizeof(object_t));
		bzero(o, sizeof(object_t));
		o->free = objects;
		objects = o;
	}
	
	return o;
}

void
freeObject(object_t *o)
{
	o->next = freeObjects;
	freeObjects = o;	
}

void
cleanupObjects()
{
	object_t *t, *o = objects;

	while (o) {
		if (o->object) {
			printf("OSUnserializeXML: releasing object o=%x object=%x\n", (int)o, (int)o->object);
			o->object->release();
		}
		if (o->data) {
			printf("OSUnserializeXML: freeing   object o=%x data=%x\n", (int)o, (int)o->data);
			free(o->data);
		}
		if (o->key) {
			printf("OSUnserializeXML: releasing object o=%x key=%x\n", (int)o, (int)o->key);
			o->key->release();
		}
		if (o->string) {
			printf("OSUnserializeXML: freeing   object o=%x string=%x\n", (int)o, (int)o->string);
			free(o->string);
		}

		t = o;
		o = o->free;
		free(t);
	}
}

// !@$&)(^Q$&*^!$(*!@$_(^%_(*Q#$(_*&!$_(*&!$_(*&!#$(*!@&^!@#%!_!#
// !@$&)(^Q$&*^!$(*!@$_(^%_(*Q#$(_*&!$_(*&!$_(*&!#$(*!@&^!@#%!_!#
// !@$&)(^Q$&*^!$(*!@$_(^%_(*Q#$(_*&!$_(*&!$_(*&!#$(*!@&^!@#%!_!#

static OSDictionary *tags;

static void 
rememberObject(int tag, OSObject *o)
{
	char key[16];
	sprintf(key, "%u", tag);

//printf("remember key %s\n", key);

	tags->setObject(key, o);
}

static object_t *
retrieveObject(int tag)
{
	char key[16];
	sprintf(key, "%u", tag);

//printf("retrieve key '%s'\n", key);

	OSObject *ref = tags->getObject(key);
	if (!ref) return 0;

	object_t *o = newObject();
	o->object = ref;
	return o;
}

// !@$&)(^Q$&*^!$(*!@$_(^%_(*Q#$(_*&!$_(*&!$_(*&!#$(*!@&^!@#%!_!#
// !@$&)(^Q$&*^!$(*!@$_(^%_(*Q#$(_*&!$_(*&!$_(*&!#$(*!@&^!@#%!_!#
// !@$&)(^Q$&*^!$(*!@$_(^%_(*Q#$(_*&!$_(*&!$_(*&!#$(*!@&^!@#%!_!#

object_t *
buildOSDictionary(object_t * header)
{
	object_t *o, *t;
	int count = 0;

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

	OSDictionary *d = OSDictionary::withCapacity(count);

	if (header->idref >= 0) rememberObject(header->idref, d);

	o = header->elements;
	while (o) {
		d->setObject(o->key, o->object);
		o->object->release();
		o->object = 0;
		o->key->release();
		o->key = 0;
		t = o;
		o = o->next;
		freeObject(t);
	}
	o = header;
	o->object = d;
	return o;
};

object_t *
buildOSArray(object_t * header)
{
	object_t *o, *t;
	int count = 0;

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

	OSArray *a = OSArray::withCapacity(count);

	if (header->idref >= 0) rememberObject(header->idref, a);

	o = header->elements;
	while (o) {
		a->setObject(o->object);
		o->object->release();
		o->object = 0;
		t = o;
		o = o->next;
		freeObject(t);
	}
	o = header;
	o->object = a;
	return o;
};

object_t *
buildOSSet(object_t *o)
{
	o = buildOSArray(o);
	OSArray *a = (OSArray *)o->object;

	OSSet *s = OSSet::withArray(a, a->getCapacity());

	//write over reference created in array
	if (o->idref >= 0) rememberObject(o->idref, s);

	a->release();
	o->object = s;
	return o;
};

object_t *
buildOSString(object_t *o)
{
	OSString *s = OSString::withCString(o->string);

	if (o->idref >= 0) rememberObject(o->idref, s);

	free(o->string);
	o->string = 0;
	o->object = s;

	return o;
};

object_t *
buildKey(object_t *o)
{
	const OSSymbol *s = OSSymbol::withCString(o->string);

	free(o->string);
	o->string = 0;
	o->key = s;

	return o;
};

object_t *
buildOSData(object_t *o)
{
	OSData *d;

	if (o->size) {
		d = OSData::withBytes(o->data, o->size);
		free(o->data);
	} else {
		d = OSData::withCapacity(0);
	}
	if (o->idref >= 0) rememberObject(o->idref, d);

	o->data = 0;
	o->object = d;
	return o;
};

object_t *
buildOSNumber(object_t *o)
{
	OSNumber *n = OSNumber::withNumber(o->number, o->size);

	if (o->idref >= 0) rememberObject(o->idref, n);

	o->object = n;
	return o;
};

object_t *
buildOSBoolean(object_t *o)
{
	OSBoolean *b = OSBoolean::withBoolean(o->number != 0);
	o->object = b;
	return o;
};

__BEGIN_DECLS
#include <kern/lock.h>
__END_DECLS

static mutex_t *lock = 0;

OSObject*
OSUnserializeXML(const char *buffer, OSString **errorString)
{
	OSObject *object;

	if (!lock) {
		lock = mutex_alloc(ETAP_IO_AHA);
		_mutex_lock(lock);
	} else {
		_mutex_lock(lock);

	}

	objects = 0;
	freeObjects = 0;
	yyerror_message[0] = 0;		//just in case
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

	cleanupObjects();
	tags->release();
	mutex_unlock(lock);

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
