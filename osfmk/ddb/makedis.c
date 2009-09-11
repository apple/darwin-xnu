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
/*
 * @OSF_COPYRIGHT@
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:48  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:26:09  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.2.1  1997/03/27  18:46:52  barbou
 * 	Created.
 * 	[1997/03/27  13:58:42  barbou]
 *
 * $EndLog$
 */

/* makedis.c - make a disassembler. */

/*    ,
   By Eamonn McManus <emcmanus@gr.osf.org>, April 1995.
   Copyright 1995 by Eamonn McManus.  Non-commercial use is permitted.  */

/* DESCRIPTION
   
   This program generates a disassembler in C from a file describing the
   opcodes of the machine in question.  Lines in the description file are
   either comments beginning with #, or contain three fields, with the
   first two being terminated by space and the third containing the rest
   of the line.  Long logical lines can be split onto several physical
   lines by ending each one except the last with a \.  A logical line
   can also be split immediately after a |.  Unlike \, | is considered
   part of the logical line.  Leading spaces on continuation lines
   following either \ or | are ignored.

   Here is a concise description of the meanings of the three fields.
   Examples later will make it clearer what they are used for.

   The first field of the three is a function name.  This will produce
   a function or array of the same name in the C output, so it should
   not conflict with other identifiers or C keywords.  By default the
   function named returns a string (a (char *) in C), but if the first
   field is preceded by %, the function returns an unsigned long
   integer.

   The second field describes the arguments of the function.  It consists
   of two parts, either but not both of which may be omitted.  The first
   part is a string which is a bitmask describing the first argument of
   the function.  Each character of the string represents one bit,
   with the least significant bit being the last.  A character can be
   0 or 1, representing that constant value, or a letter, representing
   part of a bitfield.  A given bitfield consists of all of the
   contiguous bits containing the same letter.  Upper and lower case
   letters are considered different.

   The second part of the second field is a list of parameters
   describing the parameters of the function, or the parameters after
   the first if the bitfield part was present.  The list is contained
   in parentheses () and the individual parameters are separated by
   commas.  Spaces are not allowed.  Each parameter name is a single
   letter, optionally preceded by %.  The parameter is an unsigned
   long integer if % is present, otherwise a string.  Again, upper and
   lower case parameter names are different.

   The third field describes the value of the function.  If a bitmask
   is present in the second field and it contains constant bits (0s or
   1s), then the third field is the value of the function only in the
   case where its first argument contains matching values in those bit
   positions.  There can be many different lines naming the same
   function but with different bitpatterns.  The generated C code will
   arrange to return the value corresponding to the pattern that
   matches the actual first argument of the function when it is
   called.  This argument should not have bits set in positions beyond
   those present in the bitpattern.

   It is only allowed for two different lines to name the same function
   if there is a bitstring in the second field.  It is not allowed for
   two such lines to specify exactly the same constant bit values.  But
   it is allowed for a line to have all the same constant bit values as
   another plus some extra constant values.  In this case the more
   specific line applies when all of its constant bits match, and
   otherwise the less specific line applies.

   Apart from the contents of the bitstring, the second field must be
   identical on every line referring to a given function, and the
   bitstring must always be of the same length.

   For string-valued functions, the third field is the string value.
   For integer-valued functions, it is a C integer expression
   generating the value.  In both cases there may be several special
   values:

   - A $ followed by a single letter is replaced by the value of the
     argument or bitfield with that name.  The value of a bitfield is
     shifted as if that bitfield were in the least-significant bit
     position.  Thus, a single-bit field always has value 0 or 1.

   - A $ followed by the name of a function and an argument list in
     parentheses () is replaced by the value returned by the function
     with those arguments.  An integer value cannot be inserted into a
     string without being converted by a function, nor can a string
     value be used in an integer expression.

   - A $ followed by a bitstring enclosed in [] is replaced by the
     value of that bitstring.  The bitstring has the same syntax as in
     the second field, described above.  Each contiguous sequence of
     the same repeated letter in the bitstring is replaced by the
     value of the argument or bitfield-argument with that name,
     shifted into the appropriate position.

   - A list of strings, separated by |, enclosed in
     {}, and followed by an integer expression enclosed in [], is
     replaced by the string in the list whose number matches the value
     of the expression.  The first string in the list is numbered 0.
     If there is no string corresponding to the value of the
     expression, the behaviour is undefined.  The strings in the list
     may themselves contain $ or {} operations.

   - A \ followed by any character is replaced by that
     character, without regard to any meaning it may usually have.
     This is used to obtain strings containing characters such as
     {, $, or \.  The use of backslash to split long logical
     lines takes precedence over this use, so \\ should not appear
     at the end of a line.

   The third field may also be a lone colon ":", in which case the
   function is assumed to be defined externally and only a function
   declaration (prototype) is generated.


   EXAMPLES

   Here are some examples from the description file for the Z80
   microprocessor.  This processor has 8-bit opcodes which are
   disassembled by a generated function "inst" which looks like this:

   typedef unsigned long bits;
   char *inst(bits code) {...}

   The simplest sort of line in the description file is one that looks
   like this:

   inst    01110110        halt

   The first field names the function, "inst".  The second field
   implies that that function has exactly one argument which is an
   integer, and that this line specifies the value of the function
   when this integer has the binary value 01110110 (hex 0x76).  This
   value will be the string "halt".

   A more complex line is one looking like this:

   inst    001aa111        {daa|cpl|scf|ccf}[$a]

   This line is compatible with the previous one, because it has the
   same number of bits and the constant bits are different.  It
   specifies the value of inst when its argument looks like
   001aa111, i.e., for the binary values
   00100111,
   00101111,
   00110111, and
   00111111.  The value of $a for these four values will be
   respectively binary 00, 01, 10, 11, i.e., 0 to 3.  The
   corresponding values of the inst function will be "daa", "cpl",
   "scf", and "ccf".

   The description defines a helper function "reg8" like this:

   reg8    rrr             {b|c|d|e|h|l|(hl)|a}[$r]

   This simply selects one of the eight strings between {} depending
   on the value of the argument, which is assumed to be a three-bit
   value.  This could just as easily have been written:

   reg8    (%r)            {b|c|d|e|h|l|(hl)|a}[$r]

   The generated C code is the same -- in each case makedis realises
   that the function can be represented by an array rather than
   compiling a C function.

   The reg8 function is used in lines like this one:

   inst    01rrrsss        ld $reg8($r),$reg8($s)

   Thus if the argument to inst is
	   01010011
   then $r is 010 (2) and $s is 011 (3).  Since reg8(2) is "d" and
   reg8(3) is "e", the value of inst with this argument will be the
   string "ld d,e".

   Note that the opcode for "halt" given above matches this pattern,
   but because the bitpattern for "halt" is more specific (has more
   constant bits) it is the one chosen when the argument is 01110110.

   The description also uses an external C function "hexprint" defined
   like this:

   char *hexprint(bits digits, bits n) {
       char *p = dis_alloc(digits + 1);
       sprintf(p, "%0*lx", (int) digits, n);
       return p;
   }

   The value of this function is a string containing the number n
   spelt out in hex with "digits" digits.  In the description
   file this function is declared like this:

   hexprint  (%w,%n)       :

   The names of the parameters are not important in this case as long
   as they are letters and are different from each other.

   The hexprint function is used in lines like this one:

   inst    11vvv111        rst $hexprint(2,$v << 3)

   If the argument to inst is
	   11011111
   then $v is 011 (3) and the arguments to hexprint are 2 and (3 << 3),
   i.e., 0x18.  So the value of inst with this argument will be the
   string "rst 18".

   Instead of writing $v << 3, it would be possible to write
   $[00vvv000].  For instance when $v is binary 011, this becomes
     00011000.  The leading 0s could be omitted.

   The $[...] operation is particularly useful for moving bits around.
   For instance, the HP PA-RISC opcodes contain bits assigned to
   apparently random parts of the instruction word.  One of the helper
   functions in its description file looks like this:

   im21l aaaaabbccddddddddddde l'$hex($[edddddddddddbbaaaaacc00000000000])

   So    111110011000000000001 produces 10000000000000111111100000000000.

   The $[...] operation can also be used to spell out binary constants,
   since C has no syntax for this.


   ...More to come...  */

/* To do:
   - More error detection, e.g., bitstring or arg not used in entry.
   - Better error recovery -- nearly all errors are currently fatal.
   - Clean up type handling, which is somewhat haphazard.  It works but there
     is stuff that is surely redundant.
   - Make generated functions void by default, with $ prefix to indicate
     string-value.  In a void function, instead of returning a string (or
     integer) it would be output via a user-supplied function.
   - Further optimise and tidy generated code, e.g.: arrays of one-character
     strings could be replaced by arrays of characters; switches with just
     one case could be replaced by ifs.
 */

#include <assert.h>
#include <ctype.h>
#include <sys/errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXfunction 32		/* Max function name length. */
#define MAXBITS 32			/* Max bitstring length. */
typedef unsigned long bits;
enum type {T_ERROR, T_UNKNOWN, T_INTEGER, T_STRING};
const char *const typename[] = {"error", "unknown", "integer", "string"};
enum walkstringop {COUNTARRAYS, DECLAREARRAYS, COMPILEARRAYS};
char *bitstype = "unsigned long";

int maxfunctionname, maxargwidth;
char *progname = "makedis";
char **global_argv;
char *filename;
char *headerfilename;
FILE *headerfile;
int lineno;
int indentation;
int debug, dump, warnings;

/* componentbits has a 1 bit for every possible number of strings we may want
   to concatenate together at some stage.  A separate C function is compiled
   for each such case.  */
bits componentbits;


struct entry;
struct arg;
struct string;
struct functioncall;
struct array;
struct bits;
struct bitsplice;


int main(int argc, char **argv);
int makedis(FILE *f, char *fname);
struct function *findfunction(char *function);
int parseextern(struct function *fp, FILE *f);
struct function *makefunction(char *function);
int parsebits(struct function *fp, char *bitstring, int nbits);
int parseentrybits(struct entry *ep, char *bitstring, int nbits, int issplice);
int parsecontrol(char *name, char *value);
int parseargs(struct function *fp, FILE *f, int *cp);
int parsestring(struct function *fp, char *str);
enum type makestring(struct function *fp, struct string **stringlink,
		     char **stringp, char *magic, enum type targettype);
int parsedollar(struct function *fp, char **stringp, struct string *sp);
int parsebitsplice(struct function *fp, char *bitstring, int nbits,
		   struct string *sp);
int findvariable(struct function *fp, int name, struct string *sp);
int parsefunctioncall(struct function *fp, char *start, char **stringp,
		      struct string *sp);
int parsearray(struct function *fp, char **stringp, struct string *sp,
	       enum type t);
void dumpfunctions(void);
void dumpfunction(struct function *fp);
void showentry(FILE *f, struct function *fp, struct entry *ep, bits highlight);
void showbits(FILE *f, struct entry *ep, int nbits, bits highlight);
void showargs(FILE *f, struct arg *ap, int fieldwidth);
void showstring(FILE *f, struct string *sp);
void showstringelement(FILE *f, struct string *sp);
void showfunctioncall(FILE *f, struct functioncall *fcp);
void showarray(FILE *f, struct array *ap);
int outputfunctions(void);
void outputidentity(FILE *f);
int outputdeclarations(void);
void outputconcats(void);
void outputconcat(int n);
void outputconcatheader(FILE *f, int n);
void findarrays(void);
int checkfixedlength(struct array *ap);
int outputfunction(struct function *fp);
void functionarray(struct function *fp);
void functionheader(FILE *f, struct function *fp);
int simplearray(struct array *ap);
void compiletype(FILE *f, enum type *tp);
int functionswitch(struct function *fp, bits mask, bits value);
int compilestring(int assignto, struct string *sp, enum type type);
int compilecheckedstring(int assignto, struct string *sp, enum type type);
void compileassign(int assignto);
void compiletemp(int tempno);
void compiletext(char *s);
int compileconcat(struct string *sp, enum type type);
int compilenull(enum type type);
int compilesimple(struct string *sp, enum type type);
int compilearrayref(struct array *ap);
int compilefunctioncall(struct string *sp);
int walkstring(struct string *sp, enum walkstringop op, int tempno);
int compilearray(struct array *ap);
void compilesimplearray(enum type *tp, char *name, int num, struct array *ap);
void declarearray(struct array *ap);
void compilebitstring(struct bits *bp);
void compilebitsplice(struct bitsplice *splicep);
int bitcount(bits x);
bits allbitsset(int nbits);
void findent(FILE *f);
void indent(void);
void *xrealloc(char *oldp, size_t size);
void *xmalloc(size_t size);
void *xstrdup(char *s);
int prematureeof(void);


int main(int argc, char **argv) {
    int i;
    FILE *f;

    global_argv = argv;
    if (argc > 0)
	progname = argv[0];
    for (i = 1; i < argc && argv[i][0] == '-'; i++) {
	switch (argv[i][1]) {
	case 'h':
	    if (++i >= argc)
		goto Usage;
	    headerfilename = argv[i]; break;
	case 'd':
	    debug = 1; break;
	case 'D':
	    dump = 1; break;
	case 'w':
	    warnings = 1; break;
	default:
Usage:
	    fprintf(stderr, "Usage: %s [file]\n", progname);
	    return 1;
	}
    }
    if (i == argc)
	return makedis(stdin, "<stdin>");
    if (i + 1 != argc)
	goto Usage;
    if ((f = fopen(argv[i], "r")) == NULL) {
	fprintf(stderr, "%s: %s: %s\n", progname, argv[i], strerror(errno));
	return 1;
    }
    return makedis(f, argv[i]);
}


int makedis(FILE *f, char *fname) {
    int c, i;
    char function[MAXfunction], bitstring[MAXBITS];
    static char *string = NULL;
    int stringlen = 0;
    struct function *fp;

    filename = fname;
    lineno = 1;
    /* Loop for every line in the description. */
    while (1) {
	/* Ignore initial spaces and newlines. */
	while (isspace(c = getc(f)))
	    if (c == '\n')
		lineno++;
	if (c == EOF)
	    break;

	/* Ignore comments.  # only allowed at start of line. */
	if (c == '#') {
	    while ((c = getc(f)) != '\n')
		if (c == EOF)
		    return prematureeof();
	    lineno++;
	    continue;
	}

	/* Read function name, terminated by space. */
	for (i = 0; i < sizeof function && !isspace(c); i++, c = getc(f)) {
	    if (c == EOF)
		return prematureeof();
	    function[i] = c;
	}
	if (i >= sizeof function) {
	    fprintf(stderr, "%s: %s(%d): function name is too long: %.*s\n",
		    progname, filename, lineno, i, function);
	    return 1;
	}
	function[i] = '\0';

	/* Skip to next field.  */
	while (isspace(c) && c != '\n')
	    c = getc(f);

	/* If not a control statement, read bitstring and/or arguments. */
	if (function[0] == ':')
	    fp = 0;	/* Silence gcc. */
	else {
	    fp = makefunction(function);
	    if (fp == NULL)
		return 1;

	    /* Read optional bitstring. */
	    for (i = 0; i < sizeof bitstring && isalnum(c); i++, c = getc(f)) {
		if (c == EOF)
		    return prematureeof();
		bitstring[i] = c;
	    }
	    if (isalnum(c)) {
		fprintf(stderr, "%s: %s(%d): bit string is too long: %.*s\n",
			progname, filename, lineno, i, bitstring);
		return 1;
	    }
	    if (parsebits(fp, bitstring, i) != 0)
		return 1;

	    /* Read optional arguments. */
	    if (parseargs(fp, f, &c) != 0)
		return 1;

	    /* Skip to next field. */
	    while (isspace(c) && c != '\n')
		c = getc(f);

	    /* : indicates an external (C) function. */
	    if (c == ':') {
		if (parseextern(fp, f) != 0)
		    return 1;
		continue;
	    }
	}

	/* Read associated text. */
	i = 0;
	while (1) {
	    for ( ; c != '\n'; i++, c = getc(f)) {
		if (c == EOF)
		    return prematureeof();
		if (i >= stringlen) {
		    stringlen = stringlen * 2 + 16;
		    string = xrealloc(string, stringlen);
		}
		string[i] = c;
	    }
	    lineno++;
	    if (i > 0) {
		switch (string[i - 1]) {
		case '\\':
		    i--;
		    /* Fall in... */
		case '|':
		    while (isspace(c = getc(f)) && c != '\n') ;
		    continue;
		}
	    }
	    break;
	}
	if (i >= stringlen) {
	    stringlen = stringlen * 2 + 16;
	    string = xrealloc(string, stringlen);
	}
	string[i] = '\0';

	/* Parse the line just read. */
	if (function[0] == ':') {
	    if (parsecontrol(function + 1, string) != 0)
		return 1;
	} else {
	    if (parsestring(fp, string) != 0)
		return 1;
	}
    }
    if (dump)
	dumpfunctions();
    return outputfunctions();
}


/* A function in the description file.  nbits and nargs are -1 until the
   real values are known.  */
struct function {
    struct function *next;
    char *name;
    enum type type;
    int nbits;		/* Number of bits in the bitpattern, 0 if none. */
    int nargs;		/* Number of (x,y,...) parameters, 0 if none. */
    char isarray;	/* Will be represented by a C array. */
    int fixedlength;	/* If a C array, will be a char [][N] not a char *[]. */
    struct entry *first, *last;
			/* Links to the value(s) supplied. */
    struct arg *args;	/* List of (x,y,...) names and types. */
};
struct function *functions;


/* Find the function with the given name.  If not found, create a structure
   for it, fill it out with a template, and return that.  */
struct function *findfunction(char *name) {
    struct function *fp;

    for (fp = functions; fp != NULL; fp = fp->next) {
	if (strcmp(fp->name, name) == 0)
	    return fp;
    }
    if (strlen(name) > maxfunctionname)
	maxfunctionname = strlen(name);
    fp = xmalloc(sizeof *fp);
    fp->next = functions;
    functions = fp;
    fp->name = xstrdup(name);
    fp->type = T_UNKNOWN;
    fp->nbits = fp->nargs = -1;		/* nbits will be set correctly later. */
    fp->isarray = 0;
    fp->first = fp->last = NULL;
    return fp;
}


/* Parse an external (C) function declaration.  This will look something like:
	malloc (%s) :
   We're called just after seeing the ':'.
   Return 0 if parsing is successful, 1 otherwise.  */
int parseextern(struct function *fp, FILE *f) {
    int c;

    if ((c = getc(f)) != '\n') {
	fprintf(stderr,
		"%s: %s(%d): extern declaration should be a lone `:'\n",
		progname, filename, lineno);
	return 1;
    }
    if (fp->nbits != 0) {
	fprintf(stderr,
		"%s: %s(%d): extern functions should not have bitstrings\n",
		progname, filename, lineno);
	return 1;
    }
    free(fp->first);
    fp->first = fp->last = NULL;
    return 0;
}


/* A value supplied for a function (the third field in a description line).
   In general there can be any number of such values, differing in the
   bitpattern supplied.  The mask and value fields describe the constant
   bits in the bitpattern: mask indicates which bits they are and value
   indicates the values of those bits.  So this entry matches
   ((x & mask) == value).  */
struct entry {
    struct entry *next;
    bits mask, value;
    struct bits *bits;		/* List of named bitfields. */
    struct string *string;	/* Value of function when bitpattern matched. */
    char done;			/* This entry has already been compiled. */
};


/* We've just seen a definition of function "name".  Make a structure for it
   if necessary, and a template entry that will describe the value given here.
   */
struct function *makefunction(char *name) {
    struct function *fp;
    struct entry *ep = xmalloc(sizeof *ep);
    enum type type;

    if (name[0] == '%') {
	name++;
	type = T_INTEGER;
    } else
	type = T_STRING;
    fp = findfunction(name);
    if (fp->type == T_UNKNOWN)
	fp->type = type;
    else if (fp->type != type) {
	fprintf(stderr, "%s: %s(%d): function %s previously declared as %s, "
			"here as %s\n", progname, filename, lineno, name,
			typename[fp->type], typename[type]);
	return NULL;
    }
    ep->next = NULL;
    ep->bits = NULL;
    ep->done = 0;
    if (fp->first != NULL)
	fp->last->next = ep;
    else
	fp->first = ep;
    fp->last = ep;
    return fp;
}


/* A named bitfield within the bitpattern of a function entry, or within a
   $[...] bitsplice.  The mask covers the bitfield and the shift says how
   many 0 bits there are after the last 1 in the mask.  */
struct bits {
    struct bits *next;
    int shift;
    bits mask;
    char name;
};


/* Parse the bitstring supplied for the given function.  nbits says how many
   bits there are; it can legitimately be 0.  Return value is 0 on success.  */
int parsebits(struct function *fp, char *bitstring, int nbits) {
    if (fp->nbits < 0)
	fp->nbits = nbits;
    else if (fp->nbits != nbits) {
	fprintf(stderr, "%s: %s(%d): bit string of length %d;\n",
		progname, filename, lineno, nbits);
	fprintf(stderr, "  function %s has bit strings of length %d\n",
		fp->name, fp->nbits);
	return 1;
    }
    return parseentrybits(fp->last, bitstring, nbits, 0);
}


/* Parse a bitstring that is the pattern for a function entry or that is in a
   $[...] bitsplice.  Put the result in ep.  Return value is 0 on success.  */
int parseentrybits(struct entry *ep, char *bitstring, int nbits, int issplice) {
    int i, j;
    char bit;
    bits mask, value, entrymask;
    struct bits *bp;

    mask = value = 0;
    for (i = 0; i < nbits; i++) {
	bit = bitstring[nbits - 1 - i];
	switch (bit) {
	case '1':
	    value |= 1 << i;
	    /* Fall in... */
	case '0':
	    mask |= 1 << i;
	    continue;
	}
	if (!isalpha(bit)) {
	    fprintf(stderr, "%s: %s(%d): invalid character in bitstring: %c\n",
		    progname, filename, lineno, bit);
	    return 1;
	}
	if (!issplice) {
	    for (bp = ep->bits; bp != NULL; bp = bp->next) {
		if (bp->name == bit) {
		    fprintf(stderr,
			    "%s: %s(%d): bitstring name %c used twice\n",
			    progname, filename, lineno, bit);
		    return 1;
		}
	    }
	}
	entrymask = 1 << i;
	for (j = i + 1; j < nbits && bitstring[nbits - 1 - j] == bit; j++)
	    entrymask |= 1 << j;
	bp = xmalloc(sizeof *bp);
	bp->shift = i;
	bp->mask = entrymask;
	bp->name = bit;
	bp->next = ep->bits;
	ep->bits = bp;
	i = j - 1;
    }
    ep->mask = mask;
    ep->value = value;
    return 0;
}


/* Parse a control line.  This looks something like:
   :bitstype unsigned int
   in which case we will be called with name "bitstype" and
   value "unsigned int".  */
int parsecontrol(char *name, char *value) {
    if (strcmp(name, "bitstype") == 0)
	bitstype = xstrdup(value);
    else {
	fprintf(stderr, "%s: %s(%d): unrecognised control keyword %s\n",
		progname, filename, lineno, name);
	return 1;
    }
    return 0;
}


/* A parameter to a function, e.g., x in:
   %f aaa(%x) $a + $x  */
struct arg {
    struct arg *next;
    enum type type;
    char name;
};


/* Parse the parameters (x,y,...) to a function and put the result in fp.
   The entry that is being built is fp->last.  cp points to the opening
   (; if it does not point to a ( then there are no parameters.  If
   this is the first entry for the function, fp->nargs will be -1 and
   we will build up an argument list.  Otherwise, fp->nargs will be
   >= 0 and we will only check that the arguments here are consistent
   with what went before.  Return value is 0 on success.  */
int parseargs(struct function *fp, FILE *f, int *cp) {
    struct arg **arglink, *ap;
    struct bits *bp;
    int nargs, width;
    char name;
    enum type t;

    arglink = &fp->args;
    width = nargs = 0;
    if (*cp == '(') {
	*cp = getc(f);
	if (*cp != ')') {
	    width = 1;
	    while (1) {
		nargs++;
		width += 2;
		if (fp->nargs >= 0 && nargs > fp->nargs) {
		    fprintf(stderr,
			    "%s: %s(%d): %d arg(s) instead of %d for %s\n",
			    progname, filename, lineno, nargs, fp->nargs,
			    fp->name);
		    return 1;
		}
		t = T_STRING;
		if (*cp == '%') {
		    width++;
		    t = T_INTEGER;
		    *cp = getc(f);
		}
		name = *cp;
		if (!isalpha(name)) {
		    fprintf(stderr,
			    "%s: %s(%d): argument should be letter: %c\n",
			    progname, filename, lineno, name);
		    return 1;
		}
		for (bp = fp->last->bits; bp != NULL; bp = bp->next) {
		    if (bp->name == name) {
			fprintf(stderr,
				"%s: %s(%d): %c is a bitstring and an arg\n",
				progname, filename, lineno, name);
			return 1;
		    }
		}
		if (fp->nargs >= 0) {
		    if ((*arglink)->name != name) {
			fprintf(stderr,
				"%s: %s(%d): arg %d of %s is %c not %c\n",
				progname, filename, lineno, nargs, fp->name,
				(*arglink)->name, name);
			return 1;
		    }
		    if ((*arglink)->type != t) {
			fprintf(stderr,
				"%s: %s(%d): arg %c of %s: inconsistent type\n",
				progname, filename, lineno, name, fp->name);
			return 1;
		    }
		} else {
		    for (ap = fp->args; ap != *arglink; ap = ap->next) {
			if (ap->name == name) {
			    fprintf(stderr,
				    "%s: %s(%d): argument name %c used twice\n",
				    progname, filename, lineno, name);
			    return 1;
			}
		    }
		    *arglink = xmalloc(sizeof **arglink);
		    (*arglink)->name = name;
		    (*arglink)->type = t;
		}
		arglink = &(*arglink)->next;
		*cp = getc(f);
		if (*cp == ')')
		    break;
		if (*cp != ',') {
		    fprintf(stderr,
			    "%s: %s(%d): bad character in argument list: %c\n"
			    "  (arguments must be single letters)\n",
			    progname, filename, lineno, *cp);
		    return 1;
		}
		*cp = getc(f);
	    }
	}
	*cp = getc(f);
    }
    if (fp->nargs < 0) {
	fp->nargs = nargs;
	width += fp->nbits;
	if (width > maxargwidth)
	    maxargwidth = width;
    } else if (fp->nargs != nargs) {
	fprintf(stderr, "%s: %s(%d): argument list of length %d;\n",
		progname, filename, lineno, nargs);
	fprintf(stderr, "  function %s has argument lists of length %d\n",
		fp->name, fp->nargs);
	return 1;
    }
    *arglink = NULL;
    return 0;
}


/* Parse the string describing the value of this entry for our
   function.  Return 0 on success.  */
int parsestring(struct function *fp, char *str) {
    enum type t;

    t = makestring(fp, &fp->last->string, &str, NULL, fp->type);
    if (t == T_ERROR)
	return 1;
    if (fp->type != t && t != T_UNKNOWN) {
	fprintf(stderr, "%s: %s(%d): function %s has inconsistent types\n",
		progname, filename, lineno, fp->name);
	return 1;
    }
    return 0;
}


/* A parsed representation of the whole string describing a value of a
   function, or certain strings within that (e.g., array indices).  This is a
   linked list of substrings whose type is given by the type field.  */
struct string {
    struct string *next;
    enum elementtype {
	S_TEXT, S_BITSTRING, S_BITSPLICE, S_PARAMETER, S_FUNCTIONCALL, S_ARRAY
    } type;
    union value {	/* The fields here correspond to the enum values. */
	char *text;				/* plain text */
	struct bits *bits;			/* $x where x is a bitfield */
	struct bitsplice *bitsplice;		/* $[...] */
	struct arg *parameter;			/* $x where x is a parameter */
	struct functioncall *functioncall;	/* $func(...) */
	struct array *array;			/* {...}[...] */
    } value;
};

/* The representation of a function call $func(...) in the description of a
   function value.  */
struct functioncall {
    struct function *function;
    struct stringlist *args;
};

/* The representation of an array selection {...|...}[...] in the description
   of a function value.  tempno is used when constructing a C variable name
   that will contain the strings or numbers in an array.  */
struct array {
    struct string *index;		/* what's between [...] */
    struct stringlist *elements;	/* what's between {...} */
    enum type type;			/* the type of each element */
    int tempno;	
};

/* A list of strings, being the list of arguments in a function call or the
   list of elements of an array.  This is a linked list of linked lists.  */
struct stringlist {
    struct stringlist *next;
    enum type type;
    struct string *string;
};


/* The following are the only characters with special meaning at the top level
   of parsing of a function value.  When parsing arrays or function calls,
   other characters become special.  */
#define MAKESTRING_MAGIC "${"/*}*/


/* Parse a function return-value string or substring and make a struct string
   list for it.  The string starts at *stringp and ends at a \0 or at any
   character in the `magic' string other than { or $.  *stringp is updated
   to point to the terminating character.  The parsed representation is put
   at *stringlink.  `fp' is the function whose return value is being parsed.
   `targettype' is the expected type of the result, if known.
   The return value is the actual type.  */
enum type makestring(struct function *fp, struct string **stringlink,
		     char **stringp, char *magic, enum type targettype) {
    char *p, *q;
    struct string *sp, **firststringlink;
    int n, components;
    int parenlevel = 0;
    enum type t = targettype, newt;

    if (magic == NULL)
	magic = MAKESTRING_MAGIC;
    p = *stringp;
    firststringlink = stringlink;
    components = 0;
    while (*p != '\0') {
	sp = xmalloc(sizeof *sp);
	q = p;
	n = 0;
	do {
	    if (strchr(magic, *q) != NULL) {
		if (*q != ')' || parenlevel == 0)
		    break;
	    }
	    switch (*q) {
	    case '(':
		parenlevel++; break;
	    case ')':
		parenlevel--; break;
	    case '\\':
		if (q[1] != '\0')
		    q++;
		break;
	    }
	    n++;
	} while (*++q != '\0');
	if (n > 0) {
	    sp->type = S_TEXT;
	    sp->value.text = q = xmalloc(n + 1);
	    do {
		if (*p == '\\')
		    p++;
		*q++ = *p++;
	    } while (--n > 0);
	    *q = '\0';
	    newt = t;
	} else if (*p == '$') {
	    if (parsedollar(fp, &p, sp) != 0)
		return T_ERROR;
	    switch (sp->type) {
	    case S_BITSTRING:
	    case S_BITSPLICE:
		newt = T_INTEGER;
		break;
	    case S_PARAMETER:
		newt = sp->value.parameter->type;
		break;
	    case S_FUNCTIONCALL:
		newt = sp->value.functioncall->function->type;
		break;
	    default:
		fprintf(stderr, "makestring type %d\n", sp->type);
		abort();
	    }
	} else if (*p == '{'/*}*/) {
	    if (parsearray(fp, &p, sp, t) != 0)
		return T_ERROR;
	    newt = sp->value.array->type;
	} else {
	    free(sp);
	    break;
	}
	if (t == T_UNKNOWN)
	    t = newt;
	else if (newt != T_UNKNOWN && t != newt) {
	    if (stringlink == firststringlink) {
		fprintf(stderr, "%s: %s(%d): expected %s type:\n", progname,
			filename, lineno, typename[t]);
		showstringelement(stderr, sp);
		return T_ERROR;
	    }
	    *stringlink = NULL;
	    fprintf(stderr, "%s: %s(%d): mixed types in string:\n",
		    progname, filename, lineno);
	    showstring(stderr, *firststringlink);
	    fprintf(stderr, " -- %s\n", typename[t]);
	    showstringelement(stderr, sp);
	    fprintf(stderr, " -- %s\n", typename[newt]);
	    return T_ERROR;
	}
	*stringlink = sp;
	stringlink = &sp->next;
	components++;
    }
    *stringlink = NULL;
    *stringp = p;
    if (components >= MAXBITS) {
	fprintf(stderr, "%s: %s(%d): excessively complicated string\n",
		progname, filename, lineno);
	return T_ERROR;
    }
    componentbits |= 1 << components;
    return t;
}


/* Parse a $ operation at **stringp and update *stringp to point past it.
   `fp' is the function whose return value is being parsed.  The parsed
   item will be put at *sp.  Return 0 on success, nonzero on error.  */
int parsedollar(struct function *fp, char **stringp, struct string *sp) {
    char *p, *start;

    p = *stringp;
    assert(*p == '$');
    start = ++p;
    if (*p == '[')
	p++;
    while (isalnum(*p) || *p == '_')
	p++;
    if (*start == '[') {
	if (*p != ']') {
	    fprintf(stderr, "%s: %s(%d): missing ] or bad character in $[\n",
		    progname, filename, lineno);
	    return 1;
	}
	*stringp = p + 1;
	return parsebitsplice(fp, start + 1, p - start - 1, sp);
    }
    if (p == start) {
	fprintf(stderr, "%s: %s(%d): missing identifier after $\n", progname,
		filename, lineno);
	return 1;
    }
    if (p == start + 1) {
	if (findvariable(fp, *start, sp) != 0)
	    return 1;
    } else {
	if (parsefunctioncall(fp, start, &p, sp) != 0)
	    return 1;
    }
    *stringp = p;
    return 0;
}


/* The representation of a $[...] bitsplice.  It is parsed into a
   struct entry just as if it were a bitfield parameter, then analysed
   into a chain of struct bitsplicebits.  These in conjunction with
   the constant portion of the struct entry will allow the bitsplice to
   be compiled.  Each bitsplicebits element represents either a numeric
   argument to the current function, in which case it will be shifted
   into place; or a bitfield name from the bitfield description of the
   current function, in which case it will be shifted by the difference
   between the position of the bitfield in the argument and the position
   it occurs in the bitsplice.  `shift' indicates how much to shift left
   the associated value; if it is negative the value is shifted right.
   For instance, in a function like this:
     %oh  xx00(%y)  $[yyxx]
   the bitsplicebits for y will have shift = 2 and value.arg pointing to y,
   and those for x will have shift = -2 and value.mask = binary 1100.
   As an optimisation, contiguous bitfields that are also contiguous in the
   bitsplice will be combined.  For instance:
     %oh  xxyy00    $[0xxyy0]
   will compile the same code as:
     %oh  zzzz00    $[0zzzz0].
   As another optimisation, a bitfield that occupies the entire bitstring
   for a function will be treated like a parameter in that it will not be
   masked in the bitsplice.  For instance:
     %oh  xxxxxx    $[0xxxxxx0]
   will compile the same code as:
     %oh  (%x)      $[0xxxxxx0].  */
struct bitsplice {
    struct entry entry;
    int nbits;
    struct bitsplicebits *splice;
};
struct bitsplicebits {
    struct bitsplicebits *next;
    int shift;
    enum elementtype type;
    union {
	struct arg *arg;
	bits mask;
    } value;
};


int parsebitsplice(struct function *fp, char *bitstring, int nbits,
		   struct string *sp) {
    struct bitsplice *splicep;
    struct bitsplicebits *bsp, *lastbsp, **bspp;
    struct bits *bp;
    int shift, nfrombits, ntobits;
    bits allbits, b;

    splicep = xmalloc(sizeof *splicep);
    splicep->nbits = nbits;
    if (parseentrybits(&splicep->entry, bitstring, nbits, 1) != 0)
	return 1;
    bspp = &splicep->splice;
    lastbsp = NULL;
    for (bp = splicep->entry.bits; bp != NULL; bp = bp->next) {
	if (findvariable(fp, bp->name, sp) != 0)
	    return 1;
	shift = bp->shift;
	if (sp->type == S_BITSTRING) {
	    nfrombits = bitcount(sp->value.bits->mask);
	    ntobits = bitcount(bp->mask);
	    if (warnings) {
		if (nfrombits != ntobits) {
		    fprintf(stderr, "%s: %s(%d): warning: "
				    "bitstring $%c %ser than its place "
				    "in bitsplice\n",
			    progname, filename, lineno, bp->name,
			    (nfrombits > ntobits) ? "bigg" : "small");
		}
	    }
	    shift -= sp->value.bits->shift;

	    /* See if this bitfield can be combined with a previous contiguous
	       bitfield.  */
	    if (lastbsp != NULL && lastbsp->type == S_BITSTRING
		&& lastbsp->shift == shift) {
		lastbsp->value.mask |= sp->value.bits->mask;
		continue;
	    }
	} else {
	    assert(sp->type == S_PARAMETER);
	    if (sp->value.parameter->type != T_INTEGER) {
		fprintf(stderr,
			"%s: %s(%d): variable %c in $[...] should be integer\n",
			progname, filename, lineno, sp->value.parameter->name);
		return 1;
	    }
	}
	*bspp = bsp = xmalloc(sizeof *bsp);
	bsp->type = sp->type;
	bsp->shift = shift;
	if (sp->type == S_PARAMETER)
	    bsp->value.arg = sp->value.parameter;
	else
	    bsp->value.mask = sp->value.bits->mask;
	bspp = &bsp->next;
	lastbsp = bsp;
    }
    *bspp = NULL;

    /* Look for a spliced element that is the entire bitstring argument to
       this function and therefore doesn't need to be masked.  */
    allbits = allbitsset(fp->nbits);
    for (bsp = splicep->splice; bsp != NULL; bsp = bsp->next) {
	if (bsp->type == S_BITSTRING) {
	    for (b = bsp->value.mask; b != 0 && !(b & 1); b >>= 1) ;
	    if (b == allbits)
		bsp->value.mask = 0;
	}
    }
    sp->type = S_BITSPLICE;
    sp->value.bitsplice = splicep;
    return 0;
}


int findvariable(struct function *fp, int name, struct string *sp) {
    struct bits *bp;
    struct arg *ap;

    for (bp = fp->last->bits; bp != NULL; bp = bp->next) {
	if (bp->name == name) {
	    sp->type = S_BITSTRING;
	    sp->value.bits = bp;
	    return 0;
	}
    }
    for (ap = fp->args; ap != NULL; ap = ap->next) {
	if (ap->name == name) {
	    sp->type = S_PARAMETER;
	    sp->value.parameter = ap;
	    return 0;
	}
    }
    fprintf(stderr, "%s: %s(%d): undefined parameter %c\n", progname, filename,
	    lineno, name);
    return 1;
}


int parsefunctioncall(struct function *fp, char *start, char **stringp,
		      struct string *sp) {
    char *p;
    struct functioncall *fcp;
    struct stringlist **arglink, *arg;
    enum type t;

    p = *stringp;
    if (*p != '(') {
	fprintf(stderr, "%s: %s(%d): missing ( after function %.*s\n", progname,
			filename, lineno, (int)(p - start), start);
	return 1;
    }
    sp->type = S_FUNCTIONCALL;
    sp->value.functioncall = fcp = xmalloc(sizeof *fcp);
    *p = '\0';	/* Ugly. */
    fcp->function = findfunction(start);
    *p = '(';
    arglink = &fcp->args;
    if (*++p != ')') {
	while (1) {
	    arg = xmalloc(sizeof *arg);
	    t = makestring(fp, &arg->string, &p, MAKESTRING_MAGIC ",)",
			   T_UNKNOWN);
	    if (t == T_ERROR)
		return 1;
	    arg->type = t;
	    *arglink = arg;
	    arglink = &arg->next;
	    if (*p == ')')
		break;
	    assert(*p == ',');
	    p++;
	}
    }
    *arglink = NULL;
    assert(*p == ')');
    *stringp = p + 1;
    return 0;
}


int parsearray(struct function *fp, char **stringp, struct string *sp,
	       enum type t) {
    char *p;
    struct array *ap;
    struct stringlist **elementlink, *element;

    p = *stringp;
    assert(*p == '{'/*}*/);
    sp->type = S_ARRAY;
    sp->value.array = ap = xmalloc(sizeof *ap);
    ap->tempno = -1;
    elementlink = &ap->elements;
    ap->type = t;
    if (*++p != /*{*/'}') {
	while (1) {
	    element = xmalloc(sizeof *element);
	    t = makestring(fp, &element->string, &p,
			   MAKESTRING_MAGIC /*{*/"|}", t);
	    if (t == T_ERROR)
		return 1;
	    element->type = t;
	    if (ap->type == T_UNKNOWN)
		ap->type = t;
	    else if (t != T_UNKNOWN && ap->type != t) {
		fprintf(stderr, "%s: %s(%d): mixed types in array:\n",
			progname, filename, lineno);
		showstring(stderr, ap->elements->string);
		fprintf(stderr, " -- %s\n", typename[ap->type]);
		showstring(stderr, element->string);
		fprintf(stderr, " -- %s\n", typename[t]);
		return 1;
	    }
	    *elementlink = element;
	    elementlink = &element->next;
	    if (*p == /*{*/'}')
		break;
	    assert(*p == '|');
	    p++;
	}
    }
    *elementlink = NULL;
    assert(*p == /*{*/'}');
    if (*++p != '[') {
	fprintf(stderr, "%s: %s(%d): missing [index] after array\n",
		progname, filename, lineno);
	return 1;
    }
    ++p;
    t = makestring(fp, &ap->index, &p, MAKESTRING_MAGIC "]", T_INTEGER);
    if (t == T_ERROR)
	return 1;
    if (t == T_STRING) {
	fprintf(stderr, "%s: %s(%d): array index cannot be string:\n",
		progname, filename, lineno);
	showstring(stderr, ap->index);
	return 1;
    }
    if (*p != ']') {
	fprintf(stderr, "%s: %s(%d): [ without ]\n", progname, filename,
		lineno);
	return 1;
    }
    *stringp = p + 1;
    return 0;
}


void dumpfunctions() {
    struct function *fp;

    for (fp = functions; fp != NULL; fp = fp->next)
	dumpfunction(fp);
}


void dumpfunction(struct function *fp) {
    struct entry *ep;

    for (ep = fp->first; ep != NULL; ep = ep->next)
	showentry(stderr, fp, ep, 0);
}


/* Entries are not shown exactly as they would be input, since \ would
   need to be provided before some characters such as $ or {.  But the
   characters "|},]" pose a problem since a \ is only needed in certain
   contexts and is annoying otherwise.  It's not worth doing this right,
   since it's only used for error messages.  */
void showentry(FILE *f, struct function *fp, struct entry *ep, bits highlight) {
    if (fp->type == T_INTEGER)
	putc('%', f);
    fprintf(f, "%-*s ", maxfunctionname + 1, fp->name);
    if (fp->nbits == 0 && fp->nargs == 0)
	fprintf(f, "%-*s", maxargwidth, "()");
    else {
	showbits(f, ep, fp->nbits, 0);
	showargs(f, fp->args, maxargwidth - fp->nbits);
    }
    putc(' ', f);
    showstring(f, ep->string);
    putc('\n', f);
    if (highlight != 0) {
	fprintf(f, "%-*s ", maxfunctionname + 1, "");
	showbits(f, ep, fp->nbits, highlight);
	putc('\n', f);
    }
}


void showbits(FILE *f, struct entry *ep, int nbits, bits highlight) {
    struct bits *bp;
    bits i, value;
    char zero, one;

    if (nbits == 0)
	return;
    i = 1 << (nbits - 1);
    bp = ep->bits;
    if (highlight) {
	value = highlight;
	zero = ' ';
	one = '^';
    } else {
	value = ep->value;
	zero = '0';
	one = '1';
    }
    do {
	if (highlight != 0 || (ep->mask & i)) {
	    putc((value & i) ? one : zero, f);
	    i >>= 1;
	} else {
	    assert(bp != NULL && (bp->mask & i));
	    do {
		putc(bp->name, f);
		i >>= 1;
	    } while (bp->mask & i);
	    bp = bp->next;
	}
    } while (i != 0);
}


void showargs(FILE *f, struct arg *ap, int fieldwidth) {
    int width;
    int lastc;
    int isint;

    if (ap == NULL)
	width = 0;
    else {
	width = 1;
	lastc = '(';
	do {
	    isint = (ap->type == T_INTEGER);
	    fprintf(f, "%c%s%c", lastc, isint ? "%" : "", ap->name);
	    width += 2 + isint;
	    ap = ap->next;
	    lastc = ',';
	} while (ap != NULL);
	putc(')', f);
    }
    fprintf(f, "%-*s", fieldwidth - width, "");
}


void showstring(FILE *f, struct string *sp) {
    for ( ; sp != NULL; sp = sp->next)
	showstringelement(f, sp);
}


void showstringelement(FILE *f, struct string *sp) {
    struct bitsplice *bsp;

    switch (sp->type) {
    case S_TEXT:
	fputs(sp->value.text, f);
	break;
    case S_BITSTRING:
	fprintf(f, "$%c", sp->value.bits->name);
	break;
    case S_BITSPLICE:
	fprintf(f, "$[");
	bsp = sp->value.bitsplice;
	showbits(f, &bsp->entry, bsp->nbits, 0);
	fprintf(f, "]");
	break;
    case S_PARAMETER:
	fprintf(f, "$%c", sp->value.parameter->name);
	break;
    case S_FUNCTIONCALL:
	showfunctioncall(f, sp->value.functioncall);
	break;
    case S_ARRAY:
	showarray(f, sp->value.array);
	break;
    default:
	fprintf(stderr, "showstring case %d\n", sp->type);
	abort();
    }
}


void showfunctioncall(FILE *f, struct functioncall *fcp) {
    struct stringlist *sp;
    char *last;

    fprintf(f, "$%s(", fcp->function->name);
    last = "";
    for (sp = fcp->args; sp != NULL; sp = sp->next) {
	fputs(last, f);
	last = ",";
	showstring(f, sp->string);
    }
    putc(')', f);
}


void showarray(FILE *f, struct array *ap) {
    struct stringlist *sp;
    char *last;

    putc('{'/*}*/, f);
    last = "";
    for (sp = ap->elements; sp != NULL; sp = sp->next) {
	fputs(last, f);
	last = "|";
	showstring(f, sp->string);
    }
    fputs(/*{*/"}[", f);
    showstring(f, ap->index);
    putc(']', f);
}


const char commonpreamble[] = "\
typedef %s bits;\n\
\n\
";

const char concatpreamble[] = "\
static char *dis_buf;\n\
static int dis_bufindex, dis_buflen;\n\
\n\
void *dis_alloc(size_t size)\n\
{\n\
    void *p;\n\
    int newindex = dis_bufindex + size;\n\
    if (newindex > dis_buflen) {\n\
	dis_buflen = newindex * 4;\n\
	dis_buf = malloc(dis_buflen);\n\
	/* We can't use realloc because there might be pointers extant into\n\
	   the old buffer.  So we waste the memory of the old buffer.  We\n\
	   should soon reach an adequate buffer size and stop leaking.  */\n\
	if (dis_buf == 0) {\n\
	    perror(\"malloc\");\n\
	    exit(1);\n\
	}\n\
	dis_bufindex = 0;\n\
    }\n\
    p = dis_buf + dis_bufindex;\n\
    dis_bufindex = newindex;\n\
    return p;\n\
}\n\
\n\
void dis_done()\n\
{\n\
    dis_bufindex = 0;\n\
}\n\
\n\
";

const char concatdeclarations[] = "\
#include <string.h>\n\
#include <stdlib.h>\n\
#include <sys/errno.h>\n\
\n\
extern void *dis_realloc(void *p, size_t size); /* User-provided. */\n\
void *dis_alloc(size_t size);\n\
void dis_done(void);\n\
";

const char nonconcatpreamble[] = "\
void dis_done() {}\n\
";


int outputfunctions() {
    struct function *fp;

    outputidentity(stdout);
    if (headerfilename != NULL) {
	if ((headerfile = fopen(headerfilename, "w")) == NULL) {
	    fprintf(stderr, "%s: create %s: %s\n", progname, headerfilename,
		    strerror(errno));
	    return 1;
	}
	outputidentity(headerfile);
	fprintf(headerfile, commonpreamble, bitstype);
	printf("\n#include \"%s\"\n", headerfilename);
    } else
	printf(commonpreamble, bitstype);
    findarrays();
    if (outputdeclarations() != 0)
	return 1;
    outputconcats();
    for (fp = functions; fp != NULL; fp = fp->next) {
	if (fp->isarray)
	    functionarray(fp);
    }
    for (fp = functions; fp != NULL; fp = fp->next) {
	if (fp->first != NULL && !fp->isarray) {
	    if (outputfunction(fp) != 0)
		return 1;
	}
    }
    return 0;
}


void outputidentity(FILE *f) {
    char **p;

    fprintf(f, "/*\n * This file was generated by:\n *");
    for (p = global_argv; *p != NULL; p++)
	fprintf(f, " %s", *p);
    fprintf(f, "\n */\n\n");
}


int outputdeclarations() {
    FILE *f = headerfile ? headerfile : stdout;
    struct function *fp;

    for (fp = functions; fp != NULL; fp = fp->next) {
	if (fp->type != T_UNKNOWN) {
	    if (fp->isarray) {
		fprintf(f, "extern ");
		if (fp->fixedlength > 0)
		    fprintf(f, "char %s[][%d]", fp->name, fp->fixedlength);
		else {
		    compiletype(f, &fp->type);
		    fprintf(f, "%s[]", fp->name);
		}
	    } else
		functionheader(f, fp);
	    fprintf(f, ";\n");
	}
    }
    return 0;
}


void outputconcats() {
    int i;

    if (componentbits & ~3) {
	fputs(concatdeclarations, headerfile ? headerfile : stdout);
	fputs(concatpreamble, stdout);
    } else
	fputs(nonconcatpreamble, stdout);
    for (i = 2; i < MAXBITS; i++) {
	if (componentbits & (1 << i))
	    outputconcat(i);
    }
}


void outputconcat(int n) {
    int i;
    char *last;

    assert(n > 1);
    if (headerfile) {
	outputconcatheader(headerfile, n);
	fprintf(headerfile, ";\n");
    }
    outputconcatheader(stdout, n);
    printf("\n{\n    void *p;\n    int len = ");
    last = "";
    for (i = 0; i < n; i++) {
	printf("%sstrlen(p%d)", last, i);
	last = " + ";
    }
    printf(";\n    p = dis_alloc(len + 1);\n    return ");
    for (i = 1; i < n; i++)
	printf("strcat(");
    printf("strcpy(p, p0)");
    for (i = 1; i < n; i++)
	printf(", p%d)", i);
    printf(";\n}\n\n");
}


void outputconcatheader(FILE *f, int n) {
    int i;
    char *last = "";

    fprintf(f, "char *dis_concat%d(", n);
    for (i = 0; i < n; i++) {
	fprintf(f, "%schar *p%d", last, i);
	last = ", ";
    }
    fprintf(f, ")");
}


void findarrays() {
    struct function *fp;
    struct entry *ep;
    struct string *estr, *indexstr;
    struct bits *bp;

    for (fp = functions; fp != NULL; fp = fp->next) {
	if (fp->nbits > 0 && fp->nargs > 0)
	    continue;
	if (fp->nargs > 1)
	    continue;
	ep = fp->first;
	if (ep == NULL || ep->next != NULL)
	    continue;
	estr = ep->string;
	if (estr == NULL || estr->next != NULL || estr->type != S_ARRAY)
	    continue;
	indexstr = estr->value.array->index;
	if (indexstr->next != NULL)
	    continue;
	if (fp->nbits > 0) {
	    bp = ep->bits;
	    if (bp == NULL || bp->next != NULL || bp->shift != 0)
		continue;
	    if (bp->mask != allbitsset(fp->nbits))
		continue;
	    if (indexstr->type != S_BITSTRING || indexstr->value.bits != bp)
		continue;
	} else {
	    if (indexstr->type != S_PARAMETER
		|| indexstr->value.parameter != fp->args)
		continue;
	}
	if (!simplearray(estr->value.array))
	    continue;
	fp->isarray = 1;
	fp->fixedlength =
	    (fp->type == T_INTEGER) ? 0 : checkfixedlength(estr->value.array);
    }
}


int checkfixedlength(struct array *ap) {
    int len, maxlen, wasted, n;
    struct stringlist *lp;

    maxlen = 0;
    for (lp = ap->elements; lp != NULL; lp = lp->next) {
	if (lp->string == NULL)
	    continue;
	assert(lp->string->type == S_TEXT);
	len = strlen(lp->string->value.text);
	if (len > maxlen)
	    maxlen = len;
    }
    for (wasted = n = 0, lp = ap->elements; lp != NULL; n++, lp = lp->next) {
	if (lp->string == NULL)
	    continue;
	wasted += maxlen - strlen(lp->string->value.text);
    }
    if (wasted < n * sizeof(char *))	/* Should be target's sizeof. */
	return maxlen + 1;
    return 0;
}


int outputfunction(struct function *fp) {
    printf("\n");
    functionheader(stdout, fp);
    printf("\n{\n"/*}*/);
    switch (functionswitch(fp, 0, 0)) {
    case -1:
	return 1;
    case 0:
	if (warnings) {
	    fprintf(stderr, "%s: warning: not all cases of %s covered\n",
		    progname, fp->name);
	}
    }
    printf(/*{*/"}\n");
    return 0;
}


void functionarray(struct function *fp) {
    struct array *ap;

    ap = fp->first->string->value.array;
    printf("\n");
    compilesimplearray(&fp->type, fp->name, 0, ap);
}


void functionheader(FILE *f, struct function *fp) {
    char *last;
    struct arg *ap;

    compiletype(f, &fp->type);
    fprintf(f, "%s(", fp->name);
    last = "";
    if (fp->nbits > 0) {
	fprintf(f, "bits code");
	last = ", ";
    }
    for (ap = fp->args; ap != NULL; ap = ap->next) {
	fprintf(f, "%s", last);
	compiletype(f, &ap->type);
	putc(ap->name, f);
	last = ", ";
    }
    if (*last == '\0')
	fprintf(f, "void");
    putc(')', f);
}


int simplearray(struct array *ap) {
    struct stringlist *lp;

    for (lp = ap->elements; lp != NULL; lp = lp->next) {
	if (lp->string != NULL
	    && (lp->string->next != NULL || lp->string->type != S_TEXT))
	    break;
    }
    return (lp == NULL);
}


void compiletype(FILE *f, enum type *tp) {
    switch (*tp) {
    case T_UNKNOWN:
	*tp = T_STRING;
	/* Fall in... */
    case T_STRING:
	fprintf(f, "char *");
	break;
    case T_INTEGER:
	fprintf(f, "bits ");
	break;
    default:
	fprintf(stderr, "compiletype type %d\n", *tp);
	abort();
    }
}


/* Generate code for entries in function fp whose bitstring b satisfies
   the constraint (b & mask) == value.  Return 1 if generated switch
   always does `return', 0 if not, -1 on error.
   The algorithm is as follows.  Scan the eligible entries to find the
   largest set of bits not in the passed-in mask which always have a
   constant value (are not variable).  One `default' entry is allowed
   all of whose bits are variable.  For each value of the constant bits,
   generate a `switch' case and invoke the function recursively with
   that value included in the constraint parameters.  The recursion
   stops when no set of constant bits is found, perhaps because the
   mask parameter has all bits set.
   This algorithm could be improved.  Currently it will fail if there
   are input lines "xxyy", "00xx" and "yy00", each of which is default with
   respect to the others.  The correct behaviour would then be to select
   a bit that is sometimes constant and deal with those cases first.
   But this problem has not yet arisen in real life.  */
int functionswitch(struct function *fp, bits mask, bits value) {
    struct entry *ep, *defaultcase;
    bits allbits, constbits, missingcases;
    int nhits, ncases, nconstbits, alwaysreturns;

    indentation++;
    allbits = allbitsset(fp->nbits);
    constbits = allbits & ~mask;
    if (debug) {
	findent(stderr);
	fprintf(stderr,
		"functionswitch(%s): (x & 0x%lx) == 0x%lx; const == 0x%lx\n",
		fp->name, mask, value, constbits);
    }
    defaultcase = NULL;
    ncases = nhits = 0;
    alwaysreturns = 1;
    for (ep = fp->first; ep != NULL; ep = ep->next) {
	/* If this is not one of the entries under consideration, skip.  */
	if (ep->done
	    || (ep->mask & mask) != mask || (ep->value & mask) != value)
	    continue;
	if (debug) {
	    findent(stderr);
	    showentry(stderr, fp, ep, 0);
	}
	/* If this entry has no constant bits in the still-variable portion,
	   it's the default.  */
	if ((constbits & ep->mask) == 0) {
	    if (defaultcase != NULL) {
		fprintf(stderr,
			"%s: function %s: unable to distinguish between:\n",
			progname, fp->name);
		showentry(stderr, fp, defaultcase, 0);
		showentry(stderr, fp, ep, 0);
		return -1;
	    }
	    defaultcase = ep;
	    if (debug) {
		findent(stderr);
		fprintf(stderr, "^^ default case\n");
	    }
	} else {
	    if (debug && (constbits & ~ep->mask)) {
		findent(stderr);
		fprintf(stderr, "const now 0x%lx\n", constbits & ep->mask);
	    }
	    constbits &= ep->mask;
	    nhits++;
	}
    }
    if (nhits > 0) {
	indent();
	if (constbits == allbits)
	    printf("switch (code) {\n"/*}*/);
	else
	    printf("switch (code & 0x%lx) {\n"/*}*/, constbits);
	for (ep = fp->first; ep != NULL; ep = ep->next) {
	    /* If this is not one of the entries under consideration, skip.  */
	    if ((ep->mask & mask) != mask || (ep->value & mask) != value)
		continue;
	    if (ep->done || ep == defaultcase)
		continue;
	    ncases++;
	    indent();
	    printf("case 0x%lx:\n", ep->value & constbits);
	    switch (functionswitch(fp, mask | constbits,
				value | (ep->value & constbits))) {
	    case -1:
		return -1;
	    case 0:
		alwaysreturns = 0;
		indentation++; indent(); indentation--;
		printf("break;\n");
	    }
	}
	indent();
	printf(/*{*/"}\n");
    }
    nconstbits = bitcount(constbits);
    missingcases = ((nconstbits == MAXBITS) ? 0 : 1 << nconstbits) - ncases;
    if (alwaysreturns) {
	switch (missingcases) {
	case 0:
	    if (defaultcase != NULL) {
		fprintf(stderr, "%s: warning: redundant entry:\n", progname);
		showentry(stderr, fp, defaultcase, 0);
		defaultcase = NULL;
	    }
	    break;
	case 1:
	    if (defaultcase != NULL && nconstbits != 0) {
		fprintf(stderr,
			"%s: warning: variable bit(s) could be constant:\n",
			progname);
		showentry(stderr, fp, defaultcase, constbits);
		break;
	    }
	    /* Fall in... */
	default:
	    alwaysreturns = 0;
	}
    }
    if (defaultcase != NULL) {
	/* If defaultcase has some constant bits of its own, recursion will
	   check that they have the required value.  */
	if ((defaultcase->mask & ~mask) == 0) {
	    alwaysreturns = 1;
	    if (compilestring(-1, defaultcase->string, fp->type) != 0)
		return -1;
	    defaultcase->done = 1;
	} else {
	    indentation--;
	    alwaysreturns = functionswitch(fp, mask, value);
	    indentation++;
	}
    }
    indentation--;
    return alwaysreturns;
}


int compilestring(int assignto, struct string *sp, enum type type) {
    int tempno;

    tempno = walkstring(sp, COUNTARRAYS, assignto);
    if (tempno > assignto) {
	indent();
	printf("{\n"/*}*/);
	indentation++;
	(void) walkstring(sp, DECLAREARRAYS, assignto);
	if (walkstring(sp, COMPILEARRAYS, assignto) < 0)
	    return 1;
    }
    if (compilecheckedstring(assignto, sp, type) != 0)
	return 1;
    if (tempno > assignto) {
	indentation--;
	indent();
	printf(/*{*/"}\n");
    }
    return 0;
}


int compilecheckedstring(int assignto, struct string *sp, enum type type) {
    compileassign(assignto);
    if (compileconcat(sp, type) != 0)
	return 1;
    printf(";\n");
    return 0;
}


void compileassign(int assignto) {
    indent();
    if (assignto < 0)
	printf("return ");
    else {
	compiletemp(assignto);
	printf(" = ");
    }
}


void compiletemp(int tempno) {
    printf("t__%d", tempno);
}


void compiletext(char *s) {
    putchar('"');
    if (s != NULL) {
	for ( ; *s != '\0'; s++) {
	    switch (*s) {
	    case '"':
	    case '\\':
		putchar('\\');
	    }
	    putchar(*s);
	}
    }
    putchar('"');
}


int compileconcat(struct string *sp, enum type type) {
    int elements;
    struct string *sp1;
    char *last;

    if (sp == NULL)
	return compilenull(type);
    if (sp->next == NULL)
	return compilesimple(sp, type);
    if (type != T_INTEGER) {
	for (elements = 0, sp1 = sp; sp1 != NULL; elements++, sp1 = sp1->next) ;
	printf("dis_concat%d(", elements);
    }
    last = "";
    for (sp1 = sp; sp1 != NULL; sp1 = sp1->next) {
	printf("%s", last);
	if (type != T_INTEGER)
	    last = ", ";
	if (sp1->type == S_ARRAY)
	    compilearrayref(sp1->value.array);
	else
	    if (compilesimple(sp1, type) != 0)
		return 1;
    }
    if (type != T_INTEGER)
	printf(")");
    return 0;
}


int compilenull(enum type type) {
    if (type == T_INTEGER) {
	fprintf(stderr, "%s: empty integer expression\n", progname);
	return 1;
    }
    printf("\"\"");
    return 0;
}


int compilesimple(struct string *sp, enum type type) {
    if (sp == NULL)
	return compilenull(type);
    switch (sp->type) {
    case S_TEXT:
	if (type == T_INTEGER)
	    printf("%s", sp->value.text);
	else
	    compiletext(sp->value.text);
	break;
    case S_BITSTRING:
	compilebitstring(sp->value.bits);
	break;
    case S_BITSPLICE:
	compilebitsplice(sp->value.bitsplice);
	break;
    case S_PARAMETER:
	putchar(sp->value.parameter->name);
	break;
    case S_FUNCTIONCALL:
	return compilefunctioncall(sp);
    case S_ARRAY:
	if (compilearrayref(sp->value.array) != 0)
	    return 1;
	break;
    default:
	fprintf(stderr, "compilesimple case %d", sp->type);
	abort();
    }
    return 0;
}


int compilearrayref(struct array *ap) {
    compiletemp(ap->tempno);
    if (simplearray(ap)) {
	printf("[");
	if (compileconcat(ap->index, T_INTEGER) != 0)
	    return 1;
	printf("]");
    }
    return 0;
}


int compilefunctioncall(struct string *sp) {
    struct function *fp;
    struct stringlist *actualp;
    struct arg *formalp;
    char *last;
    int nbits;
    enum type formaltype;

    assert(sp->type == S_FUNCTIONCALL);
    fp = sp->value.functioncall->function;
    printf("%s%c", fp->name, fp->isarray ? '[' : '(');
    last = "";
    nbits = fp->nbits;
    formalp = fp->args;
    actualp = sp->value.functioncall->args;
    while (actualp != NULL) {
	if (nbits > 0) {
	    nbits = 0;
	    formaltype = T_INTEGER;
	} else {
	    if (formalp == NULL) {
		fprintf(stderr, "%s: too many arguments to %s:\n", progname,
			fp->name);
		showstring(stderr, sp);
		putc('\n', stderr);
		return 1;
	    }
	    formaltype = formalp->type;
	    formalp = formalp->next;
	}
	if (actualp->type != T_UNKNOWN && actualp->type != formaltype) {
	    fprintf(stderr, "%s: argument to %s has the wrong type:\n",
		    progname, fp->name);
	    showstring(stderr, actualp->string);
	    putc('\n', stderr);
	    return 1;
	}
	printf("%s", last);
	last = ", ";
	if (compileconcat(actualp->string, formaltype) != 0)
	    return 1;
	actualp = actualp->next;
    }
    putchar(fp->isarray ? ']' : ')');
    return 0;
}


int walkstring(struct string *sp, enum walkstringop op, int tempno) {
    struct stringlist *lp;
    struct array *ap;

    for ( ; sp != NULL; sp = sp->next) {
	switch (sp->type) {
	case S_ARRAY:
	    ap = sp->value.array;
	    for (lp = ap->elements; lp != NULL; lp = lp->next)
		tempno = walkstring(lp->string, op, tempno);
	    tempno = walkstring(ap->index, op, tempno);
	    ap->tempno = ++tempno;
	    switch (op) {
	    case DECLAREARRAYS:
		if (simplearray(ap)) {
		    indent();
		    printf("static ");
		    compilesimplearray(&ap->type, NULL, tempno, ap);
		} else
		    declarearray(ap);
		break;
	    case COMPILEARRAYS:
		if (!simplearray(ap))
		    if (compilearray(ap) != 0)
			return -1;
		break;
	    default:
		break;
	    }
	    break;
	case S_FUNCTIONCALL:
	    for (lp = sp->value.functioncall->args; lp != NULL; lp = lp->next)
		tempno = walkstring(lp->string, op, tempno);
	    break;
	default:
	    break;
	}
    }
    return tempno;
}


int compilearray(struct array *ap) {
    struct stringlist *ep;
    int i;

    indent();
    printf("switch (");
    if (compileconcat(ap->index, T_INTEGER) != 0)
	return 1;
    printf(") {\n"/*}*/);
    for (i = 0, ep = ap->elements; ep != NULL; i++, ep = ep->next) {
	indent();
	printf("case %d:\n", i);
	indentation++;
	if (compilecheckedstring(ap->tempno, ep->string, ap->type) != 0)
	    return 1;
	indent();
	printf("break;\n");
	indentation--;
    }
    indent();
    printf(/*{*/"}\n");
    return 0;
}


void compilesimplearray(enum type *tp, char *name, int num, struct array *ap) {
    struct stringlist *lp;
    int fixedlength;

    fixedlength = (*tp == T_INTEGER) ? 0 : checkfixedlength(ap);
    if (fixedlength > 0)
	printf("char ");
    else
	compiletype(stdout, tp);
    if (name != NULL)
	printf("%s", name);
    else
	compiletemp(num);
    printf("[]");
    if (fixedlength > 0)
	printf("[%d]", fixedlength);
    printf(" = {\n"/*}*/);
    indentation++;
    for (lp = ap->elements; lp != NULL; lp = lp->next) {
	indent();
	compilesimple(lp->string, lp->type);
	printf(",\n");
    }
    indentation--;
    indent();
    printf(/*{*/"};\n");
}


void declarearray(struct array *ap) {
    indent();
    compiletype(stdout, &ap->type);
    compiletemp(ap->tempno);
    printf(";\n");
}


void compilebitstring(struct bits *bp) {
    printf("(");
    if (bp->shift != 0)
	printf("(");
    printf("code & 0x%lx", bp->mask);
    if (bp->shift != 0)
	printf(") >> %d", bp->shift);
    printf(")");
}


void compilebitsplice(struct bitsplice *splicep) {
    struct bitsplicebits *bsp;
    char *last = "";

    printf("(");
    for (bsp = splicep->splice; bsp != NULL; bsp = bsp->next) {
	printf("%s", last);
	last = " | ";
	if (bsp->type == S_PARAMETER)
	    putchar(bsp->value.arg->name);
	else {
	    assert(bsp->type == S_BITSTRING);
	    if (bsp->value.mask == 0)
		printf("code");
	    else
		printf("(code & 0x%lx)", bsp->value.mask);
	}
	if (bsp->shift > 0)
	    printf(" << %d", bsp->shift);
	else if (bsp->shift < 0)
	    printf(" >> %d", -bsp->shift);
    }
    if (splicep->entry.value != 0)
	printf("%s0x%lx", last, splicep->entry.value);
    printf(")");
}


int bitcount(bits x) {
    int nbits;

    for (nbits = 0; x != 0; x >>= 1) {
	if (x & 1)
	    nbits++;
    }
    return nbits;
}


bits allbitsset(int nbits) {
    return (nbits == MAXBITS) ? ~0 : (1 << nbits) - 1;
}


void findent(FILE *f) {
    int i;

    for (i = 1; i < indentation; i += 2)
	putc('\t', f);
    if (i == indentation)
	fputs("    ", f);
}


void indent() {
    findent(stdout);
}


void *xrealloc(char *oldp, size_t size) {
    void *p;

    if (oldp == NULL)
	p = malloc(size);
    else
	p = realloc(oldp, size);
    if (p == NULL) {
	fprintf(stderr, "%s: allocate of %d bytes failed: %s\n", progname,
		(int) size, strerror(errno));
	exit(1);
    }
    return p;
}


void *xmalloc(size_t size) {
    return xrealloc(NULL, size);
}


void *xstrdup(char *s) {
    char *p;

    p = xmalloc(strlen(s) + 1);
    strcpy(p, s);
    return p;
}


int prematureeof() {
    fprintf(stderr, "%s: %s(%d): premature end of file\n", progname, filename,
	    lineno);
    return 1;
}
