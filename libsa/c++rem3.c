// 45678901234567890123456789012345678901234567890123456789012345678901234567890
/*

Rules specification by
Stan Shebs of Apple Computer, Inc 2002

Parse and remangle implemented by
Godfrey van der Linden of Apple Computer, Inc 2002

Rules for demangling IOKit symbols

In Darwin versions 1.0 through at least 5.2, IOKit is compiled using
GCC version 2.  GCC 2's C++ symbol mangling algorithm ultimately
derives from the basic scheme described in the Annotated C++ Reference
Manual (ARM), section 7.2.1c, with a number of changes, mostly due to
the expansion of the language since the ARM was published in 1990.

This description is not complete.  It omits RTTI, thunks, and
templates, since they are not allowed in IOKit.  The description also
mentions mangled name constructs that are not disallowed in IOKit, but
that as of Jan 2002, did actually appear in any symbol in the base
system.

A mangled name basically consists of a function name followed
by two underscores, optionally followed by a signature computed
from the function's argument types.  (Note that in Darwin, the
compiler adds an additional underscore to all C and C++ symbols.
The description assumes this has been removed.)

<special_or_name> ::= <gnu_special>
                    | <mangled_name>

<mangled_name> ::= <prefix> [ <signature> ]

<prefix> ::= [ "_GLOBAL_" [ID] "__" ] <function_name> "__" [ <opinfo> ]

<function_name> ::= <char> <char>*
                  | NULL

Questions for Stan (@@@Stan@@@)
1> A valid <opinfo> implies a null function name.
2> I wonder if an <opinfo> is mutually exclusive with a <function_name> perhaps something like :-
<prefix> ::= [ "_GLOBAL_" ("I"|"D") "__" ] ((<function_name> "__") | <opinfo>)
3> Do constructors turn up as an opinfo or a NULL function name?

The optional "_GLOBAL_"("I"|"D")"__" sequence indicates global constructors
and destructors, but in practice these do not appear with the mach-o Apple 2.95

A Null <function_name> indicates a constructor or an operator.

Since <function_name> may include trailing underscores, the demangler
should scan forward until a non-underscore is seen, and then take the
last two as the separator between name and signature.

<function_name> may also include any number of leading underscores, so
the demangler needs to add those to <function_name> and look for the
"__" following the name.

<gnu_special> ::= ("_._"|"_$_" ) <class_name>	; destructor
                | "__vt_" <class_name>		; virtual table
                | "_" <class_name> ("."|"$") <varname> ; Variable

<class_name> ::= <counted_class_name>
               | "Q" <qualified_name>
               | "K" <qualified_name>	; ignored and illegal

<counted_class_name> ::= <count> <name>

<qualified_name> ::= <q_count> <counted_class_name> <counted_class_name>*

<opinfo> ::= "type" <type>
           | "__op" <type>
           | <opname> "__"
           | "a"

<opname> ::= "aa"	# &&
           | "aad"	# &=
           | "ad"	# &
           | "adv"	# /=
           | "aer"	# ^=
           | "als"	# <<=
           | "amd"	# %=
           | "ami"	# -=
           | "aml"	# *=
           | "aor"	# |=
           | "apl"	# +=
           | "ars"	# >>=
           | "as"	# =
           | "cl"	# ()
           | "cm"	# ,
           | "cn"	# ?:
           | "co"	# ~
           | "dl"	# delete
           | "dv"	# /
           | "eq"	# ==
           | "er"	# ^
           | "ge"	# >=
           | "gt"	# >
           | "le"	# <=
           | "ls"	# <<
           | "lt"	# <
           | "md"	# %
           | "mi"	# -
           | "ml"	# *
           | "mm"	# --
           | "mn"	# <?
           | "mx"	# >?
           | "ne"	# !=
           | "nt"	# !
           | "nw"	# new
           | "oo"	# ||
           | "or"	# |
           | "pl"	# +
           | "pp"	# ++
           | "rf"	# ->
           | "rm"	# ->*
           | "rs"	# >>
           | "sz"	# sizeof
           | "vc"	# []
           | "vd"	# delete[]
           | "vn"	# new[]

Questions for Stan (@@@Stan@@@)
1> What the hell is The "type" & "__op" stuff?

IOKit has so far only been observed to use operations new ("nw") and
delete ("dl").

The signature is a concatenated list of elements, which are usually
argument types, but may include other sorts of things.

<signature> ::= <qualifier>* <s_element> <argument_types>

<s_element> ::= <class_name>
              | "S"
              | "F" <argument_types> [ "_" <return_type> ] 

Questions for Stan (@@@Stan@@@)
1> I think the 'B' phrase should probably read '| "B" <index>'?
2> Ambiguous productions for signature
   OSObject::func(struct timeval fred) => _func__8OSObject7timeval
   signature could be parsed as
        <s_element> <s_element> or <s_element> <argument_types>
    I believe the second one must be the valid production.

<count> ::= <digit> <digit>*

<varname> :: <name>

<name> ::= <char> <char>*

The <count> is the number of characters in <name>.

Argument types are a concatenated sequence of types.

<argument_types> ::= # Empty
                   | <arg_type>+
<arg_type> ::= <type>  [ "n" <index> ]
	     | "N" <count> <pos>
             | "T" <index>

The "N" repeats and "T" references to already-seen typescan only
appear if -fno-squangle (no squashed mangling), and in practice aren't
seen in IOKit symbols.

<index> ::= <digit> | <digit> <digit> <digit>* "_"

Return types are just like any other sort of type.

<return_type> ::= <type>

Types consist of a variable number of declarators in front of a basic
type.

<type> ::= <declarator>* <base_type>

<declarator> ::= "P"            ; pointer
               | "p"            ; pointer (but never occurs?)
               | "R"            ; reference (&)
               | "A" <count>    ; array
               | "T" <index>
               | "O" <count>
               | <qualifier>

The "A" <count> production can produce an ambigous output if it is followed by a counted class name or structure name.

The "T" reference to a type does not appear in IOKit symbols, nor do
the "M" and "O" declarators.

<base_type> ::= <function_type>	; function
              | <method_type>	; method
              | <type_qualifier>* <fund_type_id>

<function_type> ::= "F" <argument_types> "_" <type>

<method_type> ::= "M" <class_name> <function_type>

A qualified name consists of a count of types, followed by all the
types concatenated together.  For instance, Namespace::Class is
Q29Namespace5Class.  For more than 9 types (which has not yet occurred
in IOKit), the multi-digit count is surrounded by underscores.

Questions for Stan (@@@Stan@@@)
1> Can the types in a qualified name really be generic types or can the set be restricted to just counted class names?

<q_count> ::= <digit> | "_" <digit> <digit>* "_"

Fundamental types are single letters representing standard built-in
types, optionally preceded by type qualifiers for properties like
signedness and constness.  For instance, CUi is a const unsigned int.

<type_qualifier> ::= "S"        ; signed (chars only)
                   | "U"        ; unsigned (any integral type)
                   | "J"        ; __complex
                   | <qualifier>

<fund_type_id> ::= <class_name>
                 | "b"          ; bool
                 | "c"          ; char
                 | "d"          ; double
                 | "f"          ; float
                 | "i"          ; int
                 | "l"          ; long
                 | "r"          ; long double
                 | "s"          ; short
                 | "v"          ; void
                 | "w"          ; wchar_t
                 | "x"          ; long long
                 | "G" <count>  ; ?????
                 | "e"		; ellipsis

"G" does not appear in IOKit symbols in this context.

<qualifier> ::= "C"             ; const
              | "V"             ; volatile
              | "u"             ; restrict (C99)
              | "G"             ; struct/union/enum unused by gcc3

The restrict qualifier has not appeared in IOKit symbols.

*/
#if KERNEL

#include <stdarg.h>
#include <string.h>

#include <sys/systm.h>

#include <libkern/OSTypes.h>

#include <libsa/stdlib.h>

enum { false = 0, true = 1 };

#else /* !KERNEL */

#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <CoreFoundation/CoreFoundation.h>
 
#endif /* KERNEL */

#include "c++rem3.h"

#define STRLEN(s) (sizeof(s)-1)
#define APPENDSTR(c, str) do { appendNStr(c, str, STRLEN(str)); } while (0)

#define MAX_COMPOUND_TYPES	128
#define MAX_ENTRIES		256
#define MAX_SDICT_ENTRIES	256
#define MAX_BDICT_ENTRIES	 64
#define MAX_RETURN_BUFFER	256

// Can't be bigger that 16 entries
typedef enum NameTypes {
    kNTUndefined,	kNTClass,	kNTFunction,	kNTFuncEnd,
    kNTMethod,		kNTBuiltIn,	kNTDeclarator,	kNTArray,
    kNTKName,		kNTSubstitute,  kNTSubQualClass
} NameTypes;

typedef struct TypeData {
    short fStartEntry, fNumEntries;
} TypeData;

typedef struct BaseTypeData {
    const char *fFundTypeID;	// May contain the type itself for kNTBuiltIt
    unsigned int fLen:16;
    unsigned int fType:4;	// Must fit a NameType
    unsigned int fVolatile:1;
    unsigned int fConst:1;
    unsigned int fSigned:1;
    unsigned int fUnsigned:1;
    unsigned int fPseudo:1;
    unsigned int fQualified:1;
} BaseTypeData;

typedef struct CheckPoint {
    const char *fInChar;
    unsigned char fNumI, fNumO, fNumT, fNumB, fNumS;
} CheckPoint;

typedef struct ParseContext {
    CheckPoint fP;
    BaseTypeData fInEntries[MAX_ENTRIES];	// Input parsed elements
    BaseTypeData fOutEntries[MAX_ENTRIES];	// Output parsed elements
    TypeData fTypeList[MAX_COMPOUND_TYPES];	// Table of types
    TypeData fSubDict[MAX_SDICT_ENTRIES];
    TypeData fBDict[MAX_BDICT_ENTRIES];		// B dictionary types
    BaseTypeData *fCurBaseP;
    const char *fInStr;
    char *fOutStrEnd;
    char *fOutChar;
    int fInSize;
    Rem3Return fRetCode;
} ParseContext;

//
// The only forward declaration necessary
//
static Boolean parse_type(ParseContext *c);

// Helper functions for walking through the string
static __inline__ char getNext(ParseContext *c)
{
    return *c->fP.fInChar++;
}

static __inline__ CheckPoint *checkPoint(ParseContext *c)
{
    return &c->fP;
}

static __inline__ void resetTo(ParseContext *c, CheckPoint *chk)
{
    c->fP = *chk;
}

static __inline__ const char *inCharFromCheck(ParseContext *c, CheckPoint *chk)
{
    return chk->fInChar;
}

static __inline__ void advance(ParseContext *c, int len)
{
    c->fP.fInChar += len;
}

static __inline__ Boolean retard(ParseContext *c, int len)
{
    const char *cp = c->fP.fInChar - len;
    if (cp < c->fInStr)
        return false;

    c->fP.fInChar = cp;
    return true;
}

static __inline__ char peekAt(ParseContext *c, int index)
{
    return c->fP.fInChar[index];
}

static __inline__ char peekNext(ParseContext *c)
{
    return peekAt(c, 0);
}

static __inline__ Boolean atEnd(ParseContext *c)
{
    return '\0' == peekNext(c);
}

static __inline__ Boolean hasRemain(ParseContext *c, int len)
{
    return (c->fP.fInChar - c->fInStr + len <= c->fInSize);
}

//
// Routines for allocating entries in the various
//
static __inline__ BaseTypeData *newIn(ParseContext *c)
{
    BaseTypeData *iP;

    if (c->fP.fNumI < MAX_ENTRIES) {
        iP = &c->fInEntries[c->fP.fNumI++];
        bzero(iP, sizeof(*iP));
        c->fCurBaseP = iP;
        return iP;
    }
    else {
        c->fRetCode = kR3InternalNotRemangled;
        return NULL;
    }
}

static __inline__ BaseTypeData *newOut(ParseContext *c)
{
    BaseTypeData *oP;

    if (c->fP.fNumO < MAX_ENTRIES) {
        oP = &c->fOutEntries[c->fP.fNumO++];
        return oP;
    }
    else {
        c->fRetCode = kR3InternalNotRemangled;
        return NULL;
    }
}

static __inline__ TypeData *
newSub(ParseContext *c, int start, int num)
{
    TypeData *sP;

    if (c->fP.fNumS < MAX_SDICT_ENTRIES) {
        sP = &c->fSubDict[c->fP.fNumS++];
        sP->fStartEntry = start;
        sP->fNumEntries = num;
        return sP;
    }
    else {
        c->fRetCode = kR3InternalNotRemangled;
        return NULL;
    }
}

static __inline__ TypeData *
newBDict(ParseContext *c, int start, int num)
{
    TypeData *bP;

    if (c->fP.fNumB < MAX_BDICT_ENTRIES) {
        bP = &c->fBDict[c->fP.fNumB++];
        bP->fStartEntry = start;
        bP->fNumEntries = num;
        return bP;
    }
    else {
        c->fRetCode = kR3InternalNotRemangled;
        return NULL;
    }
}

static __inline__ TypeData *
newType(ParseContext *c, int start)
{
    TypeData *tP;

    if (c->fP.fNumT < MAX_COMPOUND_TYPES) {
        tP = &c->fTypeList[c->fP.fNumT++];
        tP->fStartEntry = start;
        return tP;
    }
    else
        return NULL;
}

static __inline__ TypeData *
dupType(ParseContext *c, TypeData *iTP, int offset)
{
    TypeData *tP = newType(c, iTP->fStartEntry + offset);
    if (tP)
        tP->fNumEntries = iTP->fNumEntries;

    return tP;
}

//
// Identifier character recognition helpers, can be optimised
//
static __inline__ Boolean isValidFirstAlphabetic(char c)
{
    if ('a' <= c && c <= 'z')
        return true;
    else if ('A' <= c && c <= 'Z')
        return true;
    else
        return false;
}

static __inline__ Boolean isValidFirstChar(char c)
{
    if (isValidFirstAlphabetic(c))
        return true;
    else if (c == '_')
        return true;
    else
        return false;
}

static __inline__ Boolean isValidChar(char c)
{
    if (isValidFirstChar(c))
        return true;
    else if ('0' <= c && c <= '9')
        return true;
    else
        return false;
}

//
// Helper function for recognising characters and strings
//

// Check the current input is the given character
static __inline__ Boolean isNext(ParseContext *c, char ch)
{
    if (peekNext(c) == ch) {
        advance(c, 1);
        return true;
    }
    else
        return false;
}

// Check the current input is ONE of the characters in str
static Boolean charNext(ParseContext *c, char *str)
{
    if (hasRemain(c, 1)) {
        char ch = peekNext(c);
        char next;

        while ( (next = *str++) )
            if (next == ch) {
                advance(c, 1);
                return true;
            }
    }

    return false;
}

// Check the current input for 'str'
static Boolean strNext(ParseContext *c, const char *str)
{
    const char *cp = c->fP.fInChar;

    do {
        if (!*str) {
            c->fP.fInChar = (char *) cp;
            return true;
        }
        else if (!*cp)
            return false;

    } while (*cp++ == *str++);

    return false;
}

//
// Qualifier re-encoding
//
static void
decodeQual(BaseTypeData *typeP, int *qualLenP, const char **qualP)
{
    const char *qual;
    int qualLen;

    if (typeP->fConst && typeP->fVolatile)
        { qual = "VK"; qualLen = 2; }
    else if (typeP->fConst)
        { qual = "K";  qualLen = 1; }
    else if (typeP->fVolatile)
        { qual = "V";  qualLen = 1; }
    else
        { qual = NULL; qualLen = 0; }

    *qualLenP = qualLen;
    *qualP = qual;
}


//
// Output functions
//

static void appendChar(ParseContext *c, char ch)
{
    char *outAddr = c->fOutChar++;
    if (outAddr < c->fOutStrEnd)
        *outAddr = ch;
}

static void appendNStr(ParseContext *c, const char *str, int len)
{
    char *outAddr = c->fOutChar;

    c->fOutChar += len;
    if (c->fOutChar < c->fOutStrEnd)
        bcopy(str, outAddr, len);
}

static __inline__ void appendStr(ParseContext *c, const char *str)
{
    appendNStr(c, str, strlen(str));
}

static void appendSub(ParseContext *c, int ls)
{
    appendChar(c, 'S');
    if (ls) {
        if (--ls >= 36) {
            int ms;
    
            ms = ls / 36;
            appendChar(c, (ms < 10)? '0' + ms : 'A' + ms - 10);
            ls -= (ms * 36);
        }
        appendChar(c, (ls < 10)? '0' + ls : 'A' + ls - 10);
    }
    appendChar(c, '_');
}

static Boolean compareTypes(ParseContext *c, int sub, int entry, int numEntries)
{
    TypeData *subP = &c->fSubDict[sub];
    BaseTypeData *bSP, *bIP;
    int i;

    if (subP->fNumEntries != numEntries)
        return false;

    bSP = &c->fInEntries[subP->fStartEntry];
    bIP = &c->fInEntries[entry];

    for (i = 0; i < numEntries; i++, bSP++, bIP++) {
        if (bSP->fType != bIP->fType)
            return false;

        switch (bSP->fType) {
        case kNTClass:
            if (bSP->fLen != bIP->fLen)
                return false;
            else if (strncmp(bSP->fFundTypeID, bIP->fFundTypeID, bSP->fLen))
                return false;
            break;

        case kNTArray:
        case kNTBuiltIn:
        case kNTDeclarator:
            if (bSP->fFundTypeID != bIP->fFundTypeID)
                return false;
            break;

        case kNTMethod:
        case kNTFunction:
        case kNTUndefined:
        case kNTKName:
            break;		// OK so far

        default:
            return false;	// Fatal errors 
        }
    }

    return true;
}

static int searchDict(ParseContext *c, int entry, int numE)
{
    int sub, numSubs = c->fP.fNumS;

        // don't try to substitute the last builtin 
    if (numE == 1 && kNTBuiltIn == c->fInEntries[entry].fType)
        return -1;
        
    for (sub = 0; sub < numSubs; sub++)
        if (compareTypes(c, sub, entry, numE))
            return sub;

    return -1;
}

static int searchDictClass(ParseContext *c, const char *qname, int len)
{
    TypeData *subP;
    int sub, numSubs = c->fP.fNumS;

    for (sub = 0, subP = c->fSubDict; sub < numSubs; sub++, subP++) {
        BaseTypeData *iP = &c->fInEntries[subP->fStartEntry];

        if (kNTClass != iP->fType || iP->fLen != len)
            continue;
        if (!strncmp(iP->fFundTypeID, qname, len))
            return sub;
    }

    return -1;
}

static Boolean
appendQualifiedClass(ParseContext *c, int entry)
{
    BaseTypeData *iP, *oP, *sP, *endSP;
    const char *cp, *typeID;
    int sub, subEntry, prefixLen;
    int q_count;

    int decodeStart = c->fP.fNumI;

    // Scan through the incom
    iP = &c->fInEntries[entry];
    endSP = &c->fInEntries[MAX_ENTRIES];
    sP = &c->fInEntries[decodeStart];

    prefixLen = iP->fLen;
    typeID = cp = iP->fFundTypeID;
    for (q_count = 0; sP < endSP && (cp-typeID) < prefixLen; q_count++, sP++) {
        int count;

        count = strtoul(cp, (char **) &cp, 10);
        cp += count;

        sP->fType = kNTClass;
        sP->fFundTypeID = typeID;
        sP->fLen = cp - typeID;
    }
    if (sP >= endSP)
        return false;
    
    // Search backwards until I find the first substitution
    sub = -1;
    for (subEntry = q_count, sP--; subEntry > 0; subEntry--, sP--) {
        sub = searchDictClass(c, sP->fFundTypeID, sP->fLen);
        if (-1 != sub)
            break;
    }

    // Now drop the symbol into the output buffer
    oP = newOut(c);
    if (!oP)
        return false;

    if (sub < 0)
        *oP = *iP;	// No sub copy original
    else {
        // Substitution found
        prefixLen = sP->fLen;		// Length of substitution

        oP->fType = kNTSubstitute;	// Assume complete substitution
        oP->fLen = sub;
        oP->fFundTypeID = 0;

        // We have a partial substitution so tag on the unmatched bit
        if (prefixLen != iP->fLen) {
            oP->fType = kNTSubQualClass; // Re-characterise as 2 part sub
    
            oP = newOut(c);
            if (!oP)
                return false;

            *oP = *iP;			// Duplicate the original
            oP->fType = kNTSubQualClass;
            oP->fFundTypeID += prefixLen; // Skip leading substituted text
            oP->fLen -= prefixLen;
        }
    }

    // Finally insert the qualified class names into the dictionary
    for (subEntry++, sP++; subEntry < q_count; subEntry++, decodeStart++) {
        c->fInEntries[decodeStart] = *sP++;
        if (!newSub(c, decodeStart, 1))
            return false;
    }
    c->fP.fNumI = decodeStart;

    if (!newSub(c, entry, 1))
        return false;
    
    return true;
}

static int
appendType(ParseContext *c, int type)
{
    BaseTypeData *iP, *oP;
    TypeData *tP;
    int i, sub;
    int entry, numE, lastEntry;
    Boolean found;

    if (type >= c->fP.fNumT)
        return -1;

    tP = &c->fTypeList[type++];
    entry = tP->fStartEntry;
    numE  = tP->fNumEntries;
    lastEntry = entry + numE;
    iP = 0;
    for (i = 0, found = false, sub = -1; i < numE; i++) {
        iP = &c->fInEntries[entry + i];
        switch (iP->fType) {

	// Function & Builtin can't be compressed alone
        case kNTFunction:
        case kNTBuiltIn:
            i++;		// Copy the current entry
            found = true;
            break;

        case kNTClass:
        case kNTMethod:
            sub = searchDict(c, entry + i, numE - i);
            if (sub < 0 && !iP->fQualified)
                i++;
            found = true;
            break;

        case kNTDeclarator:
        case kNTArray:
            sub = searchDict(c, entry + i, numE - i);
            found = (sub >= 0);
            break;

        // Internal error's should never occur
        case kNTKName:
        case kNTSubstitute:
        case kNTSubQualClass:
        case kNTUndefined:
        default:
            return -1;
        }
        if (found)
            break;
    }

    if (!found)
        return -1;	// Internal error: no terminal symbol?

    // Copy the already input buffer to the output
    oP = &c->fOutEntries[c->fP.fNumO];
    if (i) {  
        if (c->fP.fNumO + i >= MAX_ENTRIES)
            return -1;

        bcopy(&c->fInEntries[entry], oP, i * sizeof(*oP));
        c->fP.fNumO += i;
        oP += i;
    }

    if (sub >= 0) {
        // We found a substitution
        oP->fType = kNTSubstitute;
        oP->fLen = sub;
        c->fP.fNumO++;		// Increment output for the substitution

        // Walk over types that have been substituted
        while (type < c->fP.fNumT 
           &&  c->fTypeList[type].fStartEntry < lastEntry)
                type++;
    }
    else switch (iP->fType)
    {
    case kNTMethod:
        type = appendType(c, type);	// Class Name
        if (type < 0)
            return type;
        type = appendType(c, type);	// Pointer to function
        if (type < 0)
            return type;
        break;

    case kNTFunction:
        type = appendType(c, type);	// Return type
        if (type < 0)
            return type;

        // process the argument list
        do {
            tP = &c->fTypeList[type];
            if (tP->fStartEntry < lastEntry) {
                type = appendType(c, type);
                if (type < 0)
                    return type;
            }
            else
                break;
        } while (type < c->fP.fNumT);
        oP = newOut(c);
        if (!oP)
            return -1;
        oP->fType = kNTFuncEnd;
        break;

    case kNTBuiltIn:
        i--;		// Do not store the buildit in the dictionary
        break;

    case kNTClass:	// Nothing more to do
        if (!iP->fQualified)
            break;
        else if (appendQualifiedClass(c, entry + i))
            break;
        else
            return -1;
    }
    
    // No further substititions to be had update the dictionary
    for (i += entry; --i >= entry; ) {
        if (!newSub(c, i, lastEntry - i))
            return -1;
    }
    
    return type;
}

static Boolean appendArgumentList(ParseContext *c)
{
    int i, num;

    c->fRetCode = kR3InternalNotRemangled;
    // Setup the output entry array
    num = c->fP.fNumT;
    for (i = 0; i < num; ) {
        i = appendType(c, i);
        if (i < 0)
            return false;
    }

    // First pass output uncompressed types
    for (i = 0, num = c->fP.fNumO; i < num; i++) {
        BaseTypeData *bP;

        bP = &c->fOutEntries[i];

        if (bP->fPseudo)
            continue;	// Pseudo entry do not output;

        switch (bP->fType) {

        case kNTSubstitute: appendSub(c, bP->fLen); break;

        case kNTSubQualClass:
            appendChar(c, 'N');
            appendSub(c, bP->fLen);
            i++; bP = &c->fOutEntries[i];
            appendNStr(c, bP->fFundTypeID, bP->fLen);
            appendChar(c, 'E');
            break;

        case kNTClass:
            if (bP->fQualified) {
                appendChar(c, 'N');
                appendNStr(c, bP->fFundTypeID, bP->fLen);
                appendChar(c, 'E');
            }
            else
                appendNStr(c, bP->fFundTypeID, bP->fLen);
            break;

        case kNTArray: {
            char numbuf[16];	// Bigger than MAX_LONG + 3
            int len;
            len = snprintf(numbuf, sizeof(numbuf),
                           "A%lu_", (unsigned long) bP->fFundTypeID);
            appendNStr(c, numbuf, len);
            break;
        }

        case kNTBuiltIn:
        case kNTDeclarator:	appendChar(c, (int) bP->fFundTypeID); break;
        case kNTMethod:		appendChar(c, 'M'); break;
        case kNTFunction:	appendChar(c, 'F'); break;
        case kNTFuncEnd:	appendChar(c, 'E'); break;

        case kNTUndefined:
        case kNTKName:
        default:
            return false;	// Fatal errors 
        }
    }

    // Successful remangle
    c->fRetCode = kR3Remangled;
    return true;
}

//
// Parse routines
//

// <count> ::= <digit> <digit>*
static Boolean parse_count(ParseContext *c, int *countP)
{
    int count = 0;
    char ch;

    ch = peekNext(c);
    if (ch < '1' || ch > '9')
        return false;

    count = strtol(c->fP.fInChar, (char **) &c->fP.fInChar, 10);
    if (countP)
        *countP = count;

    return true;
}


// "n" <index> can cause the following type to be ambiguous as
// n23_Pc... can be
//	  "n" <digit> <counted_class_name> ...
//	| "n" <digit> <digit> '_' <declarator> <fund_type_id> ...
// However as the class '_Pc' is probably going to be unlikely a quick
// check to see if the next field is a valid type would probably clear
// up the abiguity for the majority of cases.
// 
// <index> ::= <digit> | <digit> <digit> <digit>* "_"
static Boolean parse_index(ParseContext *c, int *indexP)
{
    CheckPoint chk = *checkPoint(c);
    char ch0, ch1;
    int index;

    ch0 = peekAt(c, 0);
    ch1 = peekAt(c, 1);

    if ( !('0' <= ch0 && ch0 <= '9') )
        goto abandonParse;
    if ('0' <= ch1 && ch1 <= '9') {
        if (!parse_count(c, &index))
            goto abandonParse;
        if (isNext(c, '_')) {
            // @@@ gvdl: Ambiguity check one day
            if (indexP)
                *indexP = index;
            return true;
        }
        else
            resetTo(c, &chk);	// Must be the one digit case
    }

    // One digit case
    advance(c, 1);
    index = ch0 - '0';

    if (indexP)
        *indexP = index;
    return true;

abandonParse:
    return false;
}


// <qualifier> ::= "C"	; const
//               | "V"	; volatile
//               | "u"	; restrict (C99) unsupported
//               | "G"	; struct/union/enum ; unused in gcc3
static Boolean parse_qualifiers(ParseContext *c)
{
    BaseTypeData *bP = c->fCurBaseP;

    for (;;) {
        if (isNext(c, 'C'))
            bP->fConst = true;		// "C"	; const
        else if (isNext(c, 'V'))
            bP->fVolatile = true;	// "V"	; volatile
        else if (isNext(c, 'u'))
            return false;		// "u"	; restrict (C99)
        else if (isNext(c, 'G'))
            continue;			// "G"	; struct/union/enum ; unused
        else
            break;
    }

    return true;
}

// Assumes we have an open fInEntry in fCurBaseP
static Boolean duplicateEntries(ParseContext *c, int start, int numE)
{
    BaseTypeData *bIP = &c->fInEntries[start];	// First duplicate entry
    BaseTypeData *bP = c->fCurBaseP;
    int i;

    // Duplicating a method
    if (kNTMethod == bIP->fType) {
        bP--;			// Strip leading 'P' declarator
        c->fP.fNumI--;
    }

    numE--;

    // do we have room available for duplication
    if (c->fP.fNumI + numE >= MAX_ENTRIES)
        return false;

    // Copy the parse entries over
    bcopy(bIP, bP, (numE + 1) * sizeof(*bP));

    // Now we have to duplicate the types for the new entry
    for (i = 0; i < c->fP.fNumT; i++) {
        TypeData *tP = &c->fTypeList[i];
        if (tP->fStartEntry < start)
            continue;
        else if (tP->fStartEntry <= start + numE)
            dupType(c, tP, bP - bIP);
        else
            break;
    } 

    c->fP.fNumI += numE;
    bP += numE;
    c->fCurBaseP = bP;

    return true;
}

// Must have a valid c->fCurBaseP pointer on entry
// <class_name> ::= <counted_class_name>	; plain class name
//                | "Q" <qualified_name>	; qualified name
//                | "B" <index>			; compressed name
//                | "K" <qualified_name>	; ignored and illegal
// <qualified_name> ::= <q_count> <counted_class_name>+
// <q_count> ::= <digit> | "_" <digit> <digit>* "_"
// <counted_class_name> ::= <count> <name>
// <name> ::= <char> <char>*
static Boolean
parse_class_name(ParseContext *c)
{
    BaseTypeData *bP = c->fCurBaseP;
    const char *typeId = c->fP.fInChar;
    char ch;
    int count;

    if (parse_count(c, &count)) {

        // <counted_class_name> ::= <count> <name>
        if (!hasRemain(c, count))
            goto abandonParse;

        bP->fType = kNTClass;
        advance(c, count);

        bP->fFundTypeID = typeId;
        bP->fLen = c->fP.fInChar - typeId;
    }
    else {
        switch (peekNext(c)) {

        case 'Q': {
            int i, q_count;

            advance(c, 1);

            //                | "Q" <qualified_name>	; qualified name
            // <qualified_name> ::= <q_count> <counted_class_name>+
            // <q_count> ::= <digit> | "_" <digit> <digit>* "_"
            if ('_' == (ch = getNext(c))) {
                advance(c, 1);
                if (!parse_count(c, &q_count) || !isNext(c, '_'))
                    goto abandonParse;
            }
            else if ('1' <= ch && ch <= '9')
                q_count = ch - '0';

            if (!q_count)
                goto abandonParse;

            typeId = c->fP.fInChar;
            bP->fType = kNTClass;
            bP->fQualified = true;
            i = 0;
            for (i = 0; i < q_count; i++) {
                if (parse_count(c, &count))
                    advance(c, count);
                else
                    goto abandonParse;
            }
            bP->fLen = c->fP.fInChar - typeId;
            bP->fFundTypeID = typeId;
            break;
        }

        case 'B':
            //               | "B" <index>
            advance(c, 1);

            if (!parse_index(c, &count) || count >= c->fP.fNumB)
                goto abandonParse;

            if (!duplicateEntries(c, c->fBDict[count].fStartEntry,
                                     c->fBDict[count].fNumEntries))
                goto abandonParse;
            return true;

        case 'K': default:
            goto abandonParse;
        }
    }

    if (newBDict(c, bP - c->fInEntries, 1))
        return true;

abandonParse:
    return false;
}

// <fund_type_id> ::= <class_name>
//                  | "b"          ; bool
//                  | "c"          ; char
//                  | "d"          ; double
//                  | "e"          ; ellipsis
//                  | "f"          ; float
//                  | "i"          ; int
//                  | "l"          ; long
//                  | "r"          ; long double
//                  | "s"          ; short
//                  | "v"          ; void
//                  | "w"          ; wchar_t
//                  | "x"          ; long long
//                  | "G" <count>  ; ???
static Boolean parse_fund_type_id(ParseContext *c)
{
    BaseTypeData *bP = c->fCurBaseP;

    if (!parse_class_name(c)) {
        // Use the TypeID pointer as a 4 character buffer
        char ch = peekNext(c);

        if (bP->fSigned && 'c' != ch)
            goto abandonParse;	// illegal only chars can be signed

        switch (ch) {

        case 'b': case 'd': case 'f': case 'v': case 'w':	// No map types
            break;

        case 'c':			// character
            if (bP->fSigned)		ch = 'a';
            else if (bP->fUnsigned)	ch = 'h';
            break;
        case 'e':			// ellipsis
                                        ch = 'z';
            break;
        case 'i':			// int
            if (bP->fUnsigned)		ch = 'j';
            break;
        case 'l':			// long
            if (bP->fUnsigned)		ch = 'm';
            break;
        case 'r':			// long double
                                        ch = 'e';
            break;
        case 's':			// short
            if (bP->fUnsigned)		ch = 't';
            break;
        case 'x':			// long long
            if (bP->fUnsigned)		ch = 'y';
            break;

        case 'G':			// Don't understand "G"
        default:
            goto abandonParse;
        }

        advance(c, 1);	// Consume the input character
        bP->fFundTypeID = (void *) (int) ch;
        bP->fLen = 0;
        bP->fType = kNTBuiltIn;
    }

    return true;

abandonParse:
    return false;
}

// <arg_type> ::= <type>  [ "n" <index> ]
//	       | "N" <count> <pos>	; Not implemented
//             | "T" <index>		; Not implemented
static Boolean parse_arg_type(ParseContext *c)
{
    // Don't bother to check point as parse_argument_types does it for us

    TypeData *typeP;
    int repeat = 0;

    typeP = &c->fTypeList[c->fP.fNumT];	// Cache type for later repeat
    if (!parse_type(c))
        return false;

    // Now check for a repeat count on this type
    if (isNext(c, 'n')) {
        if (!parse_index(c, &repeat))
            return false;

        do {
            c->fCurBaseP = newIn(c);	// Duplicate requires a fresh type
            if (!c->fCurBaseP)
                return false;
            if (!duplicateEntries(c, typeP->fStartEntry, typeP->fNumEntries))
                return false;
        } while (--repeat);
    }

    return true;
}

// <argument_types> ::= # Empty
//                    | <arg_type>+
static Boolean parse_argument_types(ParseContext *c)
{
    if (atEnd(c))
        return true;

    if (!parse_arg_type(c))
        goto abandonParse;

    while (!atEnd(c) && parse_arg_type(c))
        ;

    return true;

    // Not a counted class name so reset to checkPoint
abandonParse:
    return false;
}

// leaf function so the copy aside buffer isn't on the primary
// recursion stack.
static Boolean
rotateFunction(ParseContext *c, int argStart, int retStart)
{
    char returnTypeBuffer[MAX_RETURN_BUFFER];
    int numArg, numRet;
    int lenArg, lenRet;
    char *sArgP, *sRetP;
    int i;

    TypeData *argTP = &c->fTypeList[argStart];
    TypeData *retTP = &c->fTypeList[retStart];

    // Rotate around the entries first
    numArg = retTP->fStartEntry - argTP->fStartEntry;
    numRet = retTP->fNumEntries;
    lenArg = numArg * sizeof(BaseTypeData);
    lenRet = numRet * sizeof(BaseTypeData);

    // Copy the return type into a buffer
    if (lenRet > sizeof(returnTypeBuffer))
        return false;

    sArgP = (char *) (&c->fInEntries[argTP->fStartEntry]);
    sRetP = (char *) (&c->fInEntries[retTP->fStartEntry]);
    
    bcopy(sRetP, returnTypeBuffer, lenRet);
    bcopy(sArgP, sArgP + lenRet, lenArg);
    bcopy(returnTypeBuffer, sArgP, lenRet);

    // Retarget the argument and return types for the new entry positions
    lenArg = numArg;
    lenRet = numRet;
    numArg = retStart - argStart;
    numRet = c->fP.fNumT - retStart;
    for (i = 0; i < numArg; i++)
        c->fTypeList[argStart+i].fStartEntry += lenRet;
    for (i = 0; i < numRet; i++)
        c->fTypeList[retStart+i].fStartEntry -= lenArg;

    // Rotate the BDictionary
    for (i = 0; i < c->fP.fNumB; i++) {
        TypeData *bDP = &c->fBDict[i];
        int start = bDP->fStartEntry;

        if (start >= argTP->fStartEntry)
            bDP->fStartEntry = start + lenRet;
        else if (start >= retTP->fStartEntry)
            bDP->fStartEntry = start - lenArg;
    }

    // Finally rotate the retargeted type structures.
    lenArg = numArg * sizeof(TypeData);
    lenRet = numRet * sizeof(TypeData);

    sArgP = (char *) (&c->fTypeList[argStart]);
    sRetP = (char *) (&c->fTypeList[retStart]);

    bcopy(sRetP, returnTypeBuffer, lenRet);
    bcopy(sArgP, sArgP + lenRet, lenArg);
    bcopy(returnTypeBuffer, sArgP, lenRet);

    return true;
}

// <function_type> ::= "F" <argument_types> "_" <type>
static Boolean parse_function_type(ParseContext *c, Boolean forMethod)
{
    TypeData *bDictP = 0;
    BaseTypeData *bP = c->fCurBaseP;

    int argTypeStart, retTypeStart;

    if (!forMethod) {
        bDictP = newBDict(c, c->fP.fNumI-1, 0);
        if (!bDictP)
            goto abandonParse;
    }

    if (!isNext(c, 'F'))
        goto abandonParse;

    bP->fType = kNTFunction;

    // Note that the argument types will advance the Entry list
    argTypeStart = c->fP.fNumT;
    if (!parse_argument_types(c))
        goto abandonParse;

    if (!isNext(c, '_'))
        goto abandonParse;

    // Parse the return type
    retTypeStart = c->fP.fNumT;
    if (!parse_type(c))
        goto abandonParse;

    // gcc3 puts the return code just after the 'F' declaration
    // as this impacts the order of the compression I need to rotate
    // the return type and the argument types.
    if (!rotateFunction(c, argTypeStart, retTypeStart))
        goto abandonParse;

    if (!forMethod)
        bDictP->fNumEntries = c->fP.fNumI - bDictP->fStartEntry;

    return true;

abandonParse:
    return false;
}

// To convert 2.95 method to a 3.0 method I need to prune the
// first argument of the function type out of the parse tree.
static Boolean cleanMethodFunction(ParseContext *c, int type)
{
    TypeData *typeP, *startTP, *endTP;            
    BaseTypeData *bP;
    int i, thisStart, thisEnd, thisLen, funcRemain;

    // Get pointer for the return value's type.
    startTP = &c->fTypeList[type+1];
    endTP = &c->fTypeList[c->fP.fNumT];

    // Now look for the first type that starts after the return type
    thisEnd = startTP->fStartEntry + startTP->fNumEntries;
    for (startTP++; startTP < endTP; startTP++)
        if (startTP->fStartEntry >= thisEnd)
            break;

    if (startTP >= endTP) {
        c->fRetCode = kR3InternalNotRemangled;
        return false;	// Internal error: should never happen
    }

    // We now have a pointer to the 1st argument in the input list
    // we will need to excise the entries from the input list and don't forget
    // to remove the associated types from the type list.

    thisLen = startTP->fNumEntries;
    thisStart = startTP->fStartEntry;
    thisEnd = thisStart + thisLen;
    funcRemain = c->fP.fNumI - thisEnd;
    bP = &c->fInEntries[thisStart];

    // If we have no arguments then replace the pointer with a void
    if (!funcRemain) {
        c->fP.fNumI -= (thisLen - 1);

        bP->fFundTypeID = (void *) (int) 'v';	// Void arg list
        bP->fLen = 0;
        bP->fType = kNTBuiltIn;

        // Update the type entry for the void argument list
        startTP->fNumEntries = 1;
        return true;
    }

    // Move the argument list down to replace the 'this' pointer
    bcopy(bP + thisLen, bP, funcRemain * sizeof(*bP));
    c->fP.fNumI -= thisLen;

    // And remove the 'this' pointers type
    
    // First walk over all of the types that have to be removed
    for (typeP = startTP + 1; typeP < endTP; typeP++)
        if (typeP->fStartEntry >= thisEnd)
            break;

    if (typeP >= endTP) {
        c->fRetCode = kR3InternalNotRemangled;
        return false;	// Internal error Can't be a void argument list.
    }

    bcopy(typeP, startTP, (char *) endTP - (char *) typeP);
    
    c->fP.fNumT -= typeP - startTP;
    endTP = &c->fTypeList[c->fP.fNumT];
    for (typeP = startTP ; typeP < endTP; typeP++)
        typeP->fStartEntry -= thisLen;

    // Finally we can retarget the BDictionary lists
    for (i = 0; i < c->fP.fNumB; i++) {
        TypeData *bDP = &c->fBDict[i];
        int start = bDP->fStartEntry;

        if (start < thisStart)
            continue;
        if (start >= thisEnd)
            break;

        bDP->fStartEntry = start - thisLen;
    }

    return true;
}

// <method_type> ::= "M" <class_name> <function_type>
//
// Note this is a very bad function.  Gcc3 doesn't doesn't use pointer that
// is immediately before this entry.  We will have to delete the 'P' declarator
// that is before the method declaration.
// We will also have to prune the first type in the argument list as Gcc3
// doesn't register the 'this' pointer within the function list.
static Boolean parse_method_type(ParseContext *c)
{
    TypeData *bDictP;
    TypeData *typeP;            
    BaseTypeData *bP;

    bDictP = newBDict(c, c->fP.fNumI-2, 0);
    if (!bDictP)
        goto abandonParse;

    // Replace 'P' declarator
    c->fP.fNumI--;
    bP = c->fCurBaseP - 1;

    if (!isNext(c, 'M'))
        goto abandonParse;

    if (bP->fFundTypeID != (void *) (int) 'P')
        goto abandonParse;

    // Replace the previous 'Pointer' declarator
    bP->fType = kNTMethod;
    bP->fFundTypeID = NULL;
    bP->fLen = 0;

    // Grab the method's 'this' type specification
    typeP = newType(c, c->fP.fNumI);
    if (!newIn(c) || !typeP)
        goto abandonParse;

    if (!parse_class_name(c))
        goto abandonParse;
    typeP->fNumEntries = c->fP.fNumI - typeP->fStartEntry;

    // Grab the <function_type> specifier
    typeP = newType(c, c->fP.fNumI);
    if (!newIn(c) || !typeP)
        goto abandonParse;

    if (!parse_function_type(c, /* forMethod */ true))
        goto abandonParse;

    if (!cleanMethodFunction(c, typeP - c->fTypeList))
        goto abandonParse;
    typeP->fNumEntries = c->fP.fNumI - typeP->fStartEntry;

    // Finally update the dictionary with the M & 'this'
    bDictP->fNumEntries = c->fP.fNumI - bDictP->fStartEntry;

    return true;

abandonParse:
    return false;
}

static Boolean emitQualifiers(ParseContext *c)
{
    BaseTypeData *bP = c->fCurBaseP;

    if (bP->fVolatile || bP->fConst) {
        Boolean isConst, isVolatile, isSigned, isUnsigned;
    
        isVolatile = bP->fVolatile;
        isConst = bP->fConst;
        isSigned = bP->fSigned;
        isUnsigned = bP->fUnsigned;
        bP->fConst = bP->fVolatile = bP->fSigned = bP->fUnsigned = 0;
    
        if (isVolatile) {
            bP->fType = kNTDeclarator;
            bP->fFundTypeID = (void *) (int) 'V';
            bP->fLen = 0;
            bP = newIn(c);
            if (!bP)
                return false;
        }
        if (isConst) {
            bP->fType = kNTDeclarator;
            bP->fFundTypeID = (void *) (int) 'K';
            bP->fLen = 0;
            bP = newIn(c);
            if (!bP)
                return false;
        }
        bP->fSigned = isSigned;
        bP->fUnsigned = isUnsigned;
    }

    return true;
}


// <base_type> ::= <function_type>	; function
//               | <method_type>	; method
//               | <type_qualifier>* <fund_type_id>
// <type_qualifier> ::= "S"        ; signed (chars only)
//                    | "U"        ; unsigned (any integral type)
//                    | "J"        ; __complex
//                    | <qualifier>
static Boolean parse_base_type(ParseContext *c)
{
    if ('F' == peekNext(c)) {
        if (!parse_function_type(c, /* forMethod */ false))
            goto abandonParse;
    }
    else if ('M' == peekNext(c)) {
        if (!parse_method_type(c))
            goto abandonParse;
    }
    else {
        //               | <type_qualifier>* <fund_type_id>
        BaseTypeData *bP = c->fCurBaseP;
        for (;;) {
            if (isNext(c, 'S'))
                // <type_qualifier> ::= "S"	; signed (chars only)
                { bP->fSigned = true; continue; }
            else if (isNext(c, 'U'))
                //                    | "U"	; unsigned (any integral type)
                { bP->fUnsigned = true; continue; }
            else if (isNext(c, 'C'))
                //                    | <qualifier>
                // <qualifier> ::= "C"		; const
                { bP->fConst = true; continue; }
            else if (isNext(c, 'V'))
                //               | "V"		; volatile
                { bP->fVolatile = true; continue; }
            else if (charNext(c, "Ju"))
                goto abandonParse;	// Don't support these qualifiers
                //                    | "J"	; __complex
                //               | "u"		; restrict (C99)
            else
                break;
        }

        if (!emitQualifiers(c))
            goto abandonParse;

        if (!parse_fund_type_id(c))
            goto abandonParse;
    }
    return true;

abandonParse:
    return false;
}

// Use the top SDict as a stack of declarators.
// parses <declarator>*
// <declarator> ::= "P"            ; pointer
//                | "p"            ; pointer (but never occurs?)
//                | "R"            ; reference (&)
//                | "A" <count>    ; array
//                | "T" <index>
//                | "O" <count>
//                | <qualifier>
//
// As a side-effect the fCurBaseP is setup with any qualifiers on exit
static Boolean parse_declarators(ParseContext *c)
{
    int count;
    BaseTypeData *dP;

    // Note we MUST go through the for loop at least once
    for (count = 0; ; count++) {
        const char *curDecl;
        char ch;

        if (!newIn(c))
            goto abandonParse;

        // <declarator> ::= <qualifier> production
        if (!parse_qualifiers(c) || !emitQualifiers(c))
            goto abandonParse;

        dP = c->fCurBaseP;	// Find the current base type pointer

        curDecl = c->fP.fInChar;

        switch (peekNext(c)) {

        case 'P': case 'p': case 'R':
            // <declarator> ::= "P"            ; pointer
            //                | "p"            ; pointer (but never occurs?)
            //                | "R"            ; reference (&)

            dP->fType = kNTDeclarator;
            advance(c, 1);

            ch = *curDecl;
            if ('p' == ch) ch = 'P';
            dP->fFundTypeID = (void *) (int) ch;
            dP->fLen = 0;
            continue;	// Go around again

        case 'A':
            //                | "A" <count>    ; array
            dP->fType = kNTArray;

            advance(c, 1); curDecl++;
            curDecl = (void *)
                strtoul(curDecl, (char **) &c->fP.fInChar, 10);
            if (!curDecl)
                goto abandonParse;
            dP->fFundTypeID = curDecl;
            dP->fLen = 0;
            continue;	// Go around again

        case 'T': case 'O':
            //                | "T" <index>	Unsupported
            //                | "O" <count>	Unsupported
            goto abandonParse;

        default:
            break;
        }

        break;
    }

    dP->fLen = 0;
    return true;

abandonParse:
    return false;
}

// <type> ::= <declarator>* <base_type>
static Boolean parse_type(ParseContext *c)
{
    CheckPoint chk = *checkPoint(c);
    TypeData *typeP = newType(c, c->fP.fNumI);
    if (!typeP)
        goto abandonParse;

    // As a side-effect the fCurBaseP is setup with any qualifiers on exit
    if (!parse_declarators(c))
        goto abandonParse;

    // Merge the last qualifiers into the base type
    if (!parse_base_type(c) || kNTUndefined == c->fCurBaseP->fType)
        goto abandonParse;

    typeP->fNumEntries = c->fP.fNumI - typeP->fStartEntry;
    return true;

abandonParse:
    resetTo(c, &chk);
    return false;
}

// <function_name> ::= <char> <char>*
// No need to check point as an invalid function name is fatal
// Consumes trailing "__".
static Boolean
parse_function_name(ParseContext *c)
{
    char ch;

    while ( (ch = peekNext(c)) )
    {
        advance(c, 1);
        if ('_' == ch && '_' == peekNext(c)) {
            do {
                advance(c, 1);
            } while ('_' == peekNext(c));
            return true;
        }
    }

    return false;
}

// <opinfo> ::= "type" <type>
//            | "__op" <type>
//            | <opname> "__"	; Implies null function name
//            | "a"
// <opname> ::= "aa"	# &&	==> "aa"
//            | "aad"	# &=	==> "aN"
//            | "ad"	# &	==> "ad"
//            | "adv"	# /=	==> "dV"
//            | "aer"	# ^=	==> "eO"
//            | "als"	# <<=	==> "lS"
//            | "amd"	# %=	==> "rM"
//            | "ami"	# -=	==> "mI"
//            | "aml"	# *=	==> "mL
//            | "aor"	# |=	==> "oR
//            | "apl"	# +=	==> "pL
//            | "ars"	# >>=	==> "rS
//            | "as"	# =	==> "aS
//            | "cl"	# ()	==> "cl
//            | "cm"	# ,	==> "cm
//            | "cn"	# ?:	==> "qu
//            | "co"	# ~	==> "co
//            | "dl"	# delete ==> "dl
//            | "dv"	# /	==> "dv
//            | "eq"	# ==	==> "eq
//            | "er"	# ^	==> "eo
//            | "ge"	# >=	==> "ge
//            | "gt"	# >	==> "gt
//            | "le"	# <=	==> "le
//            | "ls"	# <<	==> "ls
//            | "lt"	# <	==> "lt
//            | "md"	# %	==> "rm
//            | "mi"	# -	==> "mi
//            | "ml"	# *	==> "ml
//            | "mm"	# --	==> "mm
//            | "mn"	# <?	==> "????????????????
//            | "mx"	# >?	==> "????????????????
//            | "ne"	# !=	==> "ne
//            | "nt"	# !	==> "nt
//            | "nw"	# new	==> "nw
//            | "oo"	# ||	==> "oo"
//            | "or"	# |	==> "or
//            | "pl"	# +	==> "pl
//            | "pp"	# ++	==> "pp
//            | "rf"	# ->	==> "pt
//            | "rm"	# ->*	==> "pm
//            | "rs"	# >>	==> "rs
//            | "sz"	# sizeof ==> "sz
//            | "vc"	# []	==> "ix
//            | "vd"	# delete[] ==> "da
//            | "vn"	# new[]	==> "na
static struct opMap { 
    const char *op295, *op3;
} opMapTable[] = {  
    {"aad", "aN" }, {"adv", "dV" }, {"aer", "eO" }, {"als", "lS" },
    {"amd", "rM" }, {"ami", "mI" }, {"aml", "mL" }, {"aor", "oR" },
    {"apl", "pL" }, {"ars", "rS" }, {"aa",  "aa" }, {"ad",  "ad" },
    {"as",  "aS" }, {"cl",  "cl" }, {"cm",  "cm" }, {"cn",  "qu" },
    {"co",  "co" }, {"dl",  "dl" }, {"dv",  "dv" }, {"eq",  "eq" },
    {"er",  "eo" }, {"ge",  "ge" }, {"gt",  "gt" }, {"le",  "le" },
    {"ls",  "ls" }, {"lt",  "lt" }, {"md",  "rm" }, {"mi",  "mi" },
    {"ml",  "ml" }, {"mm",  "mm" }, {"mn",  NULL }, {"mx",  NULL },
    {"ne",  "ne" }, {"nt",  "nt" }, {"nw",  "nw" }, {"oo",  "oo" },
    {"or",  "or" }, {"pl",  "pl" }, {"pp",  "pp" }, {"rf",  "pt" },
    {"rm",  "pm" }, {"rs",  "rs" }, {"sz",  "sz" }, {"vc",  "ix" },
    {"vd",  "da" }, {"vn",  "na" },
};

static Boolean parse_opinfo(ParseContext *c, const char **opInfoP)
{
    CheckPoint chk = *checkPoint(c);
    const char *op;
    char ch;
    int i;

    if ('a' == (ch = peekNext(c))) {
        goto abandonParse;
    }
    else if (strNext(c, "type")) {
        goto abandonParse;
    }
    else if (retard(c, 4) && strNext(c, "____op")) {
        // @@@ gvdl: check this out it may change
        // <opinfo> ::= "__op" <type>
        goto abandonParse;
    }

    // Failed till now so reset and see if we have an operator
    resetTo(c, &chk);

    // quick check to see if we may have an operator
    if (!strrchr("acdeglmnoprsv", peekNext(c)))
        goto abandonParse;

    op = NULL;
    for (i = 0; i < sizeof(opMapTable)/sizeof(opMapTable[0]); i++) {
        if (strNext(c, opMapTable[i].op295)) {
            op = opMapTable[i].op3;
            break;
        }
    }
    if (!op)
        goto abandonParse;

    if (!strNext(c, "__"))		// Trailing underbars
        goto abandonParse;

    if (opInfoP)
        *opInfoP = op;
    return true;

abandonParse:
    return false;
}

// <signature> ::= <qualifier>* <s_element> <argument_types>
// <s_element> ::= <class_name>
//               | "K" <qualified_name>
//               | "S"
//               | "F" <argument_types> [ "_" <return_type> ] 
// <return_type> ::= <type>
// Treat the prefix's s_element as a full type
static Boolean
parse_signature(ParseContext *c,
                const char *func, int funcLen, const char *op)
{
    BaseTypeData *bP;
    TypeData *tP;

    Boolean isFunction = false;

    if (isNext(c, 'F')) {
        //               | "F" <argument_types> [ "_" <return_type> ] 

        char numbuf[16];	// Bigger than MAX_INT + 4
        int len;
        isFunction = true;
        if (!funcLen)
            goto abandonParse;

        len = snprintf(numbuf, sizeof(numbuf), "__Z%d", funcLen);

        appendNStr(c, numbuf, len);
        appendNStr(c, func, funcLen);
    }
    else if (isNext(c, 'S')) {
        //         | "S"	; Ignored
        goto abandonParse;
    }
    else {
        const char *qual;
        int qualLen;

        // See if we can find a qualified class reference
        tP = newType(c, c->fP.fNumI);
        if (!tP)
            goto abandonParse;
    
        bP = newIn(c);
        if (!bP)
            goto abandonParse;
    
        // Parse any qualifiers, store results in *fCurBaseP
        bP->fPseudo = true;
        if (!parse_qualifiers(c))
            goto abandonParse;
    
        if (!parse_class_name(c))
            goto abandonParse;

        bP = c->fCurBaseP;	// class name may have redifined current
        tP->fNumEntries = c->fP.fNumI - tP->fStartEntry;

        APPENDSTR(c, "__ZN");
        decodeQual(bP, &qualLen, &qual);
        if (qualLen)
            appendNStr(c, qual, qualLen);
        appendNStr(c, bP->fFundTypeID, bP->fLen);

        if (funcLen) {
            char numbuf[16];	// Bigger than MAX_INT + 1
            int len;

            len = snprintf(numbuf, sizeof(numbuf), "%d", funcLen);
            appendNStr(c, numbuf, len);
            appendNStr(c, func, funcLen);
        }
        else if (op)
            appendStr(c, op);
        else {
            // No function & no op means constructor choose one of C1 & C2
            APPENDSTR(c, "C2");
        }
        appendChar(c, 'E');
    }

    if (atEnd(c)) {
        appendChar(c, 'v');	// void argument list
        c->fRetCode = kR3Remangled;
        return true;
    }

    c->fCurBaseP = NULL;
    if (!parse_argument_types(c))
        goto abandonParse;

    if (isFunction) {
        if (isNext(c, '_')) {
            // && !parse_type(c)	@@@ gvdl: Unsupported return
            c->fRetCode = kR3InternalNotRemangled;
            goto abandonParse;
        }
    }

    if (!atEnd(c))
        goto abandonParse;

    // OK we have a complete and successful parse now output the
    // argument list
    return appendArgumentList(c);

abandonParse:
    return false;
}

// <mangled_name> ::= <prefix> [ <signature> ]
// <prefix> ::= [ "_GLOBAL_" [ID] "__" ] <function_name> "__" [ <opinfo> ]
static Boolean parse_mangled_name(ParseContext *c)
{
    CheckPoint chk;
    CheckPoint dubBarChk;
    const char *func;

    // <prefix> parse
    if (strNext(c, "_GLOBAL_")) {	// Is this GLOBAL static constructor?
        // gvdl: can't deal with _GLOBAL_
        c->fRetCode = kR3InternalNotRemangled;
        return false;	// Can't deal with these
    }

    func = c->fP.fInChar;
    for (chk = *checkPoint(c); ; resetTo(c, &dubBarChk)) {
        int funcLen;
        const char *op = NULL;

        if (!parse_function_name(c))
            goto abandonParse;
        dubBarChk = *checkPoint(c);

        // Note that the opInfo may be earlier than the curDoubleBar
        // in which case the function name may need to be shrunk later on.
        (void) parse_opinfo(c, &op);

        if (atEnd(c))
            goto abandonParse;	// No Signature?

        funcLen = inCharFromCheck(c, &dubBarChk) - func - 2;
        if (parse_signature(c, func, funcLen, op))
            return true;

        if (kR3NotRemangled != c->fRetCode)
            goto abandonParse;

        // If no error then try again maybe another '__' exists
    }

abandonParse:
    resetTo(c, &chk);
    return false;
}

// <gnu_special> ::= ("_._" | "_$_" ) <class_name>	; destructor
//                 | "__vt_" <class_name>		; virtual table
//                 | "_" <class_name> ("."|"$") <varname>
static Boolean parse_gnu_special(ParseContext *c)
{
    CheckPoint chk = *checkPoint(c);
    BaseTypeData *bP = newIn(c);

    if (!bP)
        return false;

    // What do the intel desctructors look like
    if (strNext(c, "_._") || strNext(c, "_$_") )	// Is this a destructor
    {
        if (!parse_class_name(c) || !atEnd(c))
            goto abandonParse;
        APPENDSTR(c, "__ZN");
        appendNStr(c, bP->fFundTypeID, bP->fLen);
        APPENDSTR(c, "D2Ev");
        c->fRetCode = kR3Remangled;
        return true;
    }
    else if (strNext(c, "__vt_"))	// Is it's a vtable?
    {
        if (!parse_class_name(c) || !atEnd(c))
            goto abandonParse;

        APPENDSTR(c, "__ZTV");
        if (kNTClass != bP->fType)
            goto abandonParse;
        else if (bP->fQualified) {
            appendChar(c, 'N');
            appendNStr(c, bP->fFundTypeID, bP->fLen);
            appendChar(c, 'E');
        }
        else
            appendNStr(c, bP->fFundTypeID, bP->fLen);

        c->fRetCode = kR3Remangled;
        return true;
    }
    else if (isNext(c, '_'))		// Maybe it's a variable
    {
        const char *varname;
        int varlen, len;
        char numbuf[16];	// Bigger than MAX_INT + 1

        if (!parse_class_name(c))	// Loads up the bP structure
            goto abandonParse;

        if (!isNext(c, '.') && !isNext(c, '$'))
            goto abandonParse;

        // Parse the variable name now.
        varname = c->fP.fInChar;
        if (atEnd(c) || !isValidFirstChar(getNext(c)))
            goto abandonParse;

        while ( !atEnd(c) )
            if (!isValidChar(getNext(c)))
                goto abandonParse;

        varlen = c->fP.fInChar - varname;
        len = snprintf(numbuf, sizeof(numbuf), "%d", varlen);

        APPENDSTR(c, "__ZN");
        appendNStr(c, bP->fFundTypeID, bP->fLen);

        appendNStr(c, numbuf, len);
        appendNStr(c, varname, varlen);
        appendChar(c, 'E');

        c->fRetCode = kR3Remangled;
        return true;
    }

    // Oh well it is none of those so give up but reset scan
abandonParse:
    resetTo(c, &chk);
    return false;
}

// <special_or_name> ::= <gnu_special>
//                     | <mangled_name>
static Boolean parse_special_or_name(ParseContext *c)
{
    Boolean res;

    
    res = (parse_gnu_special(c) || parse_mangled_name(c));
    appendChar(c, '\0');

    return res;
}

Rem3Return rem3_remangle_name(char *gcc3, int *gcc3size, const char *gcc295)
{
    ParseContext *c;
    Rem3Return result;
    int size;

    if (!gcc295 || !gcc3 || !gcc3size)
        return kR3BadArgument;

    size = strlen(gcc295);
    if (size < 2)
        return kR3NotRemangled;	// Not a valid C++ symbol
    else if (*gcc295 != '_')
        return kR3NotRemangled;	// no leading '_', not valid

    c = (ParseContext *) malloc(sizeof(*c));
    if (!c)
        return kR3InternalNotRemangled;
    bzero(c, sizeof(*c));

    c->fInSize = size;
    c->fInStr = gcc295 + 1;	// Strip leading '_'
    c->fP.fInChar = c->fInStr;

    c->fOutStrEnd = gcc3 + *gcc3size;
    c->fOutChar = gcc3;

    c->fRetCode = kR3NotRemangled;
    (void) parse_special_or_name(c);

    result = c->fRetCode;
    if (kR3Remangled == result) {
        if (c->fOutChar > c->fOutStrEnd)
            result = kR3BufferTooSmallRemangled;
        *gcc3size = c->fOutChar - gcc3 - 1;	// Remove nul from len
    }

    free(c);

    return result;
}
