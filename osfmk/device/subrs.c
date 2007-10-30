/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
 *(C)UNIX System Laboratories, Inc. all or some portions of this file are
 *derived from material licensed to the University of California by
 *American Telephone and Telegraph Co. or UNIX System Laboratories,
 *Inc. and are reproduced herein with the permission of UNIX System
 *Laboratories, Inc.
 */

/* 
 * Mach Operating System
 * Copyright (c) 1993,1991,1990,1989,1988 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */
/*
 * Copyright (c) 1988 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * NOTICE: This file was modified by McAfee Research in 2004 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */
/*
 * Random device subroutines and stubs.
 */

#include <vm/vm_kern.h>
#include <kern/misc_protos.h>
#include <libsa/stdlib.h>
#include <sys/malloc.h>

/* String routines, from CMU */
#ifdef	strcpy
#undef strcmp
#undef strncmp
#undef strcpy
#undef strncpy
#undef strlen
#endif

/*
 * Abstract:
 *      strcmp (s1, s2) compares the strings "s1" and "s2".
 *      It returns 0 if the strings are identical. It returns
 *      > 0 if the first character that differs in the two strings
 *      is larger in s1 than in s2 or if s1 is longer than s2 and
 *      the contents are identical up to the length of s2.
 *      It returns < 0 if the first differing character is smaller
 *      in s1 than in s2 or if s1 is shorter than s2 and the
 *      contents are identical upto the length of s1.
 * Deprecation Warning:
 *	strcmp() is being deprecated. Please use strncmp() instead.
 */

int
strcmp(
        const char *s1,
        const char *s2)
{
        unsigned int a, b;

        do {
                a = *s1++;
                b = *s2++;
                if (a != b)
                        return a-b;     /* includes case when
                                           'a' is zero and 'b' is not zero
                                           or vice versa */
	} while (a != '\0');

        return 0;       /* both are zero */
}

/*
 * Abstract:
 *      strncmp (s1, s2, n) compares the strings "s1" and "s2"
 *      in exactly the same way as strcmp does.  Except the
 *      comparison runs for at most "n" characters.
 */

int
strncmp(
        const char *s1,
        const char *s2,
        size_t n)
{
        unsigned int a, b;

        while (n != 0) {
                a = *s1++;
                b = *s2++;
                if (a != b)
                        return a-b;     /* includes case when
                                           'a' is zero and 'b' is not zero
                                           or vice versa */
                if (a == '\0')
                        return 0;       /* both are zero */
                n--;
	}

        return 0;
}


//
// Lame implementation just for use by strcasecmp/strncasecmp
//
static int
tolower(unsigned char ch)
{
    if (ch >= 'A' && ch <= 'Z')
	ch = 'a' + (ch - 'A');

    return ch;
}

int
strcasecmp(const char *s1, const char *s2)
{
    const unsigned char *us1 = (const u_char *)s1,
                 *us2 = (const u_char *)s2;

    while (tolower(*us1) == tolower(*us2++))
	if (*us1++ == '\0')
	    return (0);
    return (tolower(*us1) - tolower(*--us2));
}

int
strncasecmp(const char *s1, const char *s2, size_t n)
{
    if (n != 0) {
	const unsigned char *us1 = (const u_char *)s1,
                     *us2 = (const u_char *)s2;

	do {
	    if (tolower(*us1) != tolower(*us2++))
		return (tolower(*us1) - tolower(*--us2));
	    if (*us1++ == '\0')
		break;
	} while (--n != 0);
    }
    return (0);
}


/*
 * Abstract:
 *      strcpy copies the contents of the string "from" including
 *      the null terminator to the string "to". A pointer to "to"
 *      is returned.
 * Deprecation Warning: 
 *	strcpy() is being deprecated. Please use strlcpy() instead.
 */

char *
strcpy(
        char *to,
        const char *from)
{
        char *ret = to;

        while ((*to++ = *from++) != '\0')
                continue;

        return ret;
}


/*
 * Abstract:
 *      strncpy copies "count" characters from the "from" string to
 *      the "to" string. If "from" contains less than "count" characters
 *      "to" will be padded with null characters until exactly "count"
 *      characters have been written. The return value is a pointer
 *      to the "to" string.
 */

char *
strncpy(
	char *s1, 
	const char *s2,
	size_t n)
{
        char *os1 = s1;
        unsigned long i;

        for (i = 0; i < n;)
                if ((*s1++ = *s2++) == '\0')
                        for (i++; i < n; i++)
                                *s1++ = '\0';
                else
                        i++;
        return (os1);
}

/*
 * atoi:
 *
 *      This function converts an ascii string into an integer.
 *
 * input        : string
 * output       : a number
 */

int
atoi(const char *cp)
{
        int     number;

        for (number = 0; ('0' <= *cp) && (*cp <= '9'); cp++)
                number = (number * 10) + (*cp - '0');

        return( number );
}

/*
 * convert an ASCII string (decimal radix) to an integer
 * inputs:
 *	p	string pointer.
 *	t	char **, return a pointer to the cahr which terminates the
 *		numeric string.
 * returns:
 *	integer value of the numeric string.
 * side effect:
 *	pointer to terminating char.
 */

int
atoi_term(
	char	*p,	/* IN */
	char	**t)	/* OUT */
{
        int n;
        int f;

        n = 0;
        f = 0;
        for(;;p++) {
                switch(*p) {
                case ' ':
                case '\t':
                        continue;
                case '-':
                        f++;
                case '+':
                        p++;
                }
                break;
        }
        while(*p >= '0' && *p <= '9')
                n = n*10 + *p++ - '0';

        /* return pointer to terminating character */
        if ( t )
                *t = p;

        return(f? -n: n);
}

/*
 * Does the same thing as strlen, except only looks up
 * to max chars inside the buffer. 
 * Taken from archive/kern-stuff/sbf_machine.c in 
 * seatbelt. 
 * inputs:
 * 	s	string whose length is to be measured
 *	max	maximum length of string to search for null
 * outputs:
 *	length of s or max; whichever is smaller
 */
size_t 
strnlen(const char *s, size_t max) {
	const char *es = s + max, *p = s;
	while(*p && p != es) 
		p++;

	return p - s;
}

/*
 * convert an integer to an ASCII string.
 * inputs:
 *	num	integer to be converted
 *	str	string pointer.
 *
 * outputs:
 *	pointer to string start.
 */

char *
itoa(
	int	num,
	char	*str)
{
        char    digits[11];
        char *dp;
        char *cp = str;

        if (num == 0) {
            *cp++ = '0';
        }
        else {
            dp = digits;
            while (num) {
                *dp++ = '0' + num % 10;
                num /= 10;
            }
            while (dp != digits) {
                *cp++ = *--dp;
            }
        }
        *cp++ = '\0';

	return str;
}

/* 
 * Deprecation Warning:
 *	strcat() is being deprecated. Please use strlcat() instead.
 */
char *
strcat(
	char *dest,
	const char *src)
{
	char *old = dest;

	while (*dest)
		++dest;
	while ((*dest++ = *src++))
		;
	return (old);
}

/*
 * Appends src to string dst of size siz (unlike strncat, siz is the
 * full size of dst, not space left).  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz <= strlen(dst)).
 * Returns strlen(src) + MIN(siz, strlen(initial dst)).
 * If retval >= siz, truncation occurred.
 */
size_t
strlcat(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;
	size_t dlen;

	/* Find the end of dst and adjust bytes left but don't go past end */
	while (n-- != 0 && *d != '\0')
		d++;
	dlen = d - dst;
	n = siz - dlen;

	if (n == 0)
		return(dlen + strlen(s));
	while (*s != '\0') {
		if (n != 1) {
			*d++ = *s;
			n--;
		}
		s++;
	}
	*d = '\0';

	return(dlen + (s - src));       /* count does not include NUL */
}

/*
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
size_t
strlcpy(char *dst, const char *src, size_t siz)
{
	char *d = dst;
	const char *s = src;
	size_t n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0 && --n != 0) {
		do {
			if ((*d++ = *s++) == 0)
				break;
		} while (--n != 0);
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (siz != 0)
			*d = '\0';		/* NUL-terminate dst */
		while (*s++)
			;
	}

	return(s - src - 1);	/* count does not include NUL */
}

/*
 * STRDUP
 *
 * Description: The STRDUP function allocates sufficient memory for a copy
 *              of the string "string", does the copy, and returns a pointer
 *              it. The pointer may subsequently be used as an argument to
 *              the macro FREE().
 *
 * Parameters:  string		String to be duplicated
 *              type		type of memory to be allocated (normally
 *              		M_TEMP)
 *
 * Returns:     char *          A pointer to the newly allocated string with
 *                              duplicated contents in it.
 *
 *              NULL		If MALLOC() fails.
 *
 * Note:        This function can *not* be called from interrupt context as
 *              it calls MALLOC with M_WAITOK.  In fact, you really
 *              shouldn't be doing string manipulation in interrupt context
 *              ever.
 *
 *              This function name violates the kernel style(9) guide
 *              by being all caps.  This was done on purpose to emphasize
 *              one should use FREE() with the allocated buffer.
 *
 */
inline char *
STRDUP(const char *string, int type)
{
	size_t len;
	char *copy;   

	len = strlen(string) + 1;
	MALLOC(copy, char *, len, type, M_WAITOK);
	if (copy == NULL)
		return (NULL);
	bcopy(string, copy, len);
	return (copy); 
}

/*
 * Return TRUE(1) if string 2 is a prefix of string 1.
 */     
int       
strprefix(register const char *s1, register const char *s2)
{               
        register int    c;
                
        while ((c = *s2++) != '\0') {
            if (c != *s1++) 
                return (0);
        }       
        return (1);
}

