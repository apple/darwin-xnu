/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
#include <pexpert/pexpert.h>

extern boolean_t isargsep( char c);
extern int argstrcpy(char *from, char *to);
extern int getval(char *s, int *val);

#define	NUM	0
#define	STR	1

boolean_t 
PE_parse_boot_arg(
	const char  *arg_string,
	void		*arg_ptr)
{
	return PE_parse_boot_argn(arg_string, arg_ptr, -1);
}

boolean_t
PE_parse_boot_argn(
	const char	*arg_string,
	void		*arg_ptr,
	int			max_len)
{
	char *args;
	char *cp, c;
	int i;
	int val;
	boolean_t arg_boolean;
	boolean_t arg_found;

	args = PE_boot_args();
	if (*args == '\0') return FALSE;

	arg_found = FALSE;

	while(isargsep(*args)) args++;

	while (*args)
	{
		if (*args == '-') 
			arg_boolean = TRUE;
		else
			arg_boolean = FALSE;

		cp = args;
		while (!isargsep (*cp) && *cp != '=')
			cp++;
		if (*cp != '=' && !arg_boolean)
			goto gotit;

		c = *cp;

		i = cp-args;
		if (strncmp(args, arg_string, i) ||
		    (i!=strlen(arg_string)))
			goto gotit;
		if (arg_boolean) {
			*(unsigned int *)arg_ptr = TRUE;
			arg_found = TRUE;
			break;
		} else {
			while (isargsep (*cp))
				cp++;
			if (*cp == '=' && c != '=') {
				args = cp+1;
				goto gotit;
			}
			if ('_' == *arg_string) /* Force a string copy if the argument name begins with an underscore */
			{
				int hacklen = 16 > max_len ? 16 : max_len;
				argstrcpy2 (++cp, (char *)arg_ptr, hacklen); /* Hack - terminate after 16 characters */
				arg_found = TRUE;
				break;
			}
			switch (getval(cp, &val)) 
			{
				case NUM:
					*(unsigned int *)arg_ptr = val;
					arg_found = TRUE;
					break;
				case STR:
					if(max_len > 0) //max_len of 0 performs no copy at all
						argstrcpy2(++cp, (char *)arg_ptr, max_len);
					else if(max_len == -1)
						argstrcpy(++cp, (char *)arg_ptr);
					arg_found = TRUE;
					break;
			}
			goto gotit;
		}
gotit:
		/* Skip over current arg */
		while(!isargsep(*args)) args++;

		/* Skip leading white space (catch end of args) */
		while(*args && isargsep(*args)) args++;
	}

	return(arg_found);
}

boolean_t isargsep(
	char c)
{
	if (c == ' ' || c == '\0' || c == '\t')
		return(TRUE);
	else
		return(FALSE);
}

int
argstrcpy(
	char *from, 
	char *to)
{
	int i = 0;

	while (!isargsep(*from)) {
		i++;
		*to++ = *from++;
	}
	*to = 0;
	return(i);
}

int
argstrcpy2(
	char *from, 
	char *to,
	unsigned maxlen)
{
	int i = 0;

	while (!isargsep(*from) && i < maxlen) {
		i++;
		*to++ = *from++;
	}
	*to = 0;
	return(i);
}

int
getval(
	char *s, 
	int *val)
{
	register unsigned radix, intval;
	register unsigned char c;
	int sign = 1;

	if (*s == '=') {
		s++;
		if (*s == '-')
			sign = -1, s++;
		intval = *s++-'0';
		radix = 10;
		if (intval == 0)
			switch(*s) {

			case 'x':
				radix = 16;
				s++;
				break;

			case 'b':
				radix = 2;
				s++;
				break;

			case '0': case '1': case '2': case '3':
			case '4': case '5': case '6': case '7':
				intval = *s-'0';
				s++;
				radix = 8;
				break;

			default:
				if (!isargsep(*s))
					return (STR);
			}
		for(;;) {
			if (((c = *s++) >= '0') && (c <= '9'))
				c -= '0';
			else if ((c >= 'a') && (c <= 'f'))
				c -= 'a' - 10;
			else if ((c >= 'A') && (c <= 'F'))
				c -= 'A' - 10;
			else if (c == 'k' || c == 'K')
				{ sign *= 1024; break; }
			else if (c == 'm' || c == 'M')
				{ sign *= 1024 * 1024; break; }
			else if (c == 'g' || c == 'G')
				{ sign *= 1024 * 1024 * 1024; break; }
			else if (isargsep(c))
				break;
			else
				return (STR);
			if (c >= radix)
				return (STR);
			intval *= radix;
			intval += c;
		}
		*val = intval * sign;
		return (NUM);
	}
	*val = 1;
	return (NUM);
}
