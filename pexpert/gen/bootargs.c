/*
 * Copyright (c) 2000-2008 Apple Inc. All rights reserved.
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
#include <pexpert/pexpert.h>
#include <pexpert/device_tree.h>

static boolean_t isargsep( char c);
#if !CONFIG_EMBEDDED
static int argstrcpy(char *from, char *to);
#endif
static int argstrcpy2(char *from,char *to, unsigned maxlen);
static int argnumcpy(int val, void *to, unsigned maxlen);
static int getval(char *s, int *val);

extern int IODTGetDefault(const char *key, void *infoAddr, unsigned int infoSize);


struct i24 {
	int32_t	i24 : 24;
	int32_t _pad : 8;
};

#define	NUM	0
#define	STR	1

#if !defined(__LP64__) && !defined(__arm__)
boolean_t 
PE_parse_boot_arg(
	const char  *arg_string,
	void		*arg_ptr)
{
	int max_len = -1;

#if CONFIG_EMBEDDED
	/* Limit arg size to 4 byte when no size is given */
	max_len = 4;
#endif

	return PE_parse_boot_argn(arg_string, arg_ptr, max_len);
}
#endif

boolean_t
PE_parse_boot_argn(
	const char	*arg_string,
	void		*arg_ptr,
	int			max_len)
{
	char *args;
	char *cp, c;
	uintptr_t i;
	int val;
	boolean_t arg_boolean;
	boolean_t arg_found;

	args = PE_boot_args();
	if (*args == '\0') return FALSE;

#if CONFIG_EMBEDDED
	if (max_len == -1) return FALSE;
#endif

	arg_found = FALSE;

	while(*args && isargsep(*args)) args++;

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
			argnumcpy(1, arg_ptr, max_len);
			arg_found = TRUE;
			break;
		} else {
			while (*cp && isargsep (*cp))
				cp++;
			if (*cp == '=' && c != '=') {
				args = cp+1;
				goto gotit;
			}
			if ('_' == *arg_string) /* Force a string copy if the argument name begins with an underscore */
			{
				int hacklen = 17 > max_len ? 17 : max_len;
				argstrcpy2 (++cp, (char *)arg_ptr, hacklen - 1); /* Hack - terminate after 16 characters */
				arg_found = TRUE;
				break;
			}
			switch (getval(cp, &val)) 
			{
				case NUM:
					argnumcpy(val, arg_ptr, max_len);
					arg_found = TRUE;
					break;
				case STR:
					if(max_len > 0) //max_len of 0 performs no copy at all
						argstrcpy2(++cp, (char *)arg_ptr, max_len - 1);
#if !CONFIG_EMBEDDED
					else if(max_len == -1) // unreachable on embedded
						argstrcpy(++cp, (char *)arg_ptr);
#endif
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

static boolean_t
isargsep(
	char c)
{
	if (c == ' ' || c == '\0' || c == '\t')
		return(TRUE);
	else
		return(FALSE);
}

#if !CONFIG_EMBEDDED
static int
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
#endif

static int
argstrcpy2(
	char *from, 
	char *to,
	unsigned maxlen)
{
	unsigned int i = 0;

	while (!isargsep(*from) && i < maxlen) {
		i++;
		*to++ = *from++;
	}
	*to = 0;
	return(i);
}

static int argnumcpy(int val, void *to, unsigned maxlen)
{
	switch (maxlen) {
		case 0:
			/* No write-back, caller just wants to know if arg was found */
			break;
		case 1:
			*(int8_t *)to = val;
			break;
		case 2:
			*(int16_t *)to = val;
			break;
		case 3:
			/* Unlikely in practice */
			((struct i24 *)to)->i24 = val;
			break;
		case 4:
		default:
			*(int32_t *)to = val;
			maxlen = 4;
			break;
	}

	return (int)maxlen;
}

static int
getval(
	char *s, 
	int *val)
{
	unsigned int radix, intval;
    unsigned char c;
	int sign = 1;

	if (*s == '=') {
		s++;
		if (*s == '-')
			sign = -1, s++;
		intval = *s++-'0';
		radix = 10;
		if (intval == 0) {
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
                } else if (intval >= radix) {
                    return (STR);
                }
		for(;;) {
                        c = *s++;
                        if (isargsep(c))
                            break;
                        if ((radix <= 10) &&
                            ((c >= '0') && (c <= ('9' - (10 - radix))))) {
                                c -= '0';
                        } else if ((radix == 16) &&
                                   ((c >= '0') && (c <= '9'))) {
				c -= '0';
                        } else if ((radix == 16) &&
                                   ((c >= 'a') && (c <= 'f'))) {
				c -= 'a' - 10;
                        } else if ((radix == 16) &&
                                   ((c >= 'A') && (c <= 'F'))) {
				c -= 'A' - 10;
                        } else if (c == 'k' || c == 'K') {
				sign *= 1024;
				break;
			} else if (c == 'm' || c == 'M') {
				sign *= 1024 * 1024;
                                break;
			} else if (c == 'g' || c == 'G') {
				sign *= 1024 * 1024 * 1024;
                                break;
			} else {
				return (STR);
                        }
			if (c >= radix)
				return (STR);
			intval *= radix;
			intval += c;
		}
                if (!isargsep(c) && !isargsep(*s))
                    return STR;
		*val = intval * sign;
		return (NUM);
	}
	*val = 1;
	return (NUM);
}

boolean_t 
PE_imgsrc_mount_supported()
{
	return TRUE;
}

boolean_t
PE_get_default(
	const char	*property_name,
	void		*property_ptr,
	unsigned int max_property)
{
	DTEntry		dte;
	void		**property_data;
	unsigned int property_size;

	/*
	 * Look for the property using the PE DT support.
	 */
	if (kSuccess == DTLookupEntry(NULL, "/defaults", &dte)) {

		/*
		 * We have a /defaults node, look for the named property.
		 */
		if (kSuccess != DTGetProperty(dte, property_name, (void **)&property_data, &property_size))
			return FALSE;

		/*
		 * This would be a fine place to do smart argument size management for 32/64
		 * translation, but for now we'll insist that callers know how big their
		 * default values are.
		 */
		if (property_size > max_property)
			return FALSE;

		/*
		 * Copy back the precisely-sized result.
		 */
		memcpy(property_ptr, property_data, property_size);
		return TRUE;
	}

	/*
	 * Look for the property using I/O Kit's DT support.
	 */
	return IODTGetDefault(property_name, property_ptr, max_property) ? FALSE : TRUE;
}
