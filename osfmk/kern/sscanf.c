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
/*
 * @OSF_FREE_COPYRIGHT@
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:32  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:56  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.8.2  1997/02/12  12:52:33  stephen
 * 	New file, reimplemented to be sure of copyright status
 * 	Initially only supports character matching and '%d'
 * 	[1997/02/12  12:43:09  stephen]
 *
 * $EndLog$
 */

#include <stdarg.h>
#include <kern/misc_protos.h>

#define isdigit(c) ((unsigned) ((c) - '0') < 10U)

/*
 * Scan items from a string in accordance with a format.  This is much
 * simpler than the C standard function: it only recognises %d without a
 * field width, and does not treat space in the format string or the
 * input any differently from other characters.  The return value is the
 * number of characters from the input string that were successfully
 * scanned, not the number of format items matched as in standard sscanf.
 * e.mcmanus@opengroup.org, 12 Feb 97
 */
int
sscanf(const char *str, const char *format, ...)
{
	const char *start = str;
	va_list args;
	
	va_start(args, format);
	for ( ; *format != '\0'; format++) {
		if (*format == '%' && format[1] == 'd') {
			int positive;
			int value;
			int *valp;
			
			if (*str == '-') {
				positive = 0;
				str++;
			} else
				positive = 1;
			if (!isdigit(*str))
				break;
			value = 0;
			do {
				value = (value * 10) - (*str - '0');
				str++;
			} while (isdigit(*str));
			if (positive)
				value = -value;
			valp = va_arg(args, int *);
			*valp = value;
			format++;
		} else if (*format == *str) {
			str++;
		} else
			break;
	}
	va_end(args);
	return str - start;
}
