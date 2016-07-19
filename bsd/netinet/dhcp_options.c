/*
 * Copyright (c) 2002-2016 Apple Inc. All rights reserved.
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
 * dhcp_options.c
 * - routines to parse and access dhcp options
 *   and create new dhcp option areas
 * - handles overloaded areas as well as vendor-specific options
 *   that are encoded using the RFC 2132 encoding
 */

/* 
 * Modification History
 *
 * March 15, 2002	Dieter Siegmund (dieter@apple)
 * - imported from bootp project
 */

#include <string.h>
#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <sys/malloc.h>
#include <netinet/dhcp.h>
#include <netinet/dhcp_options.h>

#ifndef TEST_DHCP_OPTIONS
#include <libkern/libkern.h>

#ifdef	DHCP_DEBUG
#define	dprintf(x) printf x;
#else	/* !DHCP_DEBUG */
#define	dprintf(x)
#endif	/* DHCP_DEBUG */

static __inline__ void
my_free(void * ptr)
{
    _FREE(ptr, M_TEMP);
}

static __inline__ void *
my_malloc(int size)
{
    void * data;
    MALLOC(data, void *, size, M_TEMP, M_WAITOK);
    return (data);
}

static __inline__ void *
my_realloc(void * oldptr, int oldsize, int newsize)
{
    void * data;

    MALLOC(data, void *, newsize, M_TEMP, M_WAITOK);
    bcopy(oldptr, data, oldsize);
    my_free(oldptr);
    return (data);
}
#else
/*
 * To build:
 * xcrun -sdk macosx.internal cc -DTEST_DHCP_OPTIONS -o /tmp/dhcp_options dhcp_options.c -I .. 
 */
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#define my_free	free
#define my_malloc malloc
#define my_realloc(ptr, old_size, new_size) realloc(ptr, new_size)
#define	dprintf(x) printf x;
#endif

/*
 * Functions: ptrlist_*
 * Purpose:
 *   A dynamically growable array of pointers.
 */

#define PTRLIST_NUMBER		16

static void
ptrlist_init(ptrlist_t * list)
{
    bzero(list, sizeof(*list));
    return;
}

static void
ptrlist_free(ptrlist_t * list)
{
    if (list->array)
	my_free(list->array);
    ptrlist_init(list);
    return;
}

static int
ptrlist_count(ptrlist_t * list)
{
    if (list == NULL || list->array == NULL)
	return (0);

    return (list->count);
}

static const void *
ptrlist_element(ptrlist_t * list, int i)
{
    if (list->array == NULL)
	return (NULL);
    if (i < list->count)
	return (list->array[i]);
    return (NULL);
}


static boolean_t
ptrlist_grow(ptrlist_t * list)
{
    if (list->array == NULL) {
	if (list->size == 0)
	    list->size = PTRLIST_NUMBER;
	list->count = 0;
	list->array = my_malloc(sizeof(*list->array) * list->size);
    }
    else if (list->size == list->count) {
	dprintf(("doubling %d to %d\n", list->size, list->size * 2));
	list->array = my_realloc(list->array, 
				 sizeof(*list->array) * list->size,
				 sizeof(*list->array) * list->size * 2);
	list->size *= 2;
    }
    if (list->array == NULL)
	return (FALSE);
    return (TRUE);
}

static boolean_t
ptrlist_add(ptrlist_t * list, const void * element)
{
    if (ptrlist_grow(list) == FALSE)
	return (FALSE);

    list->array[list->count++] = element;
    return (TRUE);
}

/* concatenates extra onto list */
static boolean_t
ptrlist_concat(ptrlist_t * list, ptrlist_t * extra)
{
    if (extra->count == 0)
	return (TRUE);

    if ((extra->count + list->count) > list->size) {
	int old_size = list->size;

	list->size = extra->count + list->count;
	if (list->array == NULL)
	    list->array = my_malloc(sizeof(*list->array) * list->size);
	else
	    list->array = my_realloc(list->array, old_size,
				     sizeof(*list->array) * list->size);
    }
    if (list->array == NULL)
	return (FALSE);
    bcopy(extra->array, list->array + list->count, 
	  extra->count * sizeof(*list->array));
    list->count += extra->count;
    return (TRUE);
}


/*
 * Functions: dhcpol_* 
 *
 * Purpose:
 *   Routines to parse/access existing options buffers.
 */
boolean_t
dhcpol_add(dhcpol_t * list, const void * element)
{
    return (ptrlist_add((ptrlist_t *)list, element));
}

int
dhcpol_count(dhcpol_t * list)
{
    return (ptrlist_count((ptrlist_t *)list));
}

const void *
dhcpol_element(dhcpol_t * list, int i)
{
    return (ptrlist_element((ptrlist_t *)list, i));
}

void
dhcpol_init(dhcpol_t * list)
{
    ptrlist_init((ptrlist_t *)list);
}

void
dhcpol_free(dhcpol_t * list)
{
    ptrlist_free((ptrlist_t *)list);
}

boolean_t
dhcpol_concat(dhcpol_t * list, dhcpol_t * extra)
{
    return (ptrlist_concat((ptrlist_t *)list, (ptrlist_t *)extra));
}

/*
 * Function: dhcpol_parse_buffer
 *
 * Purpose:
 *   Parse the given buffer into DHCP options, returning the
 *   list of option pointers in the given dhcpol_t.
 *   Parsing continues until we hit the end of the buffer or
 *   the end tag.
 */
boolean_t
dhcpol_parse_buffer(dhcpol_t * list, const void * buffer, int length)
{
    int			len;
    const uint8_t *	scan;
    uint8_t		tag;

    dhcpol_init(list);

    len = length;
    tag = dhcptag_pad_e;
    for (scan = (const uint8_t *)buffer;
	 tag != dhcptag_end_e && len > DHCP_TAG_OFFSET; ) {

	tag = scan[DHCP_TAG_OFFSET];

	switch (tag) {
	  case dhcptag_end_e:
	      /* remember that it was terminated */
	      dhcpol_add(list, scan);
	      scan++;
	      len--;
	      break;
	  case dhcptag_pad_e: /* ignore pad */
	      scan++;
	      len--;
	      break;
	  default:
	      if (len > DHCP_LEN_OFFSET) {
		  uint8_t	option_len;

		  option_len = scan[DHCP_LEN_OFFSET];
		  dhcpol_add(list, scan);
		  len -= (option_len + DHCP_OPTION_OFFSET);
		  scan += (option_len + DHCP_OPTION_OFFSET);
	      }
	      else {
		  len = -1;
	      }
	      break;
	}
    }
    if (len < 0) {
	/* ran off the end */
	dprintf(("dhcp_options: parse failed near tag %d\n", tag));
	dhcpol_free(list);
	return (FALSE);
    }
    return (TRUE);
}

/*
 * Function: dhcpol_find
 *
 * Purpose:
 *   Finds the first occurence of the given option, and returns its
 *   length and the option data pointer.
 *
 *   The optional start parameter allows this function to 
 *   return the next start point so that successive
 *   calls will retrieve the next occurence of the option.
 *   Before the first call, *start should be set to 0.
 */
const void *
dhcpol_find(dhcpol_t * list, int tag, int * len_p, int * start)
{
    int 	i = 0;

    if (tag == dhcptag_end_e || tag == dhcptag_pad_e)
	return (NULL);

    if (start)
	i = *start;

    for (; i < dhcpol_count(list); i++) {
	const uint8_t * 	option = dhcpol_element(list, i);
	
	if (option[DHCP_TAG_OFFSET] == tag) {
	    if (len_p)
		*len_p = option[DHCP_LEN_OFFSET];
	    if (start)
		*start = i + 1;
	    return (option + DHCP_OPTION_OFFSET);
	}
    }
    return (NULL);
}

/*
 * Function: dhcpol_parse_packet
 *
 * Purpose:
 *    Parse the option areas in the DHCP packet.
 *    Verifies that the packet has the right magic number,
 *    then parses and accumulates the option areas.
 *    First the pkt->dp_options is parsed.  If that contains
 *    the overload option, it parses pkt->dp_file if specified,
 *    then parses pkt->dp_sname if specified.
 */
boolean_t
dhcpol_parse_packet(dhcpol_t * options, const struct dhcp * pkt, int len)
{
    char		rfc_magic[4] = RFC_OPTIONS_MAGIC;

    dhcpol_init(options);	/* make sure it's empty */

    if (len < (sizeof(*pkt) + RFC_MAGIC_SIZE)) {
	dprintf(("dhcp_options: packet is too short: %d < %d\n",
		 len, (int)sizeof(*pkt) + RFC_MAGIC_SIZE));
	return (FALSE);
    }
    if (bcmp(pkt->dp_options, rfc_magic, RFC_MAGIC_SIZE)) {
	dprintf(("dhcp_options: missing magic number\n"));
	return (FALSE);
    }
    if (dhcpol_parse_buffer(options, pkt->dp_options + RFC_MAGIC_SIZE,
			    len - sizeof(*pkt) - RFC_MAGIC_SIZE) == FALSE)
	return (FALSE);
    { /* get overloaded options */
	const uint8_t *	overload;
	int		overload_len;

	overload = dhcpol_find(options, dhcptag_option_overload_e, 
			       &overload_len, NULL);
	if (overload && overload_len == 1) { /* has overloaded options */
	    dhcpol_t	extra;
	    
	    dhcpol_init(&extra);
	    if (*overload == DHCP_OVERLOAD_FILE
		|| *overload == DHCP_OVERLOAD_BOTH) {
		if (dhcpol_parse_buffer(&extra, pkt->dp_file, 
					sizeof(pkt->dp_file))) {
		    dhcpol_concat(options, &extra);
		    dhcpol_free(&extra);
		}
	    }
	    if (*overload == DHCP_OVERLOAD_SNAME
		|| *overload == DHCP_OVERLOAD_BOTH) {
		if (dhcpol_parse_buffer(&extra, pkt->dp_sname, 
					sizeof(pkt->dp_sname))) {
		    dhcpol_concat(options, &extra);
		    dhcpol_free(&extra);
		}
	    }
	}
    }
    return (TRUE);
}

#ifdef TEST_DHCP_OPTIONS
char test_empty[] = {
    99, 130, 83, 99,
    255,
};

char test_short[] = {
    99, 130, 83, 99,
    1,
};

char test_simple[] = {
    99, 130, 83, 99,
    1, 4, 255, 255, 252, 0,
    3, 4, 17, 202, 40, 1,
    255,
};

char test_vendor[] = {
    99, 130, 83, 99,
    1, 4, 255, 255, 252, 0,
    3, 4, 17, 202, 40, 1,
    43, 6, 1, 4, 1, 2, 3, 4,
    43, 6, 1, 4, 1, 2, 3, 4,
    255,
};

char test_no_end[] = {
    0x63, 0x82, 0x53, 0x63, 0x35, 0x01, 0x05, 0x36, 
    0x04, 0xc0, 0xa8, 0x01, 0x01, 0x33, 0x04, 0x80,
    0x00, 0x80, 0x00, 0x01, 0x04, 0xff, 0xff, 0xff,
    0x00, 0x03, 0x04, 0xc0, 0xa8, 0x01, 0x01, 0x06,
    0x0c, 0x18, 0x1a, 0xa3, 0x21, 0x18, 0x1a, 0xa3,
    0x20, 0x18, 0x5e, 0xa3, 0x21, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

char test_no_magic[] = {
    0x1 
};
struct test {
    char * 		name;
    char *		data;
    int			len;
    boolean_t		result;
};

struct test tests[] = {
    { "empty", test_empty, sizeof(test_empty), TRUE },
    { "simple", test_simple, sizeof(test_simple), TRUE },
    { "vendor", test_vendor, sizeof(test_vendor), TRUE },
    { "no_end", test_no_end, sizeof(test_no_end), TRUE },
    { "no magic", test_no_magic, sizeof(test_no_magic), FALSE },
    { "short", test_short, sizeof(test_short), FALSE },
    { NULL, NULL, 0, FALSE },
};


static char buf[2048];

int
main()
{
    int 	i;
    dhcpol_t 	options;
    struct dhcp * pkt = (struct dhcp *)buf;

    dhcpol_init(&options);

    for (i = 0; tests[i].name; i++) {
	printf("\nTest %d: ", i);
	bcopy(tests[i].data, pkt->dp_options, tests[i].len);
	if (dhcpol_parse_packet(&options, pkt, 
				sizeof(*pkt) + tests[i].len)
	    != tests[i].result) {
	    printf("test '%s' FAILED\n", tests[i].name);
	}
	else {
	    printf("test '%s' PASSED\n", tests[i].name);
	}
	dhcpol_free(&options);
    }
    exit(0);
}
#endif /* TEST_DHCP_OPTIONS */
