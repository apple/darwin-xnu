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

#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <sys/malloc.h>

#include <netinet/dhcp.h>
#include <netinet/dhcp_options.h>

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

static void *
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
#ifdef DEBUG
	printf("doubling %d to %d\n", list->size, list->size * 2);
#endif DEBUG
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
ptrlist_add(ptrlist_t * list, void * element)
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
dhcpol_add(dhcpol_t * list, void * element)
{
    return (ptrlist_add((ptrlist_t *)list, element));
}

int
dhcpol_count(dhcpol_t * list)
{
    return (ptrlist_count((ptrlist_t *)list));
}

void *
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
dhcpol_parse_buffer(dhcpol_t * list, void * buffer, int length,
		    unsigned char * err)
{
    int			len;
    unsigned char *	scan;
    unsigned char	tag;

    if (err)
	err[0] = '\0';

    dhcpol_init(list);

    len = length;
    tag = dhcptag_pad_e;
    for (scan = (unsigned char *)buffer; tag != dhcptag_end_e && len > 0; ) {

	tag = scan[DHCP_TAG_OFFSET];

	switch (tag) {
	  case dhcptag_end_e:
	      dhcpol_add(list, scan); /* remember that it was terminated */
	      scan++;
	      len--;
	      break;
	  case dhcptag_pad_e: /* ignore pad */
	      scan++;
	      len--;
	      break;
	  default: {
	      unsigned char	option_len = scan[DHCP_LEN_OFFSET];
	    
	      dhcpol_add(list, scan);
	      len -= (option_len + 2);
	      scan += (option_len + 2);
	      break;
	  }
	}
    }
    if (len < 0) {
	/* ran off the end */
	if (err)
	    sprintf(err, "parse failed near tag %d", tag);
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
void *
dhcpol_find(dhcpol_t * list, int tag, int * len_p, int * start)
{
    int 	i = 0;

    if (tag == dhcptag_end_e || tag == dhcptag_pad_e)
	return (NULL);

    if (start)
	i = *start;

    for (; i < dhcpol_count(list); i++) {
	unsigned char * option = dhcpol_element(list, i);
	
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
 * Function: dhcpol_get
 * 
 * Purpose:
 *   Accumulate all occurences of the given option into a
 *   malloc'd buffer, and return its length.  Used to get
 *   all occurrences of a particular option in a single
 *   data area.
 * Note:
 *   Use _FREE(val, M_TEMP) to free the returned data area.
 */
void *
dhcpol_get(dhcpol_t * list, int tag, int * len_p)
{
    int 	i;
    char *	data = NULL;
    int		data_len = 0;

    if (tag == dhcptag_end_e || tag == dhcptag_pad_e)
	return (NULL);

    for (i = 0; i < dhcpol_count(list); i++) {
	unsigned char * option = dhcpol_element(list, i);
	
	if (option[DHCP_TAG_OFFSET] == tag) {
	    int len = option[DHCP_LEN_OFFSET];

	    if (data_len == 0) {
		data = my_malloc(len);
	    }
	    else {
		data = my_realloc(data, data_len, data_len + len);
	    }
	    bcopy(option + DHCP_OPTION_OFFSET, data + data_len, len);
	    data_len += len;
	}
    }
    *len_p = data_len;
    return (data);
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
dhcpol_parse_packet(dhcpol_t * options, struct dhcp * pkt, int len,
		    unsigned char * err)
{
    char		rfc_magic[4] = RFC_OPTIONS_MAGIC;

    dhcpol_init(options);	/* make sure it's empty */

    if (err)
	err[0] = '\0';

    if (len < (sizeof(*pkt) + RFC_MAGIC_SIZE)) {
	if (err) {
	    sprintf(err, "packet is too short: %d < %d",
		    len, (int)sizeof(*pkt) + RFC_MAGIC_SIZE);
	}
	return (FALSE);
    }
    if (bcmp(pkt->dp_options, rfc_magic, RFC_MAGIC_SIZE)) {
	if (err)
	    sprintf(err, "missing magic number");
	return (FALSE);
    }
    if (dhcpol_parse_buffer(options, pkt->dp_options + RFC_MAGIC_SIZE,
			    len - sizeof(*pkt) - RFC_MAGIC_SIZE, err) == FALSE)
	return (FALSE);
    { /* get overloaded options */
	unsigned char *	overload;
	int		overload_len;

	overload = (unsigned char *)
	    dhcpol_find(options, dhcptag_option_overload_e, 
				&overload_len, NULL);
	if (overload && overload_len == 1) { /* has overloaded options */
	    dhcpol_t	extra;

	    dhcpol_init(&extra);
	    if (*overload == DHCP_OVERLOAD_FILE
		|| *overload == DHCP_OVERLOAD_BOTH) {
		if (dhcpol_parse_buffer(&extra, pkt->dp_file, 
					 sizeof(pkt->dp_file), NULL)) {
		    dhcpol_concat(options, &extra);
		    dhcpol_free(&extra);
		}
	    }
	    if (*overload == DHCP_OVERLOAD_SNAME
		|| *overload == DHCP_OVERLOAD_BOTH) {
		if (dhcpol_parse_buffer(&extra, pkt->dp_sname, 
					 sizeof(pkt->dp_sname), NULL)) {
		    dhcpol_concat(options, &extra);
		    dhcpol_free(&extra);
		}
	    }
	}
    }
    return (TRUE);
}

/*
 * Function: dhcpol_parse_vendor
 *
 * Purpose:
 *   Given a set of options, find the vendor specific option(s)
 *   and parse all of them into a single option list.
 *  
 * Return value:
 *   TRUE if vendor specific options existed and were parsed succesfully,
 *   FALSE otherwise.
 */
boolean_t
dhcpol_parse_vendor(dhcpol_t * vendor, dhcpol_t * options,
		    unsigned char * err)
{
    dhcpol_t		extra;
    boolean_t		ret = FALSE;
    int 		start = 0;

    if (err)
	err[0] = '\0';

    dhcpol_init(vendor);
    dhcpol_init(&extra);

    for (;;) {
	void *		data;
	int		len;

	data = dhcpol_find(options, dhcptag_vendor_specific_e, &len, &start);
	if (data == NULL) {
	    break; /* out of for */
	}

	if (dhcpol_parse_buffer(&extra, data, len, err) == FALSE) {
	    goto failed;
	}

	if (dhcpol_concat(vendor, &extra) == FALSE) {
	    if (err)
		sprintf(err, "dhcpol_concat() failed at %d\n", start);
	    goto failed;
	}
	dhcpol_free(&extra);
	ret = TRUE;
    }
    if (ret == FALSE) {
	if (err)
	    strcpy(err, "missing vendor specific options");
    }
    return (ret);

 failed:
    dhcpol_free(vendor);
    dhcpol_free(&extra);
    return (FALSE);
}

#ifdef TEST_DHCP_OPTIONS
char test_empty[] = {
    99, 130, 83, 99,
    255,
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

char test_too_short[] = {
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
    { "too_short", test_too_short, sizeof(test_too_short), FALSE },
    { NULL, NULL, 0, FALSE },
};


static char buf[2048];

int
main()
{
    int 	i;
    dhcpol_t 	options;
    char	error[256];
    struct dhcp * pkt = (struct dhcp *)buf;

    dhcpol_init(&options);

    for (i = 0; tests[i].name; i++) {
	printf("\nTest %d: ", i);
	bcopy(tests[i].data, pkt->dp_options, tests[i].len);
	if (dhcpol_parse_packet(&options, pkt, 
				sizeof(*pkt) + tests[i].len,
				error) != tests[i].result) {
	    printf("test '%s' FAILED\n", tests[i].name);
	    if (tests[i].result == TRUE) {
		printf("error message returned was %s\n", error);
	    }
	}
	else {
	    printf("test '%s' PASSED\n", tests[i].name);
	    if (tests[i].result == FALSE) {
		printf("error message returned was %s\n", error);
	    }
	}
	dhcpol_free(&options);
    }
    exit(0);
}
#endif TEST_DHCP_OPTIONS
