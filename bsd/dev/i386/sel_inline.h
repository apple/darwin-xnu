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
 * Copyright (c) 1992 NeXT Computer, Inc.
 *
 * Selector value conversion/validation.
 *
 * HISTORY
 *
 * 19 June 1992 ? at NeXT
 *	Created.
 */
 

static inline
unsigned int
sel_to_selector(
    sel_t		sel
)
{
    union {
	sel_t		sel;
	unsigned short	selector;
    } tconv;
    
    tconv.sel = sel;
    
    return (tconv.selector);
}

static inline
sel_t
selector_to_sel(
    unsigned int	selector
)
{
    union {
	unsigned short	selector;
	sel_t		sel;
    } tconv;
    
    tconv.selector = selector;
    
    return (tconv.sel);
}

#if 0
static inline
boolean_t
valid_user_data_selector(
    unsigned int	selector
)
{
    sel_t		sel = selector_to_sel(selector);
    
    if (selector == 0)
    	return (TRUE);

    if (sel.ti == SEL_LDT)
	return (TRUE);
    else if (sel.index < GDTSZ) {
	data_desc_t	*desc = (data_desc_t *)sel_to_gdt_entry(sel);
	
	if (desc->dpl == USER_PRIV)
	    return (TRUE);
    }
		
    return (FALSE);
}

static inline
boolean_t
valid_user_code_selector(
    unsigned int	selector
)
{
    sel_t		sel = selector_to_sel(selector);
    
    if (selector == 0)
    	return (FALSE);

    if (sel.ti == SEL_LDT) {
	if (sel.rpl == USER_PRIV)
	    return (TRUE);
    }
    else if (sel.index < GDTSZ && sel.rpl == USER_PRIV) {
    	code_desc_t	*desc = (code_desc_t *)sel_to_gdt_entry(sel);
	
	if (desc->dpl == USER_PRIV)
	    return (TRUE);
    }

    return (FALSE);
}

static inline
boolean_t
valid_user_stack_selector(
    unsigned int	selector
)
{
    sel_t		sel = selector_to_sel(selector);
    
    if (selector == 0)
    	return (FALSE);

    if (sel.ti == SEL_LDT) {
	if (sel.rpl == USER_PRIV)
	    return (TRUE);
    }
    else if (sel.index < GDTSZ && sel.rpl == USER_PRIV) {
	data_desc_t	*desc = (data_desc_t *)sel_to_gdt_entry(sel);
	
	if (desc->dpl == USER_PRIV)
	    return (TRUE);
    }
		
    return (FALSE);
}
#endif
