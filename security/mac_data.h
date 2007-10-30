/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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
/*-
 * Copyright (c) 2006 SPARTA, Inc.
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _SECURITY_MAC_DATA_H_
#define	_SECURITY_MAC_DATA_H_

/**
  @brief Mac policy module data

  This structure specifies module data that is passed in to the
  TrustedBSD MAC policy module by the kernel module loader.  The
  data is made of up key/value pairs where the key is always a
  string and the value is a string, binary data or array.  An array
  may be a list of values (actually a similar set of key/value pairs,
  but in this case the keys are always null), and may also consist of
  a set of dictionaries, which in turn are made up of a list of key/value
  pairs.

  Module data may be specified in the MAC policy module's
  Info.plist file as part of the OSModuleData dictionary.

  E.g.

  <key>OSModuleData</key>
  <dict>
	<key>foo</key>
	<string>bar</string>
	<key>Beers</key>
	<array>
	<dict>
		<key>type</key>
		<string>lager</string>
		<key>Name</key>
		<string>Anchor Steam</string>
	</dict>
	<dict>
		<key>type</key>
		<string>ale</string>
		<key>Name</key>
		<string>Sierra Nevada Pale Ale</string>
	</dict>
	</array>
  </dict>

*/
struct mac_module_data_element {
	unsigned int key_size;
	unsigned int value_size;
	unsigned int value_type;
	char *key;
	char *value;
};
struct mac_module_data_list {
	unsigned int count;
	unsigned int type;
	struct mac_module_data_element list[1];
};
struct mac_module_data {
	void *base_addr;		/* Orig base address, for ptr fixup.  */
	unsigned int size;
	unsigned int count;
	struct mac_module_data_element data[1];	/* actually bigger */
};

#define MAC_DATA_TYPE_PRIMITIVE	0	/* Primitive type (int, string, etc.) */
#define MAC_DATA_TYPE_ARRAY	1	/* Array type.                        */
#define MAC_DATA_TYPE_DICT	2	/* Dictionary type.                   */

#ifdef _SECURITY_MAC_POLICY_H_
/* XXX mac_policy_handle_t is defined in mac_policy.h, move prototype there? */
int mac_find_policy_data(const mac_policy_handle_t, const char *key,
    void **valp, size_t *sizep);
int mac_find_module_data(struct mac_module_data *mmd, const char *key,
    void **valp, size_t *sizep);

/*
 * This is a routine to fix up pointers in a mac_module_data_element when the
 * mac_module_data has been copied to a new area.  It depends on the pointers
 * all being offset from base_addr.
 */
static __inline void
mmd_fixup_ele(struct mac_module_data *oldbase,
    struct mac_module_data *newbase, struct mac_module_data_element *ele)
{
	if (ele->key != NULL) {		/* Array elements have no keys.       */
		ele->key -= (unsigned int)oldbase;
		ele->key += (unsigned int)newbase;
	}
	ele->value -= (unsigned int)oldbase;
	ele->value += (unsigned int)newbase;
}

#endif

#endif /* !_SECURITY_MAC_DATA_H_ */
