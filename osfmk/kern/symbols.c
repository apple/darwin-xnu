/*
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 2004 Networks Associates Technology, Inc.
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

#include <mach/mach_types.h>
#include <mach-o/mach_header.h>
#include <mach-o/nlist.h>
#include <mach/kmod.h>
#include <libsa/stdlib.h>
#include <kern/misc_protos.h>

static const struct nlist *
syms_find(const struct nlist *syms, int nsyms, vm_offset_t addr,
    vm_offset_t *ofs)
{
	const struct nlist *best = 0;
	int                 i;

	for (i = 0; i < nsyms; i++) {
		int st = syms[i].n_type & N_TYPE;

		if (st == N_SECT || st == N_ABS) {
			if (syms[i].n_value == addr) {
				*ofs = 0;
				return (syms+i);
			}
			else if (syms[i].n_value < addr &&
				 (best == 0 ||
				  (syms[i].n_value > best->n_value))) {
				*ofs = addr - syms[i].n_value;
				best = syms+i;
			}
		}
	}

	return (best);
}

static const char *
syms_getname(const struct symtab_command *sc, const char *ss,
	     const struct nlist *sp)
{
	if (sp->n_un.n_strx == 0)
		return ("");
	else if ((unsigned)sp->n_un.n_strx > sc->strsize)
		return ("*bad string*");
	else
		return (ss + sp->n_un.n_strx);
}

/* Search for a symbol in the given object file, which must either
 * have a LINKEDIT segment or have been read directly into memory
 * and isload passed as 1.

 * If mh has a LINKEDIT segment, an object file loaded in the normal
 * way will have the symbol table available at the load address.
 */

static const char *
syms_nameforaddr1(const struct mach_header *mh, int isload,
    vm_offset_t addr, vm_offset_t *ofs)
{
	const struct symtab_command  *sc = NULL;
	const struct segment_command *le = NULL;
	const struct segment_command *p;
	const struct segment_command *sym = NULL;
	const struct nlist           *syms;
	const char                   *strings;
	unsigned int                  i;

	p = (const struct segment_command *) (&mh[1]);

	for (i = 0; i < mh->ncmds; i++) {
		if (p->cmd == LC_SYMTAB)
			sc = (const struct symtab_command *) p;
		else if (p->cmd == LC_SEGMENT &&
		    !strncmp(p->segname, "__LINKEDIT", sizeof(p->segname)))
			le = p;

		/* only try to find a name for an address that came from
		 * a text section.
		 */
		if (p->cmd == LC_SEGMENT &&
		    addr >= p->vmaddr && addr < p->vmaddr + p->vmsize) {
			unsigned int j;

			const struct section *sp = (const struct section *)
			    (((const char *) p) + sizeof(struct segment_command));

			for (j = 0; j < p->nsects; j++) {
				if (addr >= sp[j].addr &&
				    addr <  sp[j].addr + sp[j].size &&
				    !strncmp (sp[j].sectname, "__text",
					    	sizeof(sp[j].sectname))) {
					sym = p;
					break;
				}
			}
		}
		p = (const struct segment_command *)
			(((const char *) p) + p->cmdsize);
	}

	if (sc == 0 || sym == NULL)
		return (NULL);

	if (!isload) {
		syms = (const struct nlist *) (((const char *) mh) + sc->symoff);
		strings = ((const char *) mh) + sc->stroff;
	}
	else if (le) {
		syms = (const struct nlist *) le->vmaddr;
		strings = (const char *)
			(le->vmaddr + sc->nsyms * sizeof(struct nlist));
	} else
		return (NULL);

	const struct nlist *sp = syms_find(syms, sc->nsyms, addr, ofs);
	if (sp)
		return syms_getname(sc, strings, sp);

	return (NULL);
}

extern struct mach_header  _mh_execute_header;
extern kmod_info_t        *kmod;

/* Search for a symbol and return the name, offset, and module in which the
 * address was found. A null module means the kernel itself.
 */

const char *
syms_nameforaddr(vm_offset_t addr, vm_offset_t *ofs, kmod_info_t **km)
{
	const char  *name = NULL;

	name = syms_nameforaddr1(&_mh_execute_header, 1, addr, ofs);
	if (name) {
		*km = NULL;
		return (name);
	}

	return (NULL);
}

int     snprintf(char *, size_t, const char *, ...);

/* Format the results of calling syms_nameforaddr into a single string.
 * The buffer must be at least 13 bytes long; 80 is recommended.
 */

int
syms_formataddr(vm_offset_t addr, char *out, vm_offset_t outsize)
{
	vm_offset_t  ofs;
	kmod_info_t *k = NULL;
	const char  *name;

	name = syms_nameforaddr(addr, &ofs, &k);

	if (ofs > 0x100000)
		name = NULL;

	if (name != NULL) {
		if (k != NULL)
			snprintf(out, outsize, "0x%08X <%s:%s + %d>", addr, 
			    k->name, name, ofs);
		else
			snprintf(out, outsize, "0x%08X <%s + %d>", addr, name,
			    ofs);

		return (1);
	}
	else {
		snprintf(out, outsize, "0x%08X", addr);
		return (0);
	}
}
