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
 * @APPLE_FREE_COPYRIGHT@
 */

#ifndef	_DDB_DB_LTR_H_
#define	_DDB_DB_LTR_H_

#include <machine/db_machdep.h>
#include <kern/task.h>

/* Prototypes for functions exported by this module.
 */

void db_list_pmap(
	db_expr_t	addr,
	int			have_addr,
	db_expr_t	count,
	char 		*modif
);

void db_low_trace(
	db_expr_t	addr,
	int			have_addr,
	db_expr_t	count,
	char 		*modif
);

void db_display_long(
	db_expr_t	addr,
	int			have_addr,
	db_expr_t	count,
	char 		*modif
);

void db_display_char(
	db_expr_t	addr,
	int			have_addr,
	db_expr_t	count,
	char 		*modif
);

void db_display_real(
	db_expr_t	addr,
	int			have_addr,
	db_expr_t	count,
	char 		*modif
);

void db_display_virtual(db_expr_t addr, int have_addr, db_expr_t count, char * modif);
void db_display_mappings(db_expr_t addr, int have_addr, db_expr_t count, char * modif);
void db_display_hash(db_expr_t addr, int have_addr, db_expr_t count, char * modif);
void db_display_pmap(db_expr_t addr, int have_addr, db_expr_t count, char * modif);
void db_display_iokit(db_expr_t addr, int have_addr, db_expr_t count, char * modif);
void db_display_save(db_expr_t addr, int have_addr, db_expr_t count, char * modif);
void db_display_xregs(db_expr_t addr, int have_addr, db_expr_t count, char * modif);
void db_display_kmod(db_expr_t addr, int have_addr, db_expr_t count, char * modif);
void db_gsnoop(db_expr_t addr, int have_addr, db_expr_t count, char * modif);
void db_check_mappings(db_expr_t addr, int have_addr, db_expr_t count, char * modif);
void db_check_pmaps(db_expr_t addr, int have_addr, db_expr_t count, char * modif);

#endif	/* !_DDB_DB_LTR_H_ */
