/*
 *  ccmode_ctr_setctr.c
 *  corecrypto
 *
 *  Created on 2/1/2017
 *
 *  Copyright (c) 2017 Apple Inc. All rights reserved.
 *
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

#include "ccmode_internal.h"

int ccmode_ctr_setctr(CC_UNUSED const struct ccmode_ctr *mode, ccctr_ctx *ctx, const void *ctr)
{
    CCMODE_CTR_KEY_PAD_OFFSET(ctx) = CCMODE_CTR_KEY_ECB(ctx)->block_size;
    CC_MEMCPY(CCMODE_CTR_KEY_CTR(ctx), ctr, CCMODE_CTR_KEY_ECB(ctx)->block_size);
    
    return 0;
}
