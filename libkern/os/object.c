/*
 * Copyright (c) 2008-2013 Apple Inc. All rights reserved.
 *
 * @APPLE_APACHE_LICENSE_HEADER_START@
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @APPLE_APACHE_LICENSE_HEADER_END@
 */

#include <stdbool.h>
#include <os/base.h>
#include <os/object.h>
#include <kern/assert.h>


/* XXX temporary until full vtable and refcount support */
extern struct os_log_s _os_log_default;

void*
os_retain(void *obj)
{
	/* XXX temporary nop */
	assert(obj == &_os_log_default);
	return obj;
}

void
os_release(void *obj __unused)
{
	/* XXX temporary nop */
	assert(obj == &_os_log_default);
}
