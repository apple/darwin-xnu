/*
 * Copyright (c) 2008 Apple Inc. All rights reserved.
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
#if !HFS_COMPRESSION
/* we need these symbols even though compression is turned off */
char register_decmpfs_decompressor;
char unregister_decmpfs_decompressor;
#else /* HFS_COMPRESSION */
#include <sys/kernel.h>
#include <sys/vnode_internal.h>
#include <sys/file_internal.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/xattr.h>
#include <sys/namei.h>
#include <sys/user.h>
#include <sys/mount_internal.h>
#include <sys/ubc.h>
#include <sys/decmpfs.h>
#include <sys/uio_internal.h>
#include <libkern/OSByteOrder.h>

#pragma mark --- debugging ---

#define COMPRESSION_DEBUG 0
#define COMPRESSION_DEBUG_VERBOSE 0
#define MALLOC_DEBUG 0

static const char *
baseName(const char *path)
{
    if (!path)
        return NULL;
    const char *ret = path;
    int i;
    for (i = 0; path[i] != 0; i++) {
        if (path[i] == '/')
            ret = &path[i + 1];
    }
    return ret;
}

#define ErrorLog(x, args...) printf("%s:%d:%s: " x, baseName(__FILE__), __LINE__, __FUNCTION__, ## args)

#if COMPRESSION_DEBUG
#define DebugLog ErrorLog
#else
#define DebugLog(x...) do { } while(0)
#endif

#if COMPRESSION_DEBUG_VERBOSE
#define VerboseLog ErrorLog
#else
#define VerboseLog(x...) do { } while(0)
#endif

#if MALLOC_DEBUG

static SInt32 totalAlloc;

typedef struct {
    uint32_t allocSz;
    uint32_t magic;
    const char *file;
    int line;
} allocated;

static void *
_malloc(uint32_t sz, __unused int type, __unused int flags, const char *file, int line)
{
    uint32_t allocSz = sz + 2 * sizeof(allocated);
    
    allocated *alloc = NULL;
    MALLOC(alloc, allocated *, allocSz, type, flags);
    if (!alloc) {
        ErrorLog("malloc failed\n");
        return NULL;
    }
    
    char *ret = (char*)&alloc[1];
    allocated *alloc2 = (allocated*)(ret + sz);
	
    alloc->allocSz = allocSz;
    alloc->magic = 0xdadadada;
    alloc->file = file;
    alloc->line = line;
    
    *alloc2 = *alloc;
    
    int s = OSAddAtomic(sz, &totalAlloc);
    ErrorLog("malloc(%d) -> %p, total allocations %d\n", sz, ret, s + sz);
    
    return ret;
}

static void
_free(char *ret, __unused int type, const char *file, int line)
{
    if (!ret) {
        ErrorLog("freeing null\n");
        return;
    }
    allocated *alloc = (allocated*)ret;
    alloc--;
    uint32_t sz = alloc->allocSz - 2 * sizeof(allocated);
    allocated *alloc2 = (allocated*)(ret + sz);
    
    if (alloc->magic != 0xdadadada) {
        panic("freeing bad pointer");
    }
	
    if (memcmp(alloc, alloc2, sizeof(*alloc)) != 0) {
        panic("clobbered data");
    }
    
    memset(ret, 0xce, sz);
    alloc2->file = file;
    alloc2->line = line;
    FREE(alloc, type);
    int s = OSAddAtomic(-sz, &totalAlloc);
    ErrorLog("free(%p,%d) -> total allocations %d\n", ret, sz, s - sz);
}

#undef MALLOC
#undef FREE
#define	MALLOC(space, cast, size, type, flags) (space) = (cast)_malloc(size, type, flags, __FILE__, __LINE__)
#define FREE(addr, type) _free((void *)addr, type, __FILE__, __LINE__)

#endif /* MALLOC_DEBUG */

#pragma mark --- globals ---

static lck_grp_t *decmpfs_lockgrp;

static decmpfs_registration * decompressors[CMP_MAX]; /* the registered compressors */
static lck_rw_t * decompressorsLock;
static int decompress_channel; /* channel used by decompress_file to wake up waiters */
static lck_mtx_t *decompress_channel_mtx;

vfs_context_t decmpfs_ctx;

#pragma mark --- decmp_get_func ---

#define offsetof_func(func) ((uintptr_t)(&(((decmpfs_registration*)NULL)->func)))

static void *
_func_from_offset(uint32_t type, uintptr_t offset)
{
    /* get the function at the given offset in the registration for the given type */
    decmpfs_registration *reg = decompressors[type];
    char *regChar = (char*)reg;
    char *func = &regChar[offset];
    void **funcPtr = (void**)func;

    switch (reg->decmpfs_registration) {
        case DECMPFS_REGISTRATION_VERSION_V1:
            if (offset > offsetof_func(free_data))
                return NULL;
            break;
        case DECMPFS_REGISTRATION_VERSION_V3:
            if (offset > offsetof_func(get_flags))
                return NULL;
            break;
        default:
            return NULL;
    }

    return funcPtr[0];
}

extern void IOServicePublishResource( const char * property, boolean_t value );
extern boolean_t IOServiceWaitForMatchingResource( const char * property, uint64_t timeout );
extern boolean_t IOCatalogueMatchingDriversPresent( const char * property );

static void *
_decmp_get_func(uint32_t type, uintptr_t offset)
{
	/*
	 this function should be called while holding a shared lock to decompressorsLock,
	 and will return with the lock held
	 */
	
	if (type >= CMP_MAX)
		return NULL;
	
	if (decompressors[type] != NULL) {
		// the compressor has already registered but the function might be null
		return _func_from_offset(type, offset);
	}
	
    // does IOKit know about a kext that is supposed to provide this type?
    char providesName[80];
    snprintf(providesName, sizeof(providesName), "com.apple.AppleFSCompression.providesType%u", type);
    if (IOCatalogueMatchingDriversPresent(providesName)) {
        // there is a kext that says it will register for this type, so let's wait for it
        char resourceName[80];
        uint64_t delay = 10000000ULL; // 10 milliseconds.
        snprintf(resourceName, sizeof(resourceName), "com.apple.AppleFSCompression.Type%u", type);
        printf("waiting for %s\n", resourceName);
        while(decompressors[type] == NULL) {
            lck_rw_unlock_shared(decompressorsLock); // we have to unlock to allow the kext to register
            if (IOServiceWaitForMatchingResource(resourceName, delay)) {
                lck_rw_lock_shared(decompressorsLock);
                break;
            }
            if (!IOCatalogueMatchingDriversPresent(providesName)) {
                // 
                printf("the kext with %s is no longer present\n", providesName);
                lck_rw_lock_shared(decompressorsLock);
                break;
            }
            printf("still waiting for %s\n", resourceName);
            delay *= 2;
            lck_rw_lock_shared(decompressorsLock);
        }
        // IOKit says the kext is loaded, so it should be registered too!
        if (decompressors[type] == NULL) {
            ErrorLog("we found %s, but the type still isn't registered\n", providesName);
            return NULL;
        }
        // it's now registered, so let's return the function
        return _func_from_offset(type, offset);
    }
    
	// the compressor hasn't registered, so it never will unless someone manually kextloads it
	ErrorLog("tried to access a compressed file of unregistered type %d\n", type);
	return NULL;
}

#define decmp_get_func(type, func) ((typeof(((decmpfs_registration*)NULL)->func))_decmp_get_func(type, offsetof_func(func)))

#pragma mark --- utilities ---

#if COMPRESSION_DEBUG
static char*
vnpath(vnode_t vp, char *path, int len)
{
    int origlen = len;
    path[0] = 0;
    vn_getpath(vp, path, &len);
    path[origlen - 1] = 0;
    return path;
}

static int
vnsize(vnode_t vp, uint64_t *size)
{
    struct vnode_attr va;
    VATTR_INIT(&va);
    VATTR_WANTED(&va, va_data_size);
	int error = vnode_getattr(vp, &va, decmpfs_ctx);
    if (error != 0) {
        ErrorLog("vnode_getattr err %d\n", error);
        return error;
    }
    *size = va.va_data_size;
    return 0;
}
#endif /* COMPRESSION_DEBUG */

#pragma mark --- cnode routines ---

void
decmpfs_cnode_init(decmpfs_cnode *cp)
{
    memset(cp, 0, sizeof(*cp));
	lck_rw_init(&cp->compressed_data_lock, decmpfs_lockgrp, NULL);
}

void
decmpfs_cnode_destroy(decmpfs_cnode *cp)
{
	lck_rw_destroy(&cp->compressed_data_lock, decmpfs_lockgrp);
}

boolean_t
decmpfs_trylock_compressed_data(decmpfs_cnode *cp, int exclusive)
{
	void *thread = current_thread();
	boolean_t retval = FALSE;

	if (cp->lockowner == thread) {
		/* this thread is already holding an exclusive lock, so bump the count */
		cp->lockcount++;
		retval = TRUE;
	} else if (exclusive) {
		if ((retval = lck_rw_try_lock_exclusive(&cp->compressed_data_lock))) {
			cp->lockowner = thread;
			cp->lockcount = 1;
		}
	} else {
		if ((retval = lck_rw_try_lock_shared(&cp->compressed_data_lock))) {
			cp->lockowner = (void *)-1;
		}
	}
	return retval;
}

void
decmpfs_lock_compressed_data(decmpfs_cnode *cp, int exclusive)
{
	void *thread = current_thread();
	
	if (cp->lockowner == thread) {
		/* this thread is already holding an exclusive lock, so bump the count */
		cp->lockcount++;
	} else if (exclusive) {
		lck_rw_lock_exclusive(&cp->compressed_data_lock);
		cp->lockowner = thread;
		cp->lockcount = 1;
	} else {
		lck_rw_lock_shared(&cp->compressed_data_lock);
		cp->lockowner = (void *)-1;
	}
}

void
decmpfs_unlock_compressed_data(decmpfs_cnode *cp, __unused int exclusive)
{
	void *thread = current_thread();
	
	if (cp->lockowner == thread) {
		/* this thread is holding an exclusive lock, so decrement the count */
		if ((--cp->lockcount) > 0) {
			/* the caller still has outstanding locks, so we're done */
			return;
		}
		cp->lockowner = NULL;
	}
	
	lck_rw_done(&cp->compressed_data_lock);
}

uint32_t
decmpfs_cnode_get_vnode_state(decmpfs_cnode *cp)
{
    return cp->cmp_state;
}

void
decmpfs_cnode_set_vnode_state(decmpfs_cnode *cp, uint32_t state, int skiplock)
{
	if (!skiplock) decmpfs_lock_compressed_data(cp, 1);
	cp->cmp_state = state;
    if (state == FILE_TYPE_UNKNOWN) {
        /* clear out the compression type too */
        cp->cmp_type = 0;
    }
	if (!skiplock) decmpfs_unlock_compressed_data(cp, 1);
}

static void
decmpfs_cnode_set_vnode_cmp_type(decmpfs_cnode *cp, uint32_t cmp_type, int skiplock)
{
    if (!skiplock) decmpfs_lock_compressed_data(cp, 1);
    cp->cmp_type = cmp_type;
    if (!skiplock) decmpfs_unlock_compressed_data(cp, 1);
}

static void
decmpfs_cnode_set_vnode_minimal_xattr(decmpfs_cnode *cp, int minimal_xattr, int skiplock)
{
    if (!skiplock) decmpfs_lock_compressed_data(cp, 1);
    cp->cmp_minimal_xattr = minimal_xattr;
    if (!skiplock) decmpfs_unlock_compressed_data(cp, 1);
}

uint64_t
decmpfs_cnode_get_vnode_cached_size(decmpfs_cnode *cp)
{
    return cp->uncompressed_size;
}

static void
decmpfs_cnode_set_vnode_cached_size(decmpfs_cnode *cp, uint64_t size)
{
    while(1) {
        uint64_t old = cp->uncompressed_size;
        if (OSCompareAndSwap64(old, size, (UInt64*)&cp->uncompressed_size)) {
            return;
        } else {
            /* failed to write our value, so loop */
        }
    }
}

static uint64_t
decmpfs_cnode_get_decompression_flags(decmpfs_cnode *cp)
{
    return cp->decompression_flags;
}

static void
decmpfs_cnode_set_decompression_flags(decmpfs_cnode *cp, uint64_t flags)
{
    while(1) {
        uint64_t old = cp->decompression_flags;
        if (OSCompareAndSwap64(old, flags, (UInt64*)&cp->decompression_flags)) {
            return;
        } else {
            /* failed to write our value, so loop */
        }
    }
}

#pragma mark --- decmpfs state routines ---

static int
decmpfs_fetch_compressed_header(vnode_t vp, decmpfs_cnode *cp, decmpfs_header **hdrOut, int returnInvalid)
{
    /*
     fetches vp's compression xattr, converting it into a decmpfs_header; returns 0 or errno
     if returnInvalid == 1, returns the header even if the type was invalid (out of range),
     and return ERANGE in that case
     */
    
	size_t read_size             = 0;
	size_t attr_size             = 0;
    uio_t attr_uio               = NULL;
    int err                      = 0;
    char *data                   = NULL;
    decmpfs_header *hdr = NULL;
	char uio_buf[ UIO_SIZEOF(1) ];
    
    if ((cp != NULL) &&
        (cp->cmp_type != 0) &&
        (cp->cmp_minimal_xattr != 0)) {
        /* this file's xattr didn't have any extra data when we fetched it, so we can synthesize a header from the data in the cnode */
        
        MALLOC(data, char *, sizeof(decmpfs_header), M_TEMP, M_WAITOK);
        if (!data) {
            err = ENOMEM;
            goto out;
        }
        hdr = (decmpfs_header*)data;
        hdr->attr_size = sizeof(decmpfs_disk_header);
        hdr->compression_magic = DECMPFS_MAGIC;
        hdr->compression_type  = cp->cmp_type;
        hdr->uncompressed_size = decmpfs_cnode_get_vnode_cached_size(cp);
    } else {
        /* figure out how big the xattr is on disk */
        err = vn_getxattr(vp, DECMPFS_XATTR_NAME, NULL, &attr_size, XATTR_NOSECURITY, decmpfs_ctx);
        if (err != 0)
            goto out;
        
        if (attr_size < sizeof(decmpfs_disk_header) || attr_size > MAX_DECMPFS_XATTR_SIZE) {
            err = EINVAL;
            goto out;
        }
        
        /* allocation includes space for the extra attr_size field of a compressed_header */
        MALLOC(data, char *, attr_size + sizeof(hdr->attr_size), M_TEMP, M_WAITOK);
        if (!data) {
            err = ENOMEM;
            goto out;
        }
        
        /* read the xattr into our buffer, skipping over the attr_size field at the beginning */
        attr_uio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_READ, &uio_buf[0], sizeof(uio_buf));
        uio_addiov(attr_uio, CAST_USER_ADDR_T(data + sizeof(hdr->attr_size)), attr_size);
        
        err = vn_getxattr(vp, DECMPFS_XATTR_NAME, attr_uio, &read_size, XATTR_NOSECURITY, decmpfs_ctx);
        if (err != 0)
            goto out;
        if (read_size != attr_size) {
            err = EINVAL;
            goto out;
        }
        hdr = (decmpfs_header*)data;
        hdr->attr_size = attr_size;
        /* swap the fields to native endian */
        hdr->compression_magic = OSSwapLittleToHostInt32(hdr->compression_magic);
        hdr->compression_type  = OSSwapLittleToHostInt32(hdr->compression_type);
        hdr->uncompressed_size = OSSwapLittleToHostInt64(hdr->uncompressed_size);
    }
    
    if (hdr->compression_magic != DECMPFS_MAGIC) {
        ErrorLog("invalid compression_magic 0x%08x, should be 0x%08x\n", hdr->compression_magic, DECMPFS_MAGIC);
        err = EINVAL;
		goto out;
    }
	
    if (hdr->compression_type >= CMP_MAX) {
        if (returnInvalid) {
            /* return the header even though the type is out of range */
            err = ERANGE;
        } else {
            ErrorLog("compression_type %d out of range\n", hdr->compression_type);
            err = EINVAL;
        }
		goto out;
    }
	
out:
    if (err && (err != ERANGE)) {
        DebugLog("err %d\n", err);
        if (data) FREE(data, M_TEMP);
        *hdrOut = NULL;
    } else {
        *hdrOut = hdr;
    }
    return err;
}

static int
decmpfs_fast_get_state(decmpfs_cnode *cp)
{
    /*
     return the cached state
     this should *only* be called when we know that decmpfs_file_is_compressed has already been called,
     because this implies that the cached state is valid
     */
    int cmp_state = decmpfs_cnode_get_vnode_state(cp);
	
    switch(cmp_state) {
        case FILE_IS_NOT_COMPRESSED:
        case FILE_IS_COMPRESSED:
        case FILE_IS_CONVERTING:
            return cmp_state;
        case FILE_TYPE_UNKNOWN:
            /*
             we should only get here if decmpfs_file_is_compressed was not called earlier on this vnode,
             which should not be possible
             */
            ErrorLog("decmpfs_fast_get_state called on unknown file\n");
            return FILE_IS_NOT_COMPRESSED;
        default:
            /* */
            ErrorLog("unknown cmp_state %d\n", cmp_state);
            return FILE_IS_NOT_COMPRESSED;
    }
}

static int
decmpfs_fast_file_is_compressed(decmpfs_cnode *cp)
{
    int cmp_state = decmpfs_cnode_get_vnode_state(cp);
	
    switch(cmp_state) {
        case FILE_IS_NOT_COMPRESSED:
			return 0;
        case FILE_IS_COMPRESSED:
        case FILE_IS_CONVERTING:
            return 1;
        case FILE_TYPE_UNKNOWN:
            /*
             we should only get here if decmpfs_file_is_compressed was not called earlier on this vnode,
             which should not be possible
             */
            ErrorLog("decmpfs_fast_get_state called on unknown file\n");
            return 0;
        default:
            /* */
            ErrorLog("unknown cmp_state %d\n", cmp_state);
            return 0;
    }
}

errno_t
decmpfs_validate_compressed_file(vnode_t vp, decmpfs_cnode *cp)
{
    /* give a compressor a chance to indicate that a compressed file is invalid */
    
    decmpfs_header *hdr = NULL;
    errno_t err = decmpfs_fetch_compressed_header(vp, cp, &hdr, 0);
    if (err) {
        /* we couldn't get the header */
        if (decmpfs_fast_get_state(cp) == FILE_IS_NOT_COMPRESSED) {
            /* the file is no longer compressed, so return success */
            err = 0;
        }
        goto out;
    }
    
    lck_rw_lock_shared(decompressorsLock);
    decmpfs_validate_compressed_file_func validate = decmp_get_func(hdr->compression_type, validate);
    if (validate) {    /* make sure this validation function is valid */
        /* is the data okay? */
		err = validate(vp, decmpfs_ctx, hdr);
    } else if (decmp_get_func(hdr->compression_type, fetch) == NULL) {
        /* the type isn't registered */
        err = EIO;
    } else {
        /* no validate registered, so nothing to do */
        err = 0;
    }
    lck_rw_unlock_shared(decompressorsLock);
out:
    if (hdr) FREE(hdr, M_TEMP);
#if COMPRESSION_DEBUG
    if (err) {
        DebugLog("decmpfs_validate_compressed_file ret %d, vp->v_flag %d\n", err, vp->v_flag);
    }
#endif
    return err;
}

int
decmpfs_file_is_compressed(vnode_t vp, decmpfs_cnode *cp)
{
    /*
     determines whether vp points to a compressed file
	 
     to speed up this operation, we cache the result in the cnode, and do as little as possible
     in the case where the cnode already has a valid cached state
     
     */
    
    int ret = 0;
	int error = 0;
	uint32_t cmp_state;
	struct vnode_attr va_fetch;
    decmpfs_header *hdr = NULL;
    mount_t mp = NULL;
	int cnode_locked = 0;
    int saveInvalid = 0; // save the header data even though the type was out of range
    uint64_t decompression_flags = 0;
	
    if (vnode_isnamedstream(vp)) {
        /*
         named streams can't be compressed
         since named streams of the same file share the same cnode,
         we don't want to get/set the state in the cnode, just return 0
         */
        return 0;
    }
    
    /* examine the cached a state in this cnode */    
    cmp_state = decmpfs_cnode_get_vnode_state(cp);
    switch(cmp_state) {
        case FILE_IS_NOT_COMPRESSED:
			return 0;
        case FILE_IS_COMPRESSED:
			return 1;
        case FILE_IS_CONVERTING:
            /* treat the file as compressed, because this gives us a way to block future reads until decompression is done */
            return 1;
        case FILE_TYPE_UNKNOWN:
            /* the first time we encountered this vnode, so we need to check it out */
            break;
        default:
            /* unknown state, assume file is not compressed */
            ErrorLog("unknown cmp_state %d\n", cmp_state);
            return 0;
    }
    
    if (!vnode_isreg(vp)) {
        /* only regular files can be compressed */
        ret = FILE_IS_NOT_COMPRESSED;
        goto done;
    }
    
    mp = vnode_mount(vp); 
    if (mp == NULL) {
        /*
         this should only be true before we mount the root filesystem
         we short-cut this return to avoid the call to getattr below, which
         will fail before root is mounted
         */
        ret = FILE_IS_NOT_COMPRESSED;
        goto done;
    }
    if ((mp->mnt_flag & MNT_LOCAL) == 0) {
        /* compression only supported on local filesystems */
        ret = FILE_IS_NOT_COMPRESSED;
        goto done;
    }
    
	/* lock our cnode data so that another caller doesn't change the state under us */
	decmpfs_lock_compressed_data(cp, 1);
	cnode_locked = 1;
	
	VATTR_INIT(&va_fetch);
	VATTR_WANTED(&va_fetch, va_flags);
	error = vnode_getattr(vp, &va_fetch, decmpfs_ctx);
	if (error) {
        /* failed to get the bsd flags so the file is not compressed */
        ret = FILE_IS_NOT_COMPRESSED;
        goto done;
    }
	if (va_fetch.va_flags & UF_COMPRESSED) {
		/* UF_COMPRESSED is on, make sure the file has the DECMPFS_XATTR_NAME xattr */
        error = decmpfs_fetch_compressed_header(vp, cp, &hdr, 1);
        if ((hdr != NULL) && (error == ERANGE)) {
            saveInvalid = 1;
        }
        if (error) {
            /* failed to get the xattr so the file is not compressed */
            ret = FILE_IS_NOT_COMPRESSED;
            goto done;
        }
        /* we got the xattr, so the file is compressed */
        ret = FILE_IS_COMPRESSED;
        goto done;
	}
    /* UF_COMPRESSED isn't on, so the file isn't compressed */
    ret = FILE_IS_NOT_COMPRESSED;
    
done:
    if (((ret == FILE_IS_COMPRESSED) || saveInvalid) && hdr) {
		/*
		 cache the uncompressed size away in the cnode
		 */
		
		if (!cnode_locked) {
			/*
			 we should never get here since the only place ret is set to FILE_IS_COMPRESSED
			 is after the call to decmpfs_lock_compressed_data above
			 */
			decmpfs_lock_compressed_data(cp, 1);
			cnode_locked = 1;
		}
		
        decmpfs_cnode_set_vnode_cached_size(cp, hdr->uncompressed_size);
		decmpfs_cnode_set_vnode_state(cp, ret, 1);
        decmpfs_cnode_set_vnode_cmp_type(cp, hdr->compression_type, 1);
        /* remember if the xattr's size was equal to the minimal xattr */
        if (hdr->attr_size == sizeof(decmpfs_disk_header)) {
            decmpfs_cnode_set_vnode_minimal_xattr(cp, 1, 1);
        }
        if (ret == FILE_IS_COMPRESSED) {
            /* update the ubc's size for this file */
            ubc_setsize(vp, hdr->uncompressed_size);
            
            /* update the decompression flags in the decmpfs cnode */
            lck_rw_lock_shared(decompressorsLock);
            decmpfs_get_decompression_flags_func get_flags = decmp_get_func(hdr->compression_type, get_flags);
            if (get_flags) {
                decompression_flags = get_flags(vp, decmpfs_ctx, hdr);
            }
            lck_rw_unlock_shared(decompressorsLock);
            decmpfs_cnode_set_decompression_flags(cp, decompression_flags);
        }
	} else {
		/* we might have already taken the lock above; if so, skip taking it again by passing cnode_locked as the skiplock parameter */
		decmpfs_cnode_set_vnode_state(cp, ret, cnode_locked);
	}
	
	if (cnode_locked) decmpfs_unlock_compressed_data(cp, 1);
    
    if (hdr) FREE(hdr, M_TEMP);
	
	switch(ret) {
        case FILE_IS_NOT_COMPRESSED:
			return 0;
        case FILE_IS_COMPRESSED:
        case FILE_IS_CONVERTING:
			return 1;
        default:
            /* unknown state, assume file is not compressed */
            ErrorLog("unknown ret %d\n", ret);
            return 0;
    }
}

int
decmpfs_update_attributes(vnode_t vp, struct vnode_attr *vap)
{
    int error = 0;
    
    if (VATTR_IS_ACTIVE(vap, va_flags)) {
        /* the BSD flags are being updated */
        if (vap->va_flags & UF_COMPRESSED) {
            /* the compressed bit is being set, did it change? */
            struct vnode_attr va_fetch;
            int old_flags = 0;
            VATTR_INIT(&va_fetch);
            VATTR_WANTED(&va_fetch, va_flags);
			error = vnode_getattr(vp, &va_fetch, decmpfs_ctx);
            if (error)
                return error;
            
            old_flags = va_fetch.va_flags;
            
            if (!(old_flags & UF_COMPRESSED)) {
                /*
                 * Compression bit was turned on, make sure the file has the DECMPFS_XATTR_NAME attribute.
                 * This precludes anyone from using the UF_COMPRESSED bit for anything else, and it enforces
                 * an order of operation -- you must first do the setxattr and then the chflags.
                 */
				
				if (VATTR_IS_ACTIVE(vap, va_data_size)) {
					/*
					 * don't allow the caller to set the BSD flag and the size in the same call
					 * since this doesn't really make sense
					 */
					vap->va_flags &= ~UF_COMPRESSED;
					return 0;
				}
				
                decmpfs_header *hdr = NULL;
                error = decmpfs_fetch_compressed_header(vp, NULL, &hdr, 1);
                if (error == 0) {
                    /*
                     allow the flag to be set since the decmpfs attribute is present
                     in that case, we also want to truncate the data fork of the file
                     */
                    VATTR_SET_ACTIVE(vap, va_data_size);
                    vap->va_data_size = 0;
                } else if (error == ERANGE) {
                    /* the file had a decmpfs attribute but the type was out of range, so don't muck with the file's data size */
                } else {
                    /* no DECMPFS_XATTR_NAME attribute, so deny the update */
					vap->va_flags &= ~UF_COMPRESSED;
                }
                if (hdr) FREE(hdr, M_TEMP);
            }
        }
    }
    
    return 0;
}

static int
wait_for_decompress(decmpfs_cnode *cp)
{
    int state;
    lck_mtx_lock(decompress_channel_mtx);
    do {
        state = decmpfs_fast_get_state(cp);
        if (state != FILE_IS_CONVERTING) {
            /* file is not decompressing */
            lck_mtx_unlock(decompress_channel_mtx);
            return state;
        }
        msleep((caddr_t)&decompress_channel, decompress_channel_mtx, PINOD, "wait_for_decompress", NULL);
    } while(1);
}

#pragma mark --- decmpfs hide query routines ---

int
decmpfs_hides_rsrc(vfs_context_t ctx, decmpfs_cnode *cp)
{
	/*
	 WARNING!!!
	 callers may (and do) pass NULL for ctx, so we should only use it
	 for this equality comparison
	 
	 This routine should only be called after a file has already been through decmpfs_file_is_compressed
	 */
	
	if (ctx == decmpfs_ctx)
		return 0;
	
	if (!decmpfs_fast_file_is_compressed(cp))
		return 0;
	
	/* all compressed files hide their resource fork */
	return 1;
}

int
decmpfs_hides_xattr(vfs_context_t ctx, decmpfs_cnode *cp, const char *xattr)
{
	/*
	 WARNING!!!
	 callers may (and do) pass NULL for ctx, so we should only use it
	 for this equality comparison
     
	 This routine should only be called after a file has already been through decmpfs_file_is_compressed
	 */
	
	if (ctx == decmpfs_ctx)
		return 0;
	if (strncmp(xattr, XATTR_RESOURCEFORK_NAME, 22) == 0)
		return decmpfs_hides_rsrc(ctx, cp);
	if (!decmpfs_fast_file_is_compressed(cp))
    /* file is not compressed, so don't hide this xattr */
		return 0;
	if (strncmp(xattr, DECMPFS_XATTR_NAME, 11) == 0)
    /* it's our xattr, so hide it */
		return 1;
	/* don't hide this xattr */
	return 0;
}

#pragma mark --- registration/validation routines ---

static inline int registration_valid(decmpfs_registration *registration)
{
    return registration && ((registration->decmpfs_registration == DECMPFS_REGISTRATION_VERSION_V1) || (registration->decmpfs_registration == DECMPFS_REGISTRATION_VERSION_V3));
}

errno_t
register_decmpfs_decompressor(uint32_t compression_type, decmpfs_registration *registration)
{
    /* called by kexts to register decompressors */
    
    errno_t ret = 0;
    int locked = 0;
    char resourceName[80];
    
    if ((compression_type >= CMP_MAX) || !registration_valid(registration)) {
        ret = EINVAL;
        goto out;
    }
    
    lck_rw_lock_exclusive(decompressorsLock); locked = 1;
	
    /* make sure the registration for this type is zero */
	if (decompressors[compression_type] != NULL) {
		ret = EEXIST;
		goto out;
	}
    decompressors[compression_type] = registration;
    snprintf(resourceName, sizeof(resourceName), "com.apple.AppleFSCompression.Type%u", compression_type);
    IOServicePublishResource(resourceName, TRUE);
    
out:
    if (locked) lck_rw_unlock_exclusive(decompressorsLock);
    return ret;
}

errno_t
unregister_decmpfs_decompressor(uint32_t compression_type, decmpfs_registration *registration)
{
    /* called by kexts to unregister decompressors */
    
    errno_t ret = 0;
    int locked = 0;
    char resourceName[80];

    if ((compression_type >= CMP_MAX) || !registration_valid(registration)) {
        ret = EINVAL;
        goto out;
    }
    
    lck_rw_lock_exclusive(decompressorsLock); locked = 1;
    if (decompressors[compression_type] != registration) {
        ret = EEXIST;
        goto out;
    }
    decompressors[compression_type] = NULL;
    snprintf(resourceName, sizeof(resourceName), "com.apple.AppleFSCompression.Type%u", compression_type);
    IOServicePublishResource(resourceName, FALSE);
    
out:
    if (locked) lck_rw_unlock_exclusive(decompressorsLock);
    return ret;
}

static int
compression_type_valid(decmpfs_header *hdr)
{
    /* fast pre-check to determine if the given compressor has checked in */
    int ret = 0;
    
    /* every compressor must have at least a fetch function */
    lck_rw_lock_shared(decompressorsLock);
    if (decmp_get_func(hdr->compression_type, fetch) != NULL) {
        ret = 1;
    }
    lck_rw_unlock_shared(decompressorsLock);
	
    return ret;
}

#pragma mark --- compression/decompression routines ---

static int
decmpfs_fetch_uncompressed_data(vnode_t vp, decmpfs_cnode *cp, decmpfs_header *hdr, off_t offset, user_ssize_t size, int nvec, decmpfs_vector *vec, uint64_t *bytes_read)
{
    /* get the uncompressed bytes for the specified region of vp by calling out to the registered compressor */
    
    int err          = 0;
	
    *bytes_read = 0;
    
    if ((uint64_t)offset >= hdr->uncompressed_size) {
        /* reading past end of file; nothing to do */
        err = 0;
        goto out;
    }
    if (offset < 0) {
        /* tried to read from before start of file */
        err = EINVAL;
        goto out;
    }
    if ((uint64_t)(offset + size) > hdr->uncompressed_size) {
        /* adjust size so we don't read past the end of the file */
		size = hdr->uncompressed_size - offset;
	}
    if (size == 0) {
        /* nothing to read */
        err = 0;
        goto out;
    }
    
    lck_rw_lock_shared(decompressorsLock);
    decmpfs_fetch_uncompressed_data_func fetch = decmp_get_func(hdr->compression_type, fetch);
    if (fetch) {
		err = fetch(vp, decmpfs_ctx, hdr, offset, size, nvec, vec, bytes_read);
		lck_rw_unlock_shared(decompressorsLock);
        if (err == 0) {
            uint64_t decompression_flags = decmpfs_cnode_get_decompression_flags(cp);
            if (decompression_flags & DECMPFS_FLAGS_FORCE_FLUSH_ON_DECOMPRESS) {
#if	!defined(__i386__) && !defined(__x86_64__)
                int i;
                for (i = 0; i < nvec; i++) {
                    flush_dcache64((addr64_t)(uintptr_t)vec[i].buf, vec[i].size, FALSE);
                }
#endif
            }
        }
    } else {
        err = ENOTSUP;
        lck_rw_unlock_shared(decompressorsLock);
    }
    
out:
    return err;
}

static kern_return_t
commit_upl(upl_t upl, upl_offset_t pl_offset, size_t uplSize, int flags, int abort)
{
    kern_return_t kr = 0;
    
    /* commit the upl pages */
    if (abort) {
        VerboseLog("aborting upl, flags 0x%08x\n", flags);
		kr = ubc_upl_abort_range(upl, pl_offset, uplSize, flags);
        if (kr != KERN_SUCCESS)
            ErrorLog("ubc_upl_commit_range error %d\n", (int)kr);
    } else {
        VerboseLog("committing upl, flags 0x%08x\n", flags | UPL_COMMIT_CLEAR_DIRTY);
		kr = ubc_upl_commit_range(upl, pl_offset, uplSize, flags | UPL_COMMIT_CLEAR_DIRTY);
        if (kr != KERN_SUCCESS)
            ErrorLog("ubc_upl_commit_range error %d\n", (int)kr);
    }
    return kr;
}

errno_t
decmpfs_pagein_compressed(struct vnop_pagein_args *ap, int *is_compressed, decmpfs_cnode *cp)
{
    /* handles a page-in request from vfs for a compressed file */
    
    int err                      = 0;
    struct vnode *vp             = ap->a_vp;
    upl_t pl                     = ap->a_pl;
	upl_offset_t pl_offset       = ap->a_pl_offset;
    off_t f_offset               = ap->a_f_offset;
    size_t size                  = ap->a_size;
	int flags                    = ap->a_flags;
    off_t uplPos                 = 0;
    user_ssize_t uplSize         = 0;
	void *data                   = NULL;
    decmpfs_header *hdr = NULL;
    int abort_pagein             = 0;
    uint64_t cachedSize          = 0;
	int cmpdata_locked           = 0;
	
    if(!decmpfs_trylock_compressed_data(cp, 0)) {
	    return EAGAIN;
    }
    cmpdata_locked = 1;
    
	
	if (flags & ~(UPL_IOSYNC | UPL_NOCOMMIT | UPL_NORDAHEAD)) {
		DebugLog("pagein: unknown flags 0x%08x\n", (flags & ~(UPL_IOSYNC | UPL_NOCOMMIT | UPL_NORDAHEAD)));
	}
    
    err = decmpfs_fetch_compressed_header(vp, cp, &hdr, 0);
    if (err != 0) {
        goto out;
    }
	
    cachedSize = hdr->uncompressed_size;
    
    if (!compression_type_valid(hdr)) {
        /* compressor not registered */
        err = ENOTSUP;
        goto out;
    }
    
    /* map the upl so we can fetch into it */
	kern_return_t kr = ubc_upl_map(pl, (vm_offset_t*)&data);
	if ((kr != KERN_SUCCESS) || (data == NULL)) {
		goto out;
	}
    
    uplPos = f_offset;
    uplSize = size;
	
    /* clip the size to the size of the file */
    if ((uint64_t)uplPos + uplSize > cachedSize) {
        /* truncate the read to the size of the file */
        uplSize = cachedSize - uplPos;
    }
	
    /* do the fetch */
    decmpfs_vector vec;
    
decompress:
    /* the mapped data pointer points to the first page of the page list, so we want to start filling in at an offset of pl_offset */
    vec.buf = (char*)data + pl_offset;
    vec.size = size;
    
    uint64_t did_read = 0;
	if (decmpfs_fast_get_state(cp) == FILE_IS_CONVERTING) {
		ErrorLog("unexpected pagein during decompress\n");
		/*
		 if the file is converting, this must be a recursive call to pagein from underneath a call to decmpfs_decompress_file;
		 pretend that it succeeded but don't do anything since we're just going to write over the pages anyway
		 */
		err = 0;
		did_read = 0;
	} else {
        err = decmpfs_fetch_uncompressed_data(vp, cp, hdr, uplPos, uplSize, 1, &vec, &did_read);
	}
    if (err) {
        DebugLog("decmpfs_fetch_uncompressed_data err %d\n", err);
        int cmp_state = decmpfs_fast_get_state(cp);
        if (cmp_state == FILE_IS_CONVERTING) {
            DebugLog("cmp_state == FILE_IS_CONVERTING\n");
            cmp_state = wait_for_decompress(cp);
            if (cmp_state == FILE_IS_COMPRESSED) {
                DebugLog("cmp_state == FILE_IS_COMPRESSED\n");
                /* a decompress was attempted but it failed, let's try calling fetch again */
                goto decompress;
            }
        }
        if (cmp_state == FILE_IS_NOT_COMPRESSED) {
            DebugLog("cmp_state == FILE_IS_NOT_COMPRESSED\n");
            /* the file was decompressed after we started reading it */
            abort_pagein = 1;   /* we're not going to commit our data */
            *is_compressed = 0; /* instruct caller to fall back to its normal path */
        }
    }
    
    /* zero out whatever we didn't read, and zero out the end of the last page(s) */
    uint64_t total_size = (size + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
    if (did_read < total_size) {
        memset((char*)vec.buf + did_read, 0, total_size - did_read);
    }
    
	kr = ubc_upl_unmap(pl); data = NULL; /* make sure to set data to NULL so we don't try to unmap again below */
    if (kr != KERN_SUCCESS)
        ErrorLog("ubc_upl_unmap error %d\n", (int)kr);
    else {
        if (!abort_pagein) {
            /* commit our pages */
			kr = commit_upl(pl, pl_offset, total_size, UPL_COMMIT_FREE_ON_EMPTY, 0);
        }
    }
    
out:
	if (data) ubc_upl_unmap(pl);
    if (hdr) FREE(hdr, M_TEMP);
	if (cmpdata_locked) decmpfs_unlock_compressed_data(cp, 0);
    if (err)
        ErrorLog("err %d\n", err);
    
	return err;
}

errno_t 
decmpfs_read_compressed(struct vnop_read_args *ap, int *is_compressed, decmpfs_cnode *cp)
{
    /* handles a read request from vfs for a compressed file */
	
    uio_t uio                    = ap->a_uio;
    vnode_t vp                   = ap->a_vp;
    int err                      = 0;
    int countInt                 = 0;
    off_t uplPos                 = 0;
    user_ssize_t uplSize         = 0;
    user_ssize_t uplRemaining    = 0;
    off_t curUplPos              = 0;
    user_ssize_t curUplSize      = 0;
    kern_return_t kr             = KERN_SUCCESS;
    int abort_read               = 0;
    void *data                   = NULL;
    uint64_t did_read            = 0;
    upl_t upl                    = NULL;
    upl_page_info_t *pli         = NULL;
    decmpfs_header *hdr          = NULL;
    uint64_t cachedSize          = 0;
    off_t uioPos                 = 0;
    user_ssize_t uioRemaining    = 0;
	int cmpdata_locked           = 0;
	
	decmpfs_lock_compressed_data(cp, 0); cmpdata_locked = 1;
	
    uplPos = uio_offset(uio);
    uplSize = uio_resid(uio);
    VerboseLog("uplPos %lld uplSize %lld\n", uplPos, uplSize);
	
    cachedSize = decmpfs_cnode_get_vnode_cached_size(cp);
    
    if ((uint64_t)uplPos + uplSize > cachedSize) {
        /* truncate the read to the size of the file */
        uplSize = cachedSize - uplPos;
    }
    
    /* give the cluster layer a chance to fill in whatever it already has */
    countInt = (uplSize > INT_MAX) ? INT_MAX : uplSize;
    err = cluster_copy_ubc_data(vp, uio, &countInt, 0);
    if (err != 0)
        goto out;
	
    /* figure out what's left */
    uioPos = uio_offset(uio);
    uioRemaining = uio_resid(uio);
    if ((uint64_t)uioPos + uioRemaining > cachedSize) {
        /* truncate the read to the size of the file */
        uioRemaining = cachedSize - uioPos;
    }
    
    if (uioRemaining <= 0) {
        /* nothing left */
        goto out;
    }
    
    err = decmpfs_fetch_compressed_header(vp, cp, &hdr, 0);
    if (err != 0) {
        goto out;
    }
    if (!compression_type_valid(hdr)) {
        err = ENOTSUP;
        goto out;
    }
    
    uplPos = uioPos;
    uplSize = uioRemaining;
#if COMPRESSION_DEBUG
    char path[PATH_MAX];
    DebugLog("%s: uplPos %lld uplSize %lld\n", vnpath(vp, path, sizeof(path)), (uint64_t)uplPos, (uint64_t)uplSize);
#endif
	
    lck_rw_lock_shared(decompressorsLock);
    decmpfs_adjust_fetch_region_func adjust_fetch = decmp_get_func(hdr->compression_type, adjust_fetch);
    if (adjust_fetch) {
        /* give the compressor a chance to adjust the portion of the file that we read */
		adjust_fetch(vp, decmpfs_ctx, hdr, &uplPos, &uplSize);
        VerboseLog("adjusted uplPos %lld uplSize %lld\n", (uint64_t)uplPos, (uint64_t)uplSize);
    }
    lck_rw_unlock_shared(decompressorsLock);
    
    /* clip the adjusted size to the size of the file */
    if ((uint64_t)uplPos + uplSize > cachedSize) {
        /* truncate the read to the size of the file */
        uplSize = cachedSize - uplPos;
    }
    
    if (uplSize <= 0) {
        /* nothing left */
        goto out;
    }
    
    /*
     since we're going to create a upl for the given region of the file,
     make sure we're on page boundaries
     */
    
    if (uplPos & (PAGE_SIZE - 1)) {
        /* round position down to page boundary */
        uplSize += (uplPos & (PAGE_SIZE - 1));
        uplPos &= ~(PAGE_SIZE - 1);
    }
    /* round size up to page multiple */
    uplSize = (uplSize + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
    
    VerboseLog("new uplPos %lld uplSize %lld\n", (uint64_t)uplPos, (uint64_t)uplSize);
    
    uplRemaining = uplSize;
    curUplPos = uplPos;
    curUplSize = 0;
    
    while(uplRemaining > 0) {
        /* start after the last upl */
        curUplPos += curUplSize;
        
        /* clip to max upl size */
        curUplSize = uplRemaining;
        if (curUplSize > MAX_UPL_SIZE * PAGE_SIZE) {
            curUplSize = MAX_UPL_SIZE * PAGE_SIZE;
        }
        
        /* create the upl */
        kr = ubc_create_upl(vp, curUplPos, curUplSize, &upl, &pli, UPL_SET_LITE);
        if (kr != KERN_SUCCESS) {
            ErrorLog("ubc_create_upl error %d\n", (int)kr);
            err = EINVAL;
            goto out;
        }
        VerboseLog("curUplPos %lld curUplSize %lld\n", (uint64_t)curUplPos, (uint64_t)curUplSize);
		
        /* map the upl */
        kr = ubc_upl_map(upl, (vm_offset_t*)&data);
        if (kr != KERN_SUCCESS) {
            ErrorLog("ubc_upl_map error %d\n", (int)kr);
            err = EINVAL;
            goto out;
        }
        
        /* make sure the map succeeded */
        if (!data) {
            ErrorLog("ubc_upl_map mapped null\n");
            err = EINVAL;
            goto out;
        }
        
        /* fetch uncompressed data into the mapped upl */
        decmpfs_vector vec;
    decompress:
        vec = (decmpfs_vector){ .buf = data, .size = curUplSize };
        err = decmpfs_fetch_uncompressed_data(vp, cp, hdr, curUplPos, curUplSize, 1, &vec, &did_read);
        if (err) {
            ErrorLog("decmpfs_fetch_uncompressed_data err %d\n", err);
            
            /* maybe the file is converting to decompressed */
            int cmp_state = decmpfs_fast_get_state(cp);
            if (cmp_state == FILE_IS_CONVERTING) {
                ErrorLog("cmp_state == FILE_IS_CONVERTING\n");
                cmp_state = wait_for_decompress(cp);
                if (cmp_state == FILE_IS_COMPRESSED) {
                    ErrorLog("cmp_state == FILE_IS_COMPRESSED\n");
                    /* a decompress was attempted but it failed, let's try fetching again */
                    goto decompress;
                }
            }
            if (cmp_state == FILE_IS_NOT_COMPRESSED) {
                ErrorLog("cmp_state == FILE_IS_NOT_COMPRESSED\n");
                /* the file was decompressed after we started reading it */
                abort_read = 1;     /* we're not going to commit our data */
                *is_compressed = 0; /* instruct caller to fall back to its normal path */
            }
            kr = KERN_FAILURE;
            did_read = 0;
        }
        /* zero out the remainder of the last page */
        memset((char*)data + did_read, 0, curUplSize - did_read);
        kr = ubc_upl_unmap(upl);
        if (kr == KERN_SUCCESS) {
            if (abort_read) {
				kr = commit_upl(upl, 0, curUplSize, UPL_ABORT_FREE_ON_EMPTY, 1);
            } else {
                VerboseLog("uioPos %lld uioRemaining %lld\n", (uint64_t)uioPos, (uint64_t)uioRemaining);
                if (uioRemaining) {
                    off_t uplOff = uioPos - curUplPos;
                    if (uplOff < 0) {
                        ErrorLog("uplOff %lld should never be negative\n", (int64_t)uplOff);
                        err = EINVAL;
                    } else {
                        off_t count = curUplPos + curUplSize - uioPos;
                        if (count < 0) {
                            /* this upl is entirely before the uio */
                        } else {
                            if (count > uioRemaining)
                                count = uioRemaining;
                            int io_resid = count;
                            err = cluster_copy_upl_data(uio, upl, uplOff, &io_resid);
                            int copied = count - io_resid;
                            VerboseLog("uplOff %lld count %lld copied %lld\n", (uint64_t)uplOff, (uint64_t)count, (uint64_t)copied);
                            if (err) {
                                ErrorLog("cluster_copy_upl_data err %d\n", err);
                            }
                            uioPos += copied;
                            uioRemaining -= copied;
                        }
                    }
                }
				kr = commit_upl(upl, 0, curUplSize, UPL_COMMIT_FREE_ON_EMPTY | UPL_COMMIT_INACTIVATE, 0);
                if (err) {
                    goto out;
                }
            }
        } else {
            ErrorLog("ubc_upl_unmap error %d\n", (int)kr);
        }
        
        uplRemaining -= curUplSize;
    }
    
out:
    if (hdr) FREE(hdr, M_TEMP);
	if (cmpdata_locked) decmpfs_unlock_compressed_data(cp, 0);
    if (err) {/* something went wrong */
        ErrorLog("err %d\n", err);
        return err;
    }
	
#if COMPRESSION_DEBUG
    uplSize = uio_resid(uio);
    if (uplSize)
        VerboseLog("still %lld bytes to copy\n", uplSize);
#endif
    return 0;
}

int
decmpfs_free_compressed_data(vnode_t vp, decmpfs_cnode *cp)
{
    /*
     call out to the decompressor to free remove any data associated with this compressed file
     then delete the file's compression xattr
     */
    
    decmpfs_header *hdr = NULL;
    int err = decmpfs_fetch_compressed_header(vp, cp, &hdr, 0);
    if (err) {
        ErrorLog("decmpfs_fetch_compressed_header err %d\n", err);
    } else {
        lck_rw_lock_shared(decompressorsLock);
        decmpfs_free_compressed_data_func free_data = decmp_get_func(hdr->compression_type, free_data);
        if (free_data) {
			err = free_data(vp, decmpfs_ctx, hdr);
        } else {
            /* nothing to do, so no error */
            err = 0;
        }
        lck_rw_unlock_shared(decompressorsLock);
        
        if (err != 0) {
            ErrorLog("decompressor err %d\n", err);
        }
    }
    
    /* delete the xattr */
	err = vn_removexattr(vp, DECMPFS_XATTR_NAME, 0, decmpfs_ctx);
    if (err != 0) {
        goto out;
    }
    
out:
    if (hdr) FREE(hdr, M_TEMP);
    return err;
}

#pragma mark --- file conversion routines ---

static int
unset_compressed_flag(vnode_t vp)
{
    int err = 0;
    struct vnode_attr va;
    int new_bsdflags = 0;
    
    VATTR_INIT(&va);
    VATTR_WANTED(&va, va_flags);
	err = vnode_getattr(vp, &va, decmpfs_ctx);
    
    if (err != 0) {
        ErrorLog("vnode_getattr err %d\n", err);
    } else {
        new_bsdflags = va.va_flags & ~UF_COMPRESSED;
        
        VATTR_INIT(&va);
        VATTR_SET(&va, va_flags, new_bsdflags);
		err = vnode_setattr(vp, &va, decmpfs_ctx);
        if (err != 0) {
            ErrorLog("vnode_setattr err %d\n", err);
        }
    }
    return err;
}

int
decmpfs_decompress_file(vnode_t vp, decmpfs_cnode *cp, off_t toSize, int truncate_okay, int skiplock)
{
	/* convert a compressed file to an uncompressed file */
	
	int err                      = 0;
	char *data                   = NULL;
	uio_t uio_w                  = 0;
	off_t offset                 = 0;
	uint32_t old_state           = 0;
	uint32_t new_state           = 0;
	int update_file_state        = 0;
	int allocSize                = 0;
	decmpfs_header *hdr = NULL;
	int cmpdata_locked           = 0;
	off_t remaining              = 0;
	uint64_t uncompressed_size   = 0;
	
	if (!skiplock) {
		decmpfs_lock_compressed_data(cp, 1); cmpdata_locked = 1;
	}
	
decompress:
	old_state = decmpfs_fast_get_state(cp);
	
	switch(old_state) {
		case FILE_IS_NOT_COMPRESSED:
		{
			/* someone else decompressed the file */
			err = 0;
			goto out;
		}
			
		case FILE_TYPE_UNKNOWN:
		{
			/* the file is in an unknown state, so update the state and retry */
			(void)decmpfs_file_is_compressed(vp, cp);
			
			/* try again */
			goto decompress;
		}
			
		case FILE_IS_COMPRESSED:
		{
			/* the file is compressed, so decompress it */
			break;
		}
			
		default:
		{
			/*
			 this shouldn't happen since multiple calls to decmpfs_decompress_file lock each other out,
			 and when decmpfs_decompress_file returns, the state should be always be set back to
			 FILE_IS_NOT_COMPRESSED or FILE_IS_UNKNOWN
			 */
			err = EINVAL;
			goto out;
		}
	}
	
    err = decmpfs_fetch_compressed_header(vp, cp, &hdr, 0);
	if (err != 0) {
		goto out;
	}
	
	uncompressed_size = hdr->uncompressed_size;
	if (toSize == -1)
		toSize = hdr->uncompressed_size;
	
	if (toSize == 0) {
		/* special case truncating the file to zero bytes */
		goto nodecmp;
	} else if ((uint64_t)toSize > hdr->uncompressed_size) {
		/* the caller is trying to grow the file, so we should decompress all the data */
		toSize = hdr->uncompressed_size;
	}
	
	allocSize = MIN(64*1024, toSize);
	MALLOC(data, char *, allocSize, M_TEMP, M_WAITOK);
	if (!data) {
		err = ENOMEM;
		goto out;
	}
	
	uio_w = uio_create(1, 0LL, UIO_SYSSPACE, UIO_WRITE);
	if (!uio_w) {
		err = ENOMEM;
		goto out;
	}
	uio_w->uio_flags |= UIO_FLAGS_IS_COMPRESSED_FILE;
	
	remaining = toSize;
	
	/* tell the buffer cache that this is an empty file */
	ubc_setsize(vp, 0);
	
	/* if we got here, we need to decompress the file */
	decmpfs_cnode_set_vnode_state(cp, FILE_IS_CONVERTING, 1);
	
	while(remaining > 0) {
		/* loop decompressing data from the file and writing it into the data fork */
		
		uint64_t bytes_read = 0;
		decmpfs_vector vec = { .buf = data, .size = MIN(allocSize, remaining) };
		err = decmpfs_fetch_uncompressed_data(vp, cp, hdr, offset, vec.size, 1, &vec, &bytes_read);
		if (err != 0) {
			ErrorLog("decmpfs_fetch_uncompressed_data err %d\n", err);
			goto out;
		}
		
		if (bytes_read == 0) {
			/* we're done reading data */
			break;
		}
		
		uio_reset(uio_w, offset, UIO_SYSSPACE, UIO_WRITE);
		err = uio_addiov(uio_w, CAST_USER_ADDR_T(data), bytes_read);
		if (err != 0) {
			ErrorLog("uio_addiov err %d\n", err);
			err = ENOMEM;
			goto out;
		}
		
		err = VNOP_WRITE(vp, uio_w, 0, decmpfs_ctx);
		if (err != 0) {
			/* if the write failed, truncate the file to zero bytes */
			ErrorLog("VNOP_WRITE err %d\n", err);
			break;
		}
		offset += bytes_read;
		remaining -= bytes_read;
	}
	
	if (err == 0) {
		if (offset != toSize) {
			ErrorLog("file decompressed to %lld instead of %lld\n", offset, toSize);
			err = EINVAL;
			goto out;
		}
	}
	
	if (err == 0) {
		/* sync the data and metadata */
		err = VNOP_FSYNC(vp, MNT_WAIT, decmpfs_ctx);
		if (err != 0) {
			ErrorLog("VNOP_FSYNC err %d\n", err);
			goto out;
		}
	}
	
	if (err != 0) {
		/* write, setattr, or fsync failed */
		ErrorLog("aborting decompress, err %d\n", err);
		if (truncate_okay) {
			/* truncate anything we might have written */
			int error = vnode_setsize(vp, 0, 0, decmpfs_ctx);
			ErrorLog("vnode_setsize err %d\n", error);
		}
		goto out;
	}
	
nodecmp:
	/* if we're truncating the file to zero bytes, we'll skip ahead to here */
	
	/* unset the compressed flag */
	unset_compressed_flag(vp);
	
	/* free the compressed data associated with this file */
	err = decmpfs_free_compressed_data(vp, cp);
	if (err != 0) {
		ErrorLog("decmpfs_free_compressed_data err %d\n", err);
	}
	
	/*
	 even if free_compressed_data or vnode_getattr/vnode_setattr failed, return success
	 since we succeeded in writing all of the file data to the data fork
	 */
	err = 0;
	
	/* if we got this far, the file was successfully decompressed */
	update_file_state = 1;
	new_state = FILE_IS_NOT_COMPRESSED;
	
#if COMPRESSION_DEBUG
	{
		uint64_t filesize = 0;
		vnsize(vp, &filesize);
		DebugLog("new file size %lld\n", filesize);
	}
#endif
	
out:
	if (hdr) FREE(hdr, M_TEMP);
	if (data) FREE(data, M_TEMP);
	if (uio_w) uio_free(uio_w);
	
	if (err != 0) {
		/* if there was a failure, reset compression flags to unknown and clear the buffer cache data */
		update_file_state = 1;
		new_state = FILE_TYPE_UNKNOWN;
		if (uncompressed_size) {
			ubc_setsize(vp, 0);
			ubc_setsize(vp, uncompressed_size);
        }
	}
	
	if (update_file_state) {
		lck_mtx_lock(decompress_channel_mtx);
		decmpfs_cnode_set_vnode_state(cp, new_state, 1);
		wakeup((caddr_t)&decompress_channel); /* wake up anyone who might have been waiting for decompression */
		lck_mtx_unlock(decompress_channel_mtx);
	}
	
	if (cmpdata_locked) decmpfs_unlock_compressed_data(cp, 1);
	
	return err;
}

#pragma mark --- Type1 compressor ---

/*
 The "Type1" compressor stores the data fork directly in the compression xattr
 */

static int
decmpfs_validate_compressed_file_Type1(__unused vnode_t vp, __unused vfs_context_t ctx, decmpfs_header *hdr)
{
    int err          = 0;
    
    if (hdr->uncompressed_size + sizeof(decmpfs_disk_header) != (uint64_t)hdr->attr_size) {
        err = EINVAL;
        goto out;
    }
out:
    return err;    
}

static int
decmpfs_fetch_uncompressed_data_Type1(__unused vnode_t vp, __unused vfs_context_t ctx, decmpfs_header *hdr, off_t offset, user_ssize_t size, int nvec, decmpfs_vector *vec, uint64_t *bytes_read)
{
    int err          = 0;
    int i;
    user_ssize_t remaining;
    
    if (hdr->uncompressed_size + sizeof(decmpfs_disk_header) != (uint64_t)hdr->attr_size) {
        err = EINVAL;
        goto out;
    }
    
#if COMPRESSION_DEBUG
    static int dummy = 0; // prevent syslog from coalescing printfs
    char path[PATH_MAX];
    DebugLog("%s: %d memcpy %lld at %lld\n", vnpath(vp, path, sizeof(path)), dummy++, size, (uint64_t)offset);
#endif
    
    remaining = size;
    for (i = 0; (i < nvec) && (remaining > 0); i++) {
        user_ssize_t curCopy = vec[i].size;
        if (curCopy > remaining)
            curCopy = remaining;
        memcpy(vec[i].buf, hdr->attr_bytes + offset, curCopy);
        offset += curCopy;
        remaining -= curCopy;
    }
    
    if ((bytes_read) && (err == 0))
        *bytes_read = (size - remaining);
    
out:
    return err;
}

static decmpfs_registration Type1Reg =
{
    .decmpfs_registration = DECMPFS_REGISTRATION_VERSION,
    .validate          = decmpfs_validate_compressed_file_Type1,
    .adjust_fetch      = NULL, /* no adjust necessary */
    .fetch             = decmpfs_fetch_uncompressed_data_Type1,
    .free_data         = NULL, /* no free necessary */
    .get_flags         = NULL  /* no flags */
};

#pragma mark --- decmpfs initialization ---

void decmpfs_init()
{
    static int done = 0;
    if (done) return;
    
	decmpfs_ctx = vfs_context_create(vfs_context_kernel());
	
    lck_grp_attr_t *attr = lck_grp_attr_alloc_init();
    decmpfs_lockgrp = lck_grp_alloc_init("VFSCOMP",  attr);
    decompressorsLock = lck_rw_alloc_init(decmpfs_lockgrp, NULL);
    decompress_channel_mtx = lck_mtx_alloc_init(decmpfs_lockgrp, NULL);
    
    register_decmpfs_decompressor(CMP_Type1, &Type1Reg);
    
    done = 1;
}
#endif /* HFS_COMPRESSION */
