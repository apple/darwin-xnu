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

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/proc_internal.h>
#include <sys/systm.h>
#include <sys/systm.h>
#include <sys/mount_internal.h>
#include <sys/filedesc.h>
#include <sys/vnode_internal.h>
#include <sys/imageboot.h>
#include <kern/assert.h>

#include <sys/namei.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>
#include <sys/sysproto.h>
#include <sys/csr.h>
#include <miscfs/devfs/devfsdefs.h>
#include <libkern/crypto/sha2.h>
#include <libkern/crypto/rsa.h>
#include <libkern/OSKextLibPrivate.h>

#include <kern/kalloc.h>

#include <pexpert/pexpert.h>
#include <kern/chunklist.h>

extern struct filedesc filedesc0;

extern int (*mountroot)(void);
extern char rootdevice[DEVMAXNAMESIZE];

#define DEBUG_IMAGEBOOT 0

#if DEBUG_IMAGEBOOT
#define DBG_TRACE(...) printf(__VA_ARGS__)
#else
#define DBG_TRACE(...) do {} while(0)
#endif

extern int di_root_image(const char *path, char *devname, size_t devsz, dev_t *dev_p);
extern int di_root_ramfile_buf(void *buf, size_t bufsz, char *devname, size_t devsz, dev_t *dev_p);

static boolean_t imageboot_setup_new(void);

#define kIBFilePrefix "file://"

__private_extern__ int
imageboot_format_is_valid(const char *root_path)
{
	return strncmp(root_path, kIBFilePrefix,
	           strlen(kIBFilePrefix)) == 0;
}

static void
vnode_get_and_drop_always(vnode_t vp)
{
	vnode_getalways(vp);
	vnode_rele(vp);
	vnode_put(vp);
}

__private_extern__ int
imageboot_needed(void)
{
	int result = 0;
	char *root_path = NULL;

	DBG_TRACE("%s: checking for presence of root path\n", __FUNCTION__);

	MALLOC_ZONE(root_path, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
	if (root_path == NULL) {
		panic("%s: M_NAMEI zone exhausted", __FUNCTION__);
	}

	/* Check for first layer */
	if (!(PE_parse_boot_argn("rp0", root_path, MAXPATHLEN) ||
	    PE_parse_boot_argn("rp", root_path, MAXPATHLEN) ||
	    PE_parse_boot_argn(IMAGEBOOT_ROOT_ARG, root_path, MAXPATHLEN) ||
	    PE_parse_boot_argn(IMAGEBOOT_AUTHROOT_ARG, root_path, MAXPATHLEN))) {
		goto out;
	}

	/* Sanity-check first layer */
	if (imageboot_format_is_valid(root_path)) {
		DBG_TRACE("%s: Found %s\n", __FUNCTION__, root_path);
	} else {
		goto out;
	}

	result = 1;

	/* Check for second layer */
	if (!(PE_parse_boot_argn("rp1", root_path, MAXPATHLEN) ||
	    PE_parse_boot_argn(IMAGEBOOT_CONTAINER_ARG, root_path, MAXPATHLEN))) {
		goto out;
	}

	/* Sanity-check second layer */
	if (imageboot_format_is_valid(root_path)) {
		DBG_TRACE("%s: Found %s\n", __FUNCTION__, root_path);
	} else {
		panic("%s: Invalid URL scheme for %s\n",
		    __FUNCTION__, root_path);
	}

out:
	FREE_ZONE(root_path, MAXPATHLEN, M_NAMEI);

	return result;
}


/*
 * Swaps in new root filesystem based on image path.
 * Current root filesystem is removed from mount list and
 * tagged MNTK_BACKS_ROOT, MNT_ROOTFS is cleared on it, and
 * "rootvnode" is reset.  Root vnode of currentroot filesystem
 * is returned with usecount (no iocount).
 */
__private_extern__ int
imageboot_mount_image(const char *root_path, int height)
{
	dev_t           dev;
	int             error;
	vnode_t         old_rootvnode = NULL;
	vnode_t         newdp;
	mount_t         new_rootfs;

	error = di_root_image(root_path, rootdevice, DEVMAXNAMESIZE, &dev);
	if (error) {
		panic("%s: di_root_image failed: %d\n", __FUNCTION__, error);
	}

	rootdev = dev;
	mountroot = NULL;
	printf("%s: root device 0x%x\n", __FUNCTION__, rootdev);
	error = vfs_mountroot();
	if (error != 0) {
		panic("vfs_mountroot() failed.\n");
	}

	/*
	 * Get the vnode for '/'.
	 * Set fdp->fd_fd.fd_cdir to reference it.
	 */
	if (VFS_ROOT(TAILQ_LAST(&mountlist, mntlist), &newdp, vfs_context_kernel())) {
		panic("%s: cannot find root vnode", __FUNCTION__);
	}

	if (rootvnode != NULL) {
		/* remember the old rootvnode, but remove it from mountlist */
		mount_t         old_rootfs;

		old_rootvnode = rootvnode;
		old_rootfs = rootvnode->v_mount;

		mount_list_remove(old_rootfs);

		mount_lock(old_rootfs);
#ifdef CONFIG_IMGSRC_ACCESS
		old_rootfs->mnt_kern_flag |= MNTK_BACKS_ROOT;
#endif /* CONFIG_IMGSRC_ACCESS */
		old_rootfs->mnt_flag &= ~MNT_ROOTFS;
		mount_unlock(old_rootfs);
	}

	/* switch to the new rootvnode */
	rootvnode = newdp;

	new_rootfs = rootvnode->v_mount;
	mount_lock(new_rootfs);
	new_rootfs->mnt_flag |= MNT_ROOTFS;
	mount_unlock(new_rootfs);

	vnode_ref(newdp);
	vnode_put(newdp);
	filedesc0.fd_cdir = newdp;
	DBG_TRACE("%s: root switched\n", __FUNCTION__);

	if (old_rootvnode != NULL) {
#ifdef CONFIG_IMGSRC_ACCESS
		if (height >= 0 && PE_imgsrc_mount_supported()) {
			imgsrc_rootvnodes[height] = old_rootvnode;
		} else {
			vnode_get_and_drop_always(old_rootvnode);
		}
#else
		height = 0; /* keep the compiler from complaining */
		vnode_get_and_drop_always(old_rootvnode);
#endif /* CONFIG_IMGSRC_ACCESS */
	}
	return 0;
}


/*
 * Authenticated root-dmg support
 */

#define AUTHDBG(fmt, args...) do { printf("%s: " fmt "\n", __func__, ##args); } while (0)
#define AUTHPRNT(fmt, args...) do { printf("%s: " fmt "\n", __func__, ##args); } while (0)

#define kfree_safe(x) do { if ((x)) { kfree_addr((x)); (x) = NULL; } } while (0)

enum {
	MISSING_SIG = -1,
	INVALID_SIG = -2
};

static void
key_byteswap(void *_dst, const void *_src, size_t len)
{
	uint32_t *dst __attribute__((align_value(1))) = _dst;
	const uint32_t *src __attribute__((align_value(1))) = _src;

	assert(len % sizeof(uint32_t) == 0);

	len = len / sizeof(uint32_t);
	for (size_t i = 0; i < len; i++) {
		dst[len - i - 1] = OSSwapInt32(src[i]);
	}
}

static int
read_file(const char *path, void **bufp, size_t *bufszp)
{
	int err = 0;
	struct nameidata ndp = {};
	struct vnode *vp = NULL;
	off_t fsize = 0;
	int resid = 0;
	char *buf = NULL;
	bool doclose = false;

	vfs_context_t ctx = vfs_context_kernel();
	proc_t p = vfs_context_proc(ctx);
	kauth_cred_t kerncred = vfs_context_ucred(ctx);

	NDINIT(&ndp, LOOKUP, OP_OPEN, LOCKLEAF, UIO_SYSSPACE, CAST_USER_ADDR_T(path), ctx);
	if ((err = namei(&ndp)) != 0) {
		AUTHPRNT("namei failed (%s)", path);
		goto out;
	}
	nameidone(&ndp);
	vp = ndp.ni_vp;

	if ((err = vnode_size(vp, &fsize, ctx)) != 0) {
		AUTHPRNT("failed to get vnode size");
		goto out;
	}
	if (fsize < 0) {
		panic("negative file size");
	}

	if ((err = VNOP_OPEN(vp, FREAD, ctx)) != 0) {
		AUTHPRNT("failed to open vnode");
		goto out;
	}
	doclose = true;

	/* if bufsz is non-zero, cap the read at bufsz bytes */
	if (*bufszp && *bufszp < (size_t)fsize) {
		fsize = *bufszp;
	}

	buf = kalloc(fsize);
	if (buf == NULL) {
		err = ENOMEM;
		goto out;
	}

	if ((err = vn_rdwr(UIO_READ, vp, (caddr_t)buf, fsize, 0, UIO_SYSSPACE, IO_NODELOCKED, kerncred, &resid, p)) != 0) {
		AUTHPRNT("vn_rdwr() failed");
		goto out;
	}

	if (resid) {
		/* didnt get everything we wanted */
		AUTHPRNT("vn_rdwr resid = %d", resid);
		err = EINVAL;
		goto out;
	}

out:
	if (doclose) {
		VNOP_CLOSE(vp, FREAD, ctx);
	}
	if (vp) {
		vnode_put(vp);
		vp = NULL;
	}

	if (err) {
		kfree_safe(buf);
	} else {
		*bufp = buf;
		*bufszp = fsize;
	}

	return err;
}

static int
validate_signature(const uint8_t *key_msb, size_t keylen, uint8_t *sig_msb, size_t siglen, uint8_t *digest)
{
	int err = 0;
	bool sig_valid = false;
	uint8_t *sig = NULL;

	const uint8_t exponent[] = { 0x01, 0x00, 0x01 };
	uint8_t *modulus = kalloc(keylen);
	rsa_pub_ctx *rsa_ctx = kalloc(sizeof(rsa_pub_ctx));
	sig = kalloc(siglen);

	if (modulus == NULL || rsa_ctx == NULL || sig == NULL) {
		err = ENOMEM;
		goto out;
	}

	bzero(rsa_ctx, sizeof(rsa_pub_ctx));
	key_byteswap(modulus, key_msb, keylen);
	key_byteswap(sig, sig_msb, siglen);

	err = rsa_make_pub(rsa_ctx,
	    sizeof(exponent), exponent,
	    CHUNKLIST_PUBKEY_LEN, modulus);
	if (err) {
		AUTHPRNT("rsa_make_pub() failed");
		goto out;
	}

	err = rsa_verify_pkcs1v15(rsa_ctx, CC_DIGEST_OID_SHA256,
	    SHA256_DIGEST_LENGTH, digest,
	    siglen, sig,
	    &sig_valid);
	if (err) {
		sig_valid = false;
		AUTHPRNT("rsa_verify() failed");
		err = EINVAL;
		goto out;
	}

out:
	kfree_safe(sig);
	kfree_safe(rsa_ctx);
	kfree_safe(modulus);

	if (err) {
		return err;
	} else if (sig_valid == true) {
		return 0; /* success */
	} else {
		return INVALID_SIG;
	}
}

static int
validate_chunklist(void *buf, size_t len)
{
	int err = 0;
	size_t sigsz = 0;
	size_t sig_end = 0;
	size_t chunks_end = 0;
	bool valid_sig = false;
	struct chunklist_hdr *hdr = buf;

	if (len < sizeof(struct chunklist_hdr)) {
		AUTHPRNT("no space for header");
		return EINVAL;
	}

	/* recognized file format? */
	if (hdr->cl_magic != CHUNKLIST_MAGIC ||
	    hdr->cl_file_ver != CHUNKLIST_FILE_VERSION_10 ||
	    hdr->cl_chunk_method != CHUNKLIST_SIGNATURE_METHOD_10 ||
	    hdr->cl_sig_method != CHUNKLIST_SIGNATURE_METHOD_10) {
		AUTHPRNT("unrecognized chunklist format");
		return EINVAL;
	}

	/* does the chunk list fall within the bounds of the buffer? */
	if (os_mul_and_add_overflow(hdr->cl_chunk_count, sizeof(struct chunklist_chunk), hdr->cl_chunk_offset, &chunks_end) ||
	    hdr->cl_chunk_offset < sizeof(struct chunklist_hdr) || chunks_end > len) {
		AUTHPRNT("invalid chunk_count (%llu) or chunk_offset (%llu)",
		    hdr->cl_chunk_count, hdr->cl_chunk_offset);
		return EINVAL;
	}

	/* does the signature fall within the bounds of the buffer? */
	if (os_add_overflow(hdr->cl_sig_offset, sizeof(struct chunklist_sig), &sig_end) ||
	    hdr->cl_sig_offset < sizeof(struct chunklist_hdr) ||
	    hdr->cl_sig_offset < chunks_end ||
	    hdr->cl_sig_offset > len) {
		AUTHPRNT("invalid signature offset (%llu)", hdr->cl_sig_offset);
		return EINVAL;
	}

	if (sig_end > len || os_sub_overflow(len, hdr->cl_sig_offset, &sigsz) || sigsz != CHUNKLIST_SIG_LEN) {
		/* missing or incorrect signature size */
		return MISSING_SIG;
	}

	AUTHDBG("hashing chunklist");

	/* hash the chunklist (excluding the signature) */
	uint8_t sha_digest[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha_ctx;
	SHA256_Init(&sha_ctx);
	SHA256_Update(&sha_ctx, buf, hdr->cl_sig_offset);
	SHA256_Final(sha_digest, &sha_ctx);

	AUTHDBG("validating chunklist signature against pub keys");
	for (size_t i = 0; i < CHUNKLIST_NPUBKEYS; i++) {
		const struct chunklist_pubkey *key = &chunklist_pubkeys[i];
		err = validate_signature(key->key, CHUNKLIST_PUBKEY_LEN,
		    buf + hdr->cl_sig_offset, sigsz, sha_digest);
		if (err == 0) {
			AUTHDBG("validated chunklist signature with key %lu (prod=%d)", i, key->isprod);
			valid_sig = key->isprod;
#if IMAGEBOOT_ALLOW_DEVKEYS
			if (!key->isprod) {
				/* allow dev keys in dev builds only */
				AUTHDBG("*** allowing DEV key: this will fail in customer builds ***");
				valid_sig = true;
			}
#endif
			goto out;
		} else if (err == INVALID_SIG) {
			/* try the next key */
		} else {
			goto out; /* something bad happened */
		}
	}

	/* At this point we tried all the keys: nothing went wrong but none of them
	 * signed our chunklist. */
	AUTHPRNT("signature did not verify against any known public key");

out:
	if (err) {
		return err;
	} else if (valid_sig == true) {
		return 0; /* signed, and everything checked out */
	} else {
		return EINVAL;
	}
}

static int
validate_root_image(const char *root_path, void *chunklist)
{
	int err = 0;
	struct chunklist_hdr *hdr = chunklist;
	struct chunklist_chunk *chk = NULL;
	size_t ch = 0;
	struct nameidata ndp = {};
	struct vnode *vp = NULL;
	off_t fsize = 0;
	off_t offset = 0;
	bool doclose = false;
	size_t bufsz = 0;
	void *buf = NULL;

	vfs_context_t ctx = vfs_context_kernel();
	kauth_cred_t kerncred = vfs_context_ucred(ctx);
	proc_t p = vfs_context_proc(ctx);

	AUTHDBG("validating root dmg %s", root_path);

	/*
	 * Open the DMG
	 */
	NDINIT(&ndp, LOOKUP, OP_OPEN, LOCKLEAF, UIO_SYSSPACE, CAST_USER_ADDR_T(root_path), ctx);
	if ((err = namei(&ndp)) != 0) {
		AUTHPRNT("namei failed (%s)", root_path);
		goto out;
	}
	nameidone(&ndp);
	vp = ndp.ni_vp;

	if (vp->v_type != VREG) {
		err = EINVAL;
		goto out;
	}

	if ((err = vnode_size(vp, &fsize, ctx)) != 0) {
		AUTHPRNT("failed to get vnode size");
		goto out;
	}

	if ((err = VNOP_OPEN(vp, FREAD, ctx)) != 0) {
		AUTHPRNT("failed to open vnode");
		goto out;
	}
	doclose = true;

	/*
	 * Iterate the chunk list and check each chunk
	 */
	chk = chunklist + hdr->cl_chunk_offset;
	for (ch = 0; ch < hdr->cl_chunk_count; ch++) {
		int resid = 0;

		if (!buf) {
			/* allocate buffer based on first chunk size */
			buf = kalloc(chk->chunk_size);
			if (buf == NULL) {
				err = ENOMEM;
				goto out;
			}
			bufsz = chk->chunk_size;
		}

		if (chk->chunk_size > bufsz) {
			AUTHPRNT("chunk size too big");
			err = EINVAL;
			goto out;
		}

		err = vn_rdwr(UIO_READ, vp, (caddr_t)buf, chk->chunk_size, offset, UIO_SYSSPACE, IO_NODELOCKED, kerncred, &resid, p);
		if (err) {
			AUTHPRNT("vn_rdrw fail (err = %d, resid = %d)", err, resid);
			goto out;
		}
		if (resid) {
			err = EINVAL;
			AUTHPRNT("chunk covered non-existant part of image");
			goto out;
		}

		/* calculate the SHA256 of this chunk */
		uint8_t sha_digest[SHA256_DIGEST_LENGTH];
		SHA256_CTX sha_ctx;
		SHA256_Init(&sha_ctx);
		SHA256_Update(&sha_ctx, buf, chk->chunk_size);
		SHA256_Final(sha_digest, &sha_ctx);

		/* Check the calculated SHA matches the chunk list */
		if (bcmp(sha_digest, chk->chunk_sha256, SHA256_DIGEST_LENGTH) != 0) {
			AUTHPRNT("SHA mismatch on chunk %lu (offset %lld, size %u)", ch, offset, chk->chunk_size);
			err = EINVAL;
			goto out;
		}

		if (os_add_overflow(offset, chk->chunk_size, &offset)) {
			err = EINVAL;
			goto out;
		}
		chk++;
	}

	if (offset != fsize) {
		AUTHPRNT("chunklist did not cover entire file (offset = %lld, fsize = %lld)", offset, fsize);
		err = EINVAL;
		goto out;
	}

out:
	kfree_safe(buf);
	if (doclose) {
		VNOP_CLOSE(vp, FREAD, ctx);
	}
	if (vp) {
		vnode_put(vp);
		vp = NULL;
	}

	return err;
}

static int
construct_chunklist_path(const char *root_path, char **bufp)
{
	int err = 0;
	char *path = NULL;
	size_t len = 0;

	path = kalloc(MAXPATHLEN);
	if (path == NULL) {
		AUTHPRNT("failed to allocate space for chunklist path");
		err = ENOMEM;
		goto out;
	}

	len = strnlen(root_path, MAXPATHLEN);
	if (len < MAXPATHLEN && len > strlen(".dmg")) {
		/* correctly terminated string with space for extension */
	} else {
		AUTHPRNT("malformed root path");
		err = EINVAL;
		goto out;
	}

	len = strlcpy(path, root_path, MAXPATHLEN);
	if (len >= MAXPATHLEN) {
		AUTHPRNT("root path is too long");
		err = EINVAL;
		goto out;
	}

	path[len - strlen(".dmg")] = '\0';
	len = strlcat(path, ".chunklist", MAXPATHLEN);
	if (len >= MAXPATHLEN) {
		AUTHPRNT("chunklist path is too long");
		err = EINVAL;
		goto out;
	}

out:
	if (err) {
		kfree_safe(path);
	} else {
		*bufp = path;
	}
	return err;
}

static int
authenticate_root(const char *root_path)
{
	char *chunklist_path = NULL;
	void *chunklist_buf = NULL;
	size_t chunklist_len = 32 * 1024 * 1024UL;
	int err = 0;

	err = construct_chunklist_path(root_path, &chunklist_path);
	if (err) {
		AUTHPRNT("failed creating chunklist path");
		goto out;
	}

	AUTHDBG("validating root against chunklist %s", chunklist_path);

	/*
	 * Read and authenticate the chunklist, then validate the root image against
	 * the chunklist.
	 */

	AUTHDBG("reading chunklist");
	err = read_file(chunklist_path, &chunklist_buf, &chunklist_len);
	if (err) {
		AUTHPRNT("failed to read chunklist");
		goto out;
	}

	AUTHDBG("validating chunklist");
	err = validate_chunklist(chunklist_buf, chunklist_len);
	if (err < 0) {
		AUTHDBG("missing or incorrect signature on chunklist");
		goto out;
	} else if (err) {
		AUTHPRNT("failed to validate chunklist");
		goto out;
	} else {
		AUTHDBG("successfully validated chunklist");
	}

	AUTHDBG("validating root image against chunklist");
	err = validate_root_image(root_path, chunklist_buf);
	if (err) {
		AUTHPRNT("failed to validate root image against chunklist (%d)", err);
		goto out;
	}

	/* everything checked out - go ahead and mount this */
	AUTHDBG("root image authenticated");

out:
	kfree_safe(chunklist_buf);
	kfree_safe(chunklist_path);
	return err;
}

static const uuid_t *
getuuidfromheader_safe(const void *buf, size_t bufsz, size_t *uuidsz)
{
	const struct uuid_command *cmd = NULL;
	const kernel_mach_header_t *mh = buf;

	/* space for the header and at least one load command? */
	if (bufsz < sizeof(kernel_mach_header_t) + sizeof(struct uuid_command)) {
		AUTHPRNT("libkern image too small");
		return NULL;
	}

	/* validate the mach header */
	if (mh->magic != MH_MAGIC_64 || (mh->sizeofcmds > bufsz - sizeof(kernel_mach_header_t))) {
		AUTHPRNT("invalid MachO header");
		return NULL;
	}

	/* iterate the load commands */
	size_t offset = sizeof(kernel_mach_header_t);
	for (size_t i = 0; i < mh->ncmds; i++) {
		cmd = buf + offset;

		if (cmd->cmd == LC_UUID) {
			*uuidsz = sizeof(cmd->uuid);
			return &cmd->uuid;
		}

		if (os_add_overflow(cmd->cmdsize, offset, &offset) ||
		    offset > bufsz - sizeof(struct uuid_command)) {
			return NULL;
		}
	}

	return NULL;
}

static const char *libkern_path = "/System/Library/Extensions/System.kext/PlugIns/Libkern.kext/Libkern";
static const char *libkern_bundle = "com.apple.kpi.libkern";

/*
 * Check that the UUID of the libkern currently loaded matches the one on disk.
 */
static int
auth_version_check(void)
{
	int err = 0;
	void *buf = NULL;
	size_t bufsz = 4 * 1024 * 1024UL;

	/* get the UUID of the libkern in /S/L/E */

	err = read_file(libkern_path, &buf, &bufsz);
	if (err) {
		goto out;
	}

	unsigned long uuidsz = 0;
	const uuid_t *img_uuid = getuuidfromheader_safe(buf, bufsz, &uuidsz);
	if (img_uuid == NULL || uuidsz != sizeof(uuid_t)) {
		AUTHPRNT("invalid UUID (sz = %lu)", uuidsz);
		err = EINVAL;
		goto out;
	}

	/* Get the UUID of the loaded libkern */
	uuid_t live_uuid;
	err = OSKextGetUUIDForName(libkern_bundle, live_uuid);
	if (err) {
		AUTHPRNT("could not find loaded libkern");
		goto out;
	}

	/* ... and compare them */
	if (bcmp(live_uuid, img_uuid, uuidsz) != 0) {
		AUTHPRNT("UUID of running libkern does not match %s", libkern_path);

		uuid_string_t img_uuid_str, live_uuid_str;
		uuid_unparse(*img_uuid, img_uuid_str);
		uuid_unparse(live_uuid, live_uuid_str);
		AUTHPRNT("loaded libkern UUID =  %s", live_uuid_str);
		AUTHPRNT("on-disk libkern UUID = %s", img_uuid_str);

		err = EINVAL;
		goto out;
	}

	/* UUID matches! */

out:
	kfree_safe(buf);
	return err;
}

#if 0
int
auth_imgboot_test(proc_t __unused ap, struct auth_imgboot_test_args *uap, int32_t *retval)
{
	int ret = 0;
	int err;
	char path[MAXPATHLEN];
	vm_size_t len;
	*retval = 0;

	err = copyinstr(uap->path, path, MAXPATHLEN, &len);
	if (err) {
		return err;
	}
	if (len >= MAXPATHLEN) {
		return ENAMETOOLONG;
	}

	AUTHDBG("authenticating root image at %s", path);
	err = authenticate_root(path);
	if (err) {
		AUTHPRNT("root authentication FAIL (%d)", err);
		ret = err;
	} else {
		AUTHDBG("successfully authenticated %s", path);
	}

	AUTHDBG("checking root image version");
	err = auth_version_check();
	if (err) {
		AUTHPRNT("root image version check FAIL (%d)", err);
		err = err ?: ret;
	} else {
		AUTHPRNT("root version check success (%d)", err);
	}

	if (ret < 0) {
		return EINVAL; /* negative return values have special meaning */
	}
	return ret;
}
#endif

/*
 * Attach the image at 'path' as a ramdisk and mount it as our new rootfs.
 * All existing mounts are first umounted.
 */
static int
imageboot_mount_ramdisk(const char *path)
{
	int err = 0;
	size_t bufsz = 0;
	void *buf = NULL;
	dev_t dev;
	vnode_t newdp;
	mount_t new_rootfs;

	/* Read our target image from disk */
	err = read_file(path, &buf, &bufsz);
	if (err) {
		printf("%s: failed: read_file() = %d\n", __func__, err);
		goto out;
	}
	DBG_TRACE("%s: read '%s' sz = %lu\n", __func__, path, bufsz);

#if CONFIG_IMGSRC_ACCESS
	/* Re-add all root mounts to the mount list in the correct order... */
	mount_list_remove(rootvnode->v_mount);
	for (int i = 0; i < MAX_IMAGEBOOT_NESTING; i++) {
		struct vnode *vn = imgsrc_rootvnodes[i];
		if (vn) {
			vnode_getalways(vn);
			imgsrc_rootvnodes[i] = NULLVP;

			mount_t mnt = vn->v_mount;
			mount_lock(mnt);
			mnt->mnt_flag |= MNT_ROOTFS;
			mount_list_add(mnt);
			mount_unlock(mnt);

			vnode_rele(vn);
			vnode_put(vn);
		}
	}
	mount_list_add(rootvnode->v_mount);
#endif

	/* ... and unmount everything */
	vnode_get_and_drop_always(rootvnode);
	filedesc0.fd_cdir = NULL;
	rootvnode = NULL;
	vfs_unmountall();

	/* Attach the ramfs image ... */
	err = di_root_ramfile_buf(buf, bufsz, rootdevice, DEVMAXNAMESIZE, &dev);
	if (err) {
		printf("%s: failed: di_root_ramfile_buf() = %d\n", __func__, err);
		goto out;
	}

	/* ... and mount it */
	rootdev = dev;
	mountroot = NULL;
	err = vfs_mountroot();
	if (err) {
		printf("%s: failed: vfs_mountroot() = %d\n", __func__, err);
		goto out;
	}

	/* Switch to new root vnode */
	if (VFS_ROOT(TAILQ_LAST(&mountlist, mntlist), &newdp, vfs_context_kernel())) {
		panic("%s: cannot find root vnode", __func__);
	}
	rootvnode = newdp;
	rootvnode->v_flag |= VROOT;
	new_rootfs = rootvnode->v_mount;
	mount_lock(new_rootfs);
	new_rootfs->mnt_flag |= MNT_ROOTFS;
	mount_unlock(new_rootfs);

	vnode_ref(newdp);
	vnode_put(newdp);
	filedesc0.fd_cdir = newdp;

	DBG_TRACE("%s: root switched\n", __func__);

out:
	if (err) {
		kfree_safe(buf);
	}
	return err;
}

static boolean_t
imageboot_setup_new()
{
	int error;
	char *root_path = NULL;
	int height = 0;
	boolean_t done = FALSE;
	boolean_t auth_root = FALSE;
	boolean_t ramdisk_root = FALSE;

	MALLOC_ZONE(root_path, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
	assert(root_path != NULL);

	unsigned imgboot_arg;
	if (PE_parse_boot_argn("-rootdmg-ramdisk", &imgboot_arg, sizeof(imgboot_arg))) {
		ramdisk_root = TRUE;
	}

	if (PE_parse_boot_argn(IMAGEBOOT_CONTAINER_ARG, root_path, MAXPATHLEN) == TRUE) {
		printf("%s: container image url is %s\n", __FUNCTION__, root_path);
		error = imageboot_mount_image(root_path, height);
		if (error != 0) {
			panic("Failed to mount container image.");
		}

		height++;
	}

	if (PE_parse_boot_argn(IMAGEBOOT_AUTHROOT_ARG, root_path, MAXPATHLEN) == TRUE) {
		auth_root = TRUE;
	} else if (PE_parse_boot_argn(IMAGEBOOT_ROOT_ARG, root_path, MAXPATHLEN) == FALSE) {
		if (height > 0) {
			panic("%s specified without %s?\n", IMAGEBOOT_CONTAINER_ARG, IMAGEBOOT_ROOT_ARG);
		}
		goto out;
	}

	printf("%s: root image url is %s\n", __func__, root_path);

#if CONFIG_CSR
	if (auth_root && (csr_check(CSR_ALLOW_ANY_RECOVERY_OS) == 0)) {
		AUTHPRNT("CSR_ALLOW_ANY_RECOVERY_OS set, skipping root image authentication");
		auth_root = false;
	}
#endif

	/* Make a copy of the path to URL-decode */
	char *path_alloc = kalloc(MAXPATHLEN);
	if (path_alloc == NULL) {
		panic("imageboot path allocation failed\n");
	}
	char *path = path_alloc;

	size_t len = strlen(kIBFilePrefix);
	strlcpy(path, root_path, MAXPATHLEN);
	if (strncmp(kIBFilePrefix, path, len) == 0) {
		/* its a URL - remove the file:// prefix and percent-decode */
		path += len;
		url_decode(path);
	}

	if (auth_root) {
		AUTHDBG("authenticating root image at %s", path);
		error = authenticate_root(path);
		if (error) {
			panic("root image authentication failed (err = %d)\n", error);
		}
		AUTHDBG("successfully authenticated %s", path);
	}

	if (ramdisk_root) {
		error = imageboot_mount_ramdisk(path);
	} else {
		error = imageboot_mount_image(root_path, height);
	}

	kfree_safe(path_alloc);

	if (error) {
		panic("Failed to mount root image (err=%d, auth=%d, ramdisk=%d)\n",
		    error, auth_root, ramdisk_root);
	}

	if (auth_root) {
		/* check that the image version matches the running kernel */
		AUTHDBG("checking root image version");
		error = auth_version_check();
		if (error) {
			panic("root image version check failed");
		} else {
			AUTHDBG("root image version matches kernel");
		}
	}

	done = TRUE;

out:
	FREE_ZONE(root_path, MAXPATHLEN, M_NAMEI);
	return done;
}

__private_extern__ void
imageboot_setup()
{
	int         error = 0;
	char *root_path = NULL;

	DBG_TRACE("%s: entry\n", __FUNCTION__);

	if (rootvnode == NULL) {
		panic("imageboot_setup: rootvnode is NULL.");
	}

	/*
	 * New boot-arg scheme:
	 *      root-dmg : the dmg that will be the root filesystem.
	 *      auth-root-dmg : same as root-dmg but with image authentication.
	 *      container-dmg : an optional dmg that contains the root-dmg.
	 */
	if (imageboot_setup_new()) {
		return;
	}

	MALLOC_ZONE(root_path, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
	assert(root_path != NULL);

	/*
	 * Look for outermost disk image to root from.  If we're doing a nested boot,
	 * there's some sense in which the outer image never needs to be the root filesystem,
	 * but it does need very similar treatment: it must not be unmounted, needs a fake
	 * device vnode created for it, and should not show up in getfsstat() until exposed
	 * with MNT_IMGSRC. We just make it the temporary root.
	 */
	if ((PE_parse_boot_argn("rp", root_path, MAXPATHLEN) == FALSE) &&
	    (PE_parse_boot_argn("rp0", root_path, MAXPATHLEN) == FALSE)) {
		panic("%s: no valid path to image.\n", __FUNCTION__);
	}

	printf("%s: root image url is %s\n", __FUNCTION__, root_path);

	error = imageboot_mount_image(root_path, 0);
	if (error) {
		panic("Failed on first stage of imageboot.");
	}

	/*
	 * See if we are rooting from a nested image
	 */
	if (PE_parse_boot_argn("rp1", root_path, MAXPATHLEN) == FALSE) {
		goto done;
	}

	printf("%s: second level root image url is %s\n", __FUNCTION__, root_path);

	/*
	 * If we fail to set up second image, it's not a given that we
	 * can safely root off the first.
	 */
	error = imageboot_mount_image(root_path, 1);
	if (error) {
		panic("Failed on second stage of imageboot.");
	}

done:
	FREE_ZONE(root_path, MAXPATHLEN, M_NAMEI);

	DBG_TRACE("%s: exit\n", __FUNCTION__);

	return;
}
