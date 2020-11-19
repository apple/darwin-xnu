/*
 * Copyright (c) 2019-2020 Apple Computer, Inc. All rights reserved.
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
#include <kern/mach_fat.h>

#include <sys/namei.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>
#include <sys/sysproto.h>
#include <sys/csr.h>
#include <miscfs/devfs/devfsdefs.h>
#include <libkern/crypto/sha2.h>
#include <libkern/crypto/rsa.h>
#include <libkern/OSKextLibPrivate.h>

#include <kern/chunklist.h>
#include <kern/kalloc.h>

#include <pexpert/pexpert.h>

#define AUTHDBG(fmt, args...) do { printf("%s: " fmt "\n", __func__, ##args); } while (0)
#define AUTHPRNT(fmt, args...) do { printf("%s: " fmt "\n", __func__, ##args); } while (0)
#define kheap_free_safe(h, x, l) do { if ((x)) { kheap_free(h, x, l); (x) = NULL; } } while (0)

static const char *libkern_path = "/System/Library/Extensions/System.kext/PlugIns/Libkern.kext/Libkern";
static const char *libkern_bundle = "com.apple.kpi.libkern";

extern boolean_t kernelcache_uuid_valid;
extern uuid_t kernelcache_uuid;

#if DEBUG
static const char *bootkc_path = "/System/Library/KernelCollections/BootKernelExtensions.kc.debug";
#elif KASAN
static const char *bootkc_path = "/System/Library/KernelCollections/BootKernelExtensions.kc.kasan";
#elif DEVELOPMENT
static const char *bootkc_path = "/System/Library/KernelCollections/BootKernelExtensions.kc.development";
#else
static const char *bootkc_path = "/System/Library/KernelCollections/BootKernelExtensions.kc";
#endif

/*
 * Rev1 chunklist handling
 */
const struct chunklist_pubkey rev1_chunklist_pubkeys[] = {
};
const size_t rev1_chunklist_num_pubkeys = sizeof(rev1_chunklist_pubkeys) / sizeof(rev1_chunklist_pubkeys[0]);

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
construct_chunklist_path(char path[static MAXPATHLEN], const char *root_path)
{
	size_t len = 0;

	len = strnlen(root_path, MAXPATHLEN);
	if (len < MAXPATHLEN && len > strlen(".dmg")) {
		/* correctly terminated string with space for extension */
	} else {
		AUTHPRNT("malformed root path");
		return EOVERFLOW;
	}

	len = strlcpy(path, root_path, MAXPATHLEN);
	if (len >= MAXPATHLEN) {
		AUTHPRNT("root path is too long");
		return EOVERFLOW;
	}

	path[len - strlen(".dmg")] = '\0';
	len = strlcat(path, ".chunklist", MAXPATHLEN);
	if (len >= MAXPATHLEN) {
		AUTHPRNT("chunklist path is too long");
		return EOVERFLOW;
	}

	return 0;
}

static int
validate_signature(const uint8_t *key_msb, size_t keylen, uint8_t *sig_msb, size_t siglen, uint8_t *digest)
{
	int err = 0;
	bool sig_valid = false;
	uint8_t *sig = NULL;

	const uint8_t exponent[] = { 0x01, 0x00, 0x01 };
	rsa_pub_ctx *rsa_ctx;
	uint8_t *modulus;


	modulus = kheap_alloc(KHEAP_TEMP, keylen, Z_WAITOK | Z_ZERO);
	rsa_ctx = kheap_alloc(KHEAP_TEMP, sizeof(rsa_pub_ctx),
	    Z_WAITOK | Z_ZERO);
	sig = kheap_alloc(KHEAP_TEMP, siglen, Z_WAITOK | Z_ZERO);

	if (modulus == NULL || rsa_ctx == NULL || sig == NULL) {
		err = ENOMEM;
		goto out;
	}

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
		goto out;
	}

out:
	kheap_free_safe(KHEAP_TEMP, sig, siglen);
	kheap_free_safe(KHEAP_TEMP, rsa_ctx, sizeof(*rsa_ctx));
	kheap_free_safe(KHEAP_TEMP, modulus, keylen);

	if (err) {
		return err;
	} else if (sig_valid == true) {
		return 0; /* success */
	} else {
		return EAUTH;
	}
}

static int
validate_root_image(const char *root_path, void *chunklist)
{
	int err = 0;
	struct chunklist_hdr *hdr = chunklist;
	struct chunklist_chunk *chk = NULL;
	size_t ch = 0;
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

	vp = imgboot_get_image_file(root_path, &fsize, &err);
	if (vp == NULL) {
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
			buf = kheap_alloc(KHEAP_TEMP, chk->chunk_size, Z_WAITOK);
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

		err = vn_rdwr(UIO_READ, vp, (caddr_t)buf, chk->chunk_size,
		    offset, UIO_SYSSPACE, IO_NODELOCKED, kerncred, &resid, p);
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
	kheap_free_safe(KHEAP_TEMP, buf, bufsz);
	if (doclose) {
		VNOP_CLOSE(vp, FREAD, ctx);
	}
	if (vp) {
		vnode_put(vp);
		vp = NULL;
	}

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

/*
 * Rev2 chunklist handling
 */
const struct chunklist_pubkey rev2_chunklist_pubkeys[] = {
};
const size_t rev2_chunklist_num_pubkeys = sizeof(rev2_chunklist_pubkeys) / sizeof(rev2_chunklist_pubkeys[0]);

static const struct efi_guid_t gEfiSignAppleCertTypeGuid = CHUNKLIST_REV2_SIG_HASH_GUID;
static const struct efi_guid_t gEfiSignCertTypeRsa2048Sha256Guid = EFI_CERT_TYPE_RSA2048_SHA256;

static boolean_t
validate_rev2_certificate(struct rev2_chunklist_certificate *certificate)
{
	/* Default value of current security epoch MUST be CHUNKLIST_MIN_SECURITY_EPOCH */
	uint8_t current_security_epoch = CHUNKLIST_MIN_SECURITY_EPOCH;

	/* Certificate.Length must be equal to sizeof(CERTIFICATE) */
	if (certificate->length != sizeof(struct rev2_chunklist_certificate)) {
		AUTHDBG("invalid certificate length");
		return FALSE;
	}

	/* Certificate.Revision MUST be equal to 2 */
	if (certificate->revision != 2) {
		AUTHDBG("invalid certificate revision");
		return FALSE;
	}

	/* Certificate.SecurityEpoch MUST be current or higher */
	if (PE_parse_boot_argn(CHUNKLIST_SECURITY_EPOCH, &current_security_epoch, sizeof(current_security_epoch)) &&
	    certificate->security_epoch < current_security_epoch) {
		AUTHDBG("invalid certificate security epoch");
		return FALSE;
	}

	/* Certificate.CertificateType MUST be equal to WIN_CERT_TYPE_EFI_GUID (0x0EF1) */
	if (certificate->certificate_type != WIN_CERT_TYPE_EFI_GUID) {
		AUTHDBG("invalid certificate type");
		return FALSE;
	}

	/* Certificate.CertificateGuid MUST be equal to 45E7BC51-913C-42AC-96A2-10712FFBEBA7 */
	if (0 != memcmp(&certificate->certificate_guid, &gEfiSignAppleCertTypeGuid, sizeof(struct efi_guid_t))) {
		AUTHDBG("invalid certificate GUID");
		return FALSE;
	}

	/* Certificate.HashTypeGuid MUST be equal to A7717414-C616-4977-9420-844712A735BF */
	if (0 != memcmp(&certificate->hash_type_guid, &gEfiSignCertTypeRsa2048Sha256Guid, sizeof(struct efi_guid_t))) {
		AUTHDBG("invalid hash type GUID");
		return FALSE;
	}

	return TRUE;
}

static int
validate_rev2_chunklist(uint8_t *buffer, size_t buffer_size)
{
	struct rev2_chunklist_certificate *certificate;
	size_t security_data_offset;

	/* Check input parameters to be sane */
	if (buffer == NULL || buffer_size == 0) {
		AUTHDBG("invalid parameter");
		return EINVAL;
	}

	/* Check for existing signature */
	if (buffer_size < sizeof(struct rev2_chunklist_certificate)) {
		AUTHDBG("no space for certificate");
		return EINVAL;
	}

	security_data_offset = buffer_size - sizeof(struct rev2_chunklist_certificate);
	certificate = (struct rev2_chunklist_certificate*)(buffer + security_data_offset);

	/* Check signature candidate to be a valid rev2 chunklist certificate */
	if (TRUE != validate_rev2_certificate(certificate)) {
		return EINVAL;
	}

	/* Check public key to be trusted */
	for (size_t i = 0; i < rev2_chunklist_num_pubkeys; i++) {
		const struct chunklist_pubkey *key = &rev2_chunklist_pubkeys[i];
		/* Production keys are always trusted */
		if (key->is_production != TRUE) {
			uint8_t no_rev2_dev = 0;
			/* Do not trust rev2 development keys if CHUNKLIST_NO_REV2_DEV is present */
			if (PE_parse_boot_argn(CHUNKLIST_NO_REV2_DEV, &no_rev2_dev, sizeof(no_rev2_dev))) {
				AUTHDBG("rev2 development key is not trusted");
				continue;
			}
		}

		/* Check certificate public key to be the trusted one */
		if (0 == memcmp(key->key, certificate->rsa_public_key, sizeof(certificate->rsa_public_key))) {
			AUTHDBG("certificate public key is trusted");

			/* Hash everything but signature */
			SHA256_CTX hash_ctx;
			SHA256_Init(&hash_ctx);
			SHA256_Update(&hash_ctx, buffer, security_data_offset);

			/* Include Certificate.SecurityEpoch value */
			SHA256_Update(&hash_ctx, &certificate->security_epoch, sizeof(certificate->security_epoch));

			/* Finalize hashing into the output buffer */
			uint8_t sha_digest[SHA256_DIGEST_LENGTH];
			SHA256_Final(sha_digest, &hash_ctx);

			/* Validate signature */
			return validate_signature(certificate->rsa_public_key,
			           sizeof(certificate->rsa_public_key),
			           certificate->rsa_signature,
			           sizeof(certificate->rsa_signature),
			           sha_digest);
		}
	}

	AUTHDBG("certificate public key is not trusted");
	return EINVAL;
}

/*
 * Main chunklist validation routine
 */
static int
validate_chunklist(void *buf, size_t len)
{
	int err = 0;
	size_t sigsz = 0;
	size_t sig_end = 0;
	size_t chunks_end = 0;
	size_t sig_len = 0;
	boolean_t valid_sig = FALSE;
	struct chunklist_hdr *hdr = buf;

	if (len < sizeof(struct chunklist_hdr)) {
		AUTHPRNT("no space for header");
		return EINVAL;
	}

	/* recognized file format? */
	if (hdr->cl_magic != CHUNKLIST_MAGIC ||
	    hdr->cl_file_ver != CHUNKLIST_FILE_VERSION_10 ||
	    hdr->cl_chunk_method != CHUNKLIST_CHUNK_METHOD_10) {
		AUTHPRNT("unrecognized chunklist format");
		return EINVAL;
	}

	/* determine signature length based on signature method */
	if (hdr->cl_sig_method == CHUNKLIST_SIGNATURE_METHOD_REV1) {
		AUTHPRNT("rev1 chunklist");
		sig_len = CHUNKLIST_REV1_SIG_LEN;
	} else if (hdr->cl_sig_method == CHUNKLIST_SIGNATURE_METHOD_REV2) {
		AUTHPRNT("rev2 chunklist");
		sig_len = CHUNKLIST_REV2_SIG_LEN;
	} else {
		AUTHPRNT("unrecognized chunklist signature method");
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
	if (os_add_overflow(hdr->cl_sig_offset, sig_len, &sig_end) ||
	    hdr->cl_sig_offset < sizeof(struct chunklist_hdr) ||
	    hdr->cl_sig_offset < chunks_end ||
	    hdr->cl_sig_offset > len) {
		AUTHPRNT("invalid signature offset (%llu)", hdr->cl_sig_offset);
		return EINVAL;
	}

	if (sig_end > len ||
	    os_sub_overflow(len, hdr->cl_sig_offset, &sigsz) ||
	    sigsz != sig_len) {
		/* missing or incorrect signature size */
		return EINVAL;
	}

	/* validate rev1 chunklist */
	if (hdr->cl_sig_method == CHUNKLIST_SIGNATURE_METHOD_REV1) {
		/* Do not trust rev1 chunklists if CHUNKLIST_NO_REV1 is present */
		uint8_t no_rev1;
		if (PE_parse_boot_argn(CHUNKLIST_NO_REV1, &no_rev1, sizeof(no_rev1))) {
			AUTHDBG("rev1 chunklists are not trusted");
			return EINVAL;
		}

		/* hash the chunklist (excluding the signature) */
		AUTHDBG("hashing rev1 chunklist");
		uint8_t sha_digest[SHA256_DIGEST_LENGTH];
		SHA256_CTX sha_ctx;
		SHA256_Init(&sha_ctx);
		SHA256_Update(&sha_ctx, buf, hdr->cl_sig_offset);
		SHA256_Final(sha_digest, &sha_ctx);

		AUTHDBG("validating rev1 chunklist signature against rev1 pub keys");
		for (size_t i = 0; i < rev1_chunklist_num_pubkeys; i++) {
			const struct chunklist_pubkey *key = &rev1_chunklist_pubkeys[i];
			err = validate_signature(key->key, CHUNKLIST_PUBKEY_LEN, buf + hdr->cl_sig_offset, CHUNKLIST_SIGNATURE_LEN, sha_digest);
			if (err == 0) {
				AUTHDBG("validated rev1 chunklist signature with rev1 key %lu (prod=%d)", i, key->is_production);
				valid_sig = key->is_production;
#if IMAGEBOOT_ALLOW_DEVKEYS
				if (!key->is_production) {
					/* allow dev keys in dev builds only */
					AUTHDBG("*** allowing DEV rev1 key: this will fail in customer builds ***");
					valid_sig = TRUE;
				}
#endif
				goto out;
			}
		}

		/* At this point we tried all the keys: nothing went wrong but none of them
		 * signed our chunklist. */
		AUTHPRNT("rev1 signature did not verify against any known rev1 public key");
	} else if (hdr->cl_sig_method == CHUNKLIST_SIGNATURE_METHOD_REV2) {
		AUTHDBG("validating rev2 chunklist signature against rev2 pub keys");
		err = validate_rev2_chunklist(buf, len);
		if (err) {
			goto out;
		}
		valid_sig = TRUE;
	}

out:
	if (err) {
		return err;
	} else if (valid_sig == TRUE) {
		return 0; /* signed, and everything checked out */
	} else {
		return EINVAL;
	}
}

/*
 * Authenticate a given DMG file using chunklist
 */
int
authenticate_root_with_chunklist(const char *rootdmg_path, boolean_t *out_enforced)
{
	char *chunklist_path = NULL;
	void *chunklist_buf = NULL;
	size_t chunklist_len = 32 * 1024 * 1024UL;
	boolean_t enforced = TRUE;
	int err = 0;

	chunklist_path = zalloc(ZV_NAMEI);
	err = construct_chunklist_path(chunklist_path, rootdmg_path);
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
	err = imageboot_read_file(KHEAP_TEMP, chunklist_path, &chunklist_buf, &chunklist_len);
	if (err) {
		AUTHPRNT("failed to read chunklist");
		goto out;
	}

	AUTHDBG("validating chunklist");
	err = validate_chunklist(chunklist_buf, chunklist_len);
	if (err) {
		AUTHPRNT("failed to validate chunklist");
		goto out;
	}
	AUTHDBG("successfully validated chunklist");

	AUTHDBG("validating root image against chunklist");
	err = validate_root_image(rootdmg_path, chunklist_buf);
	if (err) {
		AUTHPRNT("failed to validate root image against chunklist (%d)", err);
		goto out;
	}

	/* everything checked out - go ahead and mount this */
	AUTHDBG("root image authenticated");

out:
#if CONFIG_CSR
	if (err && (csr_check(CSR_ALLOW_ANY_RECOVERY_OS) == 0)) {
		AUTHPRNT("CSR_ALLOW_ANY_RECOVERY_OS set, allowing unauthenticated root image");
		err = 0;
		enforced = FALSE;
	}
#endif

	if (out_enforced != NULL) {
		*out_enforced = enforced;
	}
	kheap_free_safe(KHEAP_TEMP, chunklist_buf, chunklist_len);
	zfree(ZV_NAMEI, chunklist_path);
	return err;
}

int
authenticate_root_version_check(void)
{
	kc_format_t kc_format;
	if (PE_get_primary_kc_format(&kc_format) && kc_format == KCFormatFileset) {
		return authenticate_bootkc_uuid();
	} else {
		return authenticate_libkern_uuid();
	}
}

/*
 * Check that the UUID of the boot KC currently loaded matches the one on disk.
 */
int
authenticate_bootkc_uuid(void)
{
	int err = 0;
	void *buf = NULL;
	size_t bufsz = 1 * 1024 * 1024UL;

	/* get the UUID of the bootkc in /S/L/KC */
	err = imageboot_read_file(KHEAP_TEMP, bootkc_path, &buf, &bufsz);
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

	if (!kernelcache_uuid_valid) {
		AUTHPRNT("Boot KC UUID was not set at boot.");
		err = EINVAL;
		goto out;
	}

	/* ... and compare them */
	if (bcmp(&kernelcache_uuid, img_uuid, uuidsz) != 0) {
		AUTHPRNT("UUID of running bootkc does not match %s", bootkc_path);

		uuid_string_t img_uuid_str, live_uuid_str;
		uuid_unparse(*img_uuid, img_uuid_str);
		uuid_unparse(kernelcache_uuid, live_uuid_str);
		AUTHPRNT("loaded bootkc UUID =  %s", live_uuid_str);
		AUTHPRNT("on-disk bootkc UUID = %s", img_uuid_str);

		err = EINVAL;
		goto out;
	}

	/* UUID matches! */
out:
	kheap_free_safe(KHEAP_TEMP, buf, bufsz);
	return err;
}

/*
 * Check that the UUID of the libkern currently loaded matches the one on disk.
 */
int
authenticate_libkern_uuid(void)
{
	int err = 0;
	void *buf = NULL;
	size_t bufsz = 4 * 1024 * 1024UL;

	/* get the UUID of the libkern in /S/L/E */
	err = imageboot_read_file(KHEAP_TEMP, libkern_path, &buf, &bufsz);
	if (err) {
		goto out;
	}

	if (fatfile_validate_fatarches((vm_offset_t)buf, bufsz) == LOAD_SUCCESS) {
		struct fat_header *fat_header = buf;
		struct fat_arch fat_arch;
		if (fatfile_getbestarch((vm_offset_t)fat_header, bufsz, NULL, &fat_arch, FALSE) != LOAD_SUCCESS) {
			err = EINVAL;
			goto out;
		}
		kheap_free_safe(KHEAP_TEMP, buf, bufsz);
		buf = NULL;
		bufsz = MIN(fat_arch.size, 4 * 1024 * 1024UL);
		err = imageboot_read_file_from_offset(KHEAP_TEMP, libkern_path, fat_arch.offset, &buf, &bufsz);
		if (err) {
			goto out;
		}
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
	kheap_free_safe(KHEAP_TEMP, buf, bufsz);
	return err;
}
