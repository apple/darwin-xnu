/*
 * Copyright (c) 2001 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * "Portions Copyright (c) 1999 Apple Computer, Inc.  All Rights
 * Reserved.  This file contains Original Code and/or Modifications of
 * Original Code as defined in and that are subject to the Apple Public
 * Source License Version 1.0 (the 'License').  You may not use this file
 * except in compliance with the License.  Please obtain a copy of the
 * License at http://www.apple.com/publicsource and read it before using
 * this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License."
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * History:
 *  2001-05-30 	gvdl	Initial implementation of the vtable patcher.
 */
// 45678901234567890123456789012345678901234567890123456789012345678901234567890

#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>

#if KERNEL

#include <stdarg.h>
#include <string.h>

#include <sys/systm.h>

#include <libkern/OSTypes.h>

#include <libsa/stdlib.h>
#include <libsa/mach/mach.h>

#include "mach_loader.h"

#include <vm/vm_kern.h>

enum { false = 0, true = 1 };

#define vm_page_size page_size

extern load_return_t fatfile_getarch(
    void            * vp,       // normally a (struct vnode *)
    vm_offset_t       data_ptr,
    struct fat_arch * archret);

#else /* !KERNEL */
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/errno.h> 
#include <sys/fcntl.h>
#include <sys/stat.h>   
#include <sys/mman.h>   

#include <mach/mach.h>
#include <mach/mach_error.h>

#include <mach-o/arch.h>

#include <CoreFoundation/CoreFoundation.h>
 
#endif /* KERNEL */

#include "kld_patch.h"

#if 0
static __inline__ void DIE(void) { IODelay(2000000000); }

#define LOG_DELAY()	IODelay(200000)
#define DEBUG_LOG(x)	do { IOLog x; LOG_DELAY(); } while(0)
#else

#define DIE()
#define LOG_DELAY()
#define DEBUG_LOG(x)

#endif

// OSObject symbol prefixes and suffixes
#define kVTablePrefix		"___vt"
#define kReservedPrefix		"__RESERVED"
#define kSuperClassSuffix	".superClass"
#define kGMetaSuffix		".gMetaClass"
#define kLinkEditSegName	SEG_LINKEDIT

// GCC 2.95 drops 2 leading constants in the vtable
#define kVTablePreambleLen 2

// Last address that I'm willing to try find vm in
#define kTopAddr  ((unsigned char *) (1024 * 1024 * 1024))

// Size in bytes that Data Ref object's get increased in size
// Must be a power of 2
#define kDataCapacityIncrement 128

// My usual set of helper macros.  I personally find these macros
// easier to read in the code rather than an explicit error condition
// check.  If I don't make it easy then I may get lazy ond not check
// everything.  I'm sorry if you find this code harder to read.

// break_if will evaluate the expression and if it is true
// then it will print the msg, which is enclosed in parens
// and then break.  Usually used in loops are do { } while (0)
#define break_if(expr, msg) 					\
    if (expr) {							\
	errprintf msg;						\
        break;							\
    }

// return_if will evaluate expr and if true it will log the
// msg, which is enclosed in parens, and then it will return
// with the return code of ret.
#define return_if(expr, ret, msg) do {				\
    if (expr) {							\
	errprintf msg;						\
        return ret;						\
    }								\
} while (0)

#ifndef MIN
#define	MIN(a,b) (((a)<(b))?(a):(b))
#endif /* MIN */
#ifndef MAX
#define	MAX(a,b) (((a)>(b))?(a):(b))
#endif /* MAX */

typedef struct Data {
    unsigned long fLength, fCapacity;
    unsigned char *fData;
} Data, *DataRef;

struct sectionRecord {
    const struct section *fSection;
    DataRef fRelocCache;
};

enum patchState {
    kSymbolIdentical,
    kSymbolLocal,
    kSymbolPadUpdate,
    kSymbolSuperUpdate,
    kSymbolMismatch
};

struct patchRecord {
    struct nlist *fSymbol;
    enum patchState fType;
};

struct relocRecord {
    void *fValue;
    const struct nlist *fSymbol;
    struct relocation_info *fRInfo;
    void *reserved;
};

struct metaClassRecord {
    char *fSuperName;
    struct fileRecord *fFile;
    const struct nlist *fVTableSym;
    struct patchRecord *fPatchedVTable;
    char fClassName[1];
};

struct fileRecord {
    size_t fMapSize, fMachOSize;
    const char *fPath;
    unsigned char *fMap, *fMachO, *fPadEnd;
    DataRef fClassList;
    DataRef fSectData;
    DataRef fNewSymbols, fNewStrings;
    struct symtab_command *fSymtab;
    struct sectionRecord *fSections;
    char *fStringBase;
    struct nlist *fSymbolBase;
    const struct nlist *fLocalSyms;
    unsigned int fNSects;
    int fNLocal;
    int fNewStringsLen;
    Boolean fIsKernel, fNoKernelExecutable, fIsKmem;
    Boolean fImageDirty, fSymbolsDirty;
};

static DataRef sFilesTable;
static struct fileRecord *sKernelFile;

static DataRef sMergedFiles;
static DataRef sMergeMetaClasses;
static Boolean sMergedKernel;

static void errprintf(const char *fmt, ...)
{
    extern void kld_error_vprintf(const char *format, va_list ap);

    va_list ap;

    va_start(ap, fmt);
    kld_error_vprintf(fmt, ap);
    va_end(ap);

DIE();
}

static __inline__ unsigned long DataGetLength(DataRef data)
{
    return data->fLength;
}

static __inline__ unsigned char *DataGetPtr(DataRef data)
{
    return data->fData;
}


static __inline__ Boolean DataContainsAddr(DataRef data, void *vAddr)
{
    unsigned char *addr = vAddr;

    return (data->fData <= addr) && (addr < data->fData + data->fLength);
}

static __inline__ Boolean DataAddLength(DataRef data, unsigned long length)
{
    static Boolean DataSetLength(DataRef data, unsigned long length);
    return DataSetLength(data, data->fLength + length);
}

static __inline__ Boolean
DataAppendBytes(DataRef data, const void *addr, unsigned int len)
{
    unsigned long size = DataGetLength(data);

    if (!DataAddLength(data, len))
	return false;

    bcopy(addr, DataGetPtr(data) + size, len);
    return true;
}

static __inline__ Boolean DataAppendData(DataRef dst, DataRef src)
{
    return DataAppendBytes(dst, DataGetPtr(src), DataGetLength(src));
}

static Boolean DataSetLength(DataRef data, unsigned long length)
{
    // Don't bother to ever shrink a data object.
    if (length > data->fCapacity) {
	unsigned char *newData;
	unsigned long newCapacity;

	newCapacity  = length + kDataCapacityIncrement - 1;
	newCapacity &= ~(kDataCapacityIncrement - 1);
	newData = (unsigned char *) realloc(data->fData, newCapacity);
	if (!newData)
	    return false;

	bzero(newData + data->fCapacity, newCapacity - data->fCapacity);
	data->fData = newData;
	data->fCapacity = newCapacity;
    }

    data->fLength = length;
    return true;
}

static DataRef DataCreate(unsigned long length)
{
    DataRef data = (DataRef) malloc(sizeof(Data));

    if (data) {
	if (!length)
	    data->fCapacity = kDataCapacityIncrement;
	else {
	    data->fCapacity  = length + kDataCapacityIncrement - 1;
	    data->fCapacity &= ~(kDataCapacityIncrement - 1);
	}

	data->fData = (unsigned char *) malloc(data->fCapacity);
	if (!data->fData) {
	    free(data);
	    return NULL;
	}

	bzero(data->fData, data->fCapacity);
	data->fLength = length;
    }
    return data;
}

static void DataRelease(DataRef data)
{
    if (data) {
	if (data->fData)
	    free(data->fData);
	data->fData = 0;
	free(data);
    }
}

static const char *
symbolname(const struct fileRecord *file, const struct nlist *sym)
{
    unsigned long strsize;
    long strx = sym->n_un.n_strx;

    if (strx >= 0)
	return file->fStringBase + strx;

    strsize = file->fSymtab->strsize;
    strx = -strx;
    if (strx < strsize)
	return file->fStringBase + strx;

    strx -= strsize;
    return (char *) DataGetPtr(file->fNewStrings) + strx;
}

static struct fileRecord *getFile(const char *path)
{
    if (sFilesTable) {
	int i, nfiles;
	struct fileRecord **files;

        // Check to see if we have already merged this file
	nfiles = DataGetLength(sFilesTable) / sizeof(struct fileRecord *);
	files = (struct fileRecord **) DataGetPtr(sFilesTable);
	for (i = 0; i < nfiles; i++) {
	    if (!strcmp(path, files[i]->fPath))
		return files[i];
	}
    }

    return NULL;
}

static struct fileRecord * addFile(struct fileRecord *file)
{
    struct fileRecord *newFile;

    if (!sFilesTable) {
	sFilesTable = DataCreate(0);
	if (!sFilesTable)
	    return NULL;
    }

    newFile = (struct fileRecord *) malloc(sizeof(struct fileRecord));
    if (!newFile)
	return NULL;

    if (!DataAppendBytes(sFilesTable, &newFile, sizeof(newFile))) {
	free(newFile);
	return NULL;
    }

    bcopy(file, newFile, sizeof(struct fileRecord));
    return newFile;
}

// @@@ gvdl: need to clean up the sMergeMetaClasses
// @@@ gvdl: I had better fix the object file up again
static void removeFile(struct fileRecord *file)
{
    if (file->fClassList) {
	DataRelease(file->fClassList);
	file->fClassList = 0;
    }

    if (file->fSectData) {
	struct sectionRecord *section;
	unsigned int i, nsect;

	nsect = file->fNSects;
	section = file->fSections;
	for (i = 0; i < nsect; i++, section++) {
	    if (section->fRelocCache) {
		DataRelease(section->fRelocCache);
		section->fRelocCache = 0;
	    }
	}

	DataRelease(file->fSectData);
	file->fSectData = 0;
	file->fSections = 0;
	file->fNSects = 0;
    }

    if (file->fMap) {
#if KERNEL
	if (file->fIsKmem)
	    kmem_free(kernel_map, (vm_address_t) file->fMap, file->fMapSize);
#else /* !KERNEL */
	if (file->fPadEnd) {
	    vm_address_t padVM;
	    vm_size_t padSize;

	    padVM = round_page((vm_address_t) file->fMap + file->fMapSize);
	    padSize  = (vm_size_t) ((vm_address_t) file->fPadEnd - padVM);
	    (void) vm_deallocate(mach_task_self(), padVM, padSize);
	    file->fPadEnd = 0;
	}

	(void) munmap((caddr_t) file->fMap, file->fMapSize);
#endif /* !KERNEL */
	file->fMap = 0;
    }

    file->fPath = 0;
}

#if !KERNEL
static Boolean
mapObjectFile(struct fileRecord *file)
{
    Boolean result = false;
    static unsigned char *sFileMapBaseAddr;

    int fd = 0;

    if (!sFileMapBaseAddr) {
        kern_return_t ret;
	vm_address_t probeAddr;

	// If we don't already have a base addr find any random chunk
	// of 32 meg of VM and to use the 16 meg boundrary as a base.
        ret = vm_allocate(mach_task_self(), &probeAddr,
			    32 * 1024 * 1024, VM_FLAGS_ANYWHERE);
	return_if(KERN_SUCCESS != ret, false,
	    ("Unable to allocate base memory %s\n", mach_error_string(ret)));
        (void) vm_deallocate(mach_task_self(), probeAddr, 32 * 1024 * 1024);

	// Now round to the next 16 Meg boundrary
	probeAddr = (probeAddr +  (16 * 1024 * 1024 - 1))
		               & ~(16 * 1024 * 1024 - 1);
	sFileMapBaseAddr = (unsigned char *) probeAddr;
    }

    fd = open(file->fPath, O_RDONLY, 0);
    return_if(fd == -1, false, ("Can't open %s for reading - %s\n",
	file->fPath, strerror(errno)));

    do {
	kern_return_t ret;
	struct stat sb;
	int retaddr = -1;

	break_if(fstat(fd, &sb) == -1,
	    ("Can't stat %s - %s\n", file->fPath, strerror(errno)));

	file->fMapSize = sb.st_size;
	file->fMap = sFileMapBaseAddr;
	ret = KERN_SUCCESS;
	while (file->fMap < kTopAddr) {
	    vm_address_t padVM;
	    vm_address_t padVMEnd;
	    vm_size_t padSize;

	    padVM = round_page((vm_address_t) file->fMap + file->fMapSize);
	    retaddr = (int) mmap(file->fMap, file->fMapSize,
				 PROT_READ|PROT_WRITE, 
				 MAP_FIXED|MAP_FILE|MAP_PRIVATE,
				 fd, 0);
	    if (-1 == retaddr) {
		break_if(ENOMEM != errno,
		    ("mmap failed %d - %s\n", errno, strerror(errno)));

		file->fMap = (unsigned char *) padVM;
		continue;
	    }


	    // Round up padVM to the next page after the file and assign at
	    // least another fMapSize more room rounded up to the next page
	    // boundary.
	    padVMEnd = round_page(padVM + file->fMapSize);
	    padSize  = padVMEnd - padVM;
	    ret = vm_allocate(
		mach_task_self(), &padVM, padSize, VM_FLAGS_FIXED);
	    if (KERN_SUCCESS == ret) {
		file->fPadEnd = (unsigned char *) padVMEnd;
		break;
	    }
	    else {
		munmap(file->fMap, file->fMapSize);
		break_if(KERN_INVALID_ADDRESS != ret,
		    ("Unable to allocate pad vm for %s - %s\n",
			file->fPath, mach_error_string(ret)));

		file->fMap = (unsigned char *) padVMEnd;
		continue; // try again wherever the vm system wants
	    }
	}

	if (-1 == retaddr || KERN_SUCCESS != ret)
	    break;

	break_if(file->fMap >= kTopAddr,
	    ("Unable to map memory %s\n", file->fPath));

	sFileMapBaseAddr = file->fPadEnd;
	result = true;
    } while(0);

    close(fd);
    return result;
}
#endif /* !KERNEL */

static Boolean findBestArch(struct fileRecord *file)
{
    unsigned long magic;
    struct fat_header *fat;


    file->fMachOSize = file->fMapSize;
    file->fMachO = file->fMap;
    magic = ((const struct mach_header *) file->fMachO)->magic;
    fat = (struct fat_header *) file->fMachO;

    // Try to figure out what type of file this is
    return_if(file->fMapSize < sizeof(unsigned long), false,
	("%s isn't a valid object file - no magic\n", file->fPath));

#if KERNEL

    // CIGAM is byte-swapped MAGIC
    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {

        load_return_t load_return;
        struct fat_arch fatinfo;

        load_return = fatfile_getarch(NULL, (vm_address_t) fat, &fatinfo);
	return_if(load_return != LOAD_SUCCESS, false,
	    ("Extension \"%s\": has no code for this computer\n", file->fPath));

	file->fMachO = file->fMap + fatinfo.offset;
	file->fMachOSize = fatinfo.size;
	magic = ((const struct mach_header *) file->fMachO)->magic;
    }

#else /* !KERNEL */

    // Do we need to in-place swap the endianness of the fat header?
    if (magic == FAT_CIGAM) {
	unsigned long i;
	struct fat_arch *arch;

	fat->nfat_arch = NXSwapBigLongToHost(fat->nfat_arch);
	return_if(file->fMapSize < sizeof(struct fat_header)
				    + fat->nfat_arch * sizeof(struct fat_arch),
	    false, ("%s is too fat\n", file->fPath));

	arch = (struct fat_arch *) &fat[1];
	for (i = 0; i < fat->nfat_arch; i++) {
	    arch[i].cputype    = NXSwapBigLongToHost(arch[i].cputype);
	    arch[i].cpusubtype = NXSwapBigLongToHost(arch[i].cpusubtype);
	    arch[i].offset     = NXSwapBigLongToHost(arch[i].offset);
	    arch[i].size       = NXSwapBigLongToHost(arch[i].size);
	    arch[i].align      = NXSwapBigLongToHost(arch[i].align);
	}

	magic = NXSwapBigLongToHost(fat->magic);
    }

    // Now see if we can find any valid architectures
    if (magic == FAT_MAGIC) {
	const NXArchInfo *myArch;
	unsigned long fatsize;
	struct fat_arch *arch;

	fatsize = sizeof(struct fat_header)
	    + fat->nfat_arch * sizeof(struct fat_arch);
	return_if(file->fMapSize < fatsize,
	    false, ("%s isn't a valid fat file\n", file->fPath));

	myArch = NXGetLocalArchInfo();
	arch = NXFindBestFatArch(myArch->cputype, myArch->cpusubtype,
		(struct fat_arch *) &fat[1], fat->nfat_arch);
	return_if(!arch,
	    false, ("%s hasn't got arch for %s\n", file->fPath, myArch->name));
	return_if(arch->offset + arch->size > file->fMapSize,
	    false, ("%s's %s arch is incomplete\n", file->fPath, myArch->name));
	file->fMachO = file->fMap + arch->offset;
	file->fMachOSize = arch->size;
	magic = ((const struct mach_header *) file->fMachO)->magic;
    }

#endif /* KERNEL */

    return_if(magic != MH_MAGIC,
	false, ("%s isn't a valid mach-o\n", file->fPath));

    return true;
}

static Boolean
parseSegments(struct fileRecord *file, struct segment_command *seg)
{
    struct sectionRecord *sections;
    int i, nsects = seg->nsects;
    const struct segmentMap {
	struct segment_command seg;
	const struct section sect[1];
    } *segMap;

    if (!nsects) {
#if KERNEL
	// We don't need to look for the LinkEdit segment unless
	// we are running in the kernel environment.
	if (!strcmp(kLinkEditSegName, seg->segname)) {
	    // Grab symbol table from linkedit we will need this later
	    file->fSymbolBase = (void *) seg;
	}
#endif

	return true; 	// Nothing more to do, so that was easy.
    }

    if (!file->fSectData) {
	file->fSectData = DataCreate(0);
	if (!file->fSectData)
	    return false;
    }

    // Increase length of section DataRef and cache data pointer
    if (!DataAddLength(file->fSectData, nsects * sizeof(struct sectionRecord)))
	return false;
    file->fSections = (struct sectionRecord *) DataGetPtr(file->fSectData);

    // Initialise the new sections
    sections = &file->fSections[file->fNSects];
    file->fNSects += nsects;
    for (i = 0, segMap = (struct segmentMap *) seg; i < nsects; i++)
	sections[i].fSection = &segMap->sect[i];

    return true;
}

// @@@ gvdl:  These functions need to be hashed they are
// going to be way too slow for production code.
static const struct nlist *
findSymbolByAddress(const struct fileRecord *file, void *entry)
{
    // not quite so dumb linear search of all symbols
    const struct nlist *sym;
    int i, nsyms;

    // First try to find the symbol in the most likely place which is the
    // extern symbols
    sym = file->fLocalSyms;
    for (i = 0, nsyms = file->fNLocal; i < nsyms; i++, sym++) {
	if (sym->n_value == (unsigned long) entry && !(sym->n_type & N_STAB) )
	    return sym;
    }

    // Didn't find it in the external symbols so try to local symbols before
    // giving up.
    sym = file->fSymbolBase;
    for (i = 0, nsyms = file->fSymtab->nsyms; i < nsyms; i++, sym++) {
	if ( (sym->n_type & N_EXT) )
	    return NULL;
	if ( sym->n_value == (unsigned long) entry && !(sym->n_type & N_STAB) )
	    return sym;
    }

    return NULL;
}

struct searchContext {
    const char *fSymname;
    const char *fStrbase;
};

static int symbolSearch(const void *vKey, const void *vSym)
{
    const struct searchContext *key = (const struct searchContext *) vKey;
    const struct nlist *sym = (const struct nlist *) vSym;

    return strcmp(key->fSymname, key->fStrbase + sym->n_un.n_strx);
}

static const struct nlist *
findSymbolByName(struct fileRecord *file, const char *symname)
{
    struct searchContext context;

    context.fSymname = symname;
    context.fStrbase = file->fStringBase;
    return (struct nlist *)
	bsearch(&context,
		file->fLocalSyms, file->fNLocal, sizeof(struct nlist),
		symbolSearch);
}

static Boolean
relocateSection(const struct fileRecord *file, struct sectionRecord *sectionRec)
{
    const struct nlist *symbol;
    const struct section *section;
    struct relocRecord *rec;
    struct relocation_info *rinfo;
    unsigned long i;
    unsigned long r_address, r_symbolnum, r_length;
    enum reloc_type_generic r_type;
    UInt8 *sectionBase;
    void **entry;

    sectionRec->fRelocCache = DataCreate(
	sectionRec->fSection->nreloc * sizeof(struct relocRecord));
    if (!sectionRec->fRelocCache)
	return false;

    section = sectionRec->fSection;
    sectionBase = file->fMachO + section->offset;

    rec = (struct relocRecord *) DataGetPtr(sectionRec->fRelocCache);
    rinfo = (struct relocation_info *) (file->fMachO + section->reloff);
    for (i = 0; i < section->nreloc; i++, rec++, rinfo++) {

	// Totally uninterested in scattered relocation entries
	if ( (rinfo->r_address & R_SCATTERED) )
	    continue;

	r_address = rinfo->r_address;
	entry = (void **) (sectionBase + r_address);

	/*
	 * The r_address field is really an offset into the contents of the
	 * section and must reference something inside the section (Note
	 * that this is not the case for PPC_RELOC_PAIR entries but this
	 * can't be one with the above checks).
	 */
	return_if(r_address >= section->size, false,
	    ("Invalid relocation entry in %s - not in section\n", file->fPath));

	// If we don't have a VANILLA entry or the Vanilla entry isn't
	// a 'long' then ignore the entry and try the next.
	r_type = (enum reloc_type_generic) rinfo->r_type;
	r_length = rinfo->r_length;
	if (r_type != GENERIC_RELOC_VANILLA || r_length != 2)
	    continue;

	r_symbolnum = rinfo->r_symbolnum;

	/*
	 * If rinfo->r_extern is set this relocation entry is an external entry
	 * else it is a local entry.
	 */
	if (rinfo->r_extern) {
	    /*
	     * This is an external relocation entry.
	     * r_symbolnum is an index into the input file's symbol table
	     * of the symbol being refered to.  The symbol must be
	     * undefined to be used in an external relocation entry.
	     */
	    return_if(r_symbolnum >= file->fSymtab->nsyms, false, 
		("Invalid relocation entry in %s - no symbol\n", file->fPath));

	    /*
	     * If this is an indirect symbol resolve indirection (all chains
	     * of indirect symbols have been resolved so that they point at
	     * a symbol that is not an indirect symbol).
	     */
	    symbol = file->fSymbolBase;
	    if ((symbol[r_symbolnum].n_type & N_TYPE) == N_INDR)
		r_symbolnum = symbol[r_symbolnum].n_value;
	    symbol = &symbol[r_symbolnum];

	    return_if(symbol->n_type != (N_EXT | N_UNDF), false, 
		("Invalid relocation entry in %s - extern\n", file->fPath));
	}
	else {
	    /*
	     * If the symbol is not in any section then it can't be a
	     * pointer to a local segment and I don't care about it.
	     */
	    if (r_symbolnum == R_ABS)
		continue;

	    // Note segment references are offset by 1 from 0.
	    return_if(r_symbolnum > file->fNSects, false,
		("Invalid relocation entry in %s - local\n", file->fPath));

	    // Find the symbol, if any, that backs this entry 
	    symbol = findSymbolByAddress(file, *entry);
	}

	rec->fValue  = *entry;		// Save the previous value
	rec->fRInfo  =  rinfo;		// Save a pointer to the reloc
	rec->fSymbol =  symbol;		// Record the current symbol

	*entry = (void *) rec;	// Save pointer to record in object image
    }

    ((struct fileRecord *) file)->fImageDirty = true;

    return true;
}

static const struct nlist *
findSymbolRefAtLocation(const struct fileRecord *file,
			struct sectionRecord *sctn, void **loc)
{
    if (file->fIsKernel) {
	if (*loc)
	    return findSymbolByAddress(file, *loc);
    }
    else if (sctn->fRelocCache || relocateSection(file, sctn)) {
	struct relocRecord *reloc = (struct relocRecord *) *loc;

	if (DataContainsAddr(sctn->fRelocCache, reloc))
	    return reloc->fSymbol;
    }

    return NULL;
}

static Boolean
addClass(struct fileRecord *file,
	 struct metaClassRecord *inClass,
	 const char *cname)
{
    struct metaClassRecord *newClass = NULL;
    struct metaClassRecord **fileClasses = NULL;
    int len;

if (!file->fIsKernel) {	// @@@ gvdl:
    DEBUG_LOG(("Adding Class %s\n", cname));
}

    if (!file->fClassList) {
	file->fClassList = DataCreate(0);
	if (!file->fClassList)
	    return false;
    }

    do {
	// Attempt to allocate all necessary resource first
	len = strlen(cname) + 1
	    + (int) (&((struct metaClassRecord *) 0)->fClassName);
	newClass = (struct metaClassRecord *) malloc(len);
	if (!newClass)
	    break;

	if (!DataAddLength(file->fClassList, sizeof(struct metaClassRecord *)))
	    break;
	fileClasses = (struct metaClassRecord **)
	    (DataGetPtr(file->fClassList) + DataGetLength(file->fClassList));

	// Copy the meta Class structure and string name into newClass
	// and insert object at end of the file->fClassList and sMergeMetaClasses 
	*newClass = *inClass;
	strcpy(newClass->fClassName, cname);
	fileClasses[-1]   = newClass;

	return true;
    } while (0);

    if (fileClasses)
	DataAddLength(file->fClassList, -sizeof(struct metaClassRecord *));

    if (newClass)
	free(newClass);

    return false;
}

static struct metaClassRecord *getClass(DataRef classList, const char *cname)
{
    if (classList) {
	int i, nclass;
	struct metaClassRecord **classes, *thisClass;
    
	nclass = DataGetLength(classList) / sizeof(struct metaClassRecord *);
	classes = (struct metaClassRecord **) DataGetPtr(classList);
	for (i = 0; i < nclass; i++) {
	    thisClass = classes[i];
	    if (!strcmp(thisClass->fClassName, cname))
		return thisClass;
	}
    }

    return NULL;
}

// Add the class 'cname' to the list of known OSObject based classes
// Note 'sym' is the <cname>.superClass symbol. 
static Boolean
recordClass(struct fileRecord *file, const char *cname, const struct nlist *sym)
{
    char *supername = NULL;
    const char *classname = NULL;
    struct metaClassRecord newClass;
    char strbuffer[1024];

    // Only do the work actual work to find the super class if we are
    // not currently working on  the kernel.  The kernel is the end
    // of all superclass chains as by definition the kernel is binary
    // compatible with itself.
    if (!file->fIsKernel) {
	const char *dot;
	const struct nlist *supersym;
	const struct section *section;
	struct sectionRecord *sectionRec;
	unsigned char sectind = sym->n_sect;
	const char *superstr;
	void **location;

	// We can't resolve anything that isn't in a real section
	// Note that the sectind is starts at one to make room for the
	// NO_SECT flag but the fNSects field isn't offset so we have a
	// '>' test.  Which means this isn't an OSObject based class
	if (sectind == NO_SECT || sectind > file->fNSects)
	    return true;
    
	sectionRec = file->fSections + sectind - 1;
	section = sectionRec->fSection;
	location = (void **) ( file->fMachO + section->offset
			    + sym->n_value - section->addr );
    
	supersym = findSymbolRefAtLocation(file, sectionRec, location);
	if (!supersym)
	    return true;	// No superclass symbol then it isn't an OSObject.

	// Find string in file and skip leading '_' and find last '.'
	superstr = symbolname(file, supersym) + 1;
	dot = strrchr(superstr, '.');
	if (!dot || strcmp(dot, kGMetaSuffix))
	    return true;	// Not an OSObject superclass so ignore it.

	supername = (char *) malloc(dot - superstr + 1);
	strncpy(supername, superstr, dot - superstr);
	supername[dot - superstr] = '\0';
    }

    do {
	break_if(getClass(file->fClassList, cname),
	    ("Duplicate class %s in %s\n", cname, file->fPath));
    
	snprintf(strbuffer, sizeof(strbuffer), "%s%s", kVTablePrefix, cname);
	newClass.fVTableSym = findSymbolByName(file, strbuffer);
	break_if(!newClass.fVTableSym,
	    ("Can't find vtable %s in %s\n", cname, file->fPath));

	newClass.fFile = file;
	newClass.fSuperName = supername;
	newClass.fPatchedVTable = NULL;
    
	// Can't use cname as it may be a stack variable
	// However the vtable's string has the class name as a suffix
	// so why don't we use that rather than mallocing a string.
	classname = symbolname(file, newClass.fVTableSym)
		+ sizeof(kVTablePrefix) - 1;
	break_if(!addClass(file, &newClass, classname), 
		    ("recordClass - no memory?\n"));

	return true;
    } while (0);
    
    if (supername)
	free(supername);

    return false;
}

static Boolean getMetaClassGraph(struct fileRecord *file)
{
    const struct nlist *sym;
    const char *strbase;
    int i, nsyms;

    // Search the symbol table for the local symbols that are generated
    // by the metaclass system.  There are three metaclass variables
    // that are relevant.
    //
    //   <ClassName>.metaClass	A pointer to the meta class structure.
    //	 <ClassName>.superClass	A pointer to the super class's meta class.
    //	 <ClassName>.gMetaClass	The meta class structure itself.
    //	 ___vt<ClassName>	The VTable for the class <ClassName>.
    //
    // In this code I'm going to search for any symbols that
    // ends in kSuperClassSuffix as this indicates this class is a conforming
    // OSObject subclass and will need to be patched, and it also
    // contains a pointer to the super class's meta class structure.
    strbase = file->fStringBase;
    sym = file->fLocalSyms;
    for (i = 0, nsyms = file->fNLocal; i < nsyms; i++, sym++) {
	const char *symname;
	const char *dot;
	char classname[1024];
	unsigned char n_type = sym->n_type & (N_TYPE | N_EXT);

	// Check that the symbols is a global and that it has a name.
	if (((N_SECT | N_EXT) != n_type && (N_ABS | N_EXT) != n_type)
	||  !sym->n_un.n_strx)
	    continue;

	// Only search from the last '.' in the symbol.
	// but skip the leading '_' in all symbols first.
	symname = strbase + sym->n_un.n_strx + 1;
	dot = strrchr(symname, '.');
	if (!dot || strcmp(dot, kSuperClassSuffix))
	    continue;

	// Got a candidate so hand it over for class processing.
	return_if(dot - symname >= (int) sizeof(classname),
	    false, ("Symbol %s is too long\n", symname));

	bcopy(symname, classname, dot - symname);
	classname[dot - symname] = '\0';
	if (!recordClass(file, classname, sym))
	    return false;
    }

    return_if(!file->fClassList, false, ("Internal error, "
	      "getMetaClassGraph(%s) found no classes", file->fPath)); 

    DEBUG_LOG(("Found %d classes in %x for %s\n",
	DataGetLength(file->fClassList)/sizeof(void*),
	file->fClassList, file->fPath));

    return true;
}

static Boolean mergeOSObjectsForFile(const struct fileRecord *file)
{
    int i, nmerged;
    Boolean foundDuplicates = false;

DEBUG_LOG(("Merging file %s\n", file->fPath));	// @@@ gvdl:

    if (!file->fClassList)
	return true;

    if (!sMergedFiles) {
	sMergedFiles = DataCreate(0);
	return_if(!sMergedFiles, false,
	    ("Unable to allocate memory metaclass list\n", file->fPath));
    }

    // Check to see if we have already merged this file
    nmerged = DataGetLength(sMergedFiles) / sizeof(struct fileRecord *);
    for (i = 0; i < nmerged; i++) {
	if (file == ((void **) DataGetPtr(sMergedFiles))[i])
	    return true;
    }

    if (!sMergeMetaClasses) {
	sMergeMetaClasses = DataCreate(0);
	return_if(!sMergeMetaClasses, false,
	    ("Unable to allocate memory metaclass list\n", file->fPath));
    }
    else {	/* perform a duplicate check */
	int i, j, cnt1, cnt2;
	struct metaClassRecord **list1, **list2;

	list1 = (struct metaClassRecord **) DataGetPtr(file->fClassList);
	cnt1  = DataGetLength(file->fClassList)  / sizeof(*list1);
	list2 = (struct metaClassRecord **) DataGetPtr(sMergeMetaClasses);
	cnt2  = DataGetLength(sMergeMetaClasses) / sizeof(*list2);

	for (i = 0; i < cnt1; i++) {
	    for (j = 0; j < cnt2; j++) {
		if (!strcmp(list1[i]->fClassName, list2[j]->fClassName)) {
		    errprintf("duplicate class %s in %s & %s\n",
			      list1[i]->fClassName,
			      file->fPath, list2[j]->fFile->fPath);
		}
	    }
	}
    }
    if (foundDuplicates)
	return false;

    return_if(!DataAppendBytes(sMergedFiles, &file, sizeof(file)), false,
	("Unable to allocate memory to merge %s\n", file->fPath));

    return_if(!DataAppendData(sMergeMetaClasses, file->fClassList), false,
	("Unable to allocate memory to merge %s\n", file->fPath));

    if (file == sKernelFile)
	sMergedKernel = true;

    return true;
}

// Returns a pointer to the base of the section offset by the sections
// base address.  The offset is so that we can add nlist::n_values directly
// to this address and get a valid pointer in our memory.
static unsigned char *
getSectionForSymbol(const struct fileRecord *file, const struct nlist *symb,
		    void ***endP)
{
    const struct section *section;
    unsigned char sectind;
    unsigned char *base;

    sectind = symb->n_sect;	// Default to symbols section
    if ((symb->n_type & N_TYPE) == N_ABS && file->fIsKernel) {
	// Absolute symbol so we have to iterate over our sections
	for (sectind = 1; sectind <= file->fNSects; sectind++) {
	    unsigned long start, end;

	    section = file->fSections[sectind - 1].fSection;
	    start = section->addr;
	    end   = start + section->size;
	    if (start <= symb->n_value && symb->n_value < end) {
		// Found the relevant section
		break;
	    }
	}
    }

    // Is the vtable in a valid section?
    return_if(sectind == NO_SECT || sectind > file->fNSects,
	(unsigned char *) -1,
	("%s isn't a valid kext, bad section reference\n", file->fPath));

    section = file->fSections[sectind - 1].fSection;

    // for when we start walking the vtable so compute offset's now.
    base = file->fMachO + section->offset;
    *endP = (void **) (base + section->size);

    return base - section->addr;	// return with addr offset
}

static Boolean resolveKernelVTable(struct metaClassRecord *metaClass)
{
    const struct fileRecord *file;
    struct patchRecord *patchedVTable;
    void **curEntry, **vtableEntries, **endSection;
    unsigned char *sectionBase;
    struct patchRecord *curPatch;
    int classSize;

    // Should never occur but it doesn't cost us anything to check.
    if (metaClass->fPatchedVTable)
	return true;

DEBUG_LOG(("Kernel vtable %s\n", metaClass->fClassName));	// @@@ gvdl:

    // Do we have a valid vtable to patch?
    return_if(!metaClass->fVTableSym,
	false, ("Internal error - no class vtable symbol?\n"));

    file = metaClass->fFile;

    // If the metaClass we are being to ask is in the kernel then we
    // need to do a quick scan to grab the fPatchList in a reliable format
    // however we don't need to check the superclass in the kernel
    // as the kernel vtables are always correct wrt themselves.
    // Note this ends the superclass chain recursion.
    return_if(!file->fIsKernel,
	false, ("Internal error - resolveKernelVTable not kernel\n"));

    if (file->fNoKernelExecutable) {
	// Oh dear attempt to map the kernel's VM into my memory space
	return_if(file->fNoKernelExecutable, false,
	    ("Internal error - fNoKernelExecutable not implemented yet\n"));
    }

    // We are going to need the base and the end
    sectionBase = getSectionForSymbol(file, metaClass->fVTableSym, &endSection);
    if (-1 == (long) sectionBase)
	return false;

    vtableEntries  = (void **) (sectionBase + metaClass->fVTableSym->n_value);
    curEntry = vtableEntries + kVTablePreambleLen;
    for (classSize = 0; curEntry < endSection && *curEntry; classSize++)
	curEntry++;

    return_if(*curEntry, false, ("Bad kernel image, short section\n"));

    patchedVTable = (struct patchRecord *)
	malloc((classSize + 1) * sizeof(struct patchRecord));
    return_if(!patchedVTable, false, ("resolveKernelVTable - no memory\n"));

    // Copy the vtable of this class into the patch table
    curPatch = patchedVTable;
    curEntry = vtableEntries + kVTablePreambleLen;
    for (; *curEntry; curEntry++, curPatch++) {
	curPatch->fSymbol = (struct nlist *) 
	    findSymbolByAddress(file, *curEntry);
	curPatch->fType = kSymbolLocal;
    }

    // Tag the end of the patch vtable
    curPatch->fSymbol = NULL;
    metaClass->fPatchedVTable = patchedVTable;

    return true;
}

// reloc->fPatch must contain a valid pointer on entry
static struct nlist *
getNewSymbol(struct fileRecord *file,
	     const struct relocRecord *reloc, const char *supername)
{
    unsigned int size, i, namelen;
    struct nlist **sym;
    struct nlist *msym;
    const char *strbase;
    struct relocation_info *rinfo;
    long strx;

    if (!file->fNewSymbols) {
	file->fNewSymbols = DataCreate(0);
	return_if(!file->fNewSymbols, NULL,
	    ("Unable to allocate new symbol table for %s\n", file->fPath));
    }

    // Make sure we have a string table as well for the new symbol
    if (!file->fNewStrings) {
	file->fNewStrings = DataCreate(0);
	return_if(!file->fNewStrings, NULL,
	    ("Unable to allocate string table for %s\n", file->fPath));
    }

    rinfo = (struct relocation_info *) reloc->fRInfo;
    size = DataGetLength(file->fNewSymbols) / sizeof(struct nlist *);
    sym = (const struct nlist **) DataGetPtr(file->fNewSymbols);
    // remember that the n_strx for new symbols names is negated
    strbase = (const char *)
		DataGetPtr(file->fNewStrings) - file->fSymtab->strsize;
    for (i = 0; i < size; i++, sym++) {
        const char *symname = strbase - (*sym)->n_un.n_strx;

	if (!strcmp(symname, supername)) {
	    rinfo->r_symbolnum = i + file->fSymtab->nsyms;
	    file->fSymbolsDirty = true; 
	    return *sym;
	}
    }

    // Assert that this is a vaild symbol.  I need this condition to be true
    // for the later code to make non-zero.  So the first time through I'd 
    // better make sure that it is 0.
    return_if(reloc->fSymbol->n_sect, NULL,
	("Undefined symbol entry with non-zero section %s:%s\n",
	file->fPath, symbolname(file, reloc->fSymbol)));

    msym = (struct nlist *) malloc(sizeof(struct nlist));
    return_if(!msym,
	NULL, ("Unable to create symbol table entry for %s\n", file->fPath));

    // If we are here we didn't find the symbol so create a new one now
    if (!DataAppendBytes(file->fNewSymbols, &msym, sizeof(msym))) {
	free(msym);
	return_if(true,
	    NULL, ("Unable to grow symbol table for %s\n", file->fPath));
    }

    namelen = strlen(supername) + 1;
    strx = DataGetLength(file->fNewStrings);
    if (!DataAppendBytes(file->fNewStrings, supername, namelen)) {
	free(msym);
	DataAddLength(file->fNewSymbols, -sizeof(struct nlist)); // Undo harm
	return_if(true, NULL,
		 ("Unable to grow string table for %s\n", file->fPath));
    }

    // Offset the string index by the original string table size
    // and negate the address to indicate that this is a 'new' symbol
    msym->n_un.n_strx = -(strx + file->fSymtab->strsize);
    msym->n_type = (N_EXT | N_UNDF);
    msym->n_sect = NO_SECT;
    msym->n_desc = 0;
    msym->n_value = 0;

    // Mark the old symbol as being potentially deletable I can use the
    // n_sect field as the input symbol must be of type N_UNDF which means
    // that the n_sect field must be set to NO_SECT otherwise it is an
    // in valid input file.
    ((struct nlist *) reloc->fSymbol)->n_un.n_strx
	= -reloc->fSymbol->n_un.n_strx;    
    ((struct nlist *) reloc->fSymbol)->n_sect = (unsigned char) -1;

    rinfo->r_symbolnum = i + file->fSymtab->nsyms;
    file->fSymbolsDirty = true; 
    return msym;
}

static struct nlist *
fixOldSymbol(struct fileRecord *file,
	     const struct relocRecord *reloc, const char *supername)
{
    unsigned int namelen;
    struct nlist *sym = (struct nlist *) reloc->fSymbol;
    const char *oldname = symbolname(file, sym);

    // assert(sym->n_un.n_strx >= 0);

    namelen = strlen(supername);
    if (namelen < strlen(oldname)) {
	// Overwrite old string in string table
	strcpy((char *) oldname, supername);
    }
    else {
	long strx;

	// Make sure we have a string table as well for this symbol
	if (!file->fNewStrings) {
	    file->fNewStrings = DataCreate(0);
	    return_if(!file->fNewStrings, NULL,
		("Unable to allocate string table for %s\n", file->fPath));
	}

	// Find the end of the fNewStrings data structure;
	strx = DataGetLength(file->fNewStrings);
	return_if(!DataAppendBytes(file->fNewStrings, supername, namelen + 1),
	    NULL, ("Unable to grow string table for %s\n", file->fPath));

	// now add the current table size to the offset
	sym->n_un.n_strx = strx + file->fSymtab->strsize;
    }

    // Mark the symbol as having been processed by negating it.
    // Also note that we have dirtied the file and need to repair the
    // symbol table.
    sym->n_un.n_strx = -sym->n_un.n_strx;
    file->fSymbolsDirty = true; 
    return sym;
}

static enum patchState
symbolCompare(const struct fileRecord *file,
	      const struct nlist *classsym,
	      const char *supername)
{
    const char *classname;
    

    // Check to see if the target function is locally defined
    // if it is then we can assume this is a local vtable override
    if ((classsym->n_type & N_TYPE) != N_UNDF)
	return kSymbolLocal;

    // Check to see if both symbols point to the same symbol name
    // if so then we are still identical.
    classname = symbolname(file, classsym);
    if (!strcmp(classname, supername))
	return kSymbolIdentical;

    // Right now we know that the target's vtable entry is different from the
    // superclass' vtable entry.  This means that we will have to apply a
    // patch to the current entry, however before returning lets check to
    // see if we have a _RESERVEDnnn field 'cause we can use this as a
    // registration point that must align between vtables.
    if (!strncmp(supername, kReservedPrefix, sizeof(kReservedPrefix) - 1))
	return kSymbolMismatch;

    // OK, we have a superclass difference where the superclass doesn't
    // reference a pad function so assume that the superclass is correct.
    if (!strncmp(classname, kReservedPrefix, sizeof(kReservedPrefix) - 1))
	return kSymbolPadUpdate; 
    else
	return kSymbolSuperUpdate;
}

static Boolean patchVTable(struct metaClassRecord *metaClass)
{
    struct metaClassRecord *super = NULL;
    struct fileRecord *file;
    struct patchRecord *patchedVTable;
    struct relocRecord **curReloc, **vtableRelocs, **endSection;
    unsigned char *sectionBase;
    int classSize;

    // Should never occur but it doesn't cost us anything to check.
    if (metaClass->fPatchedVTable)
	return true;

    // Do we have a valid vtable to patch?
    return_if(!metaClass->fVTableSym,
	false, ("Internal error - no class vtable symbol?\n"));

    file = metaClass->fFile;

    // If the metaClass we are being to ask is in the kernel then we
    // need to do a quick scan to grab the fPatchList in a reliable format
    // however we don't need to check the superclass in the kernel
    // as the kernel vtables are always correct wrt themselves.
    // Note this ends the superclass chain recursion.
    return_if(file->fIsKernel,
	false, ("Internal error - patchVTable shouldn't used for kernel\n"));

    if (!metaClass->fSuperName)
	return false;

    // The class isn't in the kernel so make sure that the super class 
    // is patched before patching ouselves.
    super = getClass(sMergeMetaClasses, metaClass->fSuperName);
    return_if(!super, false, ("Can't find superclass for %s : %s \n",
	metaClass->fClassName, metaClass->fSuperName));

    // Superclass recursion if necessary
    if (!super->fPatchedVTable) {
	Boolean res;

	if (super->fFile->fIsKernel)
	    res = resolveKernelVTable(super);
	else
	    res = patchVTable(super);
	if (!res)
	    return false;
    }

DEBUG_LOG(("Patching %s\n", metaClass->fClassName));	// @@@ gvdl:

    // We are going to need the base and the end

    sectionBase = getSectionForSymbol(file,
	metaClass->fVTableSym, (void ***) &endSection);
    if (-1 == (long) sectionBase)
	return false;

    vtableRelocs  = (struct relocRecord **)
			(sectionBase + metaClass->fVTableSym->n_value);
    curReloc = vtableRelocs + kVTablePreambleLen;
    for (classSize = 0; curReloc < endSection && *curReloc; classSize++)
	curReloc++;

    return_if(*curReloc, false,
	("%s isn't a valid kext, short section\n", file->fPath));

    patchedVTable = (struct patchRecord *)
	malloc((classSize + 1) * sizeof(struct patchRecord));
    return_if(!patchedVTable, false, ("patchedVTable - no memory\n"));

    do {
	struct patchRecord *curPatch;
	struct nlist *symbol;

	curPatch = patchedVTable;
	curReloc = vtableRelocs + kVTablePreambleLen;

	// Grab the super table patches if necessary
	// Can't be patching a kernel table as we don't walk super
	// class chains in the kernel symbol space.
	if (super && super->fPatchedVTable) {
	    const struct patchRecord *spp;

	    spp = super->fPatchedVTable;

	    for ( ; spp->fSymbol; curReloc++, spp++, curPatch++) {
		const char *supername =
		    symbolname(super->fFile, spp->fSymbol);

                symbol = (struct nlist *) (*curReloc)->fSymbol;

		curPatch->fType = symbolCompare(file, symbol, supername);
		switch (curPatch->fType) {
		case kSymbolIdentical:
		case kSymbolLocal:
		    break;
    
		case kSymbolSuperUpdate:
		    symbol = getNewSymbol(file, (*curReloc), supername);
		    break;

		case kSymbolPadUpdate:
		    symbol = fixOldSymbol(file, (*curReloc), supername);
		    break;

		case kSymbolMismatch:
		    errprintf("%s is not compatible with its %s superclass, "
			      "broken superclass?\n",
			      metaClass->fClassName, super->fClassName);
		    goto abortPatch;

		default:
		    errprintf("Internal error - unknown patch type\n");
		    goto abortPatch;
		}
		if (symbol) {
		    curPatch->fSymbol = symbol;
		    (*curReloc)->fSymbol = symbol;
		}
		else
		    goto abortPatch;
	    }
	}

	// Copy the remainder of this class' vtable into the patch table
	for (; *curReloc; curReloc++, curPatch++) {
	    // Local reloc symbols
	    curPatch->fType = kSymbolLocal;
	    curPatch->fSymbol = (struct nlist *) (*curReloc)->fSymbol;
	}

	// Tag the end of the patch vtable
	curPatch->fSymbol = NULL;

	metaClass->fPatchedVTable = patchedVTable;
	return true;
    } while(0);

abortPatch:
    if (patchedVTable)
	free(patchedVTable);

    return false;
}

static Boolean growImage(struct fileRecord *file, vm_size_t delta)
{
#if !KERNEL
    file->fMachOSize += delta;
    return (file->fMachO + file->fMachOSize <= file->fPadEnd);
#else /* KERNEL */
    vm_address_t startMachO, endMachO, endMap;
    vm_offset_t newMachO;
    vm_size_t newsize;
    unsigned long i, nsect, nclass = 0;
    struct metaClassRecord **classes = NULL;
    struct sectionRecord *section;
    kern_return_t ret;

    startMachO = (vm_address_t) file->fMachO;
    endMachO = startMachO + file->fMachOSize + delta;
    endMap   = (vm_address_t) file->fMap + file->fMapSize;

    // Do we have room in the current mapped image
    if (endMachO < round_page(endMap)) {
	file->fMachOSize += delta;
	return true;
    }

    newsize = endMachO - startMachO;
    if (newsize < round_page(file->fMapSize)) {
	// We have room in the map if we shift the macho image within the
	// current map.  We will have to patch up pointers into the object.
	newMachO = (vm_offset_t) file->fMap;
	bcopy((char *) startMachO, (char *) newMachO, file->fMachOSize);
    }
    else if (file->fIsKmem) {
	// kmem_alloced mapping so we can try a kmem_realloc
	ret = kmem_realloc(kernel_map,
			  (vm_address_t) file->fMap,
			  (vm_size_t) file->fMapSize,
			  &newMachO,
			  newsize);
	if (KERN_SUCCESS != ret)
	    return false;

	// If the mapping didn't move then just return
	if ((vm_address_t) file->fMap == newMachO) {
	    file->fMachOSize = file->fMapSize = newsize;
	    return true;
	}

	// We have relocated the kmem image so we are going to have to
	// move all of the pointers into the image around.
    }
    else {
	// The image doesn't have room for us and I can't kmem_realloc
	// then I just have to bite the bullet and copy the object code
	// into a bigger memory segment
	ret = kmem_alloc(kernel_map, &newMachO, newsize);
	
	if (KERN_SUCCESS != ret)
	    return false;
	bcopy((char *) startMachO, (void *) newMachO, file->fMachOSize);
	file->fIsKmem = true;
    }


    file->fMap = file->fMachO = (unsigned char *) newMachO;
    file->fMapSize = newsize;
    file->fMachOSize += delta; // Increment the image size

    // If we are here then we have shifted the object image in memory
    // I really should change all of my pointers into the image to machO offsets
    // but I have run out of time.  So I'm going to very quickly go over the
    // cached data structures and add adjustments to the addresses that are
    // affected.  I wonder how long it will take me to get them all.
    //
    // For every pointer into the MachO I need to add an adjustment satisfying
    // the following simultanous equations
    // addr_old = macho_old + fixed_offset
    // addr_new = macho_new + fixed_offset	therefore:
    // addr_new = addr_old + (macho_new - macho_old)
#define REBASE(addr, delta)	( ((vm_address_t) (addr)) += (delta) )
    delta = newMachO - startMachO;

    // Rebase the cached in object 'struct symtab_command' pointer
    REBASE(file->fSymtab, delta);

    // Rebase the cached in object 'struct nlist' pointer for all symbols
    REBASE(file->fSymbolBase, delta);

    // Rebase the cached in object 'struct nlist' pointer for local symbols
    REBASE(file->fLocalSyms, delta);

    // Rebase the cached in object 'char' pointer for the string table
    REBASE(file->fStringBase, delta);

    // Ok now we have to go over all of the relocs one last time
    // to clean up the pad updates which had their string index negated
    // to indicate that we have finished with them.
    section = file->fSections;
    for (i = 0, nsect = file->fNSects; i < nsect; i++, section++)
	REBASE(section->fSection, delta);

    // We only ever grow images that contain class lists so dont bother
    // the check if file->fClassList is non-zero 'cause it can't be
    // assert(file->fClassList);
    nclass = DataGetLength(file->fClassList)
	   / sizeof(struct metaClassRecord *);
    classes = (struct metaClassRecord **) DataGetPtr(file->fClassList);
    for (i = 0; i < nclass; i++) {
	struct patchRecord *patch;

	for (patch = classes[i]->fPatchedVTable; patch->fSymbol; patch++) {
	    vm_address_t symAddr = (vm_address_t) patch->fSymbol;
	    if (symAddr >= startMachO && symAddr < endMachO)
		REBASE(patch->fSymbol, delta);
	}
    }


#undef REBASE

    return true;

#endif /* KERNEL */
}

static Boolean
prepareFileForLink(struct fileRecord *file)
{
    unsigned long i, last, numnewsyms, newsymsize, newstrsize;
    struct sectionRecord *section;
    struct nlist **symp, *sym;

    // If we didn't even do a pseudo 'relocate' and dirty the image
    // then we can just return now.
    if (!file->fImageDirty)
	return true;

DEBUG_LOG(("Linking 2 %s\n", file->fPath));	// @@@ gvdl:

    // We have to go over all of the relocs to repair the damage
    // that we have done to the image when we did our 'relocation'
    section = file->fSections;
    for (i = 0, last = file->fNSects; i < last; i++, section++) {
	unsigned char *sectionBase;
	struct relocRecord *rec;
	unsigned long j, nreloc;

	if (section->fRelocCache) {
	    sectionBase = file->fMachO + section->fSection->offset;
	    nreloc = section->fSection->nreloc;
	    rec = (struct relocRecord *) DataGetPtr(section->fRelocCache);
    
	    // We will need to repair the reloc list 
	    for (j = 0; j < nreloc; j++, rec++) {
		void **entry;
		struct nlist *sym;
    
		// Repair Damage to object image
		entry = (void **) (sectionBase + rec->fRInfo->r_address);
		*entry = rec->fValue;

		// Check if the symbol that this relocation entry points
		// to is marked as erasable 
		sym = (struct nlist *) rec->fSymbol;
		if (sym && sym->n_type == (N_EXT | N_UNDF)
		&&  sym->n_sect == (unsigned char) -1) {
		    // clear mark now
		    sym->n_un.n_strx = -sym->n_un.n_strx;
		    sym->n_sect = NO_SECT;
		}
	    }

	    // Clean up the fRelocCache we don't need it any more.
	    DataRelease(section->fRelocCache);
	    section->fRelocCache = 0;
	}
    }
    file->fImageDirty = false;	// Image is clean

    // If we didn't dirty the symbol table then just return
    if (!file->fSymbolsDirty)
	return true;

    // calculate total file size increase and check against padding
    numnewsyms  = (file->fNewSymbols)? DataGetLength(file->fNewSymbols) : 0;
    numnewsyms /= sizeof(struct nlist *);
    newsymsize  = numnewsyms * sizeof(struct nlist);
    newstrsize  = (file->fNewStrings)? DataGetLength(file->fNewStrings) : 0;
    newstrsize  = (newstrsize + 3) & ~3;	// Round to nearest word
    
    return_if(!growImage(file, newsymsize + newstrsize),
	false, ("Unable to patch the extension, no memory\n", file->fPath));

    // Push out the new symbol table if necessary
    if (numnewsyms) {
	caddr_t base;

	// Move the string table out of the way of the grown symbol table
	// Don't forget the '\0' from end of string table.
	base = (caddr_t) file->fStringBase;
	bcopy(base, base + newsymsize, file->fSymtab->strsize);
	file->fStringBase     += newsymsize;
	file->fSymtab->stroff += newsymsize;

	// Now append the new symbols to the symbol table.
	base = (caddr_t) file->fSymbolBase
	     + file->fSymtab->nsyms * sizeof(struct nlist);
	symp = (struct nlist **) DataGetPtr(file->fNewSymbols);
	for (i = 0; i < numnewsyms; i++, base += sizeof(struct nlist), symp++)
	    bcopy(*symp, base, sizeof(struct nlist));
	file->fSymtab->nsyms  += numnewsyms;

	DataRelease(file->fNewSymbols);
	file->fNewSymbols = 0;
    }

    // Push out the new string table if necessary
    if (newstrsize) {
	caddr_t base = (caddr_t) file->fStringBase + file->fSymtab->strsize;
	unsigned long actuallen = DataGetLength(file->fNewStrings);

	// Set the last word in string table to zero before copying data
	*((unsigned long *) ((char *) base + newstrsize - 4)) = 0;

	// Now append the new strings to the end of the file
	bcopy((caddr_t) DataGetPtr(file->fNewStrings), base, actuallen);

	file->fSymtab->strsize += newstrsize;

	DataRelease(file->fNewStrings);
	file->fNewStrings = 0;
    }

    // Repair the symbol table string index values
    // I used negative strx's to indicate symbol has been processed
    sym = file->fSymbolBase;
    for (i = 0, last = file->fSymtab->nsyms; i < last; i++, sym++) {
	if (sym->n_un.n_strx < 0) {
	    if ( sym->n_type != (N_EXT | N_UNDF)
	    || (unsigned char) -1 != sym->n_sect)
		sym->n_un.n_strx = -sym->n_un.n_strx;
	    else {
		// This symbol isn't being used by any vtable's reloc so
		// convert it into an N_ABS style of symbol, remove the
		// external bit and null out the symbol name.
		bzero(sym, sizeof(*sym));
		sym->n_type = N_ABS;	/* type flag, see below */
	    }
	}
    }
    file->fSymbolsDirty = false;

    return true;
}

Boolean
#if KERNEL
kld_file_map(const char *pathName,
	     unsigned char *map,
	     size_t mapSize,
	     Boolean isKmem)
#else
kld_file_map(const char *pathName)
#endif /* KERNEL */
{
    struct fileRecord file, *fp = 0;

    // Already done no need to repeat
    fp = getFile(pathName);
    if (fp)
	return true;

    bzero(&file, sizeof(file));
    file.fPath = pathName;

#if KERNEL
    file.fMap = map;
    file.fMapSize = mapSize;
    file.fIsKmem = isKmem;
#else
    if (!mapObjectFile(&file))
	return false;
#endif /* KERNEL */

    do {
	const struct machOMapping {
	    struct mach_header h;
	    struct load_command c[1];
	} *machO;
	const struct load_command *cmd;
	const struct nlist *sym;
	unsigned int i, firstlocal, nsyms;
	unsigned long strsize;
	const char *strbase;
	Boolean foundOSObject;

	if (!findBestArch(&file))
	    break;
    
	machO = (const struct machOMapping *) file.fMachO;
	if (file.fMachOSize < machO->h.sizeofcmds)
	    break;

	// If the file type is MH_EXECUTE then this must be a kernel
	// as all Kernel extensions must be of type MH_OBJECT
	for (i = 0, cmd = &machO->c[0]; i < machO->h.ncmds; i++) {
	    if (cmd->cmd == LC_SEGMENT) {
		return_if(!parseSegments(&file, (struct segment_command *) cmd),
		    false, ("%s isn't a valid mach-o, bad segment\n",
			    file.fPath));
	    }
	    else if (cmd->cmd == LC_SYMTAB)
		file.fSymtab = (struct symtab_command *) cmd;
    
	    cmd = (struct load_command *) ((UInt8 *) cmd + cmd->cmdsize);
	}
	break_if(!file.fSymtab,
	    ("%s isn't a valid mach-o, no symbols\n", file.fPath));

	// we found a link edit segment so recompute the bases
	if (file.fSymbolBase) {
	    struct segment_command *link =
		(struct segment_command *) file.fSymbolBase;

	    file.fSymbolBase = (struct nlist *)
		(link->vmaddr + (file.fSymtab->symoff - link->fileoff));
	    file.fStringBase = (char *)
		(link->vmaddr + (file.fSymtab->stroff - link->fileoff));
	    break_if( ( (caddr_t) file.fStringBase + file.fSymtab->strsize
		      > (caddr_t) link->vmaddr + link->vmsize ),
		("%s isn't a valid mach-o le, bad symbols\n", file.fPath));
	}
	else {
	    file.fSymbolBase = (struct nlist *)
		(file.fMachO + file.fSymtab->symoff); 
	    file.fStringBase = (char *)
		(file.fMachO + file.fSymtab->stroff); 
	    break_if( ( file.fSymtab->stroff + file.fSymtab->strsize
		      > file.fMachOSize ),
		("%s isn't a valid mach-o, bad symbols\n", file.fPath));
	}

	// If this file the kernel and do we have an executable image
	file.fIsKernel = (MH_EXECUTE == machO->h.filetype);
	file.fNoKernelExecutable = (vm_page_size == file.fSymtab->symoff)
				&& (file.fSections[0].fSection->size == 0);

	// Search for the first non-stab symbol in table
	strsize = file.fSymtab->strsize;
	strbase = file.fStringBase;
	sym = file.fSymbolBase;
	firstlocal = 0;
	foundOSObject = false;
	for (i = 0, nsyms = file.fSymtab->nsyms; i < nsyms; i++, sym++) {
	    if ((unsigned long) sym->n_un.n_strx > strsize)
		break;

	    // Find the first exported symbol
	    if ( !file.fLocalSyms && (sym->n_type & N_EXT) ) {
		file.fLocalSyms = sym;
		firstlocal = i;
	    }

	    // Find the a OSObject based subclass by searching for symbols
	    // that have a suffix of '.superClass'
	    if (!foundOSObject
	    && ((sym->n_type & (N_TYPE | N_EXT)) == (N_SECT | N_EXT)
	     || (sym->n_type & (N_TYPE | N_EXT)) == (N_ABS | N_EXT))
	    &&  sym->n_un.n_strx) {
		const char *dot;

		// Only search from the last '.' in the symbol.
		// but skip the leading '_' in all symbols first.
		dot = strrchr(strbase + sym->n_un.n_strx + 1, '.');
		if (dot && !strcmp(dot, kSuperClassSuffix))
		    foundOSObject = true;
	    }

	    // Find the last local symbol
	    if ( !file.fNLocal && sym->n_type == (N_EXT | N_UNDF) )
		file.fNLocal = i - firstlocal;

	}
	break_if(i < nsyms,
	    ("%s isn't a valid mach-o, bad symbol strings\n", file.fPath));

	break_if(!file.fLocalSyms, ("%s has no symbols?\n", file.fPath));

	// If we don't have any undefined symbols then all symbols
	// must be local so just compute it now if necessary.
	if ( !file.fNLocal )
	    file.fNLocal = i - firstlocal;

	fp = addFile(&file);
	if (!fp)
	    break;

	if (foundOSObject && !getMetaClassGraph(fp))
	    break;

	if (file.fIsKernel)
	    sKernelFile = fp;
#if KERNEL
	if (!sKernelFile) {
	    extern struct mach_header _mh_execute_header;
	    extern struct segment_command *getsegbyname(char *seg_name);
    
	    struct segment_command *sg;
	    size_t kernelSize;
	    Boolean ret;

	    sg = (struct segment_command *) getsegbyname(kLinkEditSegName); 
	    break_if(!sg, ("Can't find kernel link edit segment\n"));
    
	    kernelSize = sg->vmaddr + sg->vmsize - (size_t) &_mh_execute_header;
	    ret = kld_file_map(kld_basefile_name,
	        (unsigned char *) &_mh_execute_header, kernelSize,
		/* isKmem */ false);
	    break_if(!ret, ("kld can't map kernel file"));
	}
#endif	/* KERNEL */

	return true;
    } while(0);

    removeFile(&file);

    return false;
}

void *kld_file_getaddr(const char *pathName, long *size)
{
    struct fileRecord *file = getFile(pathName);

    if (!file)
	return 0;

    if (size)
	*size = file->fMachOSize;

    return file->fMachO;
}

void *kld_file_lookupsymbol(const char *pathName, const char *symname)
{
    struct fileRecord *file = getFile(pathName);
    const struct nlist *sym;
    const struct section *section;
    unsigned char *sectionBase;
    unsigned char sectind;

    return_if(!file,
	NULL, ("Unknown file %s\n", pathName));

    sym = findSymbolByName(file, symname);

    // May be a non-extern symbol so look for it there
    if (!sym) {
	const char *strbase;
	unsigned int i, nsyms;

	sym = file->fSymbolBase;
	strbase = file->fStringBase;
	for (i = 0, nsyms = file->fSymtab->nsyms; i < nsyms; i++, sym++) {
	    if ( (sym->n_type & N_EXT) ) {
		sym = 0;
		break;	// Terminate search when we hit an extern
	    }
	    if ( (sym->n_type & N_STAB) )
		continue;
	    if ( !strcmp(symname, strbase + sym->n_un.n_strx) )
		break;
	}
    }

    return_if(!sym,
	NULL, ("Unknown symbol %s in %s\n", symname, pathName));

    // Is the vtable in a valid section?
    sectind = sym->n_sect;
    return_if(sectind == NO_SECT || sectind > file->fNSects, NULL,
	("Malformed object file, invalid section reference for %s in %s\n",
	    symname, pathName));

    section = file->fSections[sectind - 1].fSection;
    sectionBase = file->fMachO + section->offset - section->addr;

    return (void *) (sectionBase + sym->n_value);
}

Boolean kld_file_merge_OSObjects(const char *pathName)
{
    struct fileRecord *file = getFile(pathName);

    return_if(!file,
	false, ("Internal error - unable to find file %s\n", pathName));

    return mergeOSObjectsForFile(file);
}

Boolean kld_file_patch_OSObjects(const char *pathName)
{
    struct fileRecord *file = getFile(pathName);
    struct metaClassRecord **classes;
    unsigned long i, last;

    return_if(!file,
	false, ("Internal error - unable to find file %s\n", pathName));

DEBUG_LOG(("Patch file %s\n", pathName));	// @@@ gvdl:

    // If we don't have any classes we can return now.
    if (!file->fClassList)
	return true;

    // If we haven't alread merged the kernel then do it now
    if (!sMergedKernel && sKernelFile)
	mergeOSObjectsForFile(sKernelFile);
    return_if(!sMergedKernel, false, ("Internal error no kernel?\n"));

    if (!mergeOSObjectsForFile(file))
	return false;

    // Patch all of the classes in this executable
    last = DataGetLength(file->fClassList) / sizeof(void *);
    classes = (struct metaClassRecord **) DataGetPtr(file->fClassList);
    for (i = 0; i < last; i++) {
	if (!patchVTable(classes[i]))
	    return false;
    }

    return true;
}

Boolean kld_file_prepare_for_link()
{
    if (sMergedFiles) {
	unsigned long i, nmerged = 0;
	struct fileRecord **files;
    
	// Check to see if we have already merged this file
	nmerged = DataGetLength(sMergedFiles) / sizeof(struct fileRecord *);
	files = (struct fileRecord **) DataGetPtr(sMergedFiles);
	for (i = 0; i < nmerged; i++) {
	    if (!prepareFileForLink(files[i]))
		return false;
	}
    }

    // Clear down the meta class table and merged file lists
    DataRelease(sMergeMetaClasses);
    DataRelease(sMergedFiles);
    sMergedFiles = sMergeMetaClasses = NULL;
    sMergedKernel = false;

    return true;
}

void kld_file_cleanup_all_resources()
{
    unsigned long i, nfiles;

#if KERNEL	// @@@ gvdl:
    // Debugger("kld_file_cleanup_all_resources");
#endif

    if (!sFilesTable || !(nfiles = DataGetLength(sFilesTable)))
	return;	// Nothing to do just return now

    nfiles /= sizeof(struct fileRecord *);
    for (i = 0; i < nfiles; i++)
	removeFile(((void **) DataGetPtr(sFilesTable))[i]);

    // Don't really have to clean up anything more as the whole
    // malloc engine is going to be released and I couldn't be bothered.
}

#if !KERNEL
Boolean kld_file_debug_dump(const char *pathName, const char *outName)
{
    const struct fileRecord *file = getFile(pathName);
    int fd;
    Boolean ret = false;

    return_if(!file, false, ("Unknown file %s for dumping\n", pathName));

    fd = open(outName, O_WRONLY|O_CREAT|O_TRUNC, 0666);
    return_if(-1 == fd, false, ("Can't create output file %s - %s(%d)\n",
	outName, strerror(errno), errno));

    do {
	break_if(-1 == write(fd, file->fMachO, file->fMachOSize),
	    ("Can't dump output file %s - %s(%d)\n", 
		outName, strerror(errno), errno));
	ret = true;
    } while(0);

    close(fd);

    return ret;
}
#endif /* !KERNEL */

