/*
 * Copyright (c) 2001 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
 * http://www.opensource.apple.com/apsl/ and read it before using this 
 * file.
 *
 * The Original Code and all software distributed under the License are 
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER 
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, 
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. 
 * Please see the License for the specific language governing rights and 
 * limitations under the License.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
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
#if !KERNEL
#include <mach-o/swap.h>
#include <libkern/OSByteOrder.h>
#endif

#if KERNEL

#include <stdarg.h>
//#include <string.h>

#include <sys/systm.h>

#include <libkern/OSTypes.h>

#include <libsa/stdlib.h>
#include <libsa/mach/mach.h>

#include "mach_loader.h"

#include <vm/vm_kern.h>

enum { false = 0, true = 1 };

#define vm_page_size page_size

extern void kld_error_vprintf(const char *format, va_list ap);

__private_extern__ char *strstr(const char *in, const char *str);
extern struct mach_header _mh_execute_header;
extern struct segment_command *getsegbyname(char *seg_name);	// 32 bit only

#else /* !KERNEL */

#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/errno.h> 
#include <sys/fcntl.h>
#include <sys/stat.h>   
#include <sys/mman.h>   
#include <sys/vm.h>   

#include <mach/mach.h>
#include <mach/mach_error.h>

#include <mach-o/arch.h>

#include <CoreFoundation/CoreFoundation.h>

#define PAGE_SIZE vm_page_size
#define PAGE_MASK (PAGE_SIZE - 1)

#endif /* KERNEL */

#include "kld_patch.h"
#include "c++rem3.h"

#if 0
#define DIE() do { for (;;) ; } while(0)

#if KERNEL
#    define LOG_DELAY()		/* IODelay(200000) */
#    define DEBUG_LOG(x)	do { IOLog x; LOG_DELAY(); } while(0)
#else
#    define LOG_DELAY()
#    define DEBUG_LOG(x)	do { printf x; } while(0)
#endif

#else

#define DIE()
#define LOG_DELAY()
#define DEBUG_LOG(x)

#endif

// OSObject symbol prefixes and suffixes
#define kCPPSymbolPrefix	"_Z"
#define kVTablePrefix		"_" kCPPSymbolPrefix "TV"
#define kOSObjPrefix		"_" kCPPSymbolPrefix "N"
#define kReservedNamePrefix	"_RESERVED"
#define k29SuperClassSuffix	"superClass"
#define k31SuperClassSuffix	"10superClassE"
#define kGMetaSuffix		"10gMetaClassE"
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
    const struct section *fSection;	// 32 bit mach object section
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
    const struct fileRecord *fFile;
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
    unsigned char *fMap, *fMachO, *fPadEnd;
    DataRef fClassList;
    DataRef fSectData;
    DataRef fNewSymbols, fNewStringBlocks;
    DataRef fSym2Strings;
    struct symtab_command *fSymtab;
    struct sectionRecord *fSections;
    vm_offset_t fVMAddr, fVMEnd;
    struct segment_command *fLinkEditSeg;
    const char **fSymbToStringTable;
    char *fStringBase;
    struct nlist *fSymbolBase;
    const struct nlist *fLocalSyms;
    unsigned int fNSects;
    int fNLocal;
    Boolean fIsKernel, fIsReloc, fIsIncrLink, fNoKernelExecutable, fIsKmem;
    Boolean fImageDirty, fSymbolsDirty;
    Boolean fRemangled, fFoundOSObject;
    Boolean fIgnoreFile;
#if !KERNEL
    Boolean fSwapped;
#endif
    const char fPath[1];
};

static DataRef sFilesTable;
static struct fileRecord *sKernelFile;

static DataRef    sMergedFiles;
static DataRef    sMergeMetaClasses;
static Boolean    sMergedKernel;
#if !KERNEL
static const NXArchInfo * sPreferArchInfo;
#endif
static const struct nlist *
findSymbolByName(struct fileRecord *file, const char *symname);

static void errprintf(const char *fmt, ...)
{
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

static __inline__ unsigned char *DataGetEndPtr(DataRef data)
{
    return data->fData + data->fLength;
}

static __inline__ unsigned long DataRemaining(DataRef data)
{
    return data->fCapacity - data->fLength;
}

static __inline__ Boolean DataContainsAddr(DataRef data, void *vAddr)
{
    vm_offset_t offset = (vm_address_t) vAddr;

    if (!data)
        return false;

    offset = (vm_address_t) vAddr - (vm_address_t) data->fData;
    return (offset < data->fLength);
}

static Boolean DataEnsureCapacity(DataRef data, unsigned long capacity)
{
    // Don't bother to ever shrink a data object.
    if (capacity > data->fCapacity) {
	unsigned char *newData;

	capacity += kDataCapacityIncrement - 1;
	capacity &= ~(kDataCapacityIncrement - 1);
	newData = (unsigned char *) realloc(data->fData, capacity);
	if (!newData)
	    return false;

	bzero(newData + data->fCapacity, capacity - data->fCapacity);
	data->fData = newData;
	data->fCapacity = capacity;
    }

    return true;
}

static __inline__ Boolean DataSetLength(DataRef data, unsigned long length)
{
    if (DataEnsureCapacity(data, length)) {
        data->fLength = length;
        return true;
    }
    else
        return false;
}

static __inline__ Boolean DataAddLength(DataRef data, unsigned long length)
{
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

static DataRef DataCreate(unsigned long capacity)
{
    DataRef data = (DataRef) malloc(sizeof(Data));

    if (data) {
	if (!capacity)
	    data->fCapacity = kDataCapacityIncrement;
	else {
	    data->fCapacity  = capacity + kDataCapacityIncrement - 1;
	    data->fCapacity &= ~(kDataCapacityIncrement - 1);
	}

	data->fData = (unsigned char *) malloc(data->fCapacity);
	if (!data->fData) {
	    free(data);
	    return NULL;
	}

	bzero(data->fData, data->fCapacity);
	data->fLength = 0;
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

static __inline__ const char *
symNameByIndex(const struct fileRecord *file, unsigned int symInd)
{
    return file->fSymbToStringTable[symInd];
}

static __inline__  const char *
symbolname(const struct fileRecord *file, const struct nlist *sym)
{
    unsigned int index;

    index = sym - file->fSymbolBase;

    if (index && !sym->n_un.n_strx)
       return file->fStringBase + sym->n_value;

    if (index < file->fSymtab->nsyms)
        return symNameByIndex(file,  index);

    if (-1 == sym->n_un.n_strx)
        return (const char *) sym->n_value;

    // If the preceding tests fail then we have a getNewSymbol patch and
    // the file it refers to has already been patched as the n_strx is set
    // to -1 temporarily while we are still processing a file.
    // Once we have finished with a file then we repair the 'strx' offset 
    // to be valid for the repaired file's string table.
    return file->fStringBase + sym->n_un.n_strx;
}

static struct fileRecord *
getFile(const char *path)
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

static struct fileRecord *
addFile(struct fileRecord *file, const char *path)
{
    struct fileRecord *newFile;

    if (!sFilesTable) {
	sFilesTable = DataCreate(0);
	if (!sFilesTable)
	    return NULL;
    }

    newFile = (struct fileRecord *) 
        malloc(sizeof(struct fileRecord) + strlen(path));
    if (!newFile)
	return NULL;

    if (!DataAppendBytes(sFilesTable, &newFile, sizeof(newFile))) {
	free(newFile);
	return NULL;
    }

    bcopy(file, newFile, sizeof(struct fileRecord) - 1);
    strcpy((char *) newFile->fPath, path);

    return newFile;
}

// @@@ gvdl: need to clean up the sMergeMetaClasses
// @@@ gvdl: I had better fix the object file up again
static void unmapFile(struct fileRecord *file)
{
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

    if (file->fSym2Strings) {
        DataRelease(file->fSym2Strings);
        file->fSym2Strings = 0;
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
}

static void removeFile(struct fileRecord *file)
{
    if (file->fClassList) {
	DataRelease(file->fClassList);
	file->fClassList = 0;
    }

    unmapFile(file);

    free(file);
}

#if !KERNEL
static Boolean
mapObjectFile(struct fileRecord *file, const char *pathName)
{
    Boolean result = false;
    static unsigned char *sFileMapBaseAddr = 0;

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

    fd = open(pathName, O_RDONLY, 0);
    return_if(fd == -1, false, ("Can't open %s for reading - %s\n",
	pathName, strerror(errno)));

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
			pathName, mach_error_string(ret)));

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

void
kld_set_architecture(const NXArchInfo * arch)
{
    sPreferArchInfo = arch;
}

// This function can only operate on 32 bit mach-o files
Boolean
kld_macho_swap(struct mach_header * mh)
{
    struct segment_command * seg;
    struct section *	     section;
    CFIndex     	     ncmds, cmd, sect;
    enum NXByteOrder	     hostOrder = NXHostByteOrder();

    if (MH_CIGAM != mh->magic)
	return (false);

    swap_mach_header(mh, hostOrder);

    ncmds = mh->ncmds;
    seg = (struct segment_command *)(mh + 1);
    for (cmd = 0;
            cmd < ncmds;
            cmd++, seg = (struct segment_command *)(((vm_offset_t)seg) + seg->cmdsize))
    {
        if (OSSwapConstInt32(LC_SYMTAB) == seg->cmd) {
	    swap_symtab_command((struct symtab_command *) seg, hostOrder);
	    swap_nlist((struct nlist *) (((vm_offset_t) mh) + ((struct symtab_command *) seg)->symoff),
		       ((struct symtab_command *) seg)->nsyms, hostOrder);
	    continue;
	}
        if (OSSwapConstInt32(LC_SEGMENT) != seg->cmd) {
	    swap_load_command((struct load_command *) seg, hostOrder);
            continue;
	}
	swap_segment_command(seg, hostOrder);
	swap_section((struct section *) (seg + 1), seg->nsects, hostOrder);

	section = (struct section *) (seg + 1);
	for (sect = 0; sect < seg->nsects; sect++, section++) {
	    if (section->nreloc)
		swap_relocation_info((struct relocation_info *) (((vm_offset_t) mh) + section->reloff),
				      section->nreloc, hostOrder);
	}
    }

    return (true);
}

// This function can only operate on 32 bit mach-o files
void
kld_macho_unswap(struct mach_header * mh, Boolean didSwap, int symbols)
{
    // symbols ==  0 => everything
    // symbols ==  1 => just nlists
    // symbols == -1 => everything but nlists

    struct segment_command * seg;
    struct section *	     section;
    unsigned long	     cmdsize;
    CFIndex     	     ncmds, cmd, sect;
    enum NXByteOrder	     hostOrder = (NXHostByteOrder() == NX_LittleEndian)
					? NX_BigEndian : NX_LittleEndian;
    if (!didSwap)
	return;

    ncmds = mh->ncmds;
    seg = (struct segment_command *)(mh + 1);
    for (cmd = 0;
            cmd < ncmds;
            cmd++, seg = (struct segment_command *)(((vm_offset_t)seg) + cmdsize))
    {
	cmdsize = seg->cmdsize;
        if (LC_SYMTAB == seg->cmd) {
	    if (symbols >= 0)
		swap_nlist((struct nlist *) (((vm_offset_t) mh) + ((struct symtab_command *) seg)->symoff),
			((struct symtab_command *) seg)->nsyms, hostOrder);
	    if (symbols > 0)
		break;
	    swap_symtab_command((struct symtab_command *) seg, hostOrder);
	    continue;
	}
	if (symbols > 0)
	    continue;
        if (LC_SEGMENT != seg->cmd) {
	    swap_load_command((struct load_command *) seg, hostOrder);
            continue;
	}

	section = (struct section *) (seg + 1);
	for (sect = 0; sect < seg->nsects; sect++, section++) {
	    if (section->nreloc)
		swap_relocation_info((struct relocation_info *) (((vm_offset_t) mh) + section->reloff),
				      section->nreloc, hostOrder);
	}
	swap_section((struct section *) (seg + 1), seg->nsects, hostOrder);
	swap_segment_command(seg, hostOrder);
    }
    if (symbols <= 0)
	swap_mach_header(mh, hostOrder);
}

#endif /* !KERNEL */

// Note: This functions is only called from kld_file_map()
// This function can only operate on 32 bit mach-o files
static Boolean findBestArch(struct fileRecord *file, const char *pathName)
{
    unsigned long magic;
    struct fat_header *fat;


    file->fMachOSize = file->fMapSize;
    file->fMachO = file->fMap;
    magic = ((const struct mach_header *) file->fMachO)->magic;
    fat = (struct fat_header *) file->fMachO;

    // Try to figure out what type of file this is
    return_if(file->fMapSize < sizeof(unsigned long), false,
	("%s isn't a valid object file - no magic\n", pathName));

#if KERNEL

    // CIGAM is byte-swapped MAGIC
    if (magic == FAT_MAGIC || magic == FAT_CIGAM) {

        load_return_t load_return;
        struct fat_arch fatinfo;

        load_return = fatfile_getarch(NULL, (vm_address_t) fat, &fatinfo);
	return_if(load_return != LOAD_SUCCESS, false,
	    ("Extension \"%s\": has no code for this computer\n", pathName));

	file->fMachO = file->fMap + fatinfo.offset;
	file->fMachOSize = fatinfo.size;
	magic = ((const struct mach_header *) file->fMachO)->magic;
    }

#else /* !KERNEL */

    // Do we need to in-place swap the endianness of the fat header?
    if (magic == FAT_CIGAM) {
	unsigned long i;
	struct fat_arch *arch;

	fat->nfat_arch = OSSwapBigToHostInt32(fat->nfat_arch);
	return_if(file->fMapSize < sizeof(struct fat_header)
				    + fat->nfat_arch * sizeof(struct fat_arch),
	    false, ("%s is too fat\n", file->fPath));

	arch = (struct fat_arch *) &fat[1];
	for (i = 0; i < fat->nfat_arch; i++) {
	    arch[i].cputype    = OSSwapBigToHostInt32(arch[i].cputype);
	    arch[i].cpusubtype = OSSwapBigToHostInt32(arch[i].cpusubtype);
	    arch[i].offset     = OSSwapBigToHostInt32(arch[i].offset);
	    arch[i].size       = OSSwapBigToHostInt32(arch[i].size);
	    arch[i].align      = OSSwapBigToHostInt32(arch[i].align);
	}

	magic = OSSwapBigToHostInt32(fat->magic);
    }

    // Now see if we can find any valid architectures
    if (magic == FAT_MAGIC) {
	const NXArchInfo *myArch;
	unsigned long fatsize;
	struct fat_arch *arch;

	fatsize = sizeof(struct fat_header)
	    + fat->nfat_arch * sizeof(struct fat_arch);
	return_if(file->fMapSize < fatsize,
	    false, ("%s isn't a valid fat file\n", pathName));

	if (sPreferArchInfo)
	    myArch = sPreferArchInfo;
	else
	    myArch = NXGetLocalArchInfo();
    
	arch = NXFindBestFatArch(myArch->cputype, myArch->cpusubtype,
		(struct fat_arch *) &fat[1], fat->nfat_arch);
	return_if(!arch,
	    false, ("%s hasn't got arch for %s\n", pathName, myArch->name));
	return_if(arch->offset + arch->size > file->fMapSize,
	    false, ("%s's %s arch is incomplete\n", pathName, myArch->name));
	file->fMachO = file->fMap + arch->offset;
	file->fMachOSize = arch->size;
	magic = ((const struct mach_header *) file->fMachO)->magic;
    }

    file->fSwapped = kld_macho_swap((struct mach_header *) file->fMachO);
    if (file->fSwapped)
	magic = ((const struct mach_header *) file->fMachO)->magic;

#endif /* KERNEL */

    return_if(magic != MH_MAGIC,
	false, ("%s isn't a valid mach-o\n", pathName));

    return true;
}

// This function can only operate on segments from 32 bit mach-o files
static Boolean
parseSegments(struct fileRecord *file, struct segment_command *seg)
{
    struct sectionRecord *sections;
    int i, nsects = seg->nsects;
    const struct segmentMap {
	struct segment_command seg;
	const struct section sect[1];
    } *segMap;

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
    {
	sections[i].fSection = &segMap->sect[i];
	file->fIsReloc |= (0 != segMap->sect[i].nreloc);
    }

    return true;
}

static Boolean
remangleExternSymbols(struct fileRecord *file, const char *pathName)
{
    const struct nlist *sym;
    int i, nsyms, len;
    DataRef strings = NULL;

    DEBUG_LOG(("Remangling %s\n", pathName));

    file->fNewStringBlocks = DataCreate(0);
    return_if(!file->fNewStringBlocks, false,
        ("Unable to allocate new string table for %s\n", pathName));

    nsyms = file->fSymtab->nsyms;
    for (i = 0, sym = file->fSymbolBase; i < nsyms; i++, sym++) {
        Rem3Return ret;
	const char *symname;
        char *newname;
        unsigned char n_type = sym->n_type;

        // Not an external symbol or it is a stab in any case don't bother
        if ((n_type ^ N_EXT) & (N_STAB | N_EXT))
            continue;

        symname = symNameByIndex(file, i);

tryRemangleAgain:
        if (!strings) {
            strings = DataCreate(16 * 1024);	// Arbitrary block size
            return_if(!strings, false,
                ("Unable to allocate new string block for %s\n", pathName));
        }

        len = DataRemaining(strings);
        newname = DataGetEndPtr(strings);
        ret = rem3_remangle_name(newname, &len, symname);
        switch (ret) {
        case kR3InternalNotRemangled:
            errprintf("Remangler fails on %s in %s\n", symname, pathName);
            /* No break */
        case kR3NotRemangled:
            break;

        case kR3Remangled:
            file->fSymbToStringTable[i] = newname;
            file->fRemangled = file->fSymbolsDirty = true; 
            DataAddLength(strings, len + 1);	// returns strlen
            break;

        case kR3BufferTooSmallRemangled:
            return_if(!DataAppendBytes
                        (file->fNewStringBlocks, &strings, sizeof(strings)),
                false, ("Unable to allocate string table for %s\n", pathName));
            strings = NULL;
            goto tryRemangleAgain;

        case kR3BadArgument:
        default:
            return_if(true, false,
                     ("Internal error - remangle of %s\n", pathName));
        }
    }

    if (strings) {
        return_if(!DataAppendBytes
                        (file->fNewStringBlocks, &strings, sizeof(strings)),
            false, ("Unable to allocate string table for %s\n", pathName));
    }

    return true;
}

// This function can only operate on symbol table files from  32 bit
// mach-o files
static Boolean parseSymtab(struct fileRecord *file, const char *pathName)
{
    const struct nlist *sym;
    unsigned int i, firstlocal, nsyms;
    unsigned long strsize;
    const char *strbase;
    Boolean foundOSObject, found295CPP, havelocal;

    // we found a link edit segment so recompute the bases
    if (file->fLinkEditSeg) {
        struct segment_command *link = file->fLinkEditSeg;

        file->fSymbolBase = (struct nlist *)
            (link->vmaddr + (file->fSymtab->symoff - link->fileoff));
        file->fStringBase = (char *)
            (link->vmaddr + (file->fSymtab->stroff - link->fileoff));
        return_if( ( (caddr_t) file->fStringBase + file->fSymtab->strsize
                    > (caddr_t) link->vmaddr + link->vmsize ), false,
            ("%s isn't a valid mach-o le, bad symbols\n", pathName));
    }
    else {
        file->fSymbolBase = (struct nlist *)
            (file->fMachO + file->fSymtab->symoff); 
        file->fStringBase = (char *)
            (file->fMachO + file->fSymtab->stroff); 
        return_if( ( file->fSymtab->stroff + file->fSymtab->strsize
                    > file->fMachOSize ), false,
            ("%s isn't a valid mach-o, bad symbols\n", pathName));
    }

    nsyms = file->fSymtab->nsyms;

    // If this file the kernel and do we have an executable image
    file->fNoKernelExecutable = (vm_page_size == file->fSymtab->symoff)
                            && (file->fSections[0].fSection->size == 0);

    // Generate a table of pointers to strings indexed by the symbol number

    file->fSym2Strings = DataCreate(nsyms * sizeof(const char *));
    DataSetLength(file->fSym2Strings, nsyms * sizeof(const char *));
    return_if(!file->fSym2Strings, false, 
	    ("Unable to allocate memory - symbol string trans\n", pathName));
    file->fSymbToStringTable = (const char **) DataGetPtr(file->fSym2Strings);

    // Search for the first non-stab symbol in table
    strsize = file->fSymtab->strsize;
    strbase = file->fStringBase;
    firstlocal = 0;
    havelocal = false;
    found295CPP = foundOSObject = false;
    for (i = 0, sym = file->fSymbolBase; i < nsyms; i++, sym++) {
        long strx = sym->n_un.n_strx;
        const char *symname = strbase + strx;
        unsigned char n_type;

        return_if(((unsigned long) strx > strsize), false,
            ("%s has an illegal string offset in symbol %d\n", pathName, i));
#if 0
        // Make all syms abs
	if (file->fIsIncrLink) {
	    if ( (sym->n_type & N_TYPE) == N_SECT) {
		sym->n_sect = NO_SECT;
		sym->n_type = (sym->n_type & ~N_TYPE) | N_ABS;
	    }
	}
#endif

	if (file->fIsIncrLink && !file->fNSects)
	{
	    // symbol set
	    struct nlist *patchsym = (struct nlist *) sym;
	    const char * lookname;
	    const struct nlist * realsym;

	    if ( (patchsym->n_type & N_TYPE) == N_INDR)
		lookname = strbase + patchsym->n_value;
	    else
		lookname = symname;
	    realsym = findSymbolByName(sKernelFile, lookname);

	    patchsym->n_sect  = NO_SECT;
	    if (realsym)
	    {
		patchsym->n_type  = realsym->n_type;
		patchsym->n_desc  = realsym->n_desc;
		patchsym->n_value = realsym->n_value;
		if ((patchsym->n_type & N_TYPE) == N_SECT)
		    patchsym->n_type = (patchsym->n_type & ~N_TYPE) | N_ABS;
	    }
	    else
	    {
		errprintf("%s: Undefined in symbol set: %s\n", pathName, symname);
		patchsym->n_type = N_ABS;
		patchsym->n_desc  = 0;
		patchsym->n_value = patchsym->n_un.n_strx;
		patchsym->n_un.n_strx = 0;
	    }

	    if (!havelocal && (patchsym->n_type & N_EXT)) {
		firstlocal = i;
		havelocal = true;
		file->fLocalSyms = patchsym;
	    }
	    continue;
	} /* symbol set */

        // Load up lookup symbol look table with sym names
	file->fSymbToStringTable[i] = symname;

        n_type = sym->n_type & (N_TYPE | N_EXT);

        // Find the first exported symbol
        if ( !firstlocal && (n_type & N_EXT) ) {
            firstlocal = i;
	    havelocal = true;
            file->fLocalSyms = sym;
        }

        // Find the a OSObject based subclass by searching for symbols
        // that have a suffix of '10superClassE'
        symname++; // Skip leading '_'

        if (!foundOSObject
        && (n_type == (N_SECT | N_EXT) || n_type == (N_ABS | N_EXT))
        &&  strx) {
            const char *suffix, *endSym;

            endSym = symname + strlen(symname);

            // Find out if this symbol has the superclass suffix.
            if (symname[0] == kCPPSymbolPrefix[0]
            &&  symname[1] == kCPPSymbolPrefix[1]) {

                suffix = endSym - sizeof(k31SuperClassSuffix) + 1;

                // Check for a gcc3 OSObject subclass
                if (suffix > symname
                && !strcmp(suffix, k31SuperClassSuffix))
                    foundOSObject = true;
            }
            else {
                suffix = endSym - sizeof(k29SuperClassSuffix);

                // Check for a gcc295 OSObject subclass
                if (suffix > symname
                && ('.' == *suffix || '$' == *suffix)
                && !strcmp(suffix+1, k29SuperClassSuffix)) {
                    found295CPP = foundOSObject = true;
                }
                else if (!found295CPP) {
                    // Finally just check if we need to remangle
                    symname++; // skip leading '__'
                    while (*symname) {
                        if ('_' == symname[0] && '_' == symname[1]) {
                            found295CPP = true;
                            break;
                        }
			symname++;
                    }
                }
            }
        }
        else if (sym->n_type == (N_EXT | N_UNDF)) {
            if ( !file->fNLocal)	// Find the last local symbol
                file->fNLocal = i - firstlocal;
            if (!found295CPP) {
                symname++;	// Skip possible second '_' at start.
                while (*symname) {
                    if ('_' == symname[0] && '_' == symname[1]) {
                        found295CPP = true;
                        break;
                    }
		    symname++;
                }
            }
        }
        // Note symname is trashed at this point
    }
    return_if(i < nsyms, false,
        ("%s isn't a valid mach-o, bad symbol strings\n", pathName));

    return_if(!file->fLocalSyms, false, ("%s has no symbols?\n", pathName));

    // If we don't have any undefined symbols then all symbols
    // must be local so just compute it now if necessary.
    if ( !file->fNLocal )
        file->fNLocal = i - firstlocal;

    file->fFoundOSObject = foundOSObject;

    if (found295CPP && !remangleExternSymbols(file, pathName))
        return false;
            
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

static const struct nlist *
findSymbolByAddressInAllFiles(__unused const struct fileRecord * fromFile, 
			    void *entry, const struct fileRecord **resultFile)
{
    int i, nfiles = 0;
    struct fileRecord **files;

    if (sFilesTable) {

        // Check to see if we have already merged this file
	nfiles = DataGetLength(sFilesTable) / sizeof(struct fileRecord *);
	files = (struct fileRecord **) DataGetPtr(sFilesTable);
	for (i = 0; i < nfiles; i++) {
	    if ((((vm_offset_t)entry) >= files[i]->fVMAddr)
	     && (((vm_offset_t)entry) <  files[i]->fVMEnd))
	    {
		const struct nlist * result;
		if (resultFile)
		    *resultFile = files[i];
		result = findSymbolByAddress(files[i], entry);
		return result;
	    }
	}
    }

    return NULL;
}

struct searchContext {
    const char *fSymname;
    const struct fileRecord *fFile;
};

static int symbolSearch(const void *vKey, const void *vSym)
{
    const struct searchContext *key = (const struct searchContext *) vKey;
    const struct nlist *sym = (const struct nlist *) vSym;

    return strcmp(key->fSymname, symbolname(key->fFile, sym));
}

static const struct nlist *
findSymbolByName(struct fileRecord *file, const char *symname)
{
    if (file->fRemangled) {
        // @@@ gvdl: Performance problem
        // Linear search as we don't sort after remangling
        const struct nlist *sym;
        int i = file->fLocalSyms - file->fSymbolBase;
        int nLocal = file->fNLocal + i;

        for (sym = file->fLocalSyms; i < nLocal; i++, sym++)
            if (!strcmp(symNameByIndex(file, i), symname))
                return sym;
        return NULL;
    }
    else {
        struct searchContext context;

        context.fSymname = symname;
        context.fFile = file;
        return (struct nlist *)
            bsearch(&context,
                    file->fLocalSyms, file->fNLocal, sizeof(struct nlist),
                    symbolSearch);
    }
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
	    void * addr = *entry;
#if !KERNEL
	    if (file->fSwapped)
		addr = (void *) OSSwapInt32((uint32_t) addr);
#endif
	    symbol = findSymbolByAddress(file, addr);
	}

	rec->fValue  = *entry;		// Save the previous value
	rec->fRInfo  =  rinfo;		// Save a pointer to the reloc
	rec->fSymbol =  symbol;		// Record the current symbol

	*entry = (void *) rec;	// Save pointer to record in object image
    }

    DataSetLength(sectionRec->fRelocCache, i * sizeof(struct relocRecord));
    ((struct fileRecord *) file)->fImageDirty = true;

    return true;
}

static const struct nlist *
findSymbolRefAtLocation(const struct fileRecord *file,
			struct sectionRecord *sctn, void **loc, const struct fileRecord **foundInFile)
{
    const struct nlist * result;

    *foundInFile = file;

    if (!file->fIsReloc) {
	if (*loc) {
	    void * addr = *loc;
#if !KERNEL
	    if (file->fSwapped)
		addr = (void *) OSSwapInt32((uint32_t) addr);
#endif
	    result = findSymbolByAddress(file, addr);
	    if (!result)
		result = findSymbolByAddressInAllFiles(file, addr, foundInFile);
	    return result;
	}
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
    Boolean result = false;
    struct metaClassRecord *newClass = NULL;
    struct metaClassRecord **fileClasses = NULL;
    int len;

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

	// Copy the meta Class structure and string name into newClass and
        // insert object at end of the file->fClassList and sMergeMetaClasses 
	*newClass = *inClass;
	strcpy(newClass->fClassName, cname);
	fileClasses[-1] = newClass;

	return true;
    } while (0);

    if (fileClasses)
	DataAddLength(file->fClassList, -sizeof(struct metaClassRecord *));

    if (newClass)
	free(newClass);

    return result;
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
// Note 'sym' is the <cname>10superClassE symbol. 
static Boolean
recordClass(struct fileRecord *file, const char *cname, const struct nlist *sym)
{
    Boolean result = false;
    char *supername = NULL;
    const char *classname = NULL;
    struct metaClassRecord newClass;
    char strbuffer[1024];

    // Only do the work to find the super class if we are
    // not currently working on the kernel.  The kernel is the end
    // of all superclass chains by definition as the kernel must be binary
    // compatible with itself.
    if (file->fIsReloc) {
	const char *suffix;
	const struct fileRecord *superfile;
	const struct nlist *supersym;
	const struct section *section;
	struct sectionRecord *sectionRec;
	unsigned char sectind = sym->n_sect;
	const char *superstr;
	void **location;
        int snamelen;

	// We can't resolve anything that isn't in a real section
	// Note that the sectind is starts at one to make room for the
	// NO_SECT flag but the fNSects field isn't offset so we have a
	// '>' test.  Which means this isn't an OSObject based class
	if (sectind == NO_SECT || sectind > file->fNSects) {
	    result = true;
	    goto finish;
        }
	sectionRec = file->fSections + sectind - 1;
	section = sectionRec->fSection;
	location = (void **) ( file->fMachO + section->offset
			    + sym->n_value - section->addr );
	
	supersym = findSymbolRefAtLocation(file, sectionRec, location, &superfile);
	if (!supersym) {
	    result = true; // No superclass symbol then it isn't an OSObject.
	    goto finish;
        }

	// Find string in file and skip leading '_' and then find the suffix
	superstr = symbolname(superfile, supersym) + 1;
	suffix = superstr + strlen(superstr) - sizeof(kGMetaSuffix) + 1;
	if (suffix <= superstr || strcmp(suffix, kGMetaSuffix)) {
	    result = true;	// Not an OSObject superclass so ignore it..
	    goto finish;
        }

	// Got a candidate so hand it over for class processing.
        snamelen = suffix - superstr - sizeof(kOSObjPrefix) + 2;
	supername = (char *) malloc(snamelen + 1);
	bcopy(superstr + sizeof(kOSObjPrefix) - 2, supername, snamelen);
	supername[snamelen] = '\0';
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

        supername = NULL;
	result = true;
    } while (0);

finish:
    if (supername)
	free(supername);

    return result;
}


static Boolean getMetaClassGraph(struct fileRecord *file)
{
    const struct nlist *sym;
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
    // ends in k31SuperClassSuffix as this indicates this class is a conforming
    // OSObject subclass and will need to be patched, and it also
    // contains a pointer to the super class's meta class structure.
    sym = file->fLocalSyms;
    for (i = 0, nsyms = file->fNLocal; i < nsyms; i++, sym++) {
	const char *symname;
	const char *suffix;
	char classname[1024];
	unsigned char n_type = sym->n_type & (N_TYPE | N_EXT);
        int cnamelen;

	// Check that the symbols is a global and that it has a name.
	if (((N_SECT | N_EXT) != n_type && (N_ABS | N_EXT) != n_type)
	||  !sym->n_un.n_strx)
	    continue;

	// Only search from the last *sep* in the symbol.
	// but skip the leading '_' in all symbols first.
	symname = symbolname(file, sym) + 1;
        if (symname[0] != kCPPSymbolPrefix[0]
        ||  symname[1] != kCPPSymbolPrefix[1])
            continue;

	suffix = symname + strlen(symname) - sizeof(k31SuperClassSuffix) + 1;
	if (suffix <= symname || strcmp(suffix, k31SuperClassSuffix))
	    continue;

	// Got a candidate so hand it over for class processing.
        cnamelen = suffix - symname - sizeof(kOSObjPrefix) + 2;
	return_if(cnamelen + 1 >= (int) sizeof(classname),
	    false, ("Symbol %s is too long", symname));

	bcopy(symname + sizeof(kOSObjPrefix) - 2, classname, cnamelen);
	classname[cnamelen] = '\0';
	if (!recordClass(file, classname, sym))
	    return false;
    }

    return_if(!file->fClassList, false, ("Internal error, "
	      "getMetaClassGraph(%s) found no classes", file->fPath)); 

    DEBUG_LOG(("Found %ld classes in %p for %s\n",
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
	int k, j, cnt1, cnt2;
	struct metaClassRecord **list1, **list2;

	list1 = (struct metaClassRecord **) DataGetPtr(file->fClassList);
	cnt1  = DataGetLength(file->fClassList)  / sizeof(*list1);
	list2 = (struct metaClassRecord **) DataGetPtr(sMergeMetaClasses);
	cnt2  = DataGetLength(sMergeMetaClasses) / sizeof(*list2);

	for (k = 0; k < cnt1; k++) {
	    for (j = 0; j < cnt2; j++) {
		if (!strcmp(list1[k]->fClassName, list2[j]->fClassName)) {
		    errprintf("duplicate class %s in %s & %s\n",
			      list1[k]->fClassName,
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
    if ((symb->n_type & N_TYPE) == N_ABS && !file->fIsReloc) {
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
    return_if(file->fIsReloc,
	false, ("Internal error - resolveKernelVTable is relocateable\n"));

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
	void * addr = *curEntry;
#if !KERNEL
	if (file->fSwapped)
	    addr = (void *) OSSwapInt32((uint32_t) addr);
#endif
	curPatch->fSymbol = (struct nlist *) 
	    findSymbolByAddress(file, addr);
	if (curPatch->fSymbol)
	{
	    curPatch->fType = kSymbolLocal;
	    curPatch->fFile = file;
	}
	else
	{
	    curPatch->fSymbol = (struct nlist *) 
		findSymbolByAddressInAllFiles(file, addr, &curPatch->fFile);
	    if (!curPatch->fSymbol) {
		errprintf("%s: !findSymbolByAddressInAllFiles(%p)\n",
			    file->fPath, addr);
		return false;
	    }
	    curPatch->fType = kSymbolLocal;
	}
    }

    // Tag the end of the patch vtable
    curPatch->fSymbol = NULL;
    metaClass->fPatchedVTable = patchedVTable;

    return true;
}

static const char *addNewString(struct fileRecord *file, 
                                const char *strname, int namelen)
{
    DataRef strings = 0;
    const char *newStr;

    namelen++;	// Include terminating '\0';

    // Make sure we have a string table as well for this symbol
    if (file->fNewStringBlocks) {
        DataRef *blockTable = (DataRef *) DataGetPtr(file->fNewStringBlocks);
        int index = DataGetLength(file->fNewStringBlocks) / sizeof(DataRef*);
        strings = blockTable[index - 1];
        if (DataRemaining(strings) < namelen)
            strings = 0;
    }
    else
    {
        file->fNewStringBlocks = DataCreate(0);
        return_if(!file->fNewStringBlocks, NULL,
            ("Unable to allocate new string table %s\n", file->fPath));
    }

    if (!strings) {
        int size = (namelen + 1023) & ~1023;
        if (size < 16 * 1024)
            size = 16 * 1024; 
        strings = DataCreate(size);
        return_if(!strings, NULL,
            ("Unable to allocate new string block %s\n", file->fPath));
        return_if(
            !DataAppendBytes(file->fNewStringBlocks, &strings, sizeof(strings)),
            false, ("Unable to allocate string table for %s\n", file->fPath));
    }

    newStr = DataGetEndPtr(strings);
    DataAppendBytes(strings, strname, namelen);
    return newStr;
}

// reloc->fPatch must contain a valid pointer
static struct nlist *
getNewSymbol(struct fileRecord *file,
	     const struct relocRecord *reloc, const char *supername)
{
    unsigned int size, i;
    struct nlist **sym;
    struct nlist *msym;
    struct relocation_info *rinfo;
    const char *newStr;

    if (!file->fNewSymbols) {
	file->fNewSymbols = DataCreate(0);
	return_if(!file->fNewSymbols, NULL,
	    ("Unable to allocate new symbol table for %s\n", file->fPath));
    }

    rinfo = (struct relocation_info *) reloc->fRInfo;
    size = DataGetLength(file->fNewSymbols) / sizeof(struct nlist *);
    sym = (struct nlist **) DataGetPtr(file->fNewSymbols);
    for (i = 0; i < size; i++, sym++) {
        int symnum = i + file->fSymtab->nsyms;
        newStr = symNameByIndex(file, symnum);
	if (!strcmp(newStr, supername)) {
	    rinfo->r_symbolnum = symnum;
	    file->fSymbolsDirty = true; 
	    return *sym;
	}
    }

    if (reloc->fSymbol->n_un.n_strx >= 0) {
        // This symbol has not been previously processed, so assert that it
        // is a valid non-local symbol.  I need this condition to be true for
	// the later code to set to -1.  Now, being the first time through,
	// I'd better make sure that n_sect is NO_SECT.

        return_if(reloc->fSymbol->n_sect != NO_SECT, NULL,
            ("Undefined symbol entry with non-zero section %s:%s\n",
            file->fPath, symbolname(file, reloc->fSymbol)));

	// Mark the original symbol entry as having been processed.
	// This means that we wont attempt to create the symbol again
	// in the future if we come through a different path.
        ((struct nlist *) reloc->fSymbol)->n_un.n_strx =
	    -reloc->fSymbol->n_un.n_strx;    

        // Mark the old symbol as being potentially deletable I can use the
        // n_sect field as the input symbol must be of type N_UNDF which means
        // that the n_sect field must be set to NO_SECT otherwise it is an
        // invalid input file.
        ((struct nlist *) reloc->fSymbol)->n_sect = (unsigned char) -1;
    }

    // If we are here we didn't find the symbol so create a new one now
    msym = (struct nlist *) malloc(sizeof(struct nlist));
    return_if(!msym,
	NULL, ("Unable to create symbol table entry for %s", file->fPath));
    return_if(!DataAppendBytes(file->fNewSymbols, &msym, sizeof(msym)),
	    NULL, ("Unable to grow symbol table for %s\n", file->fPath));

    newStr = addNewString(file, supername, strlen(supername));
    if (!newStr)
        return NULL;

    // If we are here we didn't find the symbol so create a new one now
    return_if(!DataAppendBytes(file->fSym2Strings, &newStr, sizeof(newStr)),
            NULL, ("Unable to grow symbol table for %s\n", file->fPath));
    file->fSymbToStringTable = (const char **) DataGetPtr(file->fSym2Strings);

    // Offset the string index by the original string table size
    // and negate the address to indicate that this is a 'new' symbol
    msym->n_un.n_strx = -1;
    msym->n_type = (N_EXT | N_UNDF);
    msym->n_sect = NO_SECT;
    msym->n_desc = 0;
    msym->n_value = (unsigned long) newStr;

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

    sym->n_un.n_strx = -sym->n_un.n_strx;
    if (oldname && namelen < strlen(oldname))
    {
	// Overwrite old string in string table
	strcpy((char *) oldname, supername);
        file->fSymbolsDirty = true; 
        return sym;
    }

    oldname = addNewString(file, supername, namelen);
    if (!oldname)
        return NULL;

    file->fSymbToStringTable[sym - file->fSymbolBase] = oldname;
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

    // We know that the target's vtable entry is different from the
    // superclass' vtable entry.  This means that we will have to apply a
    // patch to the current entry, however before returning lets check to
    // see if we have a _RESERVEDnnn field 'cause we can use this as a
    // registration point that must align between vtables.
    if (strstr(supername, kReservedNamePrefix))
	return kSymbolMismatch;

    // OK, we have a superclass difference where the superclass doesn't
    // reference a pad function so assume that the superclass is correct.
    if (strstr(classname, kReservedNamePrefix))
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

    if (!file->fIsReloc)
    {
	// If the metaClass we are being to ask is already relocated then we
	// need to do a quick scan to grab the fPatchList in a reliable format
	// however we don't need to check the superclass in the already linked
	// modules as the vtables are always correct wrt themselves.
	// Note this ends the superclass chain recursion.
	Boolean res;
	res = resolveKernelVTable(metaClass);
	return res;
    }

    if (!metaClass->fSuperName)
	return false;

    // The class isn't in the kernel so make sure that the super class 
    // is patched before patching ouselves.
    super = getClass(sMergeMetaClasses, metaClass->fSuperName);
    return_if(!super, false, ("Can't find superclass for %s : %s\n",
	metaClass->fClassName, metaClass->fSuperName));

    // Superclass recursion if necessary
    if (!super->fPatchedVTable) {
	Boolean res;
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
		    symbolname(spp->fFile, spp->fSymbol);

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
		    errprintf("%s is not compatible with its superclass, "
			      "%s superclass changed?\n",
			      metaClass->fClassName, super->fClassName);
		    goto abortPatch;

		default:
		    errprintf("Internal error - unknown patch type\n");
		    goto abortPatch;
		}
		if (symbol) {
		    curPatch->fSymbol = symbol;
		    (*curReloc)->fSymbol = symbol;
		    curPatch->fFile = file;
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
	    curPatch->fFile = file;
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
    unsigned long i, last = 0;
    struct metaClassRecord **classes = NULL;
    struct sectionRecord *section;
    kern_return_t ret;

    startMachO = (vm_address_t) file->fMachO;
    endMachO = startMachO + file->fMachOSize + delta;
    endMap   = (vm_address_t) file->fMap + file->fMapSize;

    // Do we have room in the current mapped image
    if (endMachO < round_page_32(endMap)) {
	file->fMachOSize += delta;
	return true;
    }

    newsize = endMachO - startMachO;
    if (newsize < round_page_32(file->fMapSize)) {
        DEBUG_LOG(("Growing image %s by moving\n", file->fPath));

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

        DEBUG_LOG(("Growing image %s by reallocing\n", file->fPath));
	// We have relocated the kmem image so we are going to have to
	// move all of the pointers into the image around.
    }
    else {
        DEBUG_LOG(("Growing image %s by allocating\n", file->fPath));
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

    // Rebase the cached-in object 'struct symtab_command' pointer
    REBASE(file->fSymtab, delta);

    // Rebase the cached-in object 'struct nlist' pointer for all symbols
    REBASE(file->fSymbolBase, delta);

    // Rebase the cached-in object 'struct nlist' pointer for local symbols
    REBASE(file->fLocalSyms, delta);

    // Rebase the cached-in object 'char' pointer for the string table
    REBASE(file->fStringBase, delta);

    // Ok now we have to go over all of the relocs one last time
    // to clean up the pad updates which had their string index negated
    // to indicate that we have finished with them.
    section = file->fSections;
    for (i = 0, last = file->fNSects; i < last; i++, section++)
	REBASE(section->fSection, delta);

    // We only ever grow images that contain class lists so dont bother
    // the check if file->fClassList is non-zero 'cause it can't be
    // assert(file->fClassList);
    last = DataGetLength(file->fClassList)
	   / sizeof(struct metaClassRecord *);
    classes = (struct metaClassRecord **) DataGetPtr(file->fClassList);
    for (i = 0; i < last; i++) {
	struct patchRecord *patch;

	for (patch = classes[i]->fPatchedVTable; patch->fSymbol; patch++) {
	    vm_address_t symAddr = (vm_address_t) patch->fSymbol;
            
            // Only need to rebase if the symbol is part of the image
            // If this is a new symbol then it was independantly allocated
	    if (symAddr >= startMachO && symAddr < endMachO)
		REBASE(patch->fSymbol, delta);
	}
    }

    // Finally rebase all of the string table pointers
    last = file->fSymtab->nsyms;
    for (i = 0; i < last; i++)
        REBASE(file->fSymbToStringTable[i], delta);

#undef REBASE

    return true;

#endif /* KERNEL */
}

// Note: This function is only called from kld_file_prepare_for_link()
// This function can only operate on 32 bit mach-o files
static Boolean
prepareFileForLink(struct fileRecord *file)
{
    unsigned long i, last, numnewsyms, newsymsize, newstrsize;
    struct sectionRecord *section;
    struct nlist **symp, *sym;
    DataRef newStrings, *stringBlocks;

    // If we didn't even do a pseudo 'relocate' and dirty the image
    // then we can just return now.
    if (!file->fImageDirty) {
#if !KERNEL
	if (file->fSwapped) {
	    kld_macho_unswap((struct mach_header *) file->fMachO, file->fSwapped, false);
	    file->fSwapped = false;
	}
#endif
	return true;
    }

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
		struct nlist *repairSym;
    
		// Repair Damage to object image
		entry = (void **) (sectionBase + rec->fRInfo->r_address);
		*entry = rec->fValue;

		// Check if the symbol that this relocation entry points
		// to is marked as erasable 
		repairSym = (struct nlist *) rec->fSymbol;
		if (repairSym && repairSym->n_type == (N_EXT | N_UNDF)
		&&  repairSym->n_sect == (unsigned char) -1) {
		    // It is in use so we better clear the mark
		    repairSym->n_un.n_strx = -repairSym->n_un.n_strx;
		    repairSym->n_sect = NO_SECT;
		}
	    }

	    // Clean up the fRelocCache we don't need it any more.
	    DataRelease(section->fRelocCache);
	    section->fRelocCache = 0;
	}
    }
    file->fImageDirty = false;	// Image is clean

    // If we didn't dirty the symbol table then just return
    if (!file->fSymbolsDirty) {
#if !KERNEL
	if (file->fSwapped) {
	    kld_macho_unswap((struct mach_header *) file->fMachO, file->fSwapped, false);
	    file->fSwapped = false;
	}
#endif
	return true;
    }

    // calculate total file size increase and check against padding
    if (file->fNewSymbols) {
        numnewsyms = DataGetLength(file->fNewSymbols);
        symp  = (struct nlist **) DataGetPtr(file->fNewSymbols);
    }
    else {
        numnewsyms = 0;
        symp = 0;
    }
    numnewsyms /= sizeof(struct nlist *);
    file->fSymtab->nsyms  += numnewsyms;

    // old sting size + 30% rounded up to nearest page
    newstrsize = file->fSymtab->strsize * 21 / 16;
    newstrsize = (newstrsize + PAGE_MASK) & ~PAGE_MASK;
    newStrings = DataCreate(newstrsize);
    return_if(!newStrings, false,
             ("Unable to allocate a copy aside buffer, no memory\n"));

    newsymsize  = numnewsyms * sizeof(struct nlist);
    file->fStringBase     += newsymsize;
    file->fSymtab->stroff += newsymsize;

    last = file->fSymtab->nsyms - numnewsyms;
    newstrsize = 0;
    DataAppendBytes(newStrings, &newstrsize, 4);	// Leading nuls
    sym = file->fSymbolBase;

    // Pre-compute an already offset new symbol pointer.  The offset is the
    // orignal symbol table.
    symp -= last;
    for (i = 0; i < file->fSymtab->nsyms; i++, sym++) {
        const char *str = symNameByIndex(file, i);
        int len = strlen(str) + 1;
        unsigned int strx;

        // Rebase sym in the new symbol region
        if (i >= last)
            sym = symp[i];

	if (sym->n_un.n_strx < 0 && sym->n_type == (N_EXT | N_UNDF)
        && (unsigned char) -1 == sym->n_sect) {
            // after patching we find that this symbol is no longer in
            // use.  So invalidate it by converting it into an N_ABS
            // symbol, remove the external bit and null out the name.
            bzero(sym, sizeof(*sym));
            sym->n_type = N_ABS;
        }
        else {
            // Repair the symbol for the getNewSymbol case.
            if (-1 == sym->n_un.n_strx)
                sym->n_value = 0;

            // Record the offset of the string in the new table
            strx = DataGetLength(newStrings);
            return_if(!DataAppendBytes(newStrings, str, len), false,
                ("Unable to append string, no memory\n"));

            sym->n_un.n_strx = strx;
            file->fSymbToStringTable[i] = file->fStringBase + strx;
        }
    }

    // Don't need the new strings any more
    
    if (file->fNewStringBlocks){
        last = DataGetLength(file->fNewStringBlocks) / sizeof(DataRef);
        stringBlocks = (DataRef *) DataGetPtr(file->fNewStringBlocks);
    }
    else{
        last =0;
        stringBlocks=0;
    }
    
    for (i = 0; i < last; i++)
        DataRelease(stringBlocks[i]);

    DataRelease(file->fNewStringBlocks);
    file->fNewStringBlocks = 0;

    newstrsize  = DataGetLength(newStrings);
    newstrsize  = (newstrsize + 3) & ~3;	// Round to nearest word
    return_if(
        !growImage(file, newsymsize + newstrsize - file->fSymtab->strsize),
	false, ("Unable to patch the extension, no memory\n", file->fPath));

    // Push out the new symbol table if necessary
    if (numnewsyms) {
	caddr_t base;

	// Append the new symbols to the original symbol table.
	base = (caddr_t) file->fSymbolBase
	     + (file->fSymtab->nsyms - numnewsyms) * sizeof(struct nlist);
	symp = (struct nlist **) DataGetPtr(file->fNewSymbols);
	for (i = 0; i < numnewsyms; i++, base += sizeof(struct nlist), symp++)
	    bcopy(*symp, base, sizeof(struct nlist));

	DataRelease(file->fNewSymbols);
	file->fNewSymbols = 0;
    }

    // Push out the new string table if necessary
    if (newStrings) {
	unsigned long *base = (unsigned long *) file->fStringBase;
	unsigned long actuallen = DataGetLength(newStrings);

	// Set the last word in string table to zero before copying data
        base[(newstrsize / sizeof(unsigned long)) - 1] = 0;

	// Now copy the new strings back to the end of the file
	bcopy((caddr_t) DataGetPtr(newStrings), file->fStringBase, actuallen);

	file->fSymtab->strsize = newstrsize;

        DataRelease(newStrings);
    }

    file->fSymbolsDirty = false;
#if !KERNEL
    if (file->fSwapped) {
	kld_macho_unswap((struct mach_header *) file->fMachO, file->fSwapped, false);
	file->fSwapped = false;
    }
#endif
    return true;
}

// This function can only operate on 32 bit mach-o files
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

#if KERNEL
    file.fMap = map;
    file.fMapSize = mapSize;
    file.fIsKmem = isKmem;
#else
    if (!mapObjectFile(&file, pathName))
	return false;
#endif /* KERNEL */

    do {
	const struct machOMapping {
	    struct mach_header h;
	    struct load_command c[1];
	} *machO;
	const struct load_command *cmd;
	boolean_t lookVMRange;
        unsigned long i;

	if (!findBestArch(&file, pathName))
	    break;

	machO = (const struct machOMapping *) file.fMachO;
	if (file.fMachOSize < machO->h.sizeofcmds)
	    break;

	// If the file type is MH_EXECUTE then this must be a kernel
	// as all Kernel extensions must be of type MH_OBJECT
        file.fIsKernel = (MH_EXECUTE == machO->h.filetype);

	for (i = 0, cmd = &machO->c[0], lookVMRange = true; i < machO->h.ncmds; i++) {
            if (cmd->cmd == LC_SYMTAB)
		file.fSymtab = (struct symtab_command *) cmd;
	    else if (cmd->cmd == LC_SEGMENT) {
                struct segment_command *seg = (struct segment_command *) cmd;
                int nsects = seg->nsects;

		if (lookVMRange) {
		    if (!strcmp("__PRELINK", seg->segname))
			// segments following __PRELINK are going to move, so ignore them
			lookVMRange = false;
		    else if (!file.fVMAddr && !file.fVMEnd) {
			file.fVMAddr = seg->vmaddr;
			file.fVMEnd = seg->vmaddr + seg->vmsize;
		    } else {
			if (seg->vmaddr < file.fVMAddr)
			    file.fVMAddr = seg->vmaddr;
			if ((seg->vmaddr + seg->vmsize) > file.fVMEnd)
			    file.fVMEnd = seg->vmaddr + seg->vmsize;
		    }
		}

                if (nsects)
                    return_if(!parseSegments(&file, seg),
                              false, ("%s isn't a valid mach-o, bad segment",
			      pathName));

                if (file.fIsKernel) {
#if KERNEL
                    // We don't need to look for the LinkEdit segment unless
                    // we are running in the kernel environment.
                    if (!strcmp(kLinkEditSegName, seg->segname))
                        file.fLinkEditSeg = seg;
#endif
                }
	    }
	    cmd = (struct load_command *) ((UInt8 *) cmd + cmd->cmdsize);
	}
	break_if(!file.fSymtab,
	    ("%s isn't a valid mach-o, no symbols\n", pathName));

	if (machO->h.flags & MH_INCRLINK) {

	    file.fIsIncrLink = true;
	    ((struct machOMapping *) machO)->h.flags &= ~MH_INCRLINK;

#if !KERNEL
	    // the symtab fileoffset is the end of seg0's vmsize,
	    // which can be (rarely) unaligned.
	    unsigned int
	    align = file.fSymtab->symoff % sizeof(long);
	    if (align != 0) {
		align = sizeof(long) - align;
		growImage(&file, align);
		bcopy(file.fMachO + file.fSymtab->symoff,
			file.fMachO + file.fSymtab->symoff + align,
			file.fSymtab->stroff + file.fSymtab->strsize - file.fSymtab->symoff);
		file.fSymtab->symoff += align;
		file.fSymtab->stroff += align;
	    }
#endif
	}

        if (!parseSymtab(&file, pathName))
            break;

	fp = addFile(&file, pathName);
	if (!fp)
	    break;

	if (file.fFoundOSObject && !getMetaClassGraph(fp))
	    break;

	if (file.fIsKernel)
	    sKernelFile = fp;

#if KERNEL
        // Automatically load the kernel's link edit segment if we are
        // attempting to load a driver.
	if (!sKernelFile) {
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

    // Failure path, then clean up
    if (fp)
        // @@@ gvdl: for the time being leak the file ref in the file table
        removeFile(fp);
    else
        unmapFile(&file);

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
	unsigned int i, nsyms;

	sym = file->fSymbolBase;
	for (i = 0, nsyms = file->fSymtab->nsyms; i < nsyms; i++, sym++) {
	    if ( (sym->n_type & N_EXT) ) {
		sym = 0;
		break;	// Terminate search when we hit an extern
	    }
	    if ( (sym->n_type & N_STAB) )
		continue;
	    if ( !strcmp(symname, symNameByIndex(file, i)) )
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
        if (!patchVTable(classes[i])) {            
            // RY: Set a flag in the file list to invalidate this data.
            // I would remove the file from the list, but that seems to be
            // not worth the effort.            
            file->fIgnoreFile = TRUE;
            
            return false;
        }
    }

    return true;
}

Boolean kld_file_prepare_for_link(void)
{
    if (sMergedFiles) {
	unsigned long i, nmerged = 0;
	struct fileRecord **files;
    
	// Check to see if we have already merged this file
	nmerged = DataGetLength(sMergedFiles) / sizeof(struct fileRecord *);
	files = (struct fileRecord **) DataGetPtr(sMergedFiles);
	for (i = 0; i < nmerged; i++) {                
            if (!files[i]->fIgnoreFile && !prepareFileForLink(files[i]))
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

void kld_file_cleanup_all_resources(void)
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

    DataRelease(sFilesTable);
    sFilesTable = NULL;

    // Don't really have to clean up anything more as the whole
    // malloc engine is going to be released and I couldn't be bothered.
}


#if !KERNEL
#if 0
static const struct fileRecord *sortFile;
static int symCompare(const void *vSym1, const void *vSym2)
{
    const struct nlist *sym1 = vSym1;
    const struct nlist *sym2 = vSym2;

    {
        unsigned int ind1, ind2;
    
        ind1 = sym1->n_type & N_TYPE;
        ind2 = sym2->n_type & N_TYPE;
        if (ind1 != ind2) {
            // if sym1 is undefined then sym1 must come later than sym2
            if (ind1 == N_UNDF)
                return 1;
            // if sym2 is undefined then sym1 must come earlier than sym2
            if (ind2 == N_UNDF)
                return -1;
            /* drop out if neither are undefined */
        }
    }

    {
        const struct fileRecord *file = sortFile;
        const char *name1, *name2;
    
        name1 = file->fStringBase + sym1->n_un.n_strx;
        name2 = file->fStringBase + sym2->n_un.n_strx;
        return strcmp(name1, name2);
    }
}
#endif /* 0 */

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
#if 0
        // Sorting doesn't work until I fix the relocs too?

        // sort the symbol table appropriately
        unsigned int nsyms = file->fSymtab->nsyms
                           - (file->fLocalSyms - file->fSymbolBase);
        sortFile = file;
        heapsort((void *) file->fLocalSyms, nsyms, sizeof(struct nlist),
                symCompare);
#endif

	break_if(-1 == write(fd, file->fMachO, file->fMachOSize),
	    ("Can't dump output file %s - %s(%d)\n", 
		outName, strerror(errno), errno));
	ret = true;
    } while(0);

    close(fd);

    return ret;
}

#endif /* !KERNEL */

