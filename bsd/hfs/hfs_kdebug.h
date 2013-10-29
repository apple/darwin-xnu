#include <sys/kdebug.h>

/*
 * KERNEL_DEBUG related definitions for HFS.
 *
 * NOTE: The Class DBG_FSYSTEM = 3, and Subclass DBG_HFS = 8, so these
 * debug codes are of the form 0x0308nnnn.
 */
#define HFSDBG_CODE(code)	FSDBG_CODE(DBG_HFS, code)

enum {
	HFSDBG_UNMAP_FREE			= HFSDBG_CODE(0),	/* 0x03080000 */
	HFSDBG_UNMAP_ALLOC			= HFSDBG_CODE(1),	/* 0x03080004 */
	HFSDBG_UNMAP_CALLBACK		= HFSDBG_CODE(2),	/* 0x03080008 */
	/* 0x0308000C is unused */
	HFSDBG_BLOCK_ALLOCATE		= HFSDBG_CODE(4),	/* 0x03080010 */
	HFSDBG_BLOCK_DEALLOCATE		= HFSDBG_CODE(5),	/* 0x03080014 */
	HFSDBG_READ_BITMAP_BLOCK	= HFSDBG_CODE(6),	/* 0x03080018 */
	HFSDBG_RELEASE_BITMAP_BLOCK	= HFSDBG_CODE(7),	/* 0x0308001C */
	HFSDBG_ALLOC_CONTIG_BITMAP	= HFSDBG_CODE(8),	/* 0x03080020 */
	HFSDBG_ALLOC_ANY_BITMAP		= HFSDBG_CODE(9),	/* 0x03080024 */
	HFSDBG_ALLOC_KNOWN_BITMAP	= HFSDBG_CODE(10),	/* 0x03080028 */
	HFSDBG_MARK_ALLOC_BITMAP	= HFSDBG_CODE(11),	/* 0x0308002C */
	HFSDBG_MARK_FREE_BITMAP		= HFSDBG_CODE(12),	/* 0x03080030 */
	HFSDBG_BLOCK_FIND_CONTIG	= HFSDBG_CODE(13),	/* 0x03080034 */
	HFSDBG_IS_ALLOCATED			= HFSDBG_CODE(14),	/* 0x03080038 */
	/* 0x0308003C is unused */
	HFSDBG_RESET_EXTENT_CACHE	= HFSDBG_CODE(16),	/* 0x03080040 */
	HFSDBG_REMOVE_EXTENT_CACHE	= HFSDBG_CODE(17),	/* 0x03080044 */
	HFSDBG_ADD_EXTENT_CACHE		= HFSDBG_CODE(18),	/* 0x03080048 */
	HFSDBG_READ_BITMAP_RANGE	= HFSDBG_CODE(19),  /* 0x0308004C */
	HFSDBG_RELEASE_SCAN_BITMAP	= HFSDBG_CODE(20),  /* 0x03080050 */
	HFSDBG_SYNCER			= HFSDBG_CODE(21),	/* 0x03080054 */
	HFSDBG_SYNCER_TIMED		= HFSDBG_CODE(22),	/* 0x03080058 */
};

/*
	Parameters logged by the above
	EVENT CODE					DBG_FUNC_START arg1, arg2, arg3, arg4 ... DBG_FUNC_END arg1, arg2, arg3, arg4
	---------------------------
	HFSDBG_UNMAP_CALLBACK		0, extentCount, 0, 0 ... 0, 0, 0, 0
	HFSDBG_UNMAP_FREE			startBlock, blockCount, 0, 0 ... err, 0, 0, 0
	HFSDBG_UNMAP_ALLOC			startBlock, blockCount, 0, 0 ... err, 0, 0, 0
	HFSDBG_REMOVE_EXTENT_CACHE	startBlock, blockCount, vcbFreeExtCnt, 0 ... 0, 0, vcbFreeExtCnt, extentsRemoved
	HFSDBG_ADD_EXTENT_CACHE		startBlock, blockCount, vcbFreeExtCnt, 0 ... 0, 0, vcbFreeExtCnt, retval
	HFSDBG_MARK_ALLOC_BITMAP	startBlock, blockCount, 0, 0 ... err, 0, 0, 0
	HFSDBG_MARK_FREE_BITMAP		startBlock, blockCount, valid, 0 ... err, 0, 0, 0
	HFSDBG_BLOCK_DEALLOCATE		startBlock, blockCount, flags, 0 ... err, 0, 0, 0
	HFSDBG_IS_ALLOCATED			startBlock, blockCount, stop, 0 ... err, 0, actualBlockCount, 0
	HFSDBG_BLOCK_ALLOCATE		startBlock, minBlocks, maxBlocks, flags ... err, actualStartBlock, actualBlockCount, 0
	HFSDBG_ALLOC_CONTIG_BITMAP	startBlock, minBlocks, maxBlocks, useMeta ... err, actualStartBlock, actualBlockCount, 0
	HFSDBG_ALLOC_ANY_BITMAP		startBlock, endBlock,  maxBlocks, useMeta ... err, actualStartBlock, actualBlockCount, 0
	HFSDBG_ALLOC_KNOWN_BITMAP	0,          0,         maxBlocks, 0 ... err, actualStartBlock, actualBlockCount, 0
	HFSDBG_BLOCK_FIND_CONTIG	startBlock, endBlock, minBlocks, maxBlocks ... err, actualStartBlock, actualBlockCount, 0
	HFSDBG_READ_BITMAP_BLOCK	startBlock, 0,          0, 0 ... err, 0, 0, 0
	HFSDBG_RELEASE_BITMAP_BLOCK	dirty, 0, 0, 0 ... 0, 0, 0, 0
	HFSDBG_RESET_EXTENT_CACHE	0, 0, 0, 0 ... 0, 0, 0, 0
	HFSDBG_READ_BITMAP_RANGE	startBlock, iosize, 0, 0 ... err, 0, 0, 0 
	HFSDBG_RELEASE_SCAN_BITMAP	0, 0, 0, 0, ... 0, 0, 0, 0
	
*/
