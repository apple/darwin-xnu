
""" Please make sure you read the README COMPLETELY BEFORE reading anything below.
    It is very critical that you read coding guidelines in Section E in README file. 
"""

from xnu import *
from utils import *

from mbufdefines import *
import xnudefines

# Macro: mbuf_stat
@lldb_command('mbuf_stat')
def MBufStat(cmd_args=None):
    """ Print extended mbuf allocator statistics. 
    """
    hdr_format = "{0: <16s} {1: >8s} {2: >8s} {3: ^16s} {4: >8s} {5: >12s} {6: >8s} {7: >8s} {8: >8s}"
    print hdr_format.format('class', 'total', 'cached', 'uncached', 'inuse', 'failed', 'waiter', 'notified', 'purge')
    print hdr_format.format('name', 'objs', 'objs', 'objs/slabs', 'objs', 'alloc count', 'count', 'count', 'count')
    print hdr_format.format('-'*16, '-'*8, '-'*8, '-'*16, '-'*8, '-'*12, '-'*8, '-'*8, '-'*8)
    entry_format = "{0: <16s} {1: >8d} {2: >8d} {3:>7d} / {4:<6d} {5: >8d} {6: >12d} {7: >8d} {8: >8d} {9: >8d}"
    num_items = sizeof(kern.globals.mbuf_table) / sizeof(kern.globals.mbuf_table[0])
    ncpus = int(kern.globals.ncpu)
    for i in range(num_items):
        mbuf = kern.globals.mbuf_table[i]        
        mcs = Cast(mbuf.mtbl_stats, 'mb_class_stat_t *')
        mc = mbuf.mtbl_cache
        total = 0
        total += int(mc.mc_full.bl_total) * int(mc.mc_cpu[0].cc_bktsize)
        ccp_arr = mc.mc_cpu
        for i in range(ncpus):
            ccp = ccp_arr[i]
            if int(ccp.cc_objs) > 0:
                total += int(ccp.cc_objs)
            if int(ccp.cc_pobjs) > 0:
                total += int(ccp.cc_pobjs)
        print entry_format.format(mcs.mbcl_cname, mcs.mbcl_total,  total,
                                  mcs.mbcl_infree, mcs.mbcl_slab_cnt,
                                  (mcs.mbcl_total - total - mcs.mbcl_infree),
                                  mcs.mbcl_fail_cnt, mbuf.mtbl_cache.mc_waiter_cnt,
                                  mcs.mbcl_notified, mcs.mbcl_purge_cnt
                                  )
# EndMacro: mbuf_stat
        
# Macro: mbuf_walkpkt
@lldb_command('mbuf_walkpkt')
def MbufWalkPacket(cmd_args=None):
    """ Walk the mbuf packet chain (m_nextpkt)
    """
    if (cmd_args == None or len(cmd_args) == 0):
            print "Missing argument 0 in user function."
            return
    mp = kern.GetValueFromAddress(cmd_args[0], 'mbuf *')
    cnt = 1
    tot = 0
    while (mp):
        out_string = ""
        mbuf_walk_packet_format = "{0:4d} 0x{1:x} [len {2:4d}, type {3:2d}, "
        out_string += mbuf_walk_packet_format.format(cnt, mp, mp.m_hdr.mh_len, mp.m_hdr.mh_type)
        if (kern.globals.mclaudit != 0):
            out_string += GetMbufBuf2Mca(mp) + ", "
        tot = tot + mp.m_hdr.mh_len
        out_string += "total " + str(tot) + "]"
        print out_string
        mp = mp.m_hdr.mh_nextpkt
        cnt += 1
# EndMacro: mbuf_walkpkt

# Macro: mbuf_walk
@lldb_command('mbuf_walk')
def MbufWalk(cmd_args=None):
    """ Walk the mbuf chain (m_next)
    """
    mp = kern.GetValueFromAddress(cmd_args[0], 'mbuf *')
    cnt = 1
    tot = 0
    while (mp):
        out_string = ""
        mbuf_walk_format = "{0:4d} 0x{1:x} [len {2:4d}, type {3:2d}, "
        out_string += mbuf_walk_format.format(cnt, mp, mp.m_hdr.mh_len, mp.m_hdr.mh_type)
        if (kern.globals.mclaudit != 0):
            out_string += GetMbufBuf2Mca(mp) + ", "
        tot = tot + mp.m_hdr.mh_len
        out_string += "total " + str(tot) + "]"
        print out_string
        mp = mp.m_hdr.mh_next
        cnt += 1
# EndMacro: mbuf_walk

# Macro: mbuf_buf2slab
@lldb_command('mbuf_buf2slab')
def MbufBuf2Slab(cmd_args=None):
    """ Given an mbuf object, find its corresponding slab address
    """
    if (cmd_args == None or len(cmd_args) == 0):
            print "Missing argument 0 in user function."
            return
    m = kern.GetValueFromAddress(cmd_args[0], 'mbuf *')
    gix = (m - Cast(kern.globals.mbutl, 'char *')) >> MBSHIFT
    slabstbl = kern.globals.slabstbl
    ix = (m - Cast(slabstbl[int(gix)].slg_slab[0].sl_base, 'char *')) >> 12
    slab = addressof(slabstbl[int(gix)].slg_slab[int(ix)])
    if (kern.ptrsize == 8):
        mbuf_slab_format = "0x{0:<16x}"
        print mbuf_slab_format.format(slab)
    else:
        mbuf_slab_format = "0x{0:<8x}"
        print mbuf_slab_format.format(slab)
# EndMacro: mbuf_buf2slab

# Macro: mbuf_buf2mca
@lldb_command('mbuf_buf2mca')
def MbufBuf2Mca(cmd_args=None):
    """ Find the mcache audit structure of the corresponding mbuf
    """
    m = kern.GetValueFromAddress(cmd_args[0], 'mbuf *')
    print GetMbufBuf2Mca(m)
    return
# EndMacro: mbuf_buf2mca

# Macro: mbuf_slabs
@lldb_command('mbuf_slabs')
def MbufSlabs(cmd_args=None):
    """ Print all slabs in the group
    """
    out_string = ""
    slg = kern.GetValueFromAddress(cmd_args[0], 'mcl_slabg_t *')
    x = 0

    if (kern.ptrsize == 8):
        slabs_string_format = "{0:>4d}: 0x{1:16x} 0x{2:16x} 0x{3:16x} {4:4s} {5:20d} {6:3d} {7:3d} {8:3d} {9:3d} {10:>6s} "
        out_string += "slot slab               next               obj                mca                tstamp     C  R  N   size flags\n"
        out_string += "---- ------------------ ------------------ ------------------ ------------------ ---------- -- -- -- ------ -----\n"
    else:
        slabs_string_format = "{0:>4d}: 0x{1:8x} 0x{2:8x} 0x{3:8x} {4:4s} {5:20d} {6:3d} {7:3d} {8:3d} {9:3d} {10:>6s} "
        out_string += "slot slab       next       obj        mca        tstamp     C  R  N   size flags\n"
        out_string += "---- ---------- ---------- ---------- ---------- ---------- -- -- -- ------ -----\n"

    mbutl = cast(kern.globals.mbutl, 'union mbigcluster *')
    while x < NSLABSPMB:
        sl = addressof(slg.slg_slab[x])
        mca = 0
        obj = sl.sl_base
        ts = 0

        if (kern.globals.mclaudit != 0):
            ix = (obj - Cast(kern.globals.mbutl, 'char *')) >> 12
            clbase = mbutl + (sizeof(dereference(mbutl)) * ix)
            mclidx = (obj  - clbase) >> 8
            mca = kern.globals.mclaudit[int(ix)].cl_audit[int(mclidx)]
            ts = mca.mca_tstamp

        out_string += slabs_string_format.format((x + 1), sl, sl.sl_next, obj, hex(mca), int(ts), int(sl.sl_class), int(sl.sl_refcnt), int(sl.sl_chunks), int(sl.sl_len), hex(sl.sl_flags))

        if (sl.sl_flags != 0):
            out_string += "<"
            if sl.sl_flags & SLF_MAPPED:
                out_string += "mapped"
            if sl.sl_flags & SLF_PARTIAL:
                out_string += ",partial"
            if sl.sl_flags & SLF_DETACHED:
                out_string += ",detached"
            out_string += ">"
        out_string += "\n"

        if sl.sl_chunks > 1:
            z = 1
            c = sl.sl_len/sl.sl_chunks

            while z < sl.sl_chunks:
                obj = sl.sl_base + (c * z)
                mca = 0
                ts = 0

                if (kern.globals.mclaudit != 0):
                    ix = (obj - Cast(kern.globals.mbutl, 'char *')) >> 12
                    clbase = mbutl + (sizeof(dereference(mbutl)) * ix)
                    mclidx = (obj  - clbase) >> 8
                    mca = kern.globals.mclaudit[int(ix)].cl_audit[int(mclidx)]
                    ts = mca.mca_tstamp

                if (kern.ptrsize == 8):
                    out_string += "                                            " + hex(obj) + " " + hex(mca) + "                    " + str(unsigned(ts)) + "\n"
                else:
                    out_string += "                            " + hex(obj) + " " + hex(mca) + "           " + str(unsigned(ts)) + "\n"

                z += 1
        x += 1
    print out_string
# EndMacro: mbuf_slabs

# Macro: mbuf_slabstbl
@lldb_command('mbuf_slabstbl')
def MbufSlabsTbl(cmd_args=None):
    """ Print slabs table
    """
    out_string = ""
    x = 0

    if (kern.ptrsize == 8):
        out_string += "slot slabg              slabs range\n"
        out_string += "---- ------------------ -------------------------------------------\n"
    else:
        out_string += "slot slabg      slabs range\n"
        out_string += "---- ---------- ---------------------------\n"

    slabstbl = kern.globals.slabstbl
    slabs_table_blank_string_format = "{0:>3d}: - \n"
    while (x < unsigned(kern.globals.maxslabgrp)):
        slg = slabstbl[x]
        if (slg == 0):
            out_string += slabs_table_blank_string_format.format(x+1)
        else:
            if (kern.ptrsize == 8):
                slabs_table_string_format = "{0:>3d}: 0x{1:16x}  [ 0x{2:16x} - 0x{3:16x} ]\n"
                out_string += slabs_table_string_format.format(x+1, slg, addressof(slg.slg_slab[0]), addressof(slg.slg_slab[NSLABSPMB-1]))
            else:
                slabs_table_string_format = "{0:>3d}: 0x{1:8x}  [ 0x{2:8x} - 0x{3:8x} ]\n"
                out_string += slabs_table_string_format.format(x+1, slg, addressof(slg.slg_slab[0]), addressof(slg.slg_slab[NSLABSPMB-1]))

        x += 1
    print out_string
# EndMacro: mbuf_slabstbl


def GetMbufBuf2Mca(m):
    ix = (m - Cast(kern.globals.mbutl, 'char *')) >> 12
    #mbutl = Cast(kern.globals.mbutl, 'union mbigcluster *')
    mbutl = cast(kern.globals.mbutl, 'union mbigcluster *')
    clbase = mbutl + (sizeof(dereference(mbutl)) * ix)
    mclidx = (m  - clbase) >> 8
    mca = kern.globals.mclaudit[int(ix)].cl_audit[int(mclidx)]
    return str(mca)

def GetMbufWalkAllSlabs(show_a, show_f, show_tr):
    out_string = ""

    kern.globals.slabstbl[0]
    
    x = 0
    total = 0
    total_a = 0
    total_f = 0

    if (show_a and not(show_f)):
        out_string += "Searching only for active... \n"
    if (not(show_a) and show_f):
        out_string += "Searching only for inactive... \n"
    if (show_a and show_f):
        out_string += "Displaying all... \n"

    if (kern.ptrsize == 8):
        show_mca_string_format = "{0:>4s} {1:>4s} {2:>16s} {3:>16s} {4:>16} {5:>12s} {6:12s}"
        out_string += show_mca_string_format.format("slot", "idx", "slab address", "mca address", "obj address", "type", "allocation state\n")
    else:
        show_mca_string_format = "{0:4s} {1:4s} {2:8s} {3:8s} {4:8} {5:12s} {6:12s}"
        out_string += show_mca_string_format.format("slot", "idx", "slab address", "mca address", "obj address", "type", "allocation state\n")

    while (x < unsigned(kern.globals.slabgrp)):
        slg = kern.globals.slabstbl[x]
        y = 0
        stop = 0
        while ((y < NSLABSPMB) and (stop == 0)):
            sl = addressof(slg.slg_slab[y])
            base = sl.sl_base
            mbutl = cast(kern.globals.mbutl, 'union mbigcluster *')
            ix = (base - mbutl) >> 12
            clbase = mbutl + (sizeof(dereference(mbutl)) * ix)
            mclidx = (base  - clbase) >> 8
            mca = kern.globals.mclaudit[int(ix)].cl_audit[int(mclidx)]
            first = 1

            while ((Cast(mca, 'int') != 0) and (unsigned(mca.mca_addr) != 0)):
                printmca = 0
                if (mca.mca_uflags & (MB_INUSE|MB_COMP_INUSE)):
                    total_a = total_a + 1
                    printmca = show_a
                else:
                    total_f = total_f + 1
                    printmca = show_f

                if (printmca != 0):
                    if (first == 1):
                        if (kern.ptrsize == 8):
                            mca_string_format = "{0:4d} {1:4d} 0x{2:16x} "
                            out_string += mca_string_format.format(x, y, sl)
                        else:
                            mca_string_format = "{0:4d} {1:4d} 0x{02:8x} "
                            out_string += mca_string_format.format(x, y, sl)
                    else:
                        if (kern.ptrsize == 8):
                            out_string += "                             "
                        else:
                            out_string += "                     "

                    if (kern.ptrsize == 8):
                        mca_string_format = "0x{0:16x} 0x{1:16x}"
                        out_string += mca_string_format.format(mca, mca.mca_addr)
                    else:
                        mca_string_format = "0x{0:8x} 0x{1:8x}"
                        out_string += mca_string_format.format(mca, mca.mca_addr)

                    out_string += GetMbufMcaCtype(mca, 0)

                    if (mca.mca_uflags & (MB_INUSE|MB_COMP_INUSE)):
                        out_string += "active        "
                    else:
                        out_string += "       freed "
                    if (first == 1):
                        first = 0
                    out_string += "\n"
                    total = total + 1

                    if (show_tr != 0):
                        out_string += "Recent transaction for this buffer (thread: 0x" + hex(mca.mca_thread) + "):\n"
                        cnt = 0
                        while (cnt < mca.mca_depth):
                            kgm_pc = mca.mca_stack[int(cnt)]
                            out_string += str(int(cnt) + 1) + " "
                            out_string += GetPc(kgm_pc) 
                            cnt += 1

                mca = mca.mca_next

            y += 1
            if (slg.slg_slab[int(y)].sl_base == 0):
                stop = 1
        x += 1

    if (total and show_a and show_f):
        out_string += "total objects = " + str(int(total)) + "\n"
        out_string += "active/unfreed objects = " + str(int(total_a)) + "\n"
        out_string += "freed/in_cache objects = " + str(int(total_f)) + "\n"

    return out_string

def GetMbufMcaCtype(mca, vopt):
    cp = mca.mca_cache
    mca_class = unsigned(cp.mc_private)
    csize = kern.globals.mbuf_table[mca_class].mtbl_stats.mbcl_size
    done = 0
    out_string = "    "
    if (csize == MSIZE):
        if (vopt):
            out_string += "M (mbuf) "
        else:
            out_string += "M     "
        return out_string
    if (csize == MCLBYTES):
        if (vopt):
            out_string += "CL (2K cluster) "
        else:
            out_string += "CL     "
        return out_string
    if (csize == NBPG):
        if (vopt):
            out_string += "BCL (4K cluster) "
        else:
            out_string += "BCL     "
        return out_string
    if (csize == M16KCLBYTES):
        if (vopt):
            out_string += "JCL (16K cluster) "
        else:
            out_string += "JCL     "
        return out_string

    if (csize == (MSIZE + MCLBYTES)):
        if (mca.mca_uflags & MB_SCVALID):
            if (mca.mca_uptr):
                out_string += "M+CL  "
                if vopt:
                    out_string += "(paired mbuf, 2K cluster) "
            else:
                out_string += "M-CL  "
                if vopt:
                    out_string += "(unpaired mbuf, 2K cluster) "
        else:
            if (mca.mca_uptr):
                out_string += "CL+M  "
                if vopt:
                    out_string += "(paired 2K cluster, mbuf) "
            else:
                out_string += "CL-M  "
                if vopt:
                    out_string += "(unpaired 2K cluster, mbuf) "
        return out_string

    if (csize == (MSIZE + NBPG)):
        if (mca.mca_uflags & MB_SCVALID):
            if (mca.mca_uptr):
                out_string += "M+BCL  "
                if vopt:
                    out_string += "(paired mbuf, 4K cluster) "
            else:
                out_string += "M-BCL  "
                if vopt:                                       
                    out_string += "(unpaired mbuf, 4K cluster) "
        else:
            if (mca.mca_uptr):
                out_string += "BCL+M  "
                if vopt:
                    out_string += "(paired 4K cluster, mbuf) "
            else:
                out_string += "BCL-m  "
                if vopt:
                    out_string += "(unpaired 4K cluster, mbuf) "
        return out_string

    if (csize == (MSIZE + M16KCLBYTES)):
        if (mca.mca_uflags & MB_SCVALID):
            if (mca.mca_uptr):
                out_string += "M+BCL  "
                if vopt:
                    out_string += "(paired mbuf, 4K cluster) "
            else:
                out_string += "M-BCL  "
                if vopt:
                    out_string += "(unpaired mbuf, 4K cluster) "
        else:
            if (mca.mca_uptr):
                out_string += "BCL+M  "
                if vopt:
                    out_string += "(paired 4K cluster, mbuf) "
            else:
                out_string += "BCL-m  "
                if vopt:
                    out_string += "(unpaired 4K cluster, mbuf) "
        return out_string

    out_string += "unknown: " + cp.mc_name
    return out_string
                  
kgm_pkmod = 0
kgm_pkmodst = 0
kgm_pkmoden = 0

def GetPointerAsString(kgm_pc):
    if (kern.ptrsize == 8):
        pointer_format_string = "0x{0:<16x} "
    else:
        pointer_format_string = "0x{0:<8x} "
    return pointer_format_string.format(kgm_pc)

def GetKmodAddrIntAsString(kgm_pc):
    global kgm_pkmod
    global kgm_pkmodst
    global kgm_pkmoden

    out_string = ""
    mh_execute_addr = int(lldb_run_command('p/x (uintptr_t *)&_mh_execute_header').split('=')[-1].strip(), 16)

    out_string += GetPointerAsString(kgm_pc)
    if ((unsigned(kgm_pc) >= unsigned(kgm_pkmodst)) and (unsigned(kgm_pc) < unsigned(kgm_pkmoden))):
            kgm_off = kgm_pc - kgm_pkmodst
            out_string += "<" + str(Cast(kgm_pkmod, 'kmod_info_t *').name) + " + 0x" + str(kgm_off) + ">"
    else:
        kgm_kmodp = kern.globals.kmod
        if ((kern.arch == 'x86_64') and (long(kgm_pc) >= long(mh_execute_addr))):
            kgm_kmodp = 0

        while kgm_kmodp:
            kgm_off = unsigned((kgm_pc - kgm_kmodp.address) & 0x00000000ffffffff)
            if ((long(kgm_kmodp.address) <= long(kgm_pc)) and (kgm_off) < unsigned(kgm_kmodp.size)):
                kgm_pkmod = kgm_kmodp
                kgm_pkmodst = unsigned(kgm_kmodp.address)
                kgm_pkmoden = unsigned(kgm_pkmodst + kgm_kmodp.size)
                kgm_kmodp = 0
            else:
                kgm_kmodp = kgm_kmodp.next
    return out_string

def GetPc(kgm_pc):
    out_string = ""
    mh_execute_addr = int(lldb_run_command('p/x (uintptr_t *)&_mh_execute_header').split('=')[-1].strip(), 16)
    if (unsigned(kgm_pc) < unsigned(mh_execute_addr) or
        unsigned(kgm_pc) >= unsigned(kern.globals.vm_kernel_top)):
        out_string += GetKmodAddrIntAsString(kgm_pc)
    else:
        out_string += GetSourceInformationForAddress(int(kgm_pc))
    return out_string + "\n"


# Macro: mbuf_showactive
@lldb_command('mbuf_showactive')
def MbufShowActive(cmd_args=None):
    """ Print all active/in-use mbuf objects
    """
    if cmd_args != None and len(cmd_args) > 0 :
        print GetMbufWalkAllSlabs(1, 0, cmd_args[0])
    else:
        print GetMbufWalkAllSlabs(1, 0, 0)
# EndMacro: mbuf_showactive


# Macro: mbuf_showinactive
@lldb_command('mbuf_showinactive')
def MbufShowInactive(cmd_args=None):
    """ Print all freed/in-cache mbuf objects
    """
    print GetMbufWalkAllSlabs(0, 1, 0)
# EndMacro: mbuf_showinactive


# Macro: mbuf_showmca
@lldb_command('mbuf_showmca')
def MbufShowMca(cmd_args=None):
    """ Print the contents of an mbuf mcache audit structure
    """
    out_string = ""
    if cmd_args != None and len(cmd_args) > 0 :
        mca = kern.GetValueFromAddress(cmd_args[0], 'mcache_audit_t *')
        cp = mca.mca_cache
        out_string += "object type:\t"
        out_string += GetMbufMcaCtype(mca, 1)
        out_string += "\nControlling mcache :\t" + hex(mca.mca_cache) + " (" + str(cp.mc_name) + ")\n"
        if (mca.mca_uflags & MB_SCVALID):
            mbutl = cast(kern.globals.mbutl, 'union mbigcluster *')
            ix = (mca.mca_addr - mbutl) >> 12
            clbase = mbutl + (sizeof(dereference(mbutl)) * ix)
            mclidx = (mca.mca_addr - clbase) >> 8
            out_string += "mbuf obj :\t\t" + hex(mca.mca_addr) + "\n"
            out_string += "mbuf index :\t\t" + str(mclidx + 1) + " (out of 16) in cluster base " + hex(clbase) + "\n"
            if (int(mca.mca_uptr) != 0):
                peer_mca = cast(mca.mca_uptr, 'mcache_audit_t *')
                out_string += "paired cluster obj :\t" + hex(peer_mca.mca_addr) + " (mca " + hex(peer_mca) + ")\n"
            out_string += "saved contents :\t" + hex(mca.mca_contents) + " (" + str(int(mca.mca_contents_size)) + " bytes)\n"
        else:
            out_string += "cluster obj :\t\t" + hex(mca.mca_addr) + "\n"
            if (mca.mca_uptr != 0):
                peer_mca = cast(mca.mca_uptr, 'mcache_audit_t *')
                out_string += "paired mbuf obj :\t" + hex(peer_mca.mca_addr) + " (mca " + hex(peer_mca) + ")\n"
        
        out_string += "Recent transaction (tstamp " + str(unsigned(mca.mca_tstamp)) + ", thread " + hex(mca.mca_thread) + ") :\n"
        cnt = 0
        while (cnt < mca.mca_depth):
            kgm_pc = mca.mca_stack[cnt]
            out_string += "  " + str(cnt + 1) + ".  "
            out_string += GetPc(kgm_pc)
            cnt += 1

        if (mca.mca_pdepth > 0):
            out_string += "previous transaction (tstamp " + str(unsigned(mca.mca_ptstamp)) + ", thread " + hex(mca.mca_pthread) + "):\n"
        cnt = 0

        while (cnt < mca.mca_pdepth):
            kgm_pc = mca.mca_pstack[cnt]
            out_string += "  " + str(cnt + 1) + ".  "
            out_string += GetPc(kgm_pc)
            cnt += 1

        if (mca.mca_uflags & MB_SCVALID):
            msc = cast(mca.mca_contents, 'mcl_saved_contents_t *')
            msa = addressof(msc.sc_scratch)
            if (msa.msa_depth > 0):
                out_string += "Recent scratch transaction (tstamp " + str(unsigned(msa.msa_tstamp)) + ", thread " + hex(msa.msa_thread) + ") :\n"
                cnt = 0
                while (cnt < msa.msa_depth):
                    kgm_pc = msa.msa_stack[cnt]
                    out_string += "  " + str(cnt + 1) + ".  "
                    out_string += GetPc(kgm_pc)
                    cnt += 1

            if (msa.msa_pdepth > 0):
                out_string += "previous scratch transaction (tstamp " + msa.msa_ptstamp + ", thread " + msa.msa_pthread + "):\n"
        cnt = 0
        while (cnt < msa.msa_pdepth):
            kgm_pc = msa.msa_pstack[cnt]
            out_string += "  " + str(cnt + 1) + ".  "
            out_string += GetPc(kgm_pc)
            cnt += 1
    else :
        out_string += "Missing argument 0 in user function."

    print out_string
# EndMacro: mbuf_showmca


# Macro: mbuf_showall
@lldb_command('mbuf_showall')
def MbufShowAll(cmd_args=None):
    """ Print all mbuf objects
    """
    print GetMbufWalkAllSlabs(1, 1, 0) 
# EndMacro: mbuf_showall

# Macro: mbuf_countchain
@lldb_command('mbuf_countchain')
def MbufCountChain(cmd_args=None):
    """ Count the length of an mbuf chain
    """
    if (cmd_args == None or len(cmd_args) == 0):
            print "Missing argument 0 in user function."
            return
    mp = kern.GetValueFromAddress(cmd_args[0], 'mbuf *')

    pkt = 0
    nxt = 0
    
    while (mp):
        pkt = pkt + 1
        mn = mp.m_hdr.mh_next
        while (mn):
            nxt = nxt + 1
            mn = mn.m_hdr.mh_next

        mp = mp.m_hdr.mh_nextpkt

        if (((pkt + nxt) % 50) == 0):
            print " ..." + str(pkt_nxt)

    print "Total: " + str(pkt + nxt) + " (via m_next: " + str(nxt) + ")"
# EndMacro: mbuf_countchain



# Macro: mbuf_topleak
@lldb_command('mbuf_topleak')
def MbufTopLeak(cmd_args=None):
    """ Print the top suspected mbuf leakers
    """
    topcnt = 0
    if (int(len(cmd_args)) > 0 and int(cmd_args[0]) < 5):
        maxcnt = cmd_args[0]
    else:
        maxcnt = 5
    while (topcnt < maxcnt):
        print GetMbufTraceLeak(kern.globals.mleak_top_trace[topcnt])
        topcnt += 1

# EndMacro: mbuf_topleak

def GetMbufTraceLeak(trace):
    out_string = ""
    if (trace.allocs != 0):
        out_string += hex(trace) + ":" + str(trace.allocs) + " outstanding allocs\n"
        out_string += "Backtrace saved " + str(trace.depth) + " deep\n"
        if (trace.depth != 0):
            cnt = 0
            while (cnt < trace.depth):
                out_string += str(cnt + 1) + ": "
                out_string += GetPc(trace.addr[cnt])
                out_string += "\n"
                cnt += 1
    return out_string


# Macro: mbuf_traceleak
@lldb_command('mbuf_traceleak')
def MbufTraceLeak(cmd_args=None):
    """ Print the leak information for a given leak address
        Given an mbuf leak trace (mtrace) structure address, print out the
        stored information with that trace
        syntax: (lldb) mbuf_traceleak <addr>
    """
    if (cmd_args == None or len(cmd_args) == 0):
            print "Missing argument 0 in user function."
            return
    trace = kern.GetValueFromAddress(cmd_args[0], 'mtrace *')
    print GetMbufTraceLeak(trace)
# EndMacro: mbuf_traceleak


# Macro: mcache_walkobj
@lldb_command('mcache_walkobj')
def McacheWalkObject(cmd_args=None):
    """ Given a mcache object address, walk its obj_next pointer
    """
    if (cmd_args == None or len(cmd_args) == 0):
            print "Missing argument 0 in user function."
            return
    out_string = ""
    p = kern.GetValueFromAddress(cmd_args[0], 'mcache_obj_t *')
    cnt = 1
    total = 0
    while (p):
        mcache_object_format = "{0:>4d}: 0x{1:>16x}"
        out_string += mcache_object_format.format(cnt, p) + "\n"
        p = p.obj_next
        cnt += 1
    print out_string
# EndMacro: mcache_walkobj

# Macro: mcache_stat
@lldb_command('mcache_stat')
def McacheStat(cmd_args=None):
    """ Print all mcaches in the system.
    """
    head = kern.globals.mcache_head
    out_string = ""
    mc = cast(head.lh_first, 'mcache *')
    if (kern.ptrsize == 8):
        mcache_stat_format_string = "{0:<24s} {1:>8s} {2:>20s} {3:>5s} {4:>5s} {5:>20s} {6:>30s} {7:>18s}"
    else:
        mcache_stat_format_string = "{0:<24s} {1:>8s} {2:>12s} {3:>5s} {4:>5s} {5:>12s} {6:>30s} {7:>18s}"
    
    if (kern.ptrsize == 8):
        mcache_stat_data_format_string = "{0:<24s} {1:>12s} {2:>20s} {3:>5s} {4:>5s} {5:>22s} {6:>12d} {7:>8d} {8:>8d} {9:>18d}"
    else:
        mcache_stat_data_format_string = "{0:<24s} {1:>12s} {2:>12s} {3:>5s} {4:>5s} {5:>14s} {6:>12d} {7:>8d} {8:>8d} {9:>18d}"
    
    out_string += mcache_stat_format_string.format("cache name", "cache state" , "cache addr", "buf size", "buf align", "backing zone", "wait     nowait     failed", "bufs incache")
    out_string += "\n"
   
    ncpu = int(kern.globals.ncpu)
    while mc != 0:
        bktsize = mc.mc_cpu[0].cc_bktsize
        cache_state = ""
        if (mc.mc_flags & MCF_NOCPUCACHE):
            cache_state = "disabled"
        else:
            if (bktsize == 0):
                cache_state = " offline"
            else:
                cache_state = " online"
        if (mc.mc_slab_zone != 0):
            backing_zone = mc.mc_slab_zone
        else:
            if (kern.ptrsize == 8):
                backing_zone = "            custom"
            else:
                backing_zone = "    custom"
        
        total = 0
        total += mc.mc_full.bl_total * bktsize
        n = 0
        while(n < ncpu):
            ccp = mc.mc_cpu[n]
            if (ccp.cc_objs > 0):
                total += ccp.cc_objs
            if (ccp.cc_pobjs > 0):
                total += ccp.cc_pobjs
            n += 1
            ccp += 1

        out_string += mcache_stat_data_format_string.format(mc.mc_name, cache_state, hex(mc), str(int(mc.mc_bufsize)), str(int(mc.mc_align)), hex(mc.mc_slab_zone), int(mc.mc_wretry_cnt), int(mc.mc_nwretry_cnt), int(mc.mc_nwfail_cnt), total)
        out_string += "\n"
        mc = cast(mc.mc_list.le_next, 'mcache *')
    print out_string
# EndMacro: mcache_stat

# Macro: mcache_showcache
@lldb_command('mcache_showcache')
def McacheShowCache(cmd_args=None):
    """Display the number of objects in cache.
    """
    out_string = ""
    cp = kern.GetValueFromAddress(cmd_args[0], 'mcache_t *')
    bktsize = cp.mc_cpu[0].cc_bktsize
    cnt = 0
    total = 0
    mcache_cache_format = "{0:<4d} {1:>8d} {2:>8d} {3:>8d}"
    out_string += "Showing cache " + str(cp.mc_name) + " :\n\n"
    out_string += " CPU  cc_objs cc_pobjs    total\n"
    out_string += "----  ------- -------- --------\n"
    ncpu = int(kern.globals.ncpu)
    while (cnt < ncpu):
        ccp = cp.mc_cpu[cnt]
        objs = ccp.cc_objs
        if (objs <= 0):
            objs = 0
        pobjs = ccp.cc_pobjs
        if (pobjs <= 0):
            pobjs = 0
        tot_cpu = objs + pobjs
        total += tot_cpu
        out_string += mcache_cache_format.format(cnt, objs, pobjs, tot_cpu)
        out_string += "\n"
        cnt += 1

    out_string += "                       ========\n"
    out_string += "                           " + str(total) + "\n\n"
    total += cp.mc_full.bl_total * bktsize

    out_string += "Total # of full buckets (" + str(int(bktsize)) + " objs/bkt):\t" + str(int(cp.mc_full.bl_total)) +"\n"
    out_string += "Total # of objects cached:\t\t" + str(total) + "\n"
    print out_string
# EndMacro: mcache_showcache
