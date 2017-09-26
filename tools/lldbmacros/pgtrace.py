#! /usr/bin/env python                                                                                                                                                                                        
# -*- coding: utf-8 -*-                                                                                                                                                                                        

from xnu import *

# Macro: pgtrace
@lldb_command('showpgtrace')
def ShowPgtrace(cmd_args=None, cmd_options={}):
    """ Display pgtrace buffer contents
        Usage: showpgtrace
    """

    max_entry = kern.globals.pgtrace.size
    rd_idx = kern.globals.pgtrace.rdidx
    wr_idx = kern.globals.pgtrace.wridx
    
    print "-"*80
    print "rd_idx=%d wr_idx=%d num_entries=%d max_entry=%d" % (rd_idx, wr_idx, wr_idx-rd_idx, max_entry)
    print "-"*80

    rw_str = { GetEnumValue('pgtrace_rw_t::PGTRACE_RW_LOAD'): "R",
                GetEnumValue('pgtrace_rw_t::PGTRACE_RW_STORE'): "W",
                GetEnumValue('pgtrace_rw_t::PGTRACE_RW_PREFETCH'): "P" }

    while rd_idx != wr_idx:
        clipped_idx = rd_idx % max_entry
        entry = kern.globals.pgtrace.logs + sizeof('log_t') * clipped_idx
        entry = kern.GetValueFromAddress(entry, 'log_t *')

        entry_str = "[%d] id=%lu time=%lu %s " % (clipped_idx, entry.id, entry.res.rr_time, rw_str[int(entry.res.rr_rw)])

        for i in range(entry.res.rr_num):
            entry_str += "%x=%x " % (entry.res.rr_addrdata[i].ad_addr, entry.res.rr_addrdata[i].ad_data)

        print entry_str
        
        rd_idx += 1
# EndMacro
