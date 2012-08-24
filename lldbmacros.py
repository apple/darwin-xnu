import lldb
import re
import getopt

# Note: This module will eventually contain loads of macros. So please bear with the Macro/EndMacro comments


# Global functions
def findGlobal(variable):
    return lldb.target.FindGlobalVariables(variable, 0).GetValueAtIndex(0)

def findGlobalValue(variable):
    return findGlobal(variable).GetValue()

def readMemberUnsigned(variable,member):
    return variable.GetChildMemberWithName(member).GetValueAsUnsigned(0)

def readMemberSigned(variable,member):
    return variable.GetChildMemberWithName(member).GetValueAsSigned()

def readMemberString(variable,member):
    return str(variable.GetChildMemberWithName(member).GetSummary()).strip('"')



class Output :
    """
    An output handler for all command. Use Output.print to direct all output of macro via the handler. 
    Currently this provide capabilities 
    -o path/to/filename
       The output of this command execution will be saved to file. Parser information or errors will 
       not be sent to file though. eg /tmp/output.txt
    -s filter_string
       the "filter_string" param is parsed to python regex expression and each line of output 
       will be printed/saved only if it matches the expression. 
       The command header will not be filtered in any case.
    """
    STDOUT  =1
    FILEOUT =2
    FILTER  =False

    def __init__(self):
        self.out = Output.STDOUT
	self.fname=None
	self.fhandle=None
	self.FILTER=False

    def printString(self, s):
        """ Handler for all commands output. By default just print to stdout """
        if self.FILTER and not self.reg.search(s): return
        if self.out == Output.STDOUT: print s
	elif self.out == Output.FILEOUT : self.fhandle.write(s+"\n")
    
    def printHeader(self,s):
        if self.out == Output.STDOUT: print s
	elif self.out == Output.FILEOUT: self.fhandle.write(s+"\n")
    
    def done(self):
        """ closes any open files. report on any errors """
        if self.fhandle != None :
		self.fhandle.close()
    
    def setOptions(self,args):
        """ parse the arguments passed to the command 
	    param : args => [] of <str> (typically args.split())
	"""
        opts=()
        try:
	  opts,args = getopt.getopt(args,'o:s:',[])
	except getopt.GetoptError,err:
	  print str(err)
	#continue with processing
	for o,a in opts :
	  if o == "-o" and len(a) > 0:
            self.fname=a.strip()
	    self.fhandle=open(self.fname,"w")
	    self.out = Output.FILEOUT
	    print "saving results in file ",str(a)
	  elif o == "-s" and len(a) > 0:
	    self.reg = re.compile(a.strip(),re.MULTILINE|re.DOTALL)
	    self.FILTER=True
	    print "showing results for regex:",a.strip()
	  else :
	    print "Error: unknown option ",o,a


# Inteface function for showallkexts command
def showallkexts_command(debugger, args, result, lldb_dict):
    kext_summary_header = findGlobal("gLoadedKextSummaries")
    result.Printf(_summarizeallkexts(kext_summary_header))
    return None

# Interface function for loaded kext summary formatter
def showallkexts_summary(kext_summary_header, lldb_dict):
    return "\n" + _summarizeallkexts(kext_summary_header)

# Internal function for walking kext summaries
def _summarizeallkexts(kext_summary_header):
    summary = "ID  Address            Size              Version    Name\n"
    summaries = kext_summary_header.GetChildMemberWithName("summaries")
    count = int(kext_summary_header.GetChildMemberWithName("numSummaries").GetValue())
    for i in range(0, count):
        summary += summaries.GetChildAtIndex(i, lldb.eNoDynamicValues, True).GetSummary() + "\n"
    return summary

# Macro: memstats
def memstats_command(debugger,args,result,lldb_dict):
    stream = Output()
    stream.setOptions(args.split())
    memstats(stream)
    stream.done()

def memstats(ostream):
    ostream.printString ( "kern_memorystatus_level: {0}".format(findGlobalValue("kern_memorystatus_level")) )
    ostream.printString ( "vm_page_throttled_count: {0}".format(findGlobalValue("vm_page_throttled_count")) )
    ostream.printString ( "vm_page_active_count:    {0}".format(findGlobalValue("vm_page_active_count")) )
    ostream.printString ( "vm_page_inactive_count:  {0}".format(findGlobalValue("vm_page_inactive_count")) )
    ostream.printString ( "vm_page_wire_count:      {0}".format(findGlobalValue("vm_page_wire_count")) )
    ostream.printString ( "vm_page_free_count:      {0}".format(findGlobalValue("vm_page_free_count")) )
    ostream.printString ( "vm_page_purgeable_count: {0}".format(findGlobalValue("vm_page_purgeable_count")) )
    ostream.printString ( "vm_page_inactive_target: {0}".format(findGlobalValue("vm_page_inactive_target")) )
    ostream.printString ( "vm_page_free_target:     {0}".format(findGlobalValue("vm_page_free_target")) )
    ostream.printString ( "insue_ptepages_count:    {0}".format(findGlobalValue("inuse_ptepages_count")) )
    ostream.printString ( "vm_page_free_reserved:   {0}".format(findGlobalValue("vm_page_free_reserved")) )
# EndMacro: memstats


# Macro: zprint
def zprint_command(debugger,args,result,lldb_dict):
    stream = Output()
    stream.setOptions(args.split())
    _zprint(stream)
    stream.done()

def _zprint(ostream):
    """Display info about memory zones"""
    ostream.printHeader ( "{0: ^20s} {1: >5s} {2: >12s} {3: >12s} {4: >7s} {5: >8s} {6: >9s} {7: >8s} {8: <20s} {9} ".format('ZONE', 'COUNT', 'TOT_SZ', 'MAX_SZ', 'ELT_SZ', 'ALLOC_SZ', 'TOT_ALLOC', 'TOT_FREE', 'NAME','') )
    format_string = '{0: >#020x} {1: >5d} {2: >12d} {3: >12d} {4: >7d} {5: >8d} {6: >9d} {7: >8d} {8: <20s} {9}'
    zone_ptr = findGlobal("first_zone");

    while zone_ptr.GetValueAsUnsigned() != 0 :
        addr = zone_ptr.GetValueAsUnsigned()
	count = readMemberUnsigned(zone_ptr, "count")
	cur_size = readMemberUnsigned(zone_ptr, "cur_size")
	max_size = readMemberUnsigned(zone_ptr, "max_size")
	elem_size = readMemberUnsigned(zone_ptr, "elem_size")
	alloc_size = readMemberUnsigned(zone_ptr, "alloc_size")
	num_allocs = readMemberUnsigned(zone_ptr, "num_allocs")
	num_frees = readMemberUnsigned(zone_ptr, "num_frees")
	name = str(readMemberString(zone_ptr, "zone_name"))
	markings=""
	if str(zone_ptr.GetChildMemberWithName("exhaustible").GetValue()) == '1' : markings+="H"
	if str(zone_ptr.GetChildMemberWithName("collectable").GetValue()) == '1' : markings+="C"
	if str(zone_ptr.GetChildMemberWithName("expandable").GetValue()) == '1' : markings+="X"
	if str(zone_ptr.GetChildMemberWithName("noencrypt").GetValue()) == '1' : markings+="$"
	
	ostream.printString(format_string.format(addr, count, cur_size, max_size, elem_size, alloc_size, num_allocs, num_frees, name, markings))
	
	zone_ptr = zone_ptr.GetChildMemberWithName("next_zone")
    return None
# EndMacro: zprint


# Macro: showioalloc
def showioalloc_command(debugger,args,result,lldb_dict):
    stream = Output()
    stream.setOptions(args.split())
    _showioalloc(stream)
    stream.done()

def _showioalloc(ostream):
    ivars_size = findGlobal("debug_ivars_size").GetValueAsUnsigned()
    container_malloc_size = findGlobal("debug_container_malloc_size").GetValueAsUnsigned()
    iomalloc_size = findGlobal("debug_iomalloc_size").GetValueAsUnsigned()
    iomallocpageable_size = findGlobal("debug_iomallocpageable_size").GetValueAsUnsigned()
    
    ostream.printString("Instance allocation  = {0:#0x} = {1:d} K".format(ivars_size, (int)(ivars_size/1024)))
    ostream.printString("Container allocation = {0:#0x} = {1:d} K".format(container_malloc_size,(int)(container_malloc_size/1024)))
    ostream.printString("IOMalloc allocation  = {0:#0x} = {1:d} K".format(iomalloc_size,(int)(iomalloc_size/1024)))
    ostream.printString("Pageable allocation  = {0:#0x} = {1:d} K".format(iomallocpageable_size,(int)(iomallocpageable_size/1024)))
    return None
# EndMacro: showioalloc


