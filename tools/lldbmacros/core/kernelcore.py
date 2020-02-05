
""" Please make sure you read the README COMPLETELY BEFORE reading anything below.
    It is very critical that you read coding guidelines in Section E in README file.
"""

from cvalue import *
from lazytarget import *
from configuration import *
from utils import *
import caching
import lldb

def IterateTAILQ_HEAD(headval, element_name):
    """ iterate over a TAILQ_HEAD in kernel. refer to bsd/sys/queue.h
        params:
            headval     - value : value object representing the head of the list
            element_name- str          :  string name of the field which holds the list links.
        returns:
            A generator does not return. It is used for iterating.
            value : an object that is of type as headval->tqh_first. Always a pointer object
        example usage:
          list_head = kern.GetGlobalVariable('mountlist')
          for entryobj in IterateTAILQ_HEAD(list_head, 'mnt_list'):
            print GetEntrySummary(entryobj)
    """
    iter_val = headval.tqh_first
    while unsigned(iter_val) != 0 :
        yield iter_val
        iter_val = iter_val.__getattr__(element_name).tqe_next
    #end of yield loop

def IterateLinkedList(element, field_name):
    """ iterate over a linked list.
        This is equivalent to elt = element; while(elt) { do_work(elt); elt = elt-><field_name>; }
        params:
            element - value : value object representing element in the list.
            field_name - str       : name of field that holds pointer to next element
        returns: Nothing. This is used as iterable
        example usage:
            first_zone = kern.GetGlobalVariable('first_zone')
            for zone in IterateLinkedList(first_zone, 'next_zone'):
                print GetZoneSummary(zone)
    """
    elt = element
    while unsigned(elt) != 0:
        yield elt
        elt = elt.__getattr__(field_name)
    #end of while loop

def IterateListEntry(element, element_type, field_name, list_prefix=''):
    """ iterate over a list as defined with LIST_HEAD in bsd/sys/queue.h
        params:
            element      - value : Value object for lh_first
            element_type - str   : Type of the next element
            field_name   - str   : Name of the field in next element's structure
            list_prefix  - str   : use 's' here to iterate SLIST_HEAD instead
        returns:
            A generator does not return. It is used for iterating
            value  : an object thats of type (element_type) head->le_next. Always a pointer object
        example usage:
            headp = kern.globals.initproc.p_children
            for pp in IterateListEntry(headp, 'struct proc *', 'p_sibling'):
                print GetProcInfo(pp)
    """
    elt = element.__getattr__(list_prefix + 'lh_first')
    if type(element_type) == str:
        element_type = gettype(element_type)
    while unsigned(elt) != 0:
        yield elt
        next_el = elt.__getattr__(field_name).__getattr__(list_prefix + 'le_next')
        elt = cast(next_el, element_type)

def IterateLinkageChain(queue_head, element_type, field_name, field_ofst=0):
    """ Iterate over a Linkage Chain queue in kernel of type queue_head_t. (osfmk/kern/queue.h method 1)
        This is equivalent to the qe_foreach_element() macro
        params:
            queue_head   - value       : Value object for queue_head.
            element_type - lldb.SBType : pointer type of the element which contains the queue_chain_t. Typically its structs like thread, task etc..
                         - str         : OR a string describing the type. ex. 'task *'
            field_name   - str         : Name of the field (in element) which holds a queue_chain_t
            field_ofst   - int         : offset from the 'field_name' (in element) which holds a queue_chain_t
                                         This is mostly useful if a particular element contains an array of queue_chain_t
        returns:
            A generator does not return. It is used for iterating.
            value  : An object thats of type (element_type). Always a pointer object
        example usage:
            coalq = kern.GetGlobalVariable('coalitions_q')
            for coal in IterateLinkageChain(coalq, 'struct coalition *', 'coalitions'):
                print GetCoalitionInfo(coal)
    """
    global kern
    if type(element_type) == str:
        element_type = gettype(element_type)

    if unsigned(queue_head) == 0:
        return

    if element_type.IsPointerType():
        elem_ofst = getfieldoffset(element_type.GetPointeeType(), field_name) + field_ofst
    else:
        elem_ofst = getfieldoffset(element_type, field_name) + field_ofst

    link = queue_head.next
    while (unsigned(link) != unsigned(queue_head)):
        addr = unsigned(link) - elem_ofst;
        # I can't use the GetValueFromAddress function of the kernel class
        # because I have no instance of that class!
        obj = value(link.GetSBValue().CreateValueFromExpression(None,'(void *)'+str(addr)))
        obj = cast(obj, element_type)
        yield obj
        link = link.next


def IterateQueue(queue_head, element_ptr_type, element_field_name, backwards=False, unpack_ptr_fn=None):
    """ Iterate over an Element Chain queue in kernel of type queue_head_t. (osfmk/kern/queue.h method 2)
        params:
            queue_head         - value : Value object for queue_head.
            element_ptr_type   - lldb.SBType : a pointer type of the element 'next' points to. Typically its structs like thread, task etc..
                               - str         : OR a string describing the type. ex. 'task *'
            element_field_name - str : name of the field in target struct.
            backwards          - backwards : traverse the queue backwards
            unpack_ptr_fn      - function : a function ptr of signature def unpack_ptr(long v) which returns long.
        returns:
            A generator does not return. It is used for iterating.
            value  : an object thats of type (element_type) queue_head->next. Always a pointer object
        example usage:
            for page_meta in IterateQueue(kern.globals.first_zone.pages.all_free, 'struct zone_page_metadata *', 'pages'):
                print page_meta
    """
    if type(element_ptr_type) == str :
        element_ptr_type = gettype(element_ptr_type)

    queue_head = queue_head.GetSBValue()
    queue_head_addr = 0x0
    if queue_head.TypeIsPointerType():
        queue_head_addr = queue_head.GetValueAsUnsigned()
    else:
        queue_head_addr = queue_head.GetAddress().GetLoadAddress(LazyTarget.GetTarget())
        
    def unpack_ptr_and_recast(v):
        if unpack_ptr_fn is None:
            return v
        v_unpacked = unpack_ptr_fn(v.GetValueAsUnsigned())
        obj = v.CreateValueFromExpression(None,'(void *)'+str(v_unpacked))
        obj.Cast(element_ptr_type)
        return obj

    if backwards:
        cur_elt = unpack_ptr_and_recast(queue_head.GetChildMemberWithName('prev'))
    else:
        cur_elt = unpack_ptr_and_recast(queue_head.GetChildMemberWithName('next'))

    while True:

        if not cur_elt.IsValid() or cur_elt.GetValueAsUnsigned() == 0 or cur_elt.GetValueAsUnsigned() == queue_head_addr:
            break
        elt = cur_elt.Cast(element_ptr_type)
        yield value(elt)
        if backwards:
            cur_elt = unpack_ptr_and_recast(elt.GetChildMemberWithName(element_field_name).GetChildMemberWithName('prev'))
        else:
            cur_elt = unpack_ptr_and_recast(elt.GetChildMemberWithName(element_field_name).GetChildMemberWithName('next'))


def IterateRBTreeEntry(element, element_type, field_name):
    """ iterate over a rbtree as defined with RB_HEAD in libkern/tree.h
            element      - value : Value object for rbh_root
            element_type - str   : Type of the link element
            field_name   - str   : Name of the field in link element's structure
        returns:
            A generator does not return. It is used for iterating
            value  : an object thats of type (element_type) head->sle_next. Always a pointer object
    """
    elt = element.__getattr__('rbh_root')
    if type(element_type) == str:
        element_type = gettype(element_type)

    # Walk to find min
    parent = elt
    while unsigned(elt) != 0:
        parent = elt
        elt = cast(elt.__getattr__(field_name).__getattr__('rbe_left'), element_type)
    elt = parent

    # Now elt is min
    while unsigned(elt) != 0:
        yield elt
        # implementation cribbed from RB_NEXT in libkern/tree.h
        right = cast(elt.__getattr__(field_name).__getattr__('rbe_right'), element_type)
        if unsigned(right) != 0:
            elt = right
            left = cast(elt.__getattr__(field_name).__getattr__('rbe_left'), element_type)
            while unsigned(left) != 0:
                elt = left
                left = cast(elt.__getattr__(field_name).__getattr__('rbe_left'), element_type)
        else:

            # avoid using GetValueFromAddress
            addr = elt.__getattr__(field_name).__getattr__('rbe_parent')&~1
            parent = value(elt.GetSBValue().CreateValueFromExpression(None,'(void *)'+str(addr)))
            parent = cast(parent, element_type)

            if unsigned(parent) != 0:
                left = cast(parent.__getattr__(field_name).__getattr__('rbe_left'), element_type)
            if (unsigned(parent) != 0) and (unsigned(elt) == unsigned(left)):
                elt = parent
            else:
                if unsigned(parent) != 0:
                    right = cast(parent.__getattr__(field_name).__getattr__('rbe_right'), element_type)
                while unsigned(parent) != 0 and (unsigned(elt) == unsigned(right)):
                    elt = parent

                    # avoid using GetValueFromAddress
                    addr = elt.__getattr__(field_name).__getattr__('rbe_parent')&~1
                    parent = value(elt.GetSBValue().CreateValueFromExpression(None,'(void *)'+str(addr)))
                    parent = cast(parent, element_type)

                    right = cast(parent.__getattr__(field_name).__getattr__('rbe_right'), element_type)

                # avoid using GetValueFromAddress
                addr = elt.__getattr__(field_name).__getattr__('rbe_parent')&~1
                elt = value(elt.GetSBValue().CreateValueFromExpression(None,'(void *)'+str(addr)))
                elt = cast(elt, element_type)


def IteratePriorityQueue(root, element_type, field_name):
    """ iterate over a priority queue as defined with struct priority_queue from osfmk/kern/priority_queue.h
            root         - value : Value object for the priority queue
            element_type - str   : Type of the link element
            field_name   - str   : Name of the field in link element's structure
        returns:
            A generator does not return. It is used for iterating
            value  : an object thats of type (element_type). Always a pointer object
    """
    def _make_pqe(addr):
        return value(root.GetSBValue().CreateValueFromExpression(None,'(struct priority_queue_entry *)'+str(addr)))

    queue = [unsigned(root.pq_root_packed) & ~3]

    while len(queue):
        elt = _make_pqe(queue.pop())

        while elt:
            yield containerof(elt, element_type, field_name)
            addr = unsigned(elt.child)
            if addr: queue.append(addr)
            elt = elt.next

def IterateMPSCQueue(root, element_type, field_name):
    """ iterate over an MPSC queue as defined with struct mpsc_queue_head from osfmk/kern/mpsc_queue.h
            root         - value : Value object for the mpsc queue
            element_type - str   : Type of the link element
            field_name   - str   : Name of the field in link element's structure
        returns:
            A generator does not return. It is used for iterating
            value  : an object thats of type (element_type). Always a pointer object
    """
    elt = root.mpqh_head.mpqc_next
    while unsigned(elt):
        yield containerof(elt, element_type, field_name)
        elt = elt.mpqc_next

class KernelTarget(object):
    """ A common kernel object that provides access to kernel objects and information.
        The class holds global lists for  task, terminated_tasks, procs, zones, zombroc etc.
        It also provides a way to symbolicate an address or create a value from an address.
    """
    def __init__(self, debugger):
        """ Initialize the kernel debugging environment.
            Target properties like architecture and connectedness are lazy-evaluted.
        """
        self._debugger = debugger # This holds an lldb.SBDebugger object for debugger state
        self._threads_list = []
        self._tasks_list = []
        self._coalitions_list = []
        self._thread_groups = []
        self._allproc = []
        self._terminated_tasks_list = []
        self._zones_list = []
        self._zombproc_list = []
        self._kernel_types_cache = {} #this will cache the Type objects as and when requested.
        self._version = None
        self._arch = None
        self._ptrsize = None # pointer size of kernel, not userspace
        self.symbolicator = None
        class _GlobalVariableFind(object):
            def __init__(self, kern):
                self._xnu_kernobj_12obscure12 = kern
            def __getattr__(self, name):
                v = self._xnu_kernobj_12obscure12.GetGlobalVariable(name)
                if not v.GetSBValue().IsValid():
                    raise ValueError('No such global variable by name: %s '%str(name))
                return v
        self.globals = _GlobalVariableFind(self)
        LazyTarget.Initialize(debugger)

    def _GetSymbolicator(self):
        """ Internal function: To initialize the symbolication from lldb.utils
        """
        if not self.symbolicator is None:
            return self.symbolicator

        from lldb.utils import symbolication
        symbolicator = symbolication.Symbolicator()
        symbolicator.target = LazyTarget.GetTarget()
        self.symbolicator = symbolicator
        return self.symbolicator

    def Symbolicate(self, addr):
        """ simple method to get name of function/variable from an address. this is equivalent of gdb 'output /a 0xaddress'
            params:
                addr - int : typically hex value like 0xffffff80002c0df0
            returns:
                str - '' if no symbol found else the symbol name.
            Note: this function only finds the first symbol. If you expect multiple symbol conflict please use SymbolicateFromAddress()
        """
        ret_str = ''
        syms = self.SymbolicateFromAddress(addr)
        if len(syms) > 0:
            ret_str +=syms[0].GetName()
        return ret_str

    def SymbolicateFromAddress(self, addr):
        """ symbolicates any given address based on modules loaded in the target.
            params:
                addr - int : typically hex value like 0xffffff80002c0df0
            returns:
                [] of SBSymbol: In case we don't find anything than empty array is returned.
                      Note: a type of symbol can be figured out by gettype() function of SBSymbol.
            example usage:
                syms = kern.Symbolicate(0xffffff80002c0df0)
                for s in syms:
                  if s.GetType() == lldb.eSymbolTypeCode:
                    print "Function", s.GetName()
                  if s.GetType() == lldb.eSymbolTypeData:
                    print "Variable", s.GetName()
        """
        if type(int(1)) != type(addr):
            if str(addr).strip().find("0x") == 0 :
                addr = int(addr, 16)
            else:
                addr = int(addr)
        addr = self.StripKernelPAC(addr)
        ret_array = []
        symbolicator = self._GetSymbolicator()
        syms = symbolicator.symbolicate(addr)
        if not syms:
            return ret_array
        for s in syms:
            ret_array.append(s.get_symbol_context().symbol)
        return ret_array

    def IsDebuggerConnected(self):
        proc_state = LazyTarget.GetProcess().state
        if proc_state == lldb.eStateInvalid : return False
        if proc_state in [lldb.eStateStopped, lldb.eStateSuspended] : return True

    def GetGlobalVariable(self, name):
        """ Get the value object representation for a kernel global variable
            params:
              name : str - name of the variable. ex. version
            returns: value - python object representing global variable.
            raises : Exception in case the variable is not found.
        """
        self._globals_cache_dict = caching.GetDynamicCacheData("kern._globals_cache_dict", {})
        if name not in self._globals_cache_dict:
            self._globals_cache_dict[name] = value(LazyTarget.GetTarget().FindGlobalVariables(name, 1).GetValueAtIndex(0))
        return self._globals_cache_dict[name]

    def GetLoadAddressForSymbol(self, name):
        """ Get the load address of a symbol in the kernel.
            params:
              name : str - name of the symbol to lookup
            returns: int - the load address as an integer. Use GetValueFromAddress to cast to a value.
            raises : LookupError - if the symbol is not found.
        """
        name = str(name)
        target = LazyTarget.GetTarget()
        syms_arr = target.FindSymbols(name)
        if syms_arr.IsValid() and len(syms_arr) > 0:
            symbol = syms_arr[0].GetSymbol()
            if symbol.IsValid():
                return int(symbol.GetStartAddress().GetLoadAddress(target))

        raise LookupError("Symbol not found: " + name)

    def GetValueFromAddress(self, addr, type_str = 'void *'):
        """ convert a address to value
            params:
                addr - int : typically hex value like 0xffffff80008dc390
                type_str - str: type to cast to. Default type will be void *
            returns:
                value : a value object which has address as addr and type is type_str
        """
        obj = value(self.globals.version.GetSBValue().CreateValueFromExpression(None,'(void *)'+str(addr)))
        obj = cast(obj, type_str)
        return obj

    def GetValueAsType(self, v, t):
        """ Retrieves a global variable 'v' of type 't' wrapped in a vue object.
            If 'v' is an address, creates a vue object of the appropriate type.
            If 'v' is a name, looks for the global variable and asserts its type.
            Throws:
                NameError - If 'v' cannot be found
                TypeError - If 'v' is of the wrong type
        """
        if islong(v):
            return self.GetValueFromAddress(v, t)
        else:
            var = LazyTarget.GetTarget().FindGlobalVariables(v, 1)[0]
            if not var:
                raise NameError("Failed to find global variable '{0}'".format(v))
            if var.GetTypeName() != t:
                raise TypeError("{0} must be of type '{1}', not '{2}'".format(v, t, var.GetTypeName()))
            return value(var)

    def _GetIterator(self, iter_head_name, next_element_name='next', iter_head_type=None):
        """ returns an iterator for a collection in kernel memory.
            params:
                iter_head_name - str : name of queue_head or list head variable.
                next_element_name - str : name of the element that leads to next element.
                                          for ex. in struct zone list 'next_zone' is the linking element.
            returns:
                iterable : typically used in conjunction with "for varname in iterable:"
        """
        head_element = self.GetGlobalVariable(iter_head_name)
        return head_element.GetSBValue().linked_list_iter(next_element_name)

    def TruncPage(self, addr):
        return (addr & ~(unsigned(self.GetGlobalVariable("page_size")) - 1))

    def RoundPage(self, addr):
        return trunc_page(addr + unsigned(self.GetGlobalVariable("page_size")) - 1)

    def StraddlesPage(self, addr, size):
        if size > unsigned(self.GetGlobalVariable("page_size")):
            return True
        val = ((addr + size) & (unsigned(self.GetGlobalVariable("page_size"))-1))
        return (val < size and val > 0)

    def StripUserPAC(self, addr):
        if self.arch != 'arm64e':
            return addr
        T0Sz = self.GetGlobalVariable('gT0Sz')
        return StripPAC(addr, T0Sz)

    def StripKernelPAC(self, addr):
        if self.arch != 'arm64e':
            return addr
        T1Sz = self.GetGlobalVariable('gT1Sz')
        return StripPAC(addr, T1Sz)

    def PhysToKVARM64(self, addr):
        ptov_table = self.GetGlobalVariable('ptov_table')
        for i in range(0, self.GetGlobalVariable('ptov_index')):
            if (addr >= long(unsigned(ptov_table[i].pa))) and (addr < (long(unsigned(ptov_table[i].pa)) + long(unsigned(ptov_table[i].len)))):
                return (addr - long(unsigned(ptov_table[i].pa)) + long(unsigned(ptov_table[i].va)))
        return (addr - unsigned(self.GetGlobalVariable("gPhysBase")) + unsigned(self.GetGlobalVariable("gVirtBase")))

    def PhysToKernelVirt(self, addr):
        if self.arch == 'x86_64':
            return (addr + unsigned(self.GetGlobalVariable('physmap_base')))
        elif self.arch.startswith('arm64'):
            return self.PhysToKVARM64(addr)
        elif self.arch.startswith('arm'):
            return (addr - unsigned(self.GetGlobalVariable("gPhysBase")) + unsigned(self.GetGlobalVariable("gVirtBase")))
        else:
            raise ValueError("PhysToVirt does not support {0}".format(self.arch))

    def GetNanotimeFromAbstime(self, abstime):
        """ convert absolute time (which is in MATUs) to nano seconds.
            Since based on architecture the conversion may differ.
            params:
                abstime - int absolute time as shown by mach_absolute_time
            returns:
                int - nanosecs of time
        """
        usec_divisor = caching.GetStaticCacheData("kern.rtc_usec_divisor", None)
        if not usec_divisor:
            if self.arch == 'x86_64':
                usec_divisor = 1000
            else:
                rtclockdata_addr = self.GetLoadAddressForSymbol('RTClockData')
                rtc = self.GetValueFromAddress(rtclockdata_addr, 'struct _rtclock_data_ *')
                usec_divisor = unsigned(rtc.rtc_usec_divisor)
            usec_divisor = int(usec_divisor)
            caching.SaveStaticCacheData('kern.rtc_usec_divisor', usec_divisor)
        nsecs = (abstime * 1000)/usec_divisor
        return nsecs

    def __getattribute__(self, name):
        if name == 'zones' :
            self._zones_list = caching.GetDynamicCacheData("kern._zones_list", [])
            if len(self._zones_list) > 0: return self._zones_list
            zone_array = self.GetGlobalVariable('zone_array')
            for i in range(0, self.GetGlobalVariable('num_zones')):
                self._zones_list.append(addressof(zone_array[i]))
            caching.SaveDynamicCacheData("kern._zones_list", self._zones_list)
            return self._zones_list

        if name == 'threads' :
            self._threads_list = caching.GetDynamicCacheData("kern._threads_list", [])
            if len(self._threads_list) > 0 : return self._threads_list
            thread_queue_head = self.GetGlobalVariable('threads')
            thread_type = LazyTarget.GetTarget().FindFirstType('thread')
            thread_ptr_type = thread_type.GetPointerType()
            for th in IterateQueue(thread_queue_head, thread_ptr_type, 'threads'):
                self._threads_list.append(th)
            caching.SaveDynamicCacheData("kern._threads_list", self._threads_list)
            return self._threads_list

        if name == 'tasks' :
            self._tasks_list = caching.GetDynamicCacheData("kern._tasks_list", [])
            if len(self._tasks_list) > 0 : return self._tasks_list
            task_queue_head = self.GetGlobalVariable('tasks')
            task_type = LazyTarget.GetTarget().FindFirstType('task')
            task_ptr_type = task_type.GetPointerType()
            for tsk in IterateQueue(task_queue_head, task_ptr_type, 'tasks'):
                self._tasks_list.append(tsk)
            caching.SaveDynamicCacheData("kern._tasks_list", self._tasks_list)
            return self._tasks_list

        if name == 'coalitions' :
            self._coalitions_list = caching.GetDynamicCacheData("kern._coalitions_list", [])
            if len(self._coalitions_list) > 0 : return self._coalitions_list
            coalition_queue_head = self.GetGlobalVariable('coalitions_q')
            coalition_type = LazyTarget.GetTarget().FindFirstType('coalition')
            coalition_ptr_type = coalition_type.GetPointerType()
            for coal in IterateLinkageChain(addressof(coalition_queue_head), coalition_ptr_type, 'coalitions'):
                self._coalitions_list.append(coal)
            caching.SaveDynamicCacheData("kern._coalitions_list", self._coalitions_list)
            return self._coalitions_list

        if name == 'thread_groups' :
            self._thread_groups_list = caching.GetDynamicCacheData("kern._thread_groups_list", [])
            if len(self._thread_groups_list) > 0 : return self._thread_groups_list
            thread_groups_queue_head = self.GetGlobalVariable('tg_queue')
            thread_group_type = LazyTarget.GetTarget().FindFirstType('thread_group')
            thread_groups_ptr_type = thread_group_type.GetPointerType()
            for coal in IterateLinkageChain(addressof(thread_groups_queue_head), thread_groups_ptr_type, 'tg_queue_chain'):
                self._thread_groups_list.append(coal)
            caching.SaveDynamicCacheData("kern._thread_groups_list", self._thread_groups_list)
            return self._thread_groups_list

        if name == 'terminated_tasks' :
            self._terminated_tasks_list = caching.GetDynamicCacheData("kern._terminated_tasks_list", [])
            if len(self._terminated_tasks_list) > 0 : return self._terminated_tasks_list
            task_queue_head = self.GetGlobalVariable('terminated_tasks')
            task_type = LazyTarget.GetTarget().FindFirstType('task')
            task_ptr_type = task_type.GetPointerType()
            for tsk in IterateQueue(task_queue_head, task_ptr_type, 'tasks'):
                self._terminated_tasks_list.append(tsk)
            caching.SaveDynamicCacheData("kern._terminated_tasks_list", self._terminated_tasks_list)
            return self._terminated_tasks_list

        if name == 'procs' :
            self._allproc = caching.GetDynamicCacheData("kern._allproc", [])
            if len(self._allproc) > 0 : return self._allproc
            all_proc_head = self.GetGlobalVariable('allproc')
            proc_val = cast(all_proc_head.lh_first, 'proc *')
            while proc_val != 0:
                self._allproc.append(proc_val)
                proc_val = cast(proc_val.p_list.le_next, 'proc *')
            caching.SaveDynamicCacheData("kern._allproc", self._allproc)
            return self._allproc

        if name == 'interrupt_stats' :
            self._interrupt_stats_list = caching.GetDynamicCacheData("kern._interrupt_stats_list", [])
            if len(self._interrupt_stats_list) > 0 : return self._interrupt_stats_list
            interrupt_stats_head = self.GetGlobalVariable('gInterruptAccountingDataList')
            interrupt_stats_type = LazyTarget.GetTarget().FindFirstType('IOInterruptAccountingData')
            interrupt_stats_ptr_type = interrupt_stats_type.GetPointerType()
            for interrupt_stats_obj in IterateQueue(interrupt_stats_head, interrupt_stats_ptr_type, 'chain'):
                self._interrupt_stats_list.append(interrupt_stats_obj)
            caching.SaveDynamicCacheData("kern._interrupt_stats", self._interrupt_stats_list)
            return self._interrupt_stats_list

        if name == 'zombprocs' :
            self._zombproc_list = caching.GetDynamicCacheData("kern._zombproc_list", [])
            if len(self._zombproc_list) > 0 : return self._zombproc_list
            zproc_head = self.GetGlobalVariable('zombproc')
            proc_val = cast(zproc_head.lh_first, 'proc *')
            while proc_val != 0:
                self._zombproc_list.append(proc_val)
                proc_val = cast(proc_val.p_list.le_next, 'proc *')
            caching.SaveDynamicCacheData("kern._zombproc_list", self._zombproc_list)
            return self._zombproc_list

        if name == 'version' :
            self._version = caching.GetStaticCacheData("kern.version", None)
            if self._version != None : return self._version
            self._version = str(self.GetGlobalVariable('version'))
            caching.SaveStaticCacheData("kern.version", self._version)
            return self._version

        if name == 'arch' :
            self._arch = caching.GetStaticCacheData("kern.arch", None)
            if self._arch != None : return self._arch
            arch = LazyTarget.GetTarget().triple.split('-')[0]
            if arch in ('armv7', 'armv7s', 'armv7k'):
                self._arch = 'arm'
            else:
                self._arch = arch
            caching.SaveStaticCacheData("kern.arch", self._arch)
            return self._arch

        if name == 'ptrsize' :
            self._ptrsize = caching.GetStaticCacheData("kern.ptrsize", None)
            if self._ptrsize != None : return self._ptrsize
            arch = LazyTarget.GetTarget().triple.split('-')[0]
            if arch == 'x86_64' or arch.startswith('arm64'):
                self._ptrsize = 8
            else:
                self._ptrsize = 4
            caching.SaveStaticCacheData("kern.ptrsize", self._ptrsize)
            return self._ptrsize

        if name == 'VM_MIN_KERNEL_ADDRESS':
            if self.arch == 'x86_64':
                return unsigned(0xFFFFFF8000000000)
            elif self.arch.startswith('arm64'):
                return unsigned(0xffffffe000000000)
            else:
                return unsigned(0x80000000)

        if name == 'VM_MIN_KERNEL_AND_KEXT_ADDRESS':
            if self.arch == 'x86_64':
                return self.VM_MIN_KERNEL_ADDRESS - 0x80000000
            else:
                return self.VM_MIN_KERNEL_ADDRESS

        return object.__getattribute__(self, name)
