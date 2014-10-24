from xnu import *

"""
Recursive ipc importance chain viewing macro. This file incorporates complex python datastructures
interspersed with cvalue based objects from lldb interface. 
"""

class TaskNode(object):
    def __init__(self, task_kobj):
        self.task = task_kobj
        self.importance_refs = []
    
    @staticmethod
    def GetHeaderString():
        return GetTaskSummary.header + " " + GetProcSummary.header + " {: <18s}".format("task_imp_base")

    def __str__(self):
        out_arr = []
        if unsigned(self.task) != 0: 
            out_arr.append(GetTaskSummary(self.task) + " " + GetProcSummary(Cast(self.task.bsd_info, 'proc *')) + " {: <#018x}".format(self.task.task_imp_base) )
        else:
            out_arr.append("Unknown task.")
        #out_arr.append("TASK: {: <#018x} {: <s}".format(self.task, GetProcNameForTask(self.task))
        for i in self.importance_refs:
            out_arr.append("\t" + i.GetBackRefChain())
        return "\n".join(out_arr)

    def AddImportanceNode(self, iinode):
        self.importance_refs.append(iinode)

class IIINode(object):
    """docstring for IIINode"""
    def __init__(self, elem, parentNode):
        super(IIINode, self).__init__()
        self.elem = elem
        self.children = []
        self.parent = parentNode

    def addChildNode(self, elemNode):
        self.children.append(elemNode)

    def __str__(self):
        if unsigned(self.elem.iii_elem.iie_bits) & 0x80000000:
            return GetIPCImportanceInheritSummary(self.elem)
        else:
            return GetIPCImportantTaskSummary(self.elem)
    
    def GetShortSummary(self):
        to_task = self.GetToTask()
        if unsigned(self.elem.iii_elem.iie_bits) & 0x80000000:
            return "{: <#018x} INH ({:d}){: <s}".format(self.elem, GetProcPIDForTask(to_task), GetProcNameForTask(to_task))
        else:
            return "{: <#018x} IIT ({:d}){: <s}".format(self.elem, GetProcPIDForTask(to_task), GetProcNameForTask(to_task))

    def GetChildSummaries(self, prefix="\t"):
        retval = []
        for i in self.children:
            retval.append(prefix + str(i))
            retval.append(i.GetChildSummaries(prefix+"\t"))
        return "\n".join(retval)

    def GetToTask(self):
        if unsigned(self.elem.iii_elem.iie_bits) & 0x80000000:
            return self.elem.iii_to_task.iit_task
        else:
            return self.elem.iit_task

    def GetParentNode(self):
        return self.parent

    def GetBackRefChain(self):
        out_str = ""
        cur_elem = self.elem
        out_str += self.GetShortSummary()
        from_elem = Cast(cur_elem.iii_from_elem, 'ipc_importance_inherit *')
        # NOTE: We are exploiting the layout of iit and iii to have iie at the begining.
        # so casting one to another is fine as long as we tread carefully.
        
        while unsigned(from_elem.iii_elem.iie_bits) & 0x80000000:
            out_str += " <- {: <#018x} INH ({:d}){: <s}".format(from_elem, GetProcPIDForTask(from_elem.iii_to_task.iit_task), GetProcNameForTask(from_elem.iii_to_task.iit_task))
            from_elem = Cast(from_elem.iii_from_elem, 'ipc_importance_inherit *')

        if unsigned(from_elem.iii_elem.iie_bits) & 0x80000000 == 0:
            iit_elem = Cast(from_elem, 'ipc_importance_task *')
            out_str += " <- {: <#018x} IIT ({:d}){: <s}".format(iit_elem, GetProcPIDForTask(iit_elem.iit_task), GetProcNameForTask(iit_elem.iit_task))
        
        return out_str

        #unused
        cur_elem = self
        while cur_elem.parent:
            out_str += "<-" + cur_elem.GetShortSummary()
            cur_elem = cur_elem.GetParentNode()
        return out_str
        
def GetIIIListFromIIE(iie, rootnode):
    """ walk the iii queue and find each III element in a list format
    """
    for i in IterateQueue(iie.iie_inherits, 'struct ipc_importance_inherit *',  'iii_inheritance'):
        iieNode = IIINode(i, rootnode)
        if unsigned(i.iii_elem.iie_bits) & 0x80000000:
            rootnode.addChildNode(iieNode)
            GetIIIListFromIIE(i.iii_elem, iieNode)
            GetTaskNodeByKernelTaskObj(iieNode.GetToTask()).AddImportanceNode(iieNode)
    return 

AllTasksCollection = {}
def GetTaskNodeByKernelTaskObj(task_kobj):
    global AllTasksCollection
    key = hex(unsigned(task_kobj))
    if key not in AllTasksCollection:
        AllTasksCollection[key] = TaskNode(task_kobj)
    return AllTasksCollection[key]
    


@lldb_command('showallipcimportance')
def ShowInheritanceChains(cmd_args=[], cmd_options={}):
    """ show boost inheritance chains.
        Usage: (lldb) showboostinheritancechains  <task_t>
    """
    print ' ' + GetIPCImportantTaskSummary.header + ' ' + GetIPCImportanceElemSummary.header
    for task in kern.tasks:
        if unsigned(task.task_imp_base):
            print " " + GetIPCImportantTaskSummary(task.task_imp_base) + ' ' + GetIPCImportanceElemSummary(addressof(task.task_imp_base.iit_elem))
            base_node = IIINode(Cast(task.task_imp_base, 'ipc_importance_inherit *'), None)
            GetIIIListFromIIE(task.task_imp_base.iit_elem, base_node)
            print base_node.GetChildSummaries(prefix="\t\t")
    
    print "\n\n ======================== TASK REVERSE CHAIN OF IMPORTANCES ========================="
    print TaskNode.GetHeaderString()
    for k in AllTasksCollection.keys():
        t = AllTasksCollection[k]
        print "\n" + str(t)

