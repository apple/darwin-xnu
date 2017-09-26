""" Please make sure you read the README COMPLETELY BEFORE reading anything below.
    It is very critical that you read coding guidelines in Section E in README file.
"""

from xnu import *
from utils import *
from string import *
from socket import *

import xnudefines
from netdefines import *
from routedefines import *

def ShowNstatTUShadow(inshadow):
    """ Display summary for an nstat_tu_shadow struct
        params:
            inshadow : cvalue object which points to 'struct nstat_tu_shadow *'
    """
    shad = Cast(inshadow, 'struct nstat_tu_shadow *')
    procdetails = shad.shad_procdetails
    out_string = ""
    if shad :
        format_string = "nstat_tu_shadow {0: <s}: next={1: <s} prev={2: <s} context (necp_client *)={3: <s} live={4: <d}"
        out_string += format_string.format(hex(shad), hex(shad.shad_link.tqe_next), hex(shad.shad_link.tqe_prev), hex(shad.shad_provider_context),shad.shad_live)

        magic = unsigned(shad.shad_magic)
        if (magic != 0xfeedf00d) :
            format_string = " INVALID shad magic {0: <s}"
            out_string += format_string.format(hex(magic))

        if (procdetails) :
            format_string = "  --> procdetails {0: <s}: pid={1: <d} name={2: <s} numflows={3: <d}"
            out_string += format_string.format(hex(procdetails), procdetails.pdet_pid, procdetails.pdet_procname, procdetails.pdet_numflows)

            procmagic = unsigned(procdetails.pdet_magic)
            if (procmagic != 0xfeedc001) :
                format_string = " INVALID proc magic {0: <s}"
                out_string += format_string.format(hex(procmagic))

    print out_string

def GetNstatProcdetailsBrief(procdetails):
    """ Display a brief summary for an nstat_procdetails struct
        params:
            procdetails : cvalue object which points to 'struct nstat_procdetails *'
        returns:
            str : A string describing various information for the nstat_procdetails structure
    """
    procdetails = Cast(procdetails, 'struct nstat_procdetails *')
    out_string = ""
    if (procdetails) :
        format_string = " --> pid={0: <d} name={1: <s} numflows={2: <d}"
        out_string += format_string.format(procdetails.pdet_pid, procdetails.pdet_procname, procdetails.pdet_numflows)

        procmagic = unsigned(procdetails.pdet_magic)
        if (procmagic != 0xfeedc001) :
            format_string = " INVALID proc magic {0: <s}"
            out_string += format_string.format(hex(procmagic))

    return out_string

def ShowNstatProcdetails(procdetails):
    """ Display a summary for an nstat_procdetails struct
        params:
            procdetails : cvalue object which points to 'struct nstat_procdetails *'
    """
    procdetails = Cast(procdetails, 'struct nstat_procdetails *')
    out_string = ""
    if (procdetails) :
        format_string = "nstat_procdetails: {0: <s} next={1: <s} prev={2: <s} "
        out_string += format_string.format(hex(procdetails), hex(procdetails.pdet_link.tqe_next), hex(procdetails.pdet_link.tqe_prev))
        out_string += GetNstatProcdetailsBrief(procdetails)

    print out_string

def GetNstatTUShadowBrief(shadow):
    """ Display a summary for an nstat_tu_shadow struct
        params:
            shadow : cvalue object which points to 'struct nstat_tu_shadow *'
        returns:
            str : A string describing various information for the nstat_tu_shadow structure
    """
    out_string = ""
    shad = Cast(shadow, 'struct nstat_tu_shadow *')
    procdetails = shad.shad_procdetails
    procdetails = Cast(procdetails, 'struct nstat_procdetails *')
    out_string = ""
    if shad :
        format_string = " shadow {0: <s}: necp_client ={1: <s} live={2: <d}"
        out_string += format_string.format(hex(shad),hex(shad.shad_provider_context),shad.shad_live)
        magic = unsigned(shad.shad_magic)
        if (magic != 0xfeedf00d) :
            format_string = " INVALID shad magic {0: <s}"
            out_string += format_string.format(hex(magic))
        elif (procdetails) :
            out_string += GetNstatProcdetailsBrief(procdetails)

    return out_string

def ShowNstatSrc(insrc):
    """ Display summary for an nstat_src struct
        params:
            insrc : cvalue object which points to 'struct nstat_src *'
    """
    src = Cast(insrc, 'nstat_src *')
    prov = src.provider
    prov = Cast(prov, 'nstat_provider *')
    prov_string = "?"
    if (prov.nstat_provider_id == 2):
        prov_string = "TCP k"
    elif (prov.nstat_provider_id == 3):
        prov_string = "TCP u"
    elif (prov.nstat_provider_id == 4):
        prov_string = "UDP k"
    elif (prov.nstat_provider_id == 5):
        prov_string = "UDP u"
    elif (prov.nstat_provider_id == 1):
        prov_string = "Route"
    elif (prov.nstat_provider_id == 6):
        prov_string = "ifnet"
    elif (prov.nstat_provider_id == 7):
        prov_string = "sysinfo"
    else:
        prov_string = "unknown-provider"

    out_string = ""
    if src :
        format_string = "  nstat_src {0: <s}: prov={1: <s} next={2: <s} prev={3: <s} ref={4: <d}"
        out_string += format_string.format(hex(src), prov_string, hex(src.ns_control_link.tqe_next), hex(src.ns_control_link.tqe_prev), src.srcref)

        if (prov.nstat_provider_id == 3):
            out_string += GetNstatTUShadowBrief(src.cookie);

    print out_string

def ShowNstatCtrl(inctrl):
    """ Display an nstat_control_state struct
        params:
            ctrl : value object representing an nstat_control_state in the kernel
    """
    ctrl = Cast(inctrl, 'nstat_control_state *')
    out_string = ""
    if ctrl :
        format_string = "nstat_control_state {0: <s}: next={1: <s} src head={2: <s} tail={3: <s}"
        out_string += format_string.format(hex(ctrl), hex(ctrl.ncs_next), hex(ctrl.ncs_src_queue.tqh_first), hex(ctrl.ncs_src_queue.tqh_last))

    print out_string

    for src in IterateTAILQ_HEAD(ctrl.ncs_src_queue, 'ns_control_link'):
        ShowNstatSrc(src)

# Macro: showallntstat

@lldb_command('showallntstat')
def ShowAllNtstat(cmd_args=None) :
    """ Show the contents of various ntstat (network statistics) data structures
    """
    print "nstat_controls list:\n"
    ctrl = kern.globals.nstat_controls
    ctrl = cast(ctrl, 'nstat_control_state *')
    while ctrl != 0:
        ShowNstatCtrl(ctrl)
        ctrl = cast(ctrl.ncs_next, 'nstat_control_state *')

    print "\nnstat_userprot_shad list:\n"
    shadows = kern.globals.nstat_userprot_shad_head
    for shad in IterateTAILQ_HEAD(shadows, 'shad_link'):
        ShowNstatTUShadow(shad)

    print "\nnstat_procdetails list:\n"
    procdetails_head = kern.globals.nstat_procdetails_head
    for procdetails in IterateTAILQ_HEAD(procdetails_head, 'pdet_link'):
        ShowNstatProcdetails(procdetails)

# EndMacro: showallntstat
