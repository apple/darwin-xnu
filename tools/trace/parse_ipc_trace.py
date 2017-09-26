#!/usr/bin/env python
# machtrace_parse.py
# Parse Mach IPC kmsg data trace from XNU
#
# Jeremy C. Andrus <jeremy_andrus@apple.com>
#
from __future__ import division

import argparse
import subprocess
import sys
import re
from collections import deque

import os.path

from collections import defaultdict

g_verbose = 0
g_min_messages = 10
g_rolling_window = 200

def RunCommand(cmd_string):
    """
        returns: (int,str) : exit_code and output_str
    """
    global g_verbose
    if g_verbose > 1:
        sys.stderr.write("\tCMD:{}\n".format(cmd_string))
    output_str = ""
    exit_code = 0
    try:
        output_str = subprocess.check_output(cmd_string, shell=True)
    except subprocess.CalledProcessError, e:
        exit_code = e.returncode
    finally:
        return (exit_code, output_str.strip())


class IPCNode:
    """ Class interface to a graph node representing a logical service name.
        In general, this should correspond to a unique binary on the system
        which could be started / stopped as different PIDs throughout the life
        of the system.
    """
    def __init__(self, name = ''):
        global g_verbose
        self.nname = "L_" + name.replace(".", "_").replace("-", "_")
        self.nicename = name
        self.outgoing = {}
        self.incoming = {}
        self.msg_stat = {'o.num':0, 'o.first':0.0, 'o.last':0.0, 'o.window':deque(), 'o.avg':0, 'o.peak':0, \
                         'i.num':0, 'i.first':0.0, 'i.last':0.0, 'i.window':deque(), 'i.avg':0, 'i.peak':0}
        self.pidset = {}
        self.scalefactor = 100.0
        if g_verbose > 0:
            sys.stderr.write(' New node: "{}"{}\n'.format(self.nname, ' '*50))

    def add_outgoing_edge(self, edge, time):
        self.outgoing[edge.ename()] = [edge, time]

    def add_incoming_edge(self, edge, time):
        self.incoming[edge.ename()] = [edge, time]

    def addpid(self, pid, time):
        if not pid in self.pidset:
            self.pidset[pid] = [time, 0]
        self.pidset[pid][1] = time

    def incoming_msg(self, size, time_us):
        global g_min_messages
        global g_rolling_window
        num = self.msg_stat['i.num'] + 1
        self.msg_stat['i.num'] = num
        time_us = float(time_us)
        if self.msg_stat['i.first'] == 0.0:
            self.msg_stat['i.first'] = time_us
            self.msg_stat['i.last'] = time_us
        else:
            self.msg_stat['i.last'] = time_us
            if num > g_min_messages:
                avg = (num * self.scalefactor) / (time_us - self.msg_stat['i.first'])
                self.msg_stat['i.avg'] = avg

        self.msg_stat['i.window'].append(time_us)
        if len(self.msg_stat['i.window']) > g_rolling_window:
            self.msg_stat['i.window'].popleft()
            n = len(self.msg_stat['i.window'])
            ravg = float(len(self.msg_stat['i.window']) * self.scalefactor) / \
                    (self.msg_stat['i.window'][-1] - self.msg_stat['i.window'][0])
            if ravg > self.msg_stat['i.peak']:
                self.msg_stat['i.peak'] = ravg

    def outgoing_msg(self, size, time_us):
        global g_min_messages
        global g_rolling_window
        num = self.msg_stat['o.num'] + 1
        self.msg_stat['o.num'] = num
        time_us = float(time_us)
        if self.msg_stat['o.first'] == 0.0:
            self.msg_stat['o.first'] = time_us
            self.msg_stat['o.last'] = time_us
        else:
            self.msg_stat['o.last'] = time_us
            if num > g_min_messages:
                avg = (num * self.scalefactor) / (time_us - self.msg_stat['o.first'])
                self.msg_stat['o.avg'] = avg

        self.msg_stat['o.window'].append(time_us)
        if len(self.msg_stat['o.window']) > g_rolling_window:
            self.msg_stat['o.window'].popleft()
            n = len(self.msg_stat['o.window'])
            ravg = float(len(self.msg_stat['o.window']) * self.scalefactor) / \
                    (self.msg_stat['o.window'][-1] - self.msg_stat['o.window'][0])
            if ravg > self.msg_stat['o.peak']:
                self.msg_stat['o.peak'] = ravg

    def nmsgs(self):
        return self.msg_stat['o.num'], self.msg_stat['i.num']

    def recycled(self):
        return len(self.pidset)

    def label(self, timebase = 1000000.0):
        oavg = float(self.msg_stat['o.avg']) / self.scalefactor
        opeak = float(self.msg_stat['o.peak']) / self.scalefactor
        oactive = self.msg_stat['o.last'] - self.msg_stat['o.first']
        iavg = float(self.msg_stat['i.avg']) / self.scalefactor
        ipeak = float(self.msg_stat['i.peak']) / self.scalefactor
        iactive = self.msg_stat['i.last'] - self.msg_stat['i.first']
        if timebase > 0.0:
            oavg = oavg * timebase
            opeak = opeak * timebase
            oactive = oactive / timebase
            iavg = iavg * timebase
            ipeak = ipeak * timebase
            iactive = iactive / timebase
        return "{:s}\\no:{:d}/({:d}:{:.1f}s)/{:.1f}:{:.1f})\\ni:{:d}({:d}:{:.1f}s)/{:.1f}:{:.1f})\\nR:{:d}"\
                .format(self.nicename, \
                        len(self.outgoing), self.msg_stat['o.num'], oactive, oavg, opeak, \
                        len(self.incoming), self.msg_stat['i.num'], iactive, iavg, ipeak, \
                        len(self.pidset))

class IPCEdge:
    """ Class interface to an graph edge representing two services / programs
        communicating via Mach IPC. Note that this communication could
        use many different PIDs. The connected graph nodes (see IPCNode)
        represent logical services on the system which could be instantiated
        as many different PIDs depending on the lifecycle of the process
        (dictated in part by launchd).
    """

    F_TRACED      = 0x00000100
    F_COMPLEX     = 0x00000200
    F_OOLMEM      = 0x00000400
    F_VCPY        = 0x00000800
    F_PCPY        = 0x00001000
    F_SND64       = 0x00002000
    F_RAISEIMP    = 0x00004000
    F_APP_SRC     = 0x00008000
    F_APP_DST     = 0x00010000
    F_DAEMON_SRC  = 0x00020000
    F_DAEMON_DST  = 0x00040000
    F_DST_NDFLTQ  = 0x00080000
    F_SRC_NDFLTQ  = 0x00100000
    F_DST_SONCE   = 0x00200000
    F_SRC_SONCE   = 0x00400000
    F_CHECKIN     = 0x00800000
    F_ONEWAY      = 0x01000000
    F_IOKIT       = 0x02000000
    F_SNDRCV      = 0x04000000
    F_DSTQFULL    = 0x08000000
    F_VOUCHER     = 0x10000000
    F_TIMER       = 0x20000000
    F_SEMA        = 0x40000000
    F_PORTS_MASK  = 0x000000FF

    DTYPES = [ 'std', 'xpc', 'iokit', 'std.reply', 'xpc.reply', 'iokit.reply' ]
    DFLAVORS = [ 'std', 'ool', 'vcpy', 'iokit' ]

    def __init__(self, src = IPCNode(), dst = IPCNode(), data = '0', flags = '0', time = 0.0):
        self.src = src
        self.dst = dst
        self.flags = 0
        self.dweight = 0
        self.pweight = 0
        self.weight = 0
        self._data  = { 'std':0, 'ool':0, 'vcpy':0, 'iokit':0 }
        self._dtype = { 'std':0, 'xpc':0, 'iokit':0, 'std.reply':0, 'xpc.reply':0, 'iokit.reply':0 }
        self._msgs  = { 'std':0, 'ool':0, 'vcpy':0, 'iokit':0 }
        self._mtype = { 'std':0, 'xpc':0, 'iokit':0, 'std.reply':0, 'xpc.reply':0, 'iokit.reply':0 }
        self.ports = 0
        self.task64 = False
        self.task32 = False
        self.src.add_outgoing_edge(self, time)
        self.dst.add_incoming_edge(self, time)
        self.addmsg(data, flags, time)

    def ename(self):
        return self.src.nname + " -> " + self.dst.nname

    def msgdata(self):
        return self._data, self._dtype

    def data(self, flavor = None):
        if not flavor:
            return sum(self._data.itervalues())
        elif flavor in self._data:
            return self._data[flavor]
        else:
            return 0

    def dtype(self, type):
        if not type:
            return sum(self._dtype.itervalues())
        elif type in self._dtype:
            return self._dtype[type]
        else:
            return 0

    def msgs(self, flavor = None):
        if not flavor:
            return sum(self._msgs.itervalues())
        elif flavor in self._msgs:
            return self._msgs[flavor]
        else:
            return 0

    def mtype(self, type):
        if not type:
            return sum(self._mtype.itervalues())
        elif type in self._mtype:
            return self._mtype[type]
        else:
            return 0

    def selfedge(self):
        if self.src.nname == self.dst.nname:
            return True
        return False

    def addmsg(self, data_hex_str, flags_str, time):
        global g_verbose
        f = int(flags_str, 16)
        self.flags |= f
        df = {f:0 for f in self.DFLAVORS}
        dt = {t:0 for t in self.DTYPES}
        if not f & self.F_TRACED:
            return df, dt
        self.weight += 1
        if f & self.F_SND64:
            self.task64 = True
        else:
            self.task32 = True
        if not f & self.F_COMPLEX:
            self.dweight += 1
            df['std'] = int(data_hex_str, 16)
            if f & self.F_IOKIT:
                df['iokit'] = df['std']
                df['std'] = 0
                self._data['iokit'] += df['iokit']
                self._msgs['iokit'] += 1
            else:
                self._data['std'] += df['std']
                self._msgs['std'] += 1
        elif f & self.F_OOLMEM:
            self.dweight += 1
            df['ool'] = int(data_hex_str, 16)
            if f & self.F_IOKIT:
                df['iokit'] = df['ool']
                df['ool'] = 0
                self._data['iokit'] += df['iokit']
                self._msgs['iokit'] += 1
            elif f & self.F_VCPY:
                df['vcpy'] = df['ool']
                df['ool'] = 0
                self._data['vcpy'] += df['vcpy']
                self._msgs['vcpy'] += 1
            else:
                self._data['ool'] += df['ool']
                self._msgs['ool'] += 1
        # Complex messages can contain ports and data
        if f & self.F_COMPLEX:
            nports = f & self.F_PORTS_MASK
            if nports > 0:
                self.pweight += 1
                self.ports += nports
        dsize = sum(df.values())
        if f & self.F_DST_SONCE:
            if f & self.F_IOKIT:
                dt['iokit.reply'] = dsize
                self._dtype['iokit.reply'] += dsize
                self._mtype['iokit.reply'] += 1
            elif f & (self.F_DST_NDFLTQ | self.F_SRC_NDFLTQ):
                dt['xpc.reply'] = dsize
                self._dtype['xpc.reply'] += dsize
                self._mtype['xpc.reply'] += 1
            else:
                dt['std.reply'] = dsize
                self._dtype['std.reply'] += dsize
                self._mtype['std.reply'] += 1
        elif f & self.F_IOKIT:
            dt['iokit'] = dsize
            self._dtype['iokit'] += dsize
            self._mtype['iokit'] += 1
        elif f & (self.F_DST_NDFLTQ | self.F_SRC_NDFLTQ):
            dt['xpc'] = dsize
            self._dtype['xpc'] += dsize
            self._mtype['xpc'] += 1
        else:
            dt['std'] = dsize
            self._dtype['std'] += dsize
            self._mtype['std'] += 1
        self.src.outgoing_msg(dsize, time)
        self.dst.incoming_msg(dsize, time)
        if g_verbose > 2:
            sys.stderr.write(' {}->{} ({}/{}){}\r'.format(self.src.nname, self.dst.nname, df['ool'], df['std'], ' ' *50))
        return df, dt

    def avgmsg(self):
        avgsz = self.data() / self.dweight
        msgs_with_data = self.dweight / self.weight
        avgports = self.ports / self.pweight
        msgs_with_ports = self.pweight / self.weight
        return (avgsz, msgs_with_data, avgports, msgs_with_ports)


class EdgeError(Exception):
    """ IPCEdge exception class
    """
    def __init__(self, edge, nm):
        self.msg = "Edge {} (w:{}) didn't match incoming name {}!".format(edge.ename(), edge.weight, nm)

class IPCGraph:
    """ Class interface to a directed graph of IPC interconnectivity
    """
    def __init__(self, name = '', timebase = 0.0):
        global g_verbose
        if len(name) == 0:
            self.name = 'ipcgraph'
        else:
            self.name = name
        if g_verbose > 0:
            sys.stderr.write('Creating new IPCGraph named {}...\n'.format(self.name))
        self.nodes = {}
        self.edges = {}
        self.msgs = defaultdict(lambda: {f:0 for f in IPCEdge.DFLAVORS})
        self.msgtypes = defaultdict(lambda: {t:0 for t in IPCEdge.DTYPES})
        self.nmsgs = 0
        self.totals = {}
        self.maxdweight = 0
        for f in IPCEdge.DFLAVORS:
            self.totals['n'+f] = 0
            self.totals['D'+f] = 0
        if timebase and timebase > 0.0:
            self.timebase = timebase
        else:
            self.timebase = 0.0

    def __iter__(self):
        return edges

    def edgename(self, src, dst):
        if src and dst:
            return src.nname + ' -> ' + dst.nname
        return ''

    def addmsg(self, src_str, src_pid, dst_str, dst_pid, data_hex_str, flags_str, time):
        src = None
        dst = None
        for k, v in self.nodes.iteritems():
            if not src and k == src_str:
                src = v
            if not dst and k == dst_str:
                dst = v 
            if src and dst:
                break
        if not src:
            src = IPCNode(src_str)
            self.nodes[src_str] = src;
        if not dst:
            dst = IPCNode(dst_str)
            self.nodes[dst_str] = dst
        src.addpid(src_pid, time)
        dst.addpid(dst_pid, time)

        nm = self.edgename(src, dst)
        msgdata = {}
        msgDtype = {}
        e = self.edges.get(nm)
        if e != None:
            if e.ename() != nm:
                raise EdgeError(e,nm)
            msgdata, msgDtype = e.addmsg(data_hex_str, flags_str, time)
        else:
            e = IPCEdge(src, dst, data_hex_str, flags_str, time)
            msgdata, msgDtype = e.msgdata()
            self.edges[nm] = e

        if self.maxdweight < e.dweight:
            self.maxdweight = e.dweight

        if sum(msgdata.values()) == 0:
            self.msgs[0]['std'] += 1
            self.msgtypes[0]['std'] += 1
            if not 'enames' in self.msgs[0]:
                self.msgs[0]['enames'] = [ nm ]
            elif not nm in self.msgs[0]['enames']:
                self.msgs[0]['enames'].append(nm)
        else:
            for k,d in msgdata.iteritems():
                if d > 0:
                    self.msgs[d][k] += 1
                    self.totals['n'+k] += 1
                    self.totals['D'+k] += d
                    if not 'enames' in self.msgs[d]:
                        self.msgs[d]['enames'] = [ nm ]
                    elif not nm in self.msgs[d]['enames']:
                        self.msgs[d]['enames'].append(nm)
            for k,d in msgDtype.iteritems():
                if d > 0:
                    self.msgtypes[d][k] += 1
        self.nmsgs += 1
        if self.nmsgs % 1024 == 0:
            sys.stderr.write(" {:d}...\r".format(self.nmsgs));

    def print_dot_node(self, ofile, node):
        omsgs, imsgs = node.nmsgs()
        recycled = node.recycled() * 5
        tcolor = 'black'
        if recycled >= 50:
            tcolor = 'white'
        if recycled == 5:
            bgcolor = 'white'
        elif recycled <= 100:
            bgcolor = 'grey{:d}'.format(100 - recycled)
        else:
            bgcolor = 'red'
        ofile.write("\t{:s} [style=filled,fontcolor={:s},fillcolor={:s},label=\"{:s}\"];\n"\
                .format(node.nname, tcolor, bgcolor, node.label()))

    def print_dot_edge(self, nm, edge, ofile):
        #weight = 100 * edge.dweight / self.maxdweight
        ##if weight < 1:
        #    weight = 1
        weight = edge.dweight
        penwidth = edge.weight / 512
        if penwidth < 0.5:
            penwidth = 0.5
        if penwidth > 7.99:
            penwidth = 8
        attrs = "weight={},penwidth={}".format(round(weight,2), round(penwidth,2))

        if edge.flags & edge.F_RAISEIMP:
            attrs += ",arrowhead=dot"

        xpc = edge.dtype('xpc') + edge.dtype('xpc.reply')
        iokit = edge.dtype('iokit') + edge.dtype('iokit.reply')
        std = edge.dtype('std') + edge.dtype('std.reply')
        if xpc > (iokit + std):
            attrs += ',color=blue'
        elif iokit > (std + xpc):
            attrs += ',color=red'

        if edge.data('vcpy') > (edge.data('ool') + edge.data('std')):
            attrs += ',style="dotted"'
        """ # block comment
         ltype = []
         if edge.flags & (edge.F_DST_NDFLTQ | edge.F_SRC_NDFLTQ):
             ltype.append('dotted')
         if edge.flags & edge.F_APP_SRC:
             ltype.append('bold')
         if len(ltype) > 0:
             attrs += ',style="' + reduce(lambda a, v: a + ',' + v, ltype) + '"'

         if edge.data('ool') > (edge.data('std') + edge.data('vcpy')):
             attrs += ",color=blue"
         if edge.data('vcpy') > (edge.data('ool') + edge.data('std')):
             attrs += ",color=green"
        """

        ofile.write("\t{:s} [{:s}];\n".format(nm, attrs))

    def print_follow_graph(self, ofile, follow, visited = None):
        ofile.write("digraph {:s} {{\n".format(self.name))
        ofile.write("\tsplines=ortho;\n")
        if not visited:
            visited = []
        for f in follow:
            sys.stderr.write("following {}\n".format(f))
        lvl = 0
        printedges = {}
        while len(follow) > 0:
            cnodes = []
            for nm, e in self.edges.iteritems():
                nicename = e.src.nicename
                # Find all nodes to which 'follow' nodes communicate
                if e.src.nicename in follow:
                    printedges[nm] = e
                    if not e.selfedge() and not e.dst in cnodes:
                        cnodes.append(e.dst)
            visited.extend(follow)
            follow = []
            for n in cnodes:
                if not n.nicename in visited:
                    follow.append(n.nicename)
            lvl += 1
            for f in follow:
                sys.stderr.write("{}following {}\n".format('  |--'*lvl, f))
        # END: while len(follow)
        for k, v in self.nodes.iteritems():
            if v.nicename in visited:
                self.print_dot_node(ofile, v)
        for nm, edge in printedges.iteritems():
            self.print_dot_edge(nm, edge, ofile)
        ofile.write("}\n\n")

    def print_graph(self, ofile, follow):
        ofile.write("digraph {:s} {{\n".format(self.name))
        ofile.write("\tsplines=ortho;\n")
        for k, v in self.nodes.iteritems():
            self.print_dot_node(ofile, v)
        for nm, edge in self.edges.iteritems():
            self.print_dot_edge(nm, edge, ofile)
        ofile.write("}\n\n")

    def print_nodegrid(self, ofile, type='msg', dfilter=None):
        showdata = False
        dfname = dfilter
        if not dfname:
            dfname = 'all'
        if type == 'data':
            showdata = True
            ofile.write("{} Data sent between nodes.\nRow == SOURCE; Column == DESTINATION\n".format(dfname))
        else:
            ofile.write("{} Messages sent between nodes.\nRow == SOURCE; Column == DESTINATION\n".format(dfname))

        if not dfilter:
            dfilter = IPCEdge.DTYPES
        ofile.write(' ,' + ','.join(self.nodes.keys()) + '\n')
        for snm, src in self.nodes.iteritems():
            odata = []
            for dnm, dst in self.nodes.iteritems():
                enm = self.edgename(src, dst)
                e = self.edges.get(enm)
                if e and enm in src.outgoing.keys():
                    if showdata:
                        dsize = reduce(lambda accum, t: accum + e.dtype(t), dfilter, 0)
                        odata.append('{:d}'.format(dsize))
                    else:
                        nmsg = reduce(lambda accum, t: accum + e.mtype(t), dfilter, 0)
                        odata.append('{:d}'.format(nmsg))
                else:
                    odata.append('0')
            ofile.write(snm + ',' + ','.join(odata) + '\n')

    def print_datasummary(self, ofile):
        m = {}
        for type in IPCEdge.DTYPES:
            m[type] = [0, 0]
        for k, v in self.edges.iteritems():
            for t in IPCEdge.DTYPES:
                m[t][0] += v.mtype(t)
                m[t][1] += v.dtype(t)
        tdata = 0
        tmsgs = 0
        for f in IPCEdge.DFLAVORS:
            tdata += self.totals['D'+f]
            tmsgs += self.totals['n'+f]
        # we account for 0-sized messages differently
        tmsgs += self.msgs[0]['std']
        ofile.write("Nodes:{:d}\nEdges:{:d}\n".format(len(self.nodes),len(self.edges)))
        ofile.write("Total Messages,{}\nTotal Data,{}\n".format(tmsgs, tdata))
        ofile.write("Flavor,Messages,Data,\n")
        for f in IPCEdge.DFLAVORS:
            ofile.write("{:s},{:d},{:d}\n".format(f, self.totals['n'+f], self.totals['D'+f]))
        ofile.write("Style,Messages,Data,\n")
        for t in IPCEdge.DTYPES:
            ofile.write("{:s},{:d},{:d}\n".format(t, m[t][0], m[t][1]))

    def print_freqdata(self, ofile, gnuplot = False):
        flavoridx = {}
        ostr = "Message Size"
        idx = 1
        for f in IPCEdge.DFLAVORS:
            ostr += ',{fmt:s} Freq,{fmt:s} CDF,{fmt:s} Data CDF,{fmt:s} Cumulative Data'.format(fmt=f)
            idx += 1
            flavoridx[f] = idx
            idx += 3
        ostr += ',#Unique SVC pairs\n'
        ofile.write(ostr)

        lastmsg = 0
        maxmsgs = {}
        totalmsgs = {}
        Tdata = {}
        for f in IPCEdge.DFLAVORS:
            maxmsgs[f] = 0
            totalmsgs[f] = 0
            Tdata[f] = 0

        for k, v in sorted(self.msgs.iteritems()):
            lastmsg = k
            _nmsgs = {}
            for f in IPCEdge.DFLAVORS:
                _nmsgs[f] = v[f]
                if v[f] > maxmsgs[f]:
                    maxmsgs[f] = v[f]
                if k > 0:
                    Tdata[f] += v[f] * k
                    totalmsgs[f] += v[f]

            cdf = {f:0 for f in IPCEdge.DFLAVORS}
            dcdf = {f:0 for f in IPCEdge.DFLAVORS}
            if k > 0: # Only use messages with data size > 0
                for f in IPCEdge.DFLAVORS:
                    if self.totals['n'+f] > 0:
                        cdf[f] = int(100 * totalmsgs[f] / self.totals['n'+f])
                    if self.totals['D'+f] > 0:
                        dcdf[f] = int(100 * Tdata[f] / self.totals['D'+f])

            ostr = "{:d}".format(k)
            for f in IPCEdge.DFLAVORS:
                ostr += ",{:d},{:d},{:d},{:d}".format(_nmsgs[f],cdf[f],dcdf[f],Tdata[f])
            ostr += ",{:d}\n".format(len(v['enames']))
            ofile.write(ostr)

        if not gnuplot:
            return

        colors = [ 'blue', 'red', 'green', 'black', 'grey', 'yellow' ]
        idx = 0
        flavorcolor = {}
        maxdata = 0
        maxmsg = max(maxmsgs.values())
        for f in IPCEdge.DFLAVORS:
            flavorcolor[f] = colors[idx]
            if self.totals['D'+f] > maxdata:
                maxdata = self.totals['D'+f]
            idx += 1

        sys.stderr.write("Creating GNUPlot...\n")

        cdf_data_fmt = """\
        set terminal postscript eps enhanced color solid 'Courier' 12
        set border 3
        set size 1.5, 1.5
        set xtics nomirror
        set ytics nomirror
        set xrange [1:2048]
        set yrange [0:100]
        set ylabel font 'Courier,14' "Total Message CDF\\n(% of total number of messages)"
        set xlabel font 'Courier,14' "Message Size (bytes)"
        set datafile separator ","
        set ytics ( '0' 0, '10' 10, '20' 20, '30' 30, '40' 40, '50' 50, '60' 60, '70' 70, '80' 80, '90' 90, '100' 100)
        plot """
        plots = []
        for f in IPCEdge.DFLAVORS:
            plots.append("'{{csvfile:s}}' using 1:{:d} title '{:s} Messages' with lines lw 2 lt 1 lc rgb \"{:s}\"".format(flavoridx[f]+1, f, flavorcolor[f]))
        cdf_data_fmt += ', \\\n'.join(plots)

        dcdf_data_fmt = """\
        set terminal postscript eps enhanced color solid 'Courier' 12
        set border 3
        set size 1.5, 1.5
        set xtics nomirror
        set ytics nomirror
        set xrange [1:32768]
        set yrange [0:100]
        set ylabel font 'Courier,14' "Total Data CDF\\n(% of total data transmitted)"
        set xlabel font 'Courier,14' "Message Size (bytes)"
        set datafile separator ","
        set ytics ( '0' 0, '10' 10, '20' 20, '30' 30, '40' 40, '50' 50, '60' 60, '70' 70, '80' 80, '90' 90, '100' 100)
        plot """
        plots = []
        for f in IPCEdge.DFLAVORS:
            plots.append("'{{csvfile:s}}' using 1:{:d} title '{:s} Message Data' with lines lw 2 lt 1 lc rgb \"{:s}\"".format(flavoridx[f]+2, f, flavorcolor[f]))
        dcdf_data_fmt += ', \\\n'.join(plots)

        freq_data_fmt = """\
        set terminal postscript eps enhanced color solid 'Courier' 12
        set size 1.5, 1.5
        set xrange [1:32768]
        set yrange [0:9000]
        set x2range [1:32768]
        set y2range [0:{maxdata:d}]
        set xtics nomirror
        set ytics nomirror
        set y2tics
        set autoscale y2
        set grid x y2
        set ylabel font 'Courier,14' "Number of Messages"
        set y2label font 'Courier,14' "Data Transferred (bytes)"
        set xlabel font 'Courier,14' "Message Size (bytes)"
        set datafile separator ","
        set tics out
        set boxwidth 1
        set style fill solid
        plot """
        plots = []
        for f in IPCEdge.DFLAVORS:
            plots.append("'{{csvfile:s}}' using 1:{:d} axes x1y1 title '{:s} Messages' with boxes lt 1 lc rgb \"{:s}\"".format(flavoridx[f], f, flavorcolor[f]))
            plots.append("'{{csvfile:s}}' using 1:{:d} axes x2y2 title '{:s} Data' with line lt 1 lw 2 lc rgb \"{:s}\"".format(flavoridx[f]+3, f, flavorcolor[f]))
        freq_data_fmt += ', \\\n'.join(plots)
        try:
            new_file = re.sub(r'(.*)\.\w+$', r'\1_cdf.plot', ofile.name)
            sys.stderr.write("\t{:s}...\n".format(new_file))
            plotfile = open(new_file, 'w')
            plotfile.write(cdf_data_fmt.format(lastmsg=lastmsg, maxdata=maxdata, maxmsg=maxmsg, csvfile=ofile.name))
            plotfile.flush()
            plotfile.close()

            new_file = re.sub(r'(.*)\.\w+$', r'\1_dcdf.plot', ofile.name)
            sys.stderr.write("\t{:s}...\n".format(new_file))
            plotfile = open(new_file, 'w')
            plotfile.write(dcdf_data_fmt.format(lastmsg=lastmsg, maxdata=maxdata, maxmsg=maxmsg, csvfile=ofile.name))
            plotfile.flush()
            plotfile.close()

            new_file = re.sub(r'(.*)\.\w+$', r'\1_hist.plot', ofile.name)
            sys.stderr.write("\t{:s}...\n".format(new_file))
            plotfile = open(new_file, 'w')
            plotfile.write(freq_data_fmt.format(lastmsg=lastmsg, maxdata=maxdata, maxmsg=maxmsg, csvfile=ofile.name))
            plotfile.flush()
            plotfile.close()
        except:
            sys.stderr.write("\nFailed to write gnuplot script!\n");
        return


def convert_raw_tracefiles(args):
    if not args.raw or len(args.raw) < 1:
        return

    if not args.tracefile:
        args.tracefile = []

    for rawfile in args.raw:
        sys.stderr.write("Converting RAW tracefile '{:s}'...\n".format(rawfile.name))
        if args.tbfreq and len(args.tbfreq) > 0:
            args.tbfreq = " -F " + args.tbfreq
        else:
            args.tbfreq = ""
        tfile = re.sub(r'(.*)(\.\w+)*$', r'\1.ascii', rawfile.name)
        cmd = 'trace -R {:s}{:s} -o {:s}'.format(rawfile.name, args.tbfreq, tfile)
        if args.tracecodes and len(args.tracecodes) > 0:
            cmd += " -N {}".format(args.tracecodes[0])
        elif os.path.isfile('bsd/kern/trace.codes'):
            cmd += " -N bsd/kern/trace.codes"
        if args.traceargs and len(args.traceargs) > 0:
            cmd += ' '.join(args.traceargs)
        (ret, outstr) = RunCommand(cmd)
        if ret != 0:
            os.stderr.write("Couldn't convert raw trace file. ret=={:d}\nE: {:s}\n".format(ret, outstr))
            sys.exit(ret)

        if not os.path.isfile(tfile):
            sys.stderr.write("Failure to convert raw trace file '{:s}'\ncmd: '{:s}'\n".format(args.raw[0].name, cmd))
            sys.exit(1)
        args.tracefile.append(open(tfile, 'r'))
    # END: for rawfile in args.raw


def parse_tracefile_line(line, exclude, include, exflags, incflags, active_proc, graph, base=16):
    val = line.split()
    if len(val) < 10:
        return
    if val[2] == "proc_exec" or val[2] == "TRACE_DATA_EXEC":
        pid = int(val[3], base)
        active_proc[pid] = val[9]
    if val[2] == "MACH_IPC_kmsg_info":
        sendpid = int(val[3], base)
        destpid = int(val[4], base)
        if sendpid == 0:
            src = "kernel_task"
        elif sendpid in active_proc:
            src = active_proc[sendpid]
        else:
            src = "{:d}".format(sendpid)
        if destpid == 0:
            dst = "kernel_task"
        elif destpid in active_proc:
            dst = active_proc[destpid]
        else:
            dst = "{:d}".format(destpid)
        if exclude and len(exclude) > 0 and (src in exclude or dst in exclude):
            return
        if include and len(include) > 0 and (not (src in include or dst in include)):
            return
        flags = int(val[6], 16)
        if exflags or incflags:
            if exflags and (flags & int(exflags[0], 0)):
                return
            if incflags and (flags & int(incflags[0], 0)) != int(incflags[0], 0):
                return
        # create a graph edge
        if (flags & IPCEdge.F_TRACED):
            graph.addmsg(src, sendpid, dst, destpid, val[5], val[6], float(val[0]))
    # END: MACH_IPC_kmsg_info

#
# Main
#
def main(argv=sys.argv):
    """ Main program entry point.

        Trace file output lines look like this:
        {abstime} {delta} MACH_IPC_kmsg_info {src_pid} {dst_pid} {msg_len} {flags} {threadid} {cpu} {proc_name}
        e.g.
        4621921.2  33.8(0.0)  MACH_IPC_kmsg_info  ac  9d  c  230002  b2e  1  MobileMail

        Or like this:
        {abstime} {delta} proc_exec {pid} 0 0 0 {threadid} {cpu} {proc_name}
        e.g.
        4292212.3  511.2  proc_exec c8  0  0  0  b44  0  voiced
    """
    global g_verbose

    parser = argparse.ArgumentParser(description='Parse an XNU Mach IPC kmsg ktrace file')

    # output a DOT formatted graph file
    parser.add_argument('--printgraph', '-g', dest='graph', default=None, type=argparse.FileType('w'), help='Output a DOT connectivity graph from the trace data')
    parser.add_argument('--graphname', dest='name', default='ipcgraph', help='A name for the DOT graph output')
    parser.add_argument('--graphfollow', dest='follow', nargs='+', metavar='NAME', help='Graph only the transitive closure of services / processes which communicate with the given service(s)')

    # output a CDF of message data
    parser.add_argument('--printfreq', '-f', dest='freq', default=None, type=argparse.FileType('w'), help='Output a frequency distribution of message data (in CSV format)')
    parser.add_argument('--gnuplot', dest='gnuplot', action='store_true', help='Write out a gnuplot file along with the frequency distribution data')

    # output a simple summary of message data
    parser.add_argument('--printsummary', '-s', dest='summary', default=None, type=argparse.FileType('w'), help='Output a summary of all messages in the trace data')

    # Output a CSV grid of node data/messages
    parser.add_argument('--printnodegrid', '-n', dest='nodegrid', default=None, type=argparse.FileType('w'), help='Output a CSV grid of all messages/data sent between nodes (defaults to # messages)')
    parser.add_argument('--ngridtype', dest='ngridtype', default=None, choices=['msgs', 'data'], help='Used with the --printnodegrid argument, this option control whether the grid will be # of messages sent between nodes, or amount of data sent between nodes')
    parser.add_argument('--ngridfilter', dest='ngridfilter', default=None, nargs='+', choices=IPCEdge.DTYPES, help='Used with the --printnodegrid argument, this option controls the type of messages or data counted')

    parser.add_argument('--raw', '-R', dest='raw', nargs='+', type=argparse.FileType('r'), metavar='tracefile', help='Process a raw tracefile using the "trace" utility on the host. This requires an ssh connection to the device, or a manual specification of the tbfrequency.')
    parser.add_argument('--tbfreq', '-T', dest='tbfreq', default=None, help='The value of sysctl hw.tbfrequency run on the device')
    parser.add_argument('--device', '-D', dest='device', nargs=1, metavar='DEV', help='The name of the iOS device reachable via "ssh DEV"')
    parser.add_argument('--tracecodes', '-N', dest='tracecodes', nargs=1, metavar='TRACE.CODES', help='Path to a custom trace.codes file. By default, the script will look for bsd/kern/trace.codes from the current directory)')
    parser.add_argument('--traceargs', dest='traceargs', nargs='+', metavar='TRACE_OPT', help='Extra options to the "trace" program run on the host')

    parser.add_argument('--psfile', dest='psfile', nargs='+', type=argparse.FileType('r'), help='Process list file output by ios_trace_ipc.sh')

    parser.add_argument('--exclude', dest='exclude', metavar='NAME', nargs='+', help='List of services to exclude from processing. Any messages sent to or originating from these services will be discarded.')
    parser.add_argument('--include', dest='include', metavar='NAME', nargs='+', help='List of services to include in processing. Only messages sent to or originating from these services will be processed.')
    parser.add_argument('--exflags', dest='exflags', metavar='0xFLAGS', nargs=1, help='Messages with any of these flags bits set will be discarded')
    parser.add_argument('--incflags', dest='incflags', metavar='0xFLAGS', nargs=1, type=int, help='Only messages with all of these flags bits set will be processed')

    parser.add_argument('--verbose', '-v', dest='verbose', action='count', help='be verbose (can be used multiple times)')
    parser.add_argument('tracefile', nargs='*', type=argparse.FileType('r'), help='Input trace file')

    args = parser.parse_args()

    g_verbose = args.verbose

    if not args.graph and not args.freq and not args.summary and not args.nodegrid:
        sys.stderr.write("Please select at least one output format: [-gfsn] {file}\n")
        sys.exit(1)

    convert_raw_tracefiles(args)

    graph = IPCGraph(args.name, args.tbfreq)

    nfiles = len(args.tracefile)
    idx = 0
    while idx < nfiles:
        active_proc = {}
        # Parse a ps output file (generated by ios_trace_ipc.sh)
        # This pre-fills the active_proc list
        if args.psfile and len(args.psfile) > idx:
            sys.stderr.write("Parsing {:s}...\n".format(args.psfile[idx].name))
            for line in args.psfile[idx]:
                if line.strip() == '':
                    continue
                parse_tracefile_line(line.strip(), None, None, None, None, active_proc, graph, 10)
        # END: for line in psfile

        sys.stderr.write("Parsing {:s}...\n".format(args.tracefile[idx].name))
        for line in args.tracefile[idx]:
            if line.strip() == '':
                continue
            parse_tracefile_line(line.strip(), args.exclude, args.include, args.exflags, args.incflags, active_proc, graph)
        # END: for line in tracefile
        idx += 1
    # END: foreach tracefile/psfile

    if args.graph:
        if args.follow and len(args.follow) > 0:
            sys.stderr.write("Writing follow-graph to {:s}...\n".format(args.graph.name))
            graph.print_follow_graph(args.graph, args.follow)
        else:
            sys.stderr.write("Writing graph output to {:s}...\n".format(args.graph.name))
            graph.print_graph(args.graph, args.follow)
    if args.freq:
        sys.stderr.write("Writing CDF data to {:s}...\n".format(args.freq.name))
        graph.print_freqdata(args.freq, args.gnuplot)
    if args.summary:
        sys.stderr.write("Writing summary data to {:s}...\n".format(args.summary.name))
        graph.print_datasummary(args.summary)
    if args.nodegrid:
        nm = args.ngridtype
        sys.stderr.write("Writing node grid data to {:s}...]\n".format(args.nodegrid.name))
        graph.print_nodegrid(args.nodegrid, args.ngridtype, args.ngridfilter)

if __name__ == '__main__':
    sys.exit(main())
