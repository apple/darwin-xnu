import getopt
import os
import sys
import re

class ArgumentError(Exception):
    """ Exception class for raising errors in command arguments. The lldb_command framework will catch this
        class of exceptions and print suitable error message to user.
    """
    def __init__(self, msg):
        self.error_message = msg
    def __str__(self):
        return str(self.error_message)


class RedirectStdStreams(object):
    def __init__(self, stdout=None, stderr=None):
        self._stdout = stdout or sys.stdout
        self._stderr = stderr or sys.stderr

    def __enter__(self):
        self.old_stdout, self.old_stderr = sys.stdout, sys.stderr
        self.old_stdout.flush(); self.old_stderr.flush()
        sys.stdout, sys.stderr = self._stdout, self._stderr

    def __exit__(self, exc_type, exc_value, traceback):
        self._stdout.flush(); self._stderr.flush()
        sys.stdout = self.old_stdout
        sys.stderr = self.old_stderr

class IndentScope(object):
    def __init__(self, O):
        self._O = O

    def __enter__(self):
        self._O._indent += '    '

    def __exit__(self, exc_type, exc_value, traceback):
        self._O._indent = self._O._indent[:-4]

class HeaderScope(object):
    def __init__(self, O, hdr, indent = False):
        self._O = O
        self._header = hdr
        self._indent = indent

    def __enter__(self):
        self._oldHeader = self._O._header
        self._oldLastHeader = self._O._lastHeader
        self._O._header = self._header
        self._O._lastHeader = None
        if self._indent:
            self._O._indent += '    '

    def __exit__(self, exc_type, exc_value, traceback):
        self._O._header = self._oldHeader
        self._O._lastHeader = self._oldLastHeader
        if self._indent:
            self._O._indent = self._O._indent[:-4]

class VT(object):
    Black        = "\033[38;5;0m"
    DarkRed      = "\033[38;5;1m"
    DarkGreen    = "\033[38;5;2m"
    Brown        = "\033[38;5;3m"
    DarkBlue     = "\033[38;5;4m"
    DarkMagenta  = "\033[38;5;5m"
    DarkCyan     = "\033[38;5;6m"
    Grey         = "\033[38;5;7m"

    DarkGrey     = "\033[38;5;8m"
    Red          = "\033[38;5;9m"
    Green        = "\033[38;5;10m"
    Yellow       = "\033[38;5;11m"
    Blue         = "\033[38;5;12m"
    Magenta      = "\033[38;5;13m"
    Cyan         = "\033[38;5;14m"
    White        = "\033[38;5;15m"

    Default      = "\033[39m"

    Bold         = "\033[1m"
    EndBold      = "\033[22m"

    Oblique      = "\033[3m"
    EndOblique   = "\033[23m"

    Underline    = "\033[4m"
    EndUnderline = "\033[24m"

    Reset        = "\033[0m"

class NOVT(object):
    def __getattribute__(self, *args):
        return ""

class CommandOutput(object):
    """
    An output handler for all commands. Use Output.print to direct all output of macro via the handler.
    These arguments are passed after a "--". eg
    (lldb) zprint -- -o /tmp/zprint.out.txt

    Currently this provide capabilities
    -h show help
    -o path/to/filename
       The output of this command execution will be saved to file. Parser information or errors will
       not be sent to file though. eg /tmp/output.txt
    -s filter_string
       the "filter_string" param is parsed to python regex expression and each line of output
       will be printed/saved only if it matches the expression.
       The command header will not be filtered in any case.
    -p <plugin_name>
       Send the output of the command to plugin.
    -v ...
       Up verbosity
    -c <always|never|auto>
       configure color
    """
    def __init__(self, cmd_name, CommandResult=None, fhandle=None):
        """ Create a new instance to handle command output.
        params:
                CommandResult : SBCommandReturnObject result param from lldb's command invocation.
        """
        self.fname=None
        self.fhandle=fhandle
        self.FILTER=False
        self.pluginRequired = False
        self.pluginName = None
        self.cmd_name = cmd_name
        self.resultObj = CommandResult
        self.verbose_level = 0
        self.target_cmd_args = []
        self.target_cmd_options = {}
        self.color = None
        self.isatty = os.isatty(sys.__stdout__.fileno())
        self._indent = ''
        self._buffer = ''

        self._header = None
        self._lastHeader = None
        self._line = 0

    def _write(self, s):
        if self.fhandle != None:
            self.fhandle.write(self._indent + s + "\n")
        else:
            self.resultObj.AppendMessage(self._indent + s)
        self._line += 1

    def _doColor(self):
        if self.color is True:
            return True;
        return self.color is None and self.isatty

    def _needsHeader(self):
        if self._header is None:
            return False
        if self._lastHeader is None:
            return True
        if not self.isatty:
            return False
        return self._line - self._lastHeader > 40

    def indent(self):
        return IndentScope(self)

    def table(self, header, indent = False):
        return HeaderScope(self, header, indent)

    def format(self, s, *args, **kwargs):
        if self._doColor():
            kwargs['VT'] = VT
        else:
            kwargs['VT'] = NOVT()

        return s.format(*args, **kwargs)

    def error(self, s, *args, **kwargs):
        print self.format("{cmd.cmd_name}: {VT.Red}"+s+"{VT.Default}", cmd=self, *args, **kwargs)

    def write(self, s):
        """ Handler for all commands output. By default just print to stdout """

        s = self._buffer + s

        while s.find('\n') != -1:
            l, s = s.split("\n", 1)
            if self.FILTER:
                if not self.reg.search(l):
                    continue
                if self._doColor():
                    l = self.reg.sub(VT.Underline + r"\g<0>" + VT.EndUnderline, l);

            if len(l) and self._needsHeader():
                for hdr in self._header.split("\n"):
                    self._write(self.format("{VT.Bold}{:s}{VT.EndBold}", hdr))
                self._lastHeader = self._line

            self._write(l)

        self._buffer = s

    def flush(self):
        if self.fhandle != None:
            self.fhandle.flush()

    def __del__(self):
        """ closes any open files. report on any errors """
        if self.fhandle != None and self.fname != None:
            self.fhandle.close()

    def setOptions(self, cmdargs, cmdoptions =''):
        """ parse the arguments passed to the command
            param :
                cmdargs => [] of <str> (typically args.split())
                cmdoptions : str - string of command level options.
                             These should be CAPITAL LETTER options only.
        """
        opts=()
        args = cmdargs
        cmdoptions = cmdoptions.upper()
        try:
            opts,args = getopt.gnu_getopt(args,'hvo:s:p:c:'+ cmdoptions,[])
            self.target_cmd_args = args
        except getopt.GetoptError,err:
            raise ArgumentError(str(err))
        #continue with processing
        for o,a in opts :
            if o == "-h":
                # This is misuse of exception but 'self' has no info on doc string.
                # The caller may handle exception and display appropriate info
                raise ArgumentError("HELP")
            if o == "-o" and len(a) > 0:
                self.fname=os.path.normpath(os.path.expanduser(a.strip()))
                self.fhandle=open(self.fname,"w")
                print "saving results in file ",str(a)
                self.fhandle.write("(lldb)%s %s \n" % (self.cmd_name, " ".join(cmdargs)))
                self.isatty = os.isatty(self.fhandle.fileno())
            elif o == "-s" and len(a) > 0:
                self.reg = re.compile(a.strip(),re.MULTILINE|re.DOTALL)
                self.FILTER=True
                print "showing results for regex:",a.strip()
            elif o == "-p" and len(a) > 0:
                self.pluginRequired = True
                self.pluginName = a.strip()
                #print "passing output to " + a.strip()
            elif o == "-v":
                self.verbose_level += 1
            elif o == "-c":
                if a in ["always", '1']:
                    self.color = True
                elif a in ["never", '0']:
                    self.color = False
                else:
                    self.color = None
            else:
                o = o.strip()
                self.target_cmd_options[o] = a


