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

class CommandOutput(object):
    """
    An output handler for all commands. Use Output.print to direct all output of macro via the handler. 
    These arguments are passed after a "--". eg
    (lldb) zprint -- -o /tmp/zprint.out.txt
    
    Currently this provide capabilities 
    -o path/to/filename
       The output of this command execution will be saved to file. Parser information or errors will 
       not be sent to file though. eg /tmp/output.txt
    -s filter_string
       the "filter_string" param is parsed to python regex expression and each line of output 
       will be printed/saved only if it matches the expression. 
       The command header will not be filtered in any case.
    """
    def __init__(self, CommandResult):
        """ Create a new instance to handle command output.
        params:
                CommandResult : SBCommandReturnObject result param from lldb's command invocation. 
        """
        self.fname=None
        self.fhandle=None
        self.FILTER=False
        self.pluginRequired = False
        self.pluginName = None
        self.resultObj = CommandResult
        self.immediateOutput = False
        self.verbose_level = 0
        self.target_cmd_args = []
        self.target_cmd_options = {}

    def write(self, s):
        """ Handler for all commands output. By default just print to stdout """
        if self.FILTER and not self.reg.search(s): return
        if self.FILTER : s+="\n"
        if self.fhandle != None: self.fhandle.write(s)
        else:
            if self.immediateOutput:
                sys.__stdout__.write(s)
            else:
                res_str = s
                if s.endswith("\n"):
                    res_str = s[:-1]
                if self.resultObj and len(res_str) > 0: self.resultObj.AppendMessage(res_str)

    def flush(self):
        if self.fhandle != None:
            self.fhandle.flush()
        
    def __del__(self):
        """ closes any open files. report on any errors """
        if self.fhandle != None :
            self.fhandle.close()
    
    def setOptions(self,cmdargs, cmdoptions =''):
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
            opts,args = getopt.gnu_getopt(args,'hvo:s:p:'+ cmdoptions,[])
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
                self.fhandle.write("(lldb)%s \n" % " ".join(cmdargs))
            elif o == "-s" and len(a) > 0:
                self.reg = re.compile(a.strip(),re.MULTILINE|re.DOTALL)
                self.FILTER=True
                print "showing results for regex:",a.strip()
            elif o == "-p" and len(a) > 0:
                self.pluginRequired = True
                self.pluginName = a.strip()
                #print "passing output to " + a.strip()
            elif o == "-v" :
                self.verbose_level += 1
            else:
                o = o.strip()
                self.target_cmd_options[o] = a

            
        

