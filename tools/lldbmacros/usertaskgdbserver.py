from xnu import *
import logging
_usertaskdebugging_availabe = False
try:
    from usertaskdebugging import userprocess
    from usertaskdebugging import gdbserver
    _usertaskdebugging_availabe = True
except ImportError:
    pass

def setupLogging(debug_level):
    log_level = debug_level
    log_filename = "/tmp/kdbserver.log"
    logging.basicConfig(level=log_level,
                      format='%(asctime)s %(module)s %(levelname)s: %(message)s',
                      datefmt='%Y-%m-%d %H:%M:%S')


@lldb_command('beginusertaskdebugging', 'DW')
def DoUserTaskDebuggingServer(cmd_args = [], cmd_options ={}):
    """ starts a gdb protocol server that is backed by <task_t> in kernel debugging session.
        Usage: (lldb) beginusertaskdebugging <task_t>
        options: -D for debug level logging
                 -W for warning level logging. 
        default is error level logging
    """
    if not _usertaskdebugging_availabe:
        print "You do not have the usertask debugging files available. "
        return
