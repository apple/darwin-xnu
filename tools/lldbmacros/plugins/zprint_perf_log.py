# A basic Plugin that creates performance reports from zprint output
kern_version = None

def plugin_init(kernel_target, config, lldb_obj, isConnected):
    """ initialize the common data as required by plugin """
    global kern_version
    kern_version = str(kernel_target.version)

def plugin_execute(command_name, result_output):
    """ The xnu framework will call this function with output of a command. 
        The options for returning are as follows
        returns:  (status, outstr, further_cmds)
           status: Boolean - specifying whether plugin execution succeeded(True) or failed. If failed then xnu will stop doing any further work with this command.
           outstr: str - string output for user to be printed at the prompt
           further_cmds: [] of str - this holds set of commands to execute at the lldb prompt. Empty array if nothing is required.
    """
    status = True
    outstr = 'Nothing to be done here'
    further_cmds = []
    further_cmds.append("memstats -- --plugin zprint_perf_log ")
    
    if command_name != 'zprint' : 
        status = False
    else:
        num_zones = len(result_output.split("\n")) -1
        outstr += "Num of zones analyzed =" + str(num_zones) + "\n"
    return (status, outstr, further_cmds)

def plugin_cleanup():
    """ A cleanup call from xnu which is a signal to wrap up any open file descriptors etc. """
    return None
