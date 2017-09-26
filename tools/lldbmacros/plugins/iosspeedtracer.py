# Feed user stacks to ios/speedtracer

def plugin_init(kernel_target, config, lldb_obj, isConnected):
    """ initialize the common data as required by plugin """
    return None

def plugin_execute(command_name, result_output):
    """ The xnu framework will call this function with output of a command. 
        The options for returning are as follows
        returns:  (status, outstr, further_cmds)
           status: Boolean - specifying whether plugin execution succeeded(True) or failed. If failed then xnu will stop doing any further work with this command.
           outstr: str - string output for user to be printed at the prompt
           further_cmds: [] of str - this holds set of commands to execute at the lldb prompt. Empty array if nothing is required.
    """
    import subprocess,os
    status = True
    outstr = ''
    further_cmds = []

    if command_name != 'showtaskuserstacks' :
        status = False
    else:
        ios_process = subprocess.Popen([os.path.join(os.path.dirname(os.path.abspath(__file__)), "iosspeedtracer.sh")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        outstr += ios_process.communicate(input=result_output)[0]

    return (status, outstr, further_cmds)

def plugin_cleanup():
    """ A cleanup call from xnu which is a signal to wrap up any open file descriptors etc. """
    return None


