import json, urllib, urllib2
from urllib2 import Request, urlopen, HTTPError

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
    outstr = ''
    further_cmds = []
    submitvars = {}
    submitvars['log_content']=result_output

    submiturl = "https://speedtracer.apple.com/api/v2/trace"
    encoded_data = urllib.urlencode(submitvars)
    request = urllib2.Request(submiturl, encoded_data)
    request.add_header("Accept", "application/json")
    request.add_header("X-ST-GroupName", "core-os")
    try:
        response = urllib2.urlopen(request)
        response_str = response.read()
        j = json.loads(response_str)
        outstr += "\nspeedtracer output:\n\n"
        stacks = j.get("symbolicated_log")
        if stacks:
            outstr += stacks
        else:
            outstr += json.dumps(j)
    except HTTPError as e:
        outstr += "speedtracer replied with\n" + str(e.info())     
        status = False
 
    return (status, outstr, further_cmds)

def plugin_cleanup():
    """ A cleanup call from xnu which is a signal to wrap up any open file descriptors etc. """
    return None


