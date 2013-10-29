# A basic Plugin that creates performance reports from zprint output
import urllib, urllib2

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
    submitvars['type']="text"
    submitvars['log']=result_output

    submiturl = "http://speedtracer.apple.com/trace/analyze?format=xml"
    encoded_data = urllib.urlencode(submitvars)
    request = urllib2.Request(submiturl, encoded_data, {"Accept":"application/xml"})
    response = urllib2.urlopen(request)

    status = response.info()['status']
    if status == 201 or status == '201':
        outstr += "CrashTracer data found at " + response.info()['location']
        newurl = response.info()['location']
        import webbrowser
        webbrowser.open(newurl)
        status = True
    else:
        outstr += "unknown response from server \n" + str(response.info())     
        status = False
    
    return (status, outstr, further_cmds)

def plugin_cleanup():
    """ A cleanup call from xnu which is a signal to wrap up any open file descriptors etc. """
    return None


