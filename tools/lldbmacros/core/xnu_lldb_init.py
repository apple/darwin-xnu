import os

def GetSettingsValues(debugger, setting_variable_name):
    """ Queries the lldb internal settings
        params:
            debugger : lldb.SBDebugger instance 
            setting_variable_name: str - string name of the setting(eg prompt)
        returns:
            [] : Array of strings. Empty array if setting is not found/set
    """
    retval = []
    settings_val_list = debugger.GetInternalVariableValue(setting_variable_name, debugger.GetInstanceName())
    for s in settings_val_list:
        retval.append(str(s))
    return retval

def __lldb_init_module(debugger, internal_dict):
    debug_session_enabled = False
    if "DEBUG_XNU_LLDBMACROS" in os.environ and len(os.environ['DEBUG_XNU_LLDBMACROS']) > 0:
        debug_session_enabled = True
    prev_os_plugin = "".join(GetSettingsValues(debugger, 'target.process.python-os-plugin-path'))
    print "Loading kernel debugging from %s" % __file__
    print "LLDB version %s" % debugger.GetVersionString()
    self_path = str(__file__)
    base_dir_name = self_path[:self_path.rfind("/")]
    core_os_plugin = base_dir_name + "/lldbmacros/core/operating_system.py"
    osplugin_cmd = "settings set target.process.python-os-plugin-path \"%s\"" % core_os_plugin
    intel_whitelist = ['hndl_allintrs', 'hndl_alltraps', 'trap_from_kernel', 'hndl_double_fault', 'hndl_machine_check']
    arm_whitelist = ['_fleh_prefabt', '_ExceptionVectorsBase', '_ExceptionVectorsTable', '_fleh_undef', '_fleh_dataabt', '_fleh_irq', '_fleh_decirq', '_fleh_fiq_generic', '_fleh_dec']
    whitelist_trap_cmd = "settings set target.trap-handler-names %s %s" % (' '.join(intel_whitelist), ' '.join(arm_whitelist))
    xnu_debug_path = base_dir_name + "/lldbmacros/xnu.py"
    xnu_load_cmd = "command script import \"%s\"" % xnu_debug_path
    if debug_session_enabled :
        if len(prev_os_plugin) > 0:
            print "\nDEBUG_XNU_LLDBMACROS is set. Skipping the setting of OS plugin from dSYM.\nYou can manually set the OS plugin by running\n" + osplugin_cmd
        else:
            print osplugin_cmd
            debugger.HandleCommand(osplugin_cmd)
        print "\nDEBUG_XNU_LLDBMACROS is set. Skipping the load of xnu debug framework.\nYou can manually load the framework by running\n" + xnu_load_cmd
    else:
        print osplugin_cmd
        debugger.HandleCommand(osplugin_cmd)
        print whitelist_trap_cmd
        debugger.HandleCommand(whitelist_trap_cmd)
        print xnu_load_cmd
        debugger.HandleCommand(xnu_load_cmd)
    print "\n"

