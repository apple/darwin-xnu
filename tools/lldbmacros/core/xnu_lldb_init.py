import os
import re

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

def GetSymbolsFilePathFromModule(m):
    """ Get a file path from a module.
        params: m - lldb.target.module
        returns:
            str : path to first file based symbol. Note this might be dir path inside sources.
    """
    for s in m.symbols:
        if s.type == 8:
            return os.path.dirname(str(s.name))
    return ""

def GetSourcePathSettings(binary_path, symbols_path):
    """ Parse the binary path and symbols_path to find if source-map setting is applicable
        params:
            binary_path: str path of the kernel module
            symbols_path: str path of the symbols stored in binary. Use
        returns:
            str : string command to set the source-map setting.
    """
    retval = ""
    train_re = re.compile(r"dsyms/([a-zA-Z]+)/")
    _t_arr = train_re.findall(binary_path)
    train = ''
    if _t_arr:
        train = _t_arr[0]
    if not train:
        return retval
    new_path = "~rc/Software/{}/Projects/".format(train)
    new_path = os.path.expanduser(new_path)
    new_path = os.path.normpath(new_path)
    common_path_re = re.compile("(^.*?Sources/)(xnu.*?)/.*$")
    _t_arr = common_path_re.findall(symbols_path)
    srcpath = ""
    projpath = "xnu"
    if _t_arr:
        srcpath = "".join(_t_arr[0])
        projpath = _t_arr[0][-1]
    else:
        return retval

    new_path = new_path + os.path.sep +  projpath
    cmd = "settings append target.source-map {} {}"
    retval =  cmd.format(srcpath, new_path)
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
    disable_optimization_warnings_cmd = "settings set target.process.optimization-warnings false"

    source_map_cmd = ""
    try:
        source_map_cmd = GetSourcePathSettings(base_dir_name, GetSymbolsFilePathFromModule(debugger.GetTargetAtIndex(0).modules[0]) )
    except Exception as e:
        pass
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
        print disable_optimization_warnings_cmd
        debugger.HandleCommand(disable_optimization_warnings_cmd)
        if source_map_cmd:
            print source_map_cmd
            debugger.HandleCommand(source_map_cmd)

        load_kexts = True
        if "XNU_LLDBMACROS_NOBUILTINKEXTS" in os.environ and len(os.environ['XNU_LLDBMACROS_NOBUILTINKEXTS']) > 0:
            load_kexts = False
        builtinkexts_path = os.path.join(os.path.dirname(self_path), "lldbmacros", "builtinkexts")
        if os.access(builtinkexts_path, os.F_OK):
            kexts = os.listdir(builtinkexts_path)
            if len(kexts) > 0:
                print "\nBuiltin kexts: %s\n" % kexts
                if load_kexts == False:
                    print "XNU_LLDBMACROS_NOBUILTINKEXTS is set, not loading:\n"
                for kextdir in kexts:
                    script = os.path.join(builtinkexts_path, kextdir, kextdir.split('.')[-1] + ".py")
                    import_kext_cmd = "command script import \"%s\"" % script
                    print "%s" % import_kext_cmd
                    if load_kexts:
                        debugger.HandleCommand(import_kext_cmd)

    print "\n"

