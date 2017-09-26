
""" Module to abstract lazy evaluation of lldb.SBTarget
    for kernel
"""

import lldb

class LazyTarget(object):
    """ A common object that lazy-evaluates and caches the lldb.SBTarget
        and lldb.SBProcess for the current interactive debugging session.
    """
    _debugger = None # This holds an lldb.SBDebugger object for debugger state
    _target   = None # This holds an lldb.SBTarget object for symbol lookup
    _process  = None # This holds an lldb.SBProcess object for reading memory

    @staticmethod
    def Initialize(debugger):
        """ Initialize the LazyTarget with an SBDebugger.
        """
        LazyTarget._debugger = debugger
        LazyTarget._target = None
        LazyTarget._process = None

    @staticmethod
    def GetTarget():
        """ Get an SBTarget for the most recently selected
            target, or throw an exception.
        """
        if not LazyTarget._target is None:
            return LazyTarget._target

        target = LazyTarget._debugger.GetSelectedTarget()
        if target is None:
            raise AttributeError('No target selected')

        if not target.IsValid():
            raise AttributeError('Target is not valid')

        LazyTarget._target = target
        return target

    @staticmethod
    def GetProcess():
        """ Get an SBProcess for the most recently selected
            target, or throw an exception.
        """

        target = LazyTarget.GetTarget()
        process = target.process

        if process is None:
            raise AttributeError('Target does not have a process')

        if not process.IsValid():
            raise AttributeError('Process is not valid')

        return process
