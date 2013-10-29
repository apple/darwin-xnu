""" 
A basic caching module for xnu debug macros to use.
It is recommended to use [Get|Save][Static|Dynamic]CacheData() apis for 
your caching needs. These APIs will handle the case of clearing caches when 
a debugger continues and stops or hit a breakpoint. 

Use Static caches for data that will not change if the program is run and stopped again. e.g. typedata, version numbers etc.
An example invocation could be like
def getDSYMPathForUUID(uuid):
    # Get the data from cache
    cached_data = caching.GetStaticCacheData('dsym.for.uuid', {})
    
    if uuid in cached_data:
        return cached_data[uuid]
    else:
        path = #get info for uuid
        cached_data[uuid] = path

    # save the cached_data object to cache.
    caching.SaveStaticCacheData('dsym.for.uuid', cached_data)
    
    return cached_data[uuid]

And use Dynamic caches for things like thread data, zones information etc. 
These will automatically be dropped when debugger continues the target 
An example use of Dynamic cache could be as follows

def GetExecutablePathForPid(pid):
    # Get the data from cache
    cached_data = caching.GetDynamicCacheData('exec_for_path', {})
    
    if pid in cached_data:
        return cached_data[pid]
    else:
        exec_path = "/path/to/exec"  #get exec path for pid
        cached_data[pid] = path

    # save the cached_data object to cache.
    caching.SaveDynamicCacheData('exec_for_path', cached_data)
    
    return cached_data[pid]

"""

#Private Routines and objects

from configuration import *

import sys

"""
The format for the saved data dictionaries is 
{
    'key' : (valueobj, versno),
    ...
}

The versno is an int defining the version of obj. In case of version mismatch it will set valueobj to default upon access.

"""
_static_data = {}
_dynamic_data = {}



def _GetDebuggerSessionID():
    """ A default callable function that _GetCurrentSessionID uses to 
        identify a stopped session.
    """
    return 0

def _GetCurrentSessionID():
    """ Get the current session id. This will update whenever
        system is continued or if there is new information that would
        cause the dynamic cache to be deleted.

        returns: int - session id number.
    """
    session_id = _GetDebuggerSessionID()
    return session_id;


#Public APIs 

def GetSizeOfCache():
    """ Returns number of bytes held in cache.
        returns:
            int - size of cache including static and dynamic
    """
    global _static_data, _dynamic_data
    return sys.getsizeof(_static_data) + sys.getsizeof(_dynamic_data)


def GetStaticCacheData(key, default_value = None):
    """ Get cached object based on key from the cache of static information. 
        params:
            key: str - a unique string identifying your data.
            default_value : obj - an object that should be returned if key is not found.
        returns:
            default_value - if the static cache does not have your data.
            obj  - The data obj saved with SaveStaticCacheData()
    """
    global _static_data
    key = str(key)
    if key in _static_data:
        return _static_data[key][0]
    return default_value

def SaveStaticCacheData(key, value):
    """ Save data into the cache identified by key.
        It will overwrite any data that was previously associated with key
        params:
            key  : str - a unique string identifying your data
            value: obj - any object that is to be cached.
        returns:
            Nothing
    """
    global _static_data

    if not config['CacheStaticData']:
        return
    
    key = str(key)
    _static_data[key] = (value, _GetCurrentSessionID())
    return


def GetDynamicCacheData(key, default_value=None):
    """ Get cached object based on key from the cache of dynamic information.
        params:
            key: str - a unique string identifying cached object
            default_value : obj - an object that should be returned if key is not found.
        returns:
            default_value - if dynamic cache does not have data or if the saved version mismatches with current session id.
            obj  - The data obj saved with SaveDynamicCacheData()
    """
    global _dynamic_data
    key = str(key)
    if key in _dynamic_data:
        if _GetCurrentSessionID() == _dynamic_data[key][1]:
            return _dynamic_data[key][0]
        else:
            del _dynamic_data[key]

    return default_value


def SaveDynamicCacheData(key, value):
    """ Save data into the cache identified by key.
        It will overwrite any data that was previously associated with key
        params:
            key  : str - a unique string identifying your data
            value: obj - any object that is to be cached.
        returns:
            Nothing
    """
    global _dynamic_data

    if not config['CacheDynamicData']:
        return

    key = str(key)
    _dynamic_data[key] = (value, _GetCurrentSessionID())

    return
