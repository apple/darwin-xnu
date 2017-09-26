# global configs to be included by everybody. The recommended way is 
# from core.configuration import *
# verbosity levels
(vSILENT, vHUMAN, vSCRIPT, vDETAIL) = (0, 1, 2, 3)

config = {'debug': False, 'verbosity': vHUMAN, 'showTypeSummary': False, "CacheStaticData":True, "CacheDynamicData": True}
# Note: The above configuration dictionary holds the default values.
# 'debug' when True enables debug print messages in whole of xnu lldbmacros framework
# 'CacheStaticData' when True caches static data. Types, uuids etc.
# 'CacheDymanicData' when True caches dynamic data which will get cleared upon continuing, single stepping or detaching.
