from xnu import *
from utils import *
import ctypes

MBSHIFT = 20
MSIZE = 256
MCLBYTES = 2048
MBIGCLBYTES = 4096
M16KCLBYTES = 16384

MB_SCVALID = 4

MB_INUSE = 1
MB_COMP_INUSE = 2 

SLF_MAPPED = 0x0001
SLF_PARTIAL = 0x0002
SLF_DETACHED = 0x0004

INTP = ctypes.POINTER(ctypes.c_int)

kgm_manual_pkt_ppc    = 0x549C
kgm_manual_pkt_i386   = 0x249C
kgm_manual_pkt_x86_64 = 0xFFFFFF8000002930
kgm_manual_pkt_arm    = 0xFFFF13A0
kgm_kdp_pkt_data_len   = 128

MCF_NOCPUCACHE = 0x10
