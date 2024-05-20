from variable_const import *
from capstone import *
import logging
t_logger = None
ROOTFS = "D:/Python/Environment/Python_3.87/install_pack_by_myself/qiling/examples/rootfs/x8664_windows"
pack_path = ""
unpack_path = "xxx.exe"
debug_level = 1
Target_Mode = 0
capstone_Arch = CS_ARCH_X86
capstone_Mode = CS_MODE_64
unicornPE = 0
src_level_trace = 0
unpacking_mode = 1
tag_hooking_dll_loader = 0

def debug(pt):
    global t_logger
    t_logger.debug(pt)

def set_pack_path(path):
    import shutil,os
    global pack_path,ROOTFS
    exe_name = os.path.basename(path)
    pack_path = rf"{ROOTFS}/bin/{exe_name}"
    shutil.copyfile(path, pack_path)
    

def set_ROOTFS(path="D:/Python/Environment/Python_3.87/install_pack_by_myself/qiling/examples/rootfs/x8664_windows"):
    global ROOTFS
    ROOTFS = path

def set_debug_level(debug = 1):
    global debug_level,t_logger
    debug_level = debug
    
    # DEBUG < INFO < WARNING < ERROR <  CRITICAL
    t_logger = logging.getLogger('tlsn')
    if debug_level >= 1:
        t_logger.setLevel(logging.DEBUG)
    else:
        t_logger.setLevel(logging.INFO)

    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    # create formatter
    formatter = logging.Formatter('[=]\t%(message)s')

    # add formatter to ch
    ch.setFormatter(formatter)

    # add ch to logger
    t_logger.addHandler(ch)



def set_unpack_path(path):
    global unpack_path
    unpack_path = path

def set_Target_Mode(Mode):
    global Target_Mode
    Target_Mode = Mode

def set_capstone_Arch(Arch):
    global capstone_Arch
    capstone_Arch = Arch

def set_capstone_Mode(Mode):
    global capstone_Mode
    capstone_Mode =Mode 

def set_dependency_Arch_Mode(Mode):
    set_Target_Mode(Mode=Mode)
    if Mode == W_x86:
        set_capstone_Arch(CS_ARCH_X86)
        set_capstone_Mode(CS_MODE_32)
    elif Mode == W_x64:
        set_capstone_Arch(CS_ARCH_X86)
        set_capstone_Mode(CS_MODE_64)
    elif Mode == L_X86:
        set_capstone_Arch(CS_ARCH_X86)
        set_capstone_Mode(CS_MODE_32)
    elif Mode == L_X64:
        set_capstone_Arch(CS_ARCH_X86)
        set_capstone_Mode(CS_MODE_64)


def set_unicorn_PE(tag):
    global unicornPE
    unicornPE = tag


def set_src_trace(src_trace):
    global src_level_trace
    src_level_trace = src_trace

def set_unpacking_mode(mode):
    global unpacking_mode
    unpacking_mode = mode

def set_hooking_dll_loader(tag):
    global tag_hooking_dll_loader
    debug("set hooking dll loader")
    tag_hooking_dll_loader = tag
