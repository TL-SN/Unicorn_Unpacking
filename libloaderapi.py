#!/usr/bin/env python3
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
#

import os

from qiling import Qiling
from qiling.exception import QlErrorNotImplemented
from qiling.os.windows.api import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *
from qiling.os.windows.utils import has_lib_ext

#################################################################################################################
# hook qiling , the main task is hooking these api: LoadLibrary , GetProcAddress

class iat_table:
    def __init__(self):
        self.dll_name = ""
        self.dll_base = -1
        self.dll_load_addr = -1
        self.fun_name = []
        self.fun_addr = []
        self.fun_load_addr = []


import_table_message = {}

def hook_import_table_message():
    global import_table_message
        
    return import_table_message

def hook_qiling_libloader():
    return hook_import_table_message()    
#################################################################################################################



def _GetModuleHandle(ql: Qiling, address: int, params):
    global import_table_message
    from variable import tag_hooking_dll_loader
    
    lpModuleName = params["lpModuleName"]
    if lpModuleName == 0:
        ret = ql.loader.pe_image_address
    else:
        if not has_lib_ext(lpModuleName):
            lpModuleName = f'{lpModuleName}.dll'

        image = ql.loader.get_image_by_name(lpModuleName, casefold=True)

        if image:
#########################################################################################
            # hook _GetModuleHandle
            # if (".dll" in lpModuleName or ".DLL" in lpModuleName) and tag_hooking_dll_loader==1: 
            if tag_hooking_dll_loader==1:
                iat = iat_table()
                iat.dll_base = image.base
                iat.dll_load_addr = address
                iat.dll_name = lpModuleName
                import_table_message[image.base] = iat
#########################################################################################
            ret = image.base
        else:
            ql.log.debug(f'Library "{lpModuleName}" not imported')
            ret = 0

    return ret

# HMODULE GetModuleHandleA(
#   LPCSTR lpModuleName
# );
@winsdkapi(cc=STDCALL, params={
    'lpModuleName' : LPCSTR
})
def hook_GetModuleHandleA(ql: Qiling, address: int, params):
    return _GetModuleHandle(ql, address, params)

# HMODULE GetModuleHandleW(
#   LPCWSTR lpModuleName
# );
@winsdkapi(cc=STDCALL, params={
    'lpModuleName' : LPCWSTR
})
def hook_GetModuleHandleW(ql: Qiling, address: int, params):
    return _GetModuleHandle(ql, address, params)

# BOOL GetModuleHandleExW(
#   DWORD   dwFlags,
#   LPCWSTR lpModuleName,
#   HMODULE *phModule
# );
@winsdkapi(cc=STDCALL, params={
    'dwFlags'      : DWORD,
    'lpModuleName' : LPCWSTR,
    'phModule'     : HMODULE
})
def hook_GetModuleHandleExW(ql: Qiling, address: int, params):
    res = _GetModuleHandle(ql, address, params)
    dst = params["phModule"]

    ql.mem.write_ptr(dst, res)

    return res

def __GetModuleFileName(ql: Qiling, address: int, params, *, wide: bool):
    hModule = params["hModule"]
    lpFilename = params["lpFilename"]
    nSize = params["nSize"]

    if not hModule:
        if ql.code:
            raise QlErrorNotImplemented('cannot retrieve module file name in shellcode mode')

        hModule = ql.loader.pe_image_address

    hpath = next((image.path for image in ql.loader.images if image.base == hModule), None)

    if hpath is None:
        ql.os.last_error = ERROR_INVALID_HANDLE
        return 0

    encname = 'utf-16le' if wide else 'latin'
    vpath = ql.os.path.host_to_virtual_path(hpath)
    truncated = vpath[:nSize - 1] + '\x00'
    encoded = truncated.encode(encname)

    if len(vpath) + 1 > nSize:
        ql.os.last_error = ERROR_INSUFFICIENT_BUFFER

    ql.mem.write(lpFilename, encoded)

    return min(len(vpath), nSize)

# DWORD GetModuleFileNameA(
#   HMODULE hModule,
#   LPSTR   lpFilename,
#   DWORD   nSize
# );
@winsdkapi(cc=STDCALL, params={
    'hModule'    : HMODULE,
    'lpFilename' : LPSTR,
    'nSize'      : DWORD
})
def hook_GetModuleFileNameA(ql: Qiling, address: int, params):
    return __GetModuleFileName(ql, address, params, wide=False)

# DWORD GetModuleFileNameW(
#   HMODULE hModule,
#   LPSTR   lpFilename,
#   DWORD   nSize
# );
@winsdkapi(cc=STDCALL, params={
    'hModule'    : HMODULE,
    'lpFilename' : LPWSTR,
    'nSize'      : DWORD
})
def hook_GetModuleFileNameW(ql: Qiling, address: int, params):
    return __GetModuleFileName(ql, address, params, wide=True)

# FARPROC GetProcAddress(
#   HMODULE hModule,
#   LPCSTR  lpProcName
# );
@winsdkapi(cc=STDCALL, params={
    'hModule'    : HMODULE,
    'lpProcName' : POINTER # LPCSTR
})
def hook_GetProcAddress(ql: Qiling, address: int, params):
    global import_table_message
    from variable import tag_hooking_dll_loader

    hModule = params['hModule']
    lpProcName = params['lpProcName']

    if lpProcName > MAXUSHORT:
        # Look up by name
        params["lpProcName"] = ql.os.utils.read_cstring(lpProcName)
        lpProcName = bytes(params["lpProcName"], "ascii")
    else:
        # Look up by ordinal
        lpProcName = params["lpProcName"]
    

    # TODO fix for gandcrab
    if lpProcName == "RtlComputeCrc32":
        return 0

    # Check if dll is loaded
    dll_name = next((os.path.basename(image.path).casefold() for image in ql.loader.images if image.base == hModule), None)

    if dll_name is None:
        ql.log.info('Failed to import function "%s" with handle 0x%X' % (lpProcName, hModule))
        return 0

    # Handle case where module is self
    if dll_name == os.path.basename(ql.loader.path).casefold():
        for addr, export in ql.loader.export_symbols.items():
            if export['name'] == lpProcName:
                return addr


    iat = ql.loader.import_address_table[dll_name]
    if lpProcName in iat:
##############################################################################333
        # hook GetProcAddress
        
        if tag_hooking_dll_loader == 1:
            dll_base = hModule
            if dll_base in import_table_message:
                h_iat:iat_table = import_table_message[dll_base]
                new_lpProcName = lpProcName
                if type(new_lpProcName) == type(b"tlsn"):
                    new_lpProcName = new_lpProcName.decode()
                if new_lpProcName not in h_iat.fun_name:
                    h_iat.fun_name.append(new_lpProcName)
                    h_iat.fun_addr.append(iat[lpProcName])
                    h_iat.fun_load_addr.append(address)
##############################################################################
        return iat[lpProcName]

    return 0

def _LoadLibrary(ql: Qiling, address: int, params):
    from variable import tag_hooking_dll_loader
    lpLibFileName = params["lpLibFileName"]

    # TODO: this searches only by basename; do we need to search by full path as well?
    dll = ql.loader.get_image_by_name(lpLibFileName, casefold=True)

    if dll is not None:

######################################################################
        # Hook qiling的LoadLibrary加载器
        
        if tag_hooking_dll_loader == 1:
            iat = iat_table()
            iat.dll_name = lpLibFileName
            iat.dll_base = dll.base
            iat.dll_load_addr = address
            import_table_message[dll.base] = iat
###################################################################### 
        return dll.base
######################################################################
    if tag_hooking_dll_loader == 1:
        iat = iat_table()
        iat.dll_name = lpLibFileName
        iat.dll_base = ql.loader.load_dll(lpLibFileName)
        iat.dll_load_addr = address
        import_table_message[iat.dll_base] = iat
        return iat.dll_base
######################################################################
    else:    
        return ql.loader.load_dll(lpLibFileName)

def _LoadLibraryEx(ql: Qiling, address: int, params):
    from variable import tag_hooking_dll_loader
    lpLibFileName = params["lpLibFileName"]
    
    if tag_hooking_dll_loader == 1:
        iat = iat_table()
        iat.dll_name = lpLibFileName
        iat.dll_base = ql.loader.load_dll(lpLibFileName)
        iat.dll_load_addr = address
        import_table_message[iat.dll_base] = iat
        return iat.dll_base
    else:
        return ql.loader.load_dll(lpLibFileName)

# HMODULE LoadLibraryA(
#   LPCSTR lpLibFileName
# );
@winsdkapi(cc=STDCALL, params={
    'lpLibFileName' : LPCSTR
})
def hook_LoadLibraryA(ql: Qiling, address: int, params):
    return _LoadLibrary(ql, address, params)

# HMODULE LoadLibraryExA(
#   LPCSTR lpLibFileName,
#   HANDLE hFile,
#   DWORD  dwFlags
# );
@winsdkapi(cc=STDCALL, params={
    'lpLibFileName' : LPCSTR,
    'hFile'         : HANDLE,
    'dwFlags'       : DWORD
})
def hook_LoadLibraryExA(ql: Qiling, address: int, params):
    return _LoadLibraryEx(ql, address, params)

# HMODULE LoadLibraryW(
#   LPCWSTR lpLibFileName
# );
@winsdkapi(cc=STDCALL, params={
    'lpLibFileName' : LPCWSTR
})
def hook_LoadLibraryW(ql: Qiling, address: int, params):
    return _LoadLibrary(ql, address, params)

# HMODULE LoadLibraryExW(
#   LPCSTR lpLibFileName,
#   HANDLE hFile,
#   DWORD  dwFlags
# );
@winsdkapi(cc=STDCALL, params={
    'lpLibFileName' : LPCWSTR,
    'hFile'         : HANDLE,
    'dwFlags'       : DWORD
})
def hook_LoadLibraryExW(ql: Qiling, address: int, params):
    return _LoadLibraryEx(ql, address, params)

# DWORD SizeofResource(
#   HMODULE hModule,
#   HRSRC   hResInfo
# );
@winsdkapi(cc=STDCALL, params={
    'hModule'  : HMODULE,
    'hResInfo' : HRSRC
})
def hook_SizeofResource(ql: Qiling, address: int, params):
    # Return size of resource
    # TODO set a valid value. More tests have to be made to find it.
    return 0x8

# HGLOBAL LoadResource(
#   HMODULE hModule,
#   HRSRC   hResInfo
# );
@winsdkapi(cc=STDCALL, params={
    'hModule'  : HMODULE,
    'hResInfo' : HRSRC
})
def hook_LoadResource(ql: Qiling, address: int, params):
    pointer = params["hResInfo"]

    return pointer

# LPVOID LockResource(
#   HGLOBAL hResData
# );
@winsdkapi(cc=STDCALL, params={
    'hResData' : HGLOBAL
})
def hook_LockResource(ql: Qiling, address: int, params):
    pointer = params["hResData"]

    return pointer

# BOOL DisableThreadLibraryCalls(
#  HMODULE hLibModule
# );
@winsdkapi(cc=STDCALL, params={
    'hLibModule' : HMODULE
})
def hook_DisableThreadLibraryCalls(ql: Qiling, address: int, params):
    return 1

# BOOL FreeLibrary(
#   HMODULE hLibModule
# );
@winsdkapi(cc=STDCALL, params={
    'hLibModule' : HMODULE
})
def hook_FreeLibrary(ql: Qiling, address: int, params):
    return 1

# BOOL SetDefaultDllDirectories(
#   DWORD DirectoryFlags
# );
@winsdkapi(cc=STDCALL, params={
    'DirectoryFlags' : DWORD
})
def hook_SetDefaultDllDirectories(ql: Qiling, address: int, params):
    value = params["DirectoryFlags"]

    if value == LOAD_LIBRARY_SEARCH_USER_DIRS:
        # TODO we have to probably set an handler for this, since it can be a not default value.
        #  And we have to change the default path of load
        raise QlErrorNotImplemented("API not implemented")

    return 1
