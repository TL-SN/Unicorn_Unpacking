import lief
import pefile
import os
from unicorn_unpack import get_import_iat_mess_and_dump
from struct import unpack,pack
from variable_const import *
def rva2foa(pe,rva):
    if rva < pe.optional_header.sizeof_headers:
        return rva
    for section in pe.sections:
        if  rva >= section.virtual_address and rva < section.virtual_address + section.virtual_size:
            offset = rva - section.virtual_address + section.pointerto_raw_data
            return offset
    

def foa2rva(pe,foa):
    if foa < pe.optional_header.sizeof_headers:
        return foa
    for section in pe.sections:
        if section.pointerto_raw_data <= foa and foa < section.pointerto_raw_data + section.sizeof_raw_data:
            rva = foa - section.pointerto_raw_data  + section.virtual_address
            return rva





# 打印导入表信息
def pt_import_table(pe_path):
    import_mess = get_import_iat_mess_and_dump()
    for iat in import_mess:
        print(iat.dll_name)
        for fun in iat.fun:
            print(" ",fun)


# 获取导入表信息


def get_import_table_mess(pe_path ):
    import_mess = get_import_iat_mess_and_dump()
    return import_mess


def find_file(root_folder, file_name:str):
    import os
    for root, dirs, files in os.walk(root_folder):
        if file_name.upper() in files or file_name.lower() in files:
            return os.path.join(root, file_name.lower())

def get_funname_by_id(dll_name,id):
    from variable import ROOTFS
    dll_path = find_file(ROOTFS, dll_name)

    dll = lief.parse(dll_path)
    exports = dll.get_export()
    ordinal = id
    for export in exports.entries:
        if export.ordinal == ordinal:
            return export.name
    else:
        print("error id")
        assert 0




# 向IAT表中填入一个函数
def add_new_fun_for_iat_table(pe,func_name,dll_name):
    library  = next((imp for imp in pe.imports if imp.name.lower() == dll_name.lower()), None)

    if library  is None:
        library = pe.add_library(dll_name )
        
    if not any(entry.name == func_name for entry in library.entries):
        if type(func_name) == type("tlsn"):
            library.add_entry(func_name)   
        else:
            func_name = get_funname_by_id(dll_name=dll_name,id=func_name)
            library.add_entry(func_name)

def rebuild_import_table(pe):

    from variable import unpack_path
    builder = lief.PE.Builder(pe)
    builder.build_imports(True)  # 重建导入表
    builder.build()  # 应用修改
    builder.write(unpack_path)  # 写入到新的文件以保留原文件



def pt_import_table_mess(import_table_mess):
    for iat_table in import_table_mess:
        print(iat_table.dll_name)
        for fun,addr in zip(iat_table.fun,iat_table.fun_addr):
            print(" ",fun," ",hex(addr))

# 在加入导入表项之前还得移除导入表项
def fix_import_table(pe,import_table_mess):
    pe.remove_all_libraries()
    # import_table_mess = get_import_table_mess()
    for dll_base in import_table_mess:
        iat : iat_table= import_table_mess[dll_base]
        dll_name = iat.dll_name
        for fun in iat.fun_name:
            if type(fun) == type(b"tlsn"):
                fun = fun.decode()
            add_new_fun_for_iat_table(pe,fun,dll_name)

    rebuild_import_table(pe)

# 程序在启动的时候会通过加载器，获取导入函数的地址，并填入IAT表中，如果IAT表指向的位置本来就有具体的地址，那么加载器将不会重新填充IAT表。
# 但是从内存中dump的exe程序的IAT表，显然是包含原来地址的，正因为如此，我们重建导入表后，需要把first_thunk指向原来的IAT表的位置，这样以后，加载器就可以刷新IAT表
# 修复导入表的first_thunk字段(first_thunk指向的就是IAT表辣)
def fix_fist_thunk(dump_path,import_table_mess):
    pe_lief = lief.parse(dump_path)
    foa_fixed_pointers = get_fist_thunk_list(dump_path,import_table_mess)
    
    cnt = 0
    # print("the FirstThunk addr is :")
    
    pe = pefile.PE(dump_path)
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        # print("No import table found.")
        return
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        entry.struct.FirstThunk = foa2rva(pe_lief,foa_fixed_pointers[cnt])
        # print(" ",hex(entry.struct.FirstThunk))
        cnt += 1
    pe.write(dump_path + ".bin")
    pe.close()
    os.remove(dump_path)
    os.rename(dump_path+".bin",dump_path)



# 获取原来的iat表的地址列表（所有导入表的 FirstThunk字段）
# 目前的一种思路就是再对qiling进行hook，按照dll 得到fun对应的所有地址
def get_fist_thunk_list(path,import_table_mess):
    from variable import Target_Mode
    foa_fixed_pointers = []
    fp = open(path,"rb")
    data = fp.read()
    for dlls_base in import_table_mess:
        iat = import_table_mess[dlls_base]
        pattern_bt = b""
        for addr in iat.fun_addr:
            if Target_Mode == W_x64 or Target_Mode == L_X64:
                pattern_bt += pack("<Q",addr)
            elif Target_Mode == W_x86 or Target_Mode == L_X86:
                pattern_bt += pack("<I",addr)
            else:
                assert 0
        cnt = data.count(pattern_bt)
        if cnt != 1:
            print(cnt)
            assert 0
        suspicious_pointer = data.find(pattern_bt)
        if suspicious_pointer == -1:
            assert 0

        else:
            foa_fixed_pointers.append(suspicious_pointer)
    
    return foa_fixed_pointers 



def pt_all_first_thunk(pe):
    for import_ in pe.imports:
        print(f"Library: {import_.name}")
        print(f"FirstThunk: {hex(import_.import_address_table_rva)}")    # FirstThunk






# def add_section_to_pe(file_path, new_section_name, section_content, section_size, characteristics):    
#     from variable import unpack_path
#     pe = lief.parse(file_path)
#     new_section = lief.PE.Section()
#     new_section.name = new_section_name
    
#     new_section.content = [ord(c) for c in section_content]  # 设置节内容为字节列表
#     new_section.size = section_size  # 设置节的大小
#     new_section.virtual_size = section_size  # 设置节的虚拟大小
#     new_section.characteristics = characteristics
    
#     pe.add_section(new_section, lief.PE.SECTION_TYPES.DATA)


#     builder = lief.PE.Builder(pe)
#     builder.build_imports(True)
#     builder.build()
    
