# 在qiling 1.44版本中模拟运行带upx壳的elf文件会有bug!!!
from qiling import *
import lief
from qiling.const import QL_VERBOSE
from struct import unpack,pack
unpack_path = "Selected_upx"    # "./Selected_x86_upx.exe or .\Selected_x86_upx.exe are wrong!!! "
dump_path = "Selected_upx_unicorn"
ROOTFS="D:/Python/Environment/Python_3.87/install_pack_by_myself/qiling/examples/rootfs/x8664_linux" # set your qiling ROOTS
ql = Qiling([rf"{ROOTFS}/bin/{unpack_path}"], ROOTFS,verbose=QL_VERBOSE.DEFAULT)
# ql.debugger = "qdb:0x000555555555189"


# def dump_elf(ql: Qiling):
#     global dump_path
#     sections = []
#     dump_section = []
#     new_file_data = b""
#     tag = 0
#     dump_file = open(dump_path,"wb")

#     for section in ql.mem.map_info:
#         sections.append(section)
#         begin_addr = section[0]
#         if begin_addr < 0x555555554000:
#             continue
#         end_addr = section[1]
#         Name = section[3]
#         # if "[hook_mem]" in Name:
#         #     tag = 1
#         if tag == 0:
#             dump_section.append(section)
#             content = ql.mem.read(begin_addr,end_addr-begin_addr)
#             new_file_data += content
#         if "[hook_mem]" in Name:
#             tag = 1

#     dump_file.write(new_file_data)
#     print("dump sections is :")
#     for sec in dump_section:
#         print("",hex(sec[0]),hex(sec[1]),sec[2],sec[3],sec[4])

#     def debug():
#         for sec in sections:
#             print(hex(sec[0]),hex(sec[1]),sec[2],sec[3],sec[4])
#     # debug()
    
#     return 

def Word(ql:Qiling,address):
    Qdata = ql.mem.read(addr=address,size=2)
    return unpack("<H",Qdata)[0]

def Dword(ql:Qiling,address):
    Ddata = ql.mem.read(addr=address,size=4)
    return unpack("<I",Ddata)[0]

def Qword(ql:Qiling,address):
    Qdata = ql.mem.read(addr=address,size=8)
    return unpack("<Q",Qdata)[0]

def dump(fp,ql:Qiling,start_addr,end_addr,offset):
    size=end_addr-start_addr
    fp.seek(offset)
    segdata = ql.mem.read(start_addr,size)
    fp.write(segdata)


def dump_elf(ql:Qiling):
    global dump_path
    PT_LOAD = 1
    PT_DYNAMIC = 2
    ImageBase = 0x555555554000
    if Dword(ql,ImageBase) == 0x7f454c46 or Dword(ql,ImageBase) == 0x464c457f:
        fp = open(dump_path,"wb")
        e_phoff = ImageBase +  Qword(ql,ImageBase + 0x20)
        e_phnum=Word(ql,ImageBase+0x38)
        for i in range(e_phnum):
            if Dword(ql,e_phoff) == PT_LOAD or Dword(ql,e_phoff) == PT_DYNAMIC:
                p_offset=Qword(ql,e_phoff+0x8)
                StartImg=Qword(ql,e_phoff+0x10) + ImageBase
                EndImg=StartImg+Qword(ql,e_phoff+0x28)
                dump(fp = fp,ql = ql,start_addr=StartImg,end_addr=EndImg,offset=p_offset)
            e_phoff += 0x38
        fp.seek(0x3c)
        fp.write(b"\x00\x00\x00\x00")
        fp.seek(0x28)
        fp.write(b"\x00" * 8)
        fp.close()
    else:
        wd = ql.mem.read(ImageBase,0x100)
        print(wd)
        assert 0

import lief

def add_symbol_to_elf(elf_path, symbol_name, symbol_address):
    # 加载ELF文件
    elf = lief.parse(elf_path)

    # 创建一个新的符号
    new_symbol = lief.ELF.Symbol()
    new_symbol.name = symbol_name
    new_symbol.value = symbol_address
    new_symbol.binding = lief.ELF.SYMBOL_BINDINGS.GLOBAL
    new_symbol.type = lief.ELF.SYMBOL_TYPES.FUNC
    new_symbol.shndx = lief.ELF.SHN_UNDEF  # 表示这是一个未定义的符号（通常用于导入）

    # 添加符号到动态符号表
    elf.add_dynamic_symbol(new_symbol)

    # 如果需要，可以直接创建或修改动态重定位表
    # 比如添加一个重定位入口
    # rela_entry = lief.ELF.Rela()
    # rela_entry.symbol = new_symbol
    # rela_entry.type = lief.ELF.RELOCATION_X86_64.GLOB_DAT
    # rela_entry.addend = 0
    # elf.add_relocation(rela_entry)

    # 保存修改后的文件
    elf.write("modified_" + elf_path)

# 调用函数以添加新符号
add_symbol_to_elf("your_elf_file.elf", "new_function", 0x123456)



ql.hook_address(dump_elf,0x0005555555550A0)
ql.run(end = 0x0005555555550A4)
