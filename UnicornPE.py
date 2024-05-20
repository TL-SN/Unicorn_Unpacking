import lief
from capstone import *
def rva2foa(pe,rva):
    if rva < pe.optional_header.sizeof_headers:
        return rva
    for section in pe.sections:
        if  rva >= section.virtual_address and rva < section.virtual_address + section.virtual_size:
            offset = rva - section.virtual_address + section.pointerto_raw_data
            return offset

def get_old_oep_foa_rva(pe):
    oep_rva = pe.optional_header.addressof_entrypoint
    oep_foa = rva2foa(pe,oep_rva)
    return oep_foa,oep_rva + pe.optional_header.imagebase

def stack_brk_address(path,old_oep_foa,old_oep_rva):
    fp = open(path,"rb")
    exe_data = fp.read()
    x64code = exe_data[old_oep_foa : ]
    from variable import Target_Mode,capstone_Arch,capstone_Mode
    CP = Cs(capstone_Arch, capstone_Mode)

    last_push_address = -1
    for i in CP.disasm(x64code, old_oep_rva):
        dis = format("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str)) #汇编指令 操作对象字符串
        if "push" in dis:
            last_push_address = i.address + i.size
            return last_push_address 
        if "call" in dis:
            break
    return last_push_address 


def handle_unicorn_PE(tag):
    if tag == 0:
        return 
    from variable import unpack_path
    unpack_path = "Selected_upx.exe"
    pe = lief.parse(unpack_path)
    old_oep_foa,old_oep_rva =  get_old_oep_foa_rva(pe)
    stack_brk = stack_brk_address(unpack_path,old_oep_foa,old_oep_rva)
    if stack_brk == -1:
        print("Don't find stack_brk")
        assert 0
    print(hex(stack_brk),hex(stack_brk - pe.optional_header.imagebase))

handle_unicorn_PE(1)


