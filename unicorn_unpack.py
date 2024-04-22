import lief
import os
from qiling import *
from qiling.os.windows.dlls.kernel32.libloaderapi import hook_qiling_libloader
from capstone import *
from variable_const import *
RealOEP = -1 
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



import_table_mess = None
def pt_import_table_message():
    global import_table_mess
    debug("the import table is:")
    import_table_mess = hook_qiling_libloader()
    for dll_base in import_table_mess:
        iat:iat_table = import_table_mess[dll_base]
        debug(iat.dll_name)
        for fun_name in iat.fun_name:
            debug("\t" + fun_name)


def get_import_table_message(ql:Qiling,userdata:PeEmulation):
    global import_table_mess
    print("get import table...")
    from variable import debug_level
    if debug_level >= 1:
        pt_import_table_message()

    dump_exe_memory(ql = ql)  
    ql.emu_stop()

def debug(pt):
    from variable import t_logger
    t_logger.debug(pt)

# dump后需要修改oep，切记!!
def dump_exe_memory(ql:Qiling):
    print("dump...")
    from variable import dump_path as pe_unpack_path
    start_addr = ql.loader.pe_image_address
    mem_size = ql.loader.pe_image_size
    debug(f"start_addr is {hex(start_addr)}")
    debug(f"the mem_size is {hex(mem_size)}")
   
    dump_memory = ql.mem.read(start_addr,mem_size)
    fp = open(pe_unpack_path,"wb")
    fp.write(dump_memory)
    fp.close()
    fix_dumped_exe(pe_unpack_path)
    

def fix_dumped_exe(pe_unpack_path : str):
    print("fix the dump file ...")
    # 1、修复oep

    fix_oep(pe_unpack_path)

    # 2、修复sections的标志位
    fix_sections_characteristics(pe_unpack_path)

    # 3、修正一些节的标志位(主要是 SizeOfRawData 和 PointerToRawData)，这里参考了scally源码，scally的思路是经可能的缩小磁盘文件file的大小，我们这里以简便出发，不考虑这么多
    fix_section_header(pe_unpack_path)

    # 4、清除垃圾数据(存盘，这一步很关键)
    image2file(pe_unpack_path)

def fix_sections_characteristics(pe_unpack_path : str):
    characters_rwx = lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE | lief.PE.SECTION_CHARACTERISTICS.MEM_READ | lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE 
    pe = lief.parse(pe_unpack_path)
    for section in pe.sections:
        section.characteristics |= characters_rwx
        
    pe.write(pe_unpack_path)



def fix_oep(pe_unpack_path:str):
    global RealOEP
    pe = lief.parse(pe_unpack_path)
    # 1、修改oep
    pe.optional_header.addressof_entrypoint = RealOEP - pe.optional_header.imagebase
    pe.write(pe_unpack_path)

def image2file(pe_unpack_path : str):
    pe = lief.parse(pe_unpack_path)
    fp = open(pe_unpack_path,"rb")
    data =fp.read()
    offset = 0
    cp_len = 0
    cp_len += pe.optional_header.sizeof_headers
    for section in pe.sections:
        cp_len += section.sizeof_raw_data
    cp_exe = bytearray(b"\x00" * cp_len)

    # 1、Copy SizeOfHeaders
    cp_exe[:pe.optional_header.sizeof_headers] = data[:pe.optional_header.sizeof_headers]
    offset += pe.optional_header.sizeof_headers

    # 2、读取节
    for section in pe.sections:
        cp_exe[offset : offset + section.sizeof_raw_data] = data[section.virtual_address : section.virtual_address + section.sizeof_raw_data]
        offset += section.sizeof_raw_data

    # 3、写回
    fp1 = open(pe_unpack_path,"wb")
    # fp1 = open("Selected_upx.exe.unicorn_dump_cp.exe","wb")
    fp1.write(cp_exe)
    fp1.close()
    fp.close()
    
    fp2 = open(pe_unpack_path + "_dump.exe","wb")
    fp2.write(cp_exe)
    fp2.close()



def alignValue(badValue,alignTo):
    return (((badValue + alignTo - 1) // alignTo) * alignTo)

# 这里参考了scally源码，scally的思路是经可能的缩小磁盘文件file的大小，我们这里以简便出发，不考虑这么多，只要标志位正确就行
# 没办法,lief老是做一些我意料之外的工作，所以我选择使用pefile完成这项工作
# 注意，一定要节对齐！这很关键
import pefile
def fix_section_header(pe_unpack_path : str):
    pe = pefile.PE(pe_unpack_path)
    sectionAlignment = pe.OPTIONAL_HEADER.SectionAlignment
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    
    offset = 0
    if len(pe.sections) == 0:
        return 

    
    offset = pe.sections[0].PointerToRawData 
    for section in pe.sections:
        section.VirtualAddress = alignValue(section.VirtualAddress,sectionAlignment)
        section.Misc_VirtualSize = alignValue(section.Misc_VirtualSize,sectionAlignment)
        section.PointerToRawData = alignValue(offset,file_alignment)
        section.SizeOfRawData = alignValue(section.SizeOfRawData,file_alignment)
        offset = section.PointerToRawData + section.SizeOfRawData

    offset = pe.sections[0].PointerToRawData 
    for section in pe.sections:
        virtual_size = section.Misc_VirtualSize
        if section.SizeOfRawData < virtual_size:
            section.SizeOfRawData = virtual_size
            section.PointerToRawData = offset
            offset += section.SizeOfRawData
        else:
            section.PointerToRawData = offset
            offset += section.SizeOfRawData


    pe.write(pe_unpack_path+".bin")
    pe.close()
    os.remove(pe_unpack_path)
    os.rename(pe_unpack_path+".bin",pe_unpack_path)
        

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

def get_old_oep_foa_rva(pe):
    oep_rva = pe.optional_header.addressof_entrypoint
    oep_foa = rva2foa(pe,oep_rva)
    return oep_foa,oep_rva + pe.optional_header.imagebase

def get_segment_message():
    from variable import ROOTFS,unpack_path
    pe = lief.parse(rf"{ROOTFS}/{unpack_path}")
    seg_mess = []
    for section in pe.sections:
        seg_mess.append((section.virtual_address + pe.optional_header.imagebase,section.virtual_size))
    return seg_mess

def is_cross_segment_jump(src_addr,target_addr,seg_mess):
    cnt = 0
    src = -1
    tar = -1
    for seg in seg_mess:
        if src_addr >= seg[0] and src_addr < seg[0] + seg[1]:
            src = cnt
        if target_addr >= seg[0] and target_addr < seg[0] + seg[1] :
            tar = cnt
        cnt += 1
    if src == -1 or tar == -1:
        print("what?")
        assert 0
    if src == tar:
        return 0
    else:
        return 1




# # 重写这个函数吧
# def hook_stack(ql:Qiling,access,address,size,value,userdata:PeEmulation):
#     from variable import Target_Mode,capstone_Arch,capstone_Mode
#     rip = 0
#     if Target_Mode == W_x64 or Target_Mode == L_X64:
#         rip = ql.arch.regs.read(WL_X64_RIP)
#     elif Target_Mode == W_x86 or Target_Mode == L_X86:
#         rip = ql.arch.regs.read(WL_X86_EIP)
#     else:
#         assert 0
#     x64code = ql.mem.read(rip,100)
#     CP = Cs(capstone_Arch, capstone_Mode)
#     CP.detail = True
#     seg_mess = get_segment_message()
#     for i in CP.disasm(x64code, rip):
#         dis = format("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            
#         if "jmp" in dis:
#             try:
#                 tar = int(i.op_str,16)
#             except:
#                 continue
#             if is_cross_segment_jump(i.address,tar,seg_mess) == 1:
#                 # 得到入口点
#                 global RealOEP
#                 RealOEP = tar
#                 print(f"{hex(rip)} : the oep is {hex(RealOEP)}")
                
#                 ctx : PeEmulation = userdata
#                 ql.hook_del(ctx.hook_queue.pop("hook_stack"))
#                 # 2、获取导入表信息并进行dump
#                 handle1 = ql.hook_address(get_import_table_message,RealOEP,user_data=ctx)
#                 # handle2 = ql.hook_address(dump_exe_memory,RealOEP,user_data=ctx)
                
#                 ctx.hook_queue["get_import_table_message"] = handle1
#                 # ctx.hook_queue["dump_exe_memory"] = handle2
                
#                 break        

#         # if "ret" in dis:

def find_cross_segment_transfer(ql:Qiling,address:int,size:int,userdata:PeEmulation):
    ctx : PeEmulation =  userdata
    
    if is_cross_segment_jump(src_addr=ctx.last_pc,target_addr=address,seg_mess=ctx.seg_mess):
        # 这里即为oep
        global RealOEP
        RealOEP  = address
        debug(f"the oep is {hex(RealOEP)}")
        get_import_table_message(ql=ql,userdata=userdata)
        ql.emu_stop()
    else:
        return 


# hook_read_memory的这个address好像是内存的地址
def hook_stack(ql:Qiling,access:int,address:int,size:int,value:int,userdata:PeEmulation):
    from variable import Target_Mode
    seg_mess = get_segment_message()
    ctx : PeEmulation =  userdata
    rip = -1
    if Target_Mode == W_x64 or Target_Mode == L_X64:
        rip = ql.arch.regs.read(WL_X64_RIP)
    elif Target_Mode == W_x86 or Target_Mode == L_X86:
        rip = ql.arch.regs.read(WL_X86_EIP)
    else:
        assert 0

    ql.hook_del(ctx.hook_queue["hook_stack"])
    print("find oep...")
    handle = ql.hook_code(find_cross_segment_transfer,user_data=ctx)
    ctx.hook_queue["find_cross_segment_transfer"] = handle
    ctx.seg_mess = seg_mess
    ctx.last_pc = rip
    # 这里的address不一定对


def set_next_brk(ql:Qiling,userdata:PeEmulation):
    
    from variable import Target_Mode,capstone_Arch,capstone_Mode
    stack_top_address = 0
    if Target_Mode == W_x64 or Target_Mode == L_X64:
        stack_top_address = ql.arch.regs.read("rsp")
    elif Target_Mode == W_x86 or Target_Mode == L_X86:
        stack_top_address = ql.arch.regs.read("esp")
    else:
        assert 0
    start_addr = stack_top_address
    end_addr = -1
    if Target_Mode == W_x64 or Target_Mode == L_X64:
        end_addr = start_addr + 8
    elif Target_Mode == W_x86 or Target_Mode == L_X86:
        end_addr = start_addr + 4
    else:
        assert 0
    
    ctx :PeEmulation = userdata
    ql.hook_del(ctx.hook_queue["set_next_brk"])
    ctx.hook_queue.pop("set_next_brk")
    handle = ql.hook_mem_read(hook_stack,begin=start_addr,end = end_addr,user_data=ctx)
    ctx.hook_queue["hook_stack"] = handle

def get_import_iat_mess_and_dump():
    from variable import ROOTFS,unpack_path,debug_level
   
    # 1、发现oep
    pe = lief.parse(rf"{ROOTFS}/{unpack_path}")
    old_oep_foa,old_oep_rva =  get_old_oep_foa_rva(pe)
    stack_brk = stack_brk_address(rf"{ROOTFS}/{unpack_path}",old_oep_foa,old_oep_rva)
    if stack_brk == -1:
        print("Don't find stack_brk")
        assert 0
    ql = Qiling([rf"{ROOTFS}/{unpack_path}"], ROOTFS,verbose=debug_level)
    
    ctx = PeEmulation()
    handle  = ql.hook_address(set_next_brk,stack_brk,user_data=ctx)
    ctx.hook_queue["set_next_brk"] = handle
    ql.run()
    
    global import_table_mess
    return import_table_mess
