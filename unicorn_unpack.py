import lief
import os
from qiling import *
from qiling.os.windows.dlls.kernel32.libloaderapi import hook_qiling_libloader
from capstone import *
from variable_const import *
from variable import set_hooking_dll_loader

RealOEP = -1 
# Last_src_addr = -1  # trace 源程序中的last_addr，不trace库函数 # 可以用于查看qiling终止时所在的地址
trace_tagg = 0
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
            if type(fun_name) != type("tlsn"):
                debug("\t" + str(fun_name))
            else:
                debug("\t" + fun_name)


def get_import_table_message(ql:Qiling,userdata:PeEmulation):
    global import_table_mess
    print("get import table...")
    from variable import debug_level
    if debug_level >= 1:
        pt_import_table_message()
    else:
        import_table_mess = hook_qiling_libloader()
    dump_exe_memory(ql = ql)  
    ql.emu_stop()

def debug(pt):
    from variable import t_logger
    t_logger.debug(pt)


def capstone_dis(ql:Qiling,size=20,ins_count=1):
    from variable import Target_Mode,capstone_Arch,capstone_Mode
    CP = Cs(capstone_Arch, capstone_Mode)
    rip = 0
    if Target_Mode == W_x64 or Target_Mode == L_X64:
        rip = ql.arch.regs.read(WL_X64_RIP)
    elif Target_Mode == W_x86 or Target_Mode == L_X86:
        rip = ql.arch.regs.read(WL_X86_EIP)
    else:
        assert 0
    x64code = ql.mem.read(rip,size)
    
    cnt = 0
    for i in CP.disasm(x64code, rip):
        dis = format("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str)) #汇编指令 操作对象字符串
        print(dis)
        cnt +=1
        if cnt >= ins_count:
            break

# dump后需要修改oep，切记!!
def dump_exe_memory(ql:Qiling):
    print("dump...")
    from variable import unpack_path as pe_unpack_path
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
    characters_rwx = lief.PE.Section.CHARACTERISTICS.MEM_WRITE | lief.PE.Section.CHARACTERISTICS.MEM_READ | lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE 
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
    if offset == 0:         # 有的exe程序第一个段pointer为0
        offset = pe.OPTIONAL_HEADER.SizeOfHeaders
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
    from variable import ROOTFS,pack_path
    pe = lief.parse(rf"{pack_path}")
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
        return 0
    if src == tar:
        return 0
    else:
        return 1



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
        ctx.last_pc = address
        return 


# hook_read_memory的这个address好像是内存的地址
def hook_stack(ql:Qiling,access:int,address:int,size:int,value:int,userdata:PeEmulation):
    from variable import Target_Mode,capstone_Arch,capstone_Mode
    rip = 0
    if Target_Mode == W_x64 or Target_Mode == L_X64:
        rip = ql.arch.regs.read(WL_X64_RIP)
    elif Target_Mode == W_x86 or Target_Mode == L_X86:
        rip = ql.arch.regs.read(WL_X86_EIP)
    else:
        assert 0
    x64code = ql.mem.read(rip,20)
    ans = 0
    CP = Cs(capstone_Arch, capstone_Mode)
    for i in CP.disasm(x64code, rip):
        dis = format("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))  
        if "pop" not in dis:
            pass
        else:
            ans = i.address
            break
    
    if ans == 0:
        return 
    else:
        print(f"found pop => {hex(ans)}")
    seg_mess = get_segment_message()
    ctx : PeEmulation =  userdata

    ql.hook_del(ctx.hook_queue["hook_stack"])
    print("finding oep...")
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

# def get_import_iat_mess_and_dump():
#     from variable import ROOTFS,pack_path,debug_level
   
#     # 1、发现oep
#     pe = lief.parse(rf"{ROOTFS}/{pack_path}")
#     old_oep_foa,old_oep_rva =  get_old_oep_foa_rva(pe)
#     stack_brk = stack_brk_address(rf"{ROOTFS}/{pack_path}",old_oep_foa,old_oep_rva)
#     debug(f"the first address is {hex(stack_brk)}")
#     if stack_brk == -1:
#         print("Don't find stack_brk")
#         assert 0
#     ql = Qiling([rf"{ROOTFS}/{pack_path}"], ROOTFS,verbose=debug_level)
    
#     ctx = PeEmulation()
#     handle  = ql.hook_address(set_next_brk,stack_brk,user_data=ctx)
#     ctx.hook_queue["set_next_brk"] = handle
#     ql.run()
    
#     global import_table_mess
#     return import_table_mess


def find_first_push_ins(ql:Qiling,address:int,size:int,userdata:PeEmulation):
    from variable import capstone_Arch,capstone_Mode
    xcode = ql.mem.read(address,20)
    CP = Cs(capstone_Arch, capstone_Mode)
    dis = ""
    for i in CP.disasm(xcode, address):
        dis = format("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))  
        debug(dis)
        break
    if dis == "":
        assert 0
    

    ctx :PeEmulation = userdata
    if ctx.first_address == address:
        debug(f"=> find the first address => {hex(address)} <=")        

        from variable import Target_Mode,capstone_Arch,capstone_Mode
        set_hooking_dll_loader(1)           # 设置hook
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
        
        ql.hook_del(ctx.hook_queue["find_first_push_ins"])
        ctx.hook_queue.pop("find_first_push_ins")
        handle = ql.hook_mem_read(hook_stack,begin=start_addr,end = end_addr,user_data=ctx)
        ctx.hook_queue["hook_stack"] = handle
        return 
    
    elif "push" in dis:
            ctx.first_address = address + size   


def src_trace(ql:Qiling,address:int,size:int,userdata:PeEmulation):
    userdata.Last_src_addr = address
    from variable import capstone_Arch,capstone_Mode
    x64code = ql.mem.read(address,size)
    CP = Cs(capstone_Arch, capstone_Mode)
    for i in CP.disasm(x64code, address):
        dis = format("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))  
        print(dis)
        break

def record_cross_segment_message(ql:Qiling,address:int,size:int,userdata:PeEmulation):
    ctx : PeEmulation =  userdata
    start_addr = ql.loader.pe_image_address
    end_start = ql.loader.pe_image_size + start_addr
    if address < start_addr or address > end_start:
        return 
    if is_cross_segment_jump(src_addr=ctx.last_pc,target_addr=address,seg_mess=ctx.seg_mess):        
        # print(f"[=>] {hex(ctx.last_pc)} ===>  {hex(address)}")
        
        ctx.cross_segment_message.append((ctx.last_pc,address))
        ctx.last_pc = address
    else:
        ctx.last_pc = address
        return 

def arrive_oep_and_get_import_iat(ql:Qiling,userdata:PeEmulation):
    get_import_table_message(ql=ql,userdata=userdata)
    ql.emu_stop()
    

def ptctx(ctx:PeEmulation):
    print(f"first_address => {hex(ctx.first_address)}")
    print(f"RealOep => {hex(ctx.realoep)}")
    print(f"last_pc => {hex(ctx.last_pc)}")
    print("seg mess:")
    for seg in ctx.seg_mess:
        print(f"{hex(seg[0])} --- {hex(seg[1])}")
    if ctx.cross_segment_message == []:
        pass
    else:
        print("cross_segment_message :")
        for seg in ctx.cross_segment_message:
            print(f"{hex(seg[0])} --> {hex(seg[1])}")


def get_import_iat_mess_and_dump():
    from variable import ROOTFS,pack_path,debug_level,src_level_trace,unpacking_mode
   
    # 1、发现oep
    ql = Qiling([rf"{pack_path}"], ROOTFS,verbose=debug_level)
    start_addr = ql.loader.pe_image_address
    end_start = ql.loader.pe_image_size + start_addr
    ctx = PeEmulation()
    ctx.seg_mess = get_segment_message()
    ctx.last_pc = ql.loader.entry_point
    

    if src_level_trace == 1:
        ql.hook_code(callback=src_trace,user_data=ctx,begin=start_addr,end=end_start)
    


    if unpacking_mode == CROSS_SEGMENT_MODE:
        ql.hook_code(callback=record_cross_segment_message,user_data=ctx,begin = start_addr,end=end_start)
        global RealOEP
        try:
            ql.run()
        except Exception as e:
            debug(e)
            debug("cross_segmen:")
            RealOEP = -1
            for seg in ctx.cross_segment_message:
                debug(f"[=>] {hex(seg[0])} ===>  {hex(seg[1])}")
                RealOEP = seg[1]
        if RealOEP == -1:
            print("unreach")
            assert 0
        debug(f"the oep is {hex(RealOEP)}")
        ql2 = Qiling([rf"{pack_path}"], ROOTFS,verbose=debug_level)
        ctx2 = PeEmulation()
        ctx2.seg_mess = get_segment_message()
        ctx2.last_pc = ql.loader.entry_point
        ctx2.realoep = RealOEP
        set_hooking_dll_loader(1)           # 设置hook
        ql2.hook_address(callback=arrive_oep_and_get_import_iat,address=RealOEP,user_data=ctx2)
        ql2.run()
        ptctx(ctx=ctx2)


    elif unpacking_mode == ESP_LAW_MODE:
        handle  = ql.hook_code(callback=find_first_push_ins,user_data=ctx,begin=start_addr,end=end_start)
        ctx.hook_queue["find_first_push_ins"] = handle
        ql.run()
        ptctx(ctx=ctx)
    else:
        assert 0
    
    
    global import_table_mess
    return import_table_mess


# def gaven_oep_op(ql:Qiling,userdata:PeEmulation):
#     get_import_table_message(ql=ql,userdata=userdata)


# def test_get_import_iat_mess_and_dump():
#     from variable import ROOTFS,pack_path,debug_level
   
#     ql = Qiling([rf"{ROOTFS}/{pack_path}"], ROOTFS,verbose=debug_level)
    
#     ctx = PeEmulation()
#     ctx.seg_mess = get_segment_message()

#     ql.hook_address(gaven_oep_op,0x042AEE0,user_data=ctx)
#     ql.run(end=0x042AEE3)
#     global import_table_mess
#     return import_table_mess



# def record_cross_segment_message(ql:Qiling,address:int,size:int,userdata:PeEmulation):
#     ctx : PeEmulation =  userdata
    
#     start_addr = ql.loader.pe_image_address
#     end_start = ql.loader.pe_image_size + start_addr
#     if address < start_addr or address > end_start:
#         return 
    
#     global Last_app_addr,trace_tagg
#     Last_app_addr = address
#     if trace_tagg == 1:
#         # print(hex(address))
#         from variable import Target_Mode,capstone_Arch,capstone_Mode
#         rip = 0
#         if Target_Mode == W_x64 or Target_Mode == L_X64:
#             rip = ql.arch.regs.read(WL_X64_RIP)
#         elif Target_Mode == W_x86 or Target_Mode == L_X86:
#             rip = ql.arch.regs.read(WL_X86_EIP)
#         else:
#             assert 0
#         x64code = ql.mem.read(rip,20)
#         CP = Cs(capstone_Arch, capstone_Mode)
#         for i in CP.disasm(x64code, rip + 0x29a00):
#             dis = format("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))  
#             print(dis)
#             break
#     if is_cross_segment_jump(src_addr=ctx.last_pc,target_addr=address,seg_mess=ctx.seg_mess):
#         from variable import Target_Mode

#         rip = -1
#         if Target_Mode == W_x64 or Target_Mode == L_X64:
#             rip = ql.arch.regs.read(WL_X64_RIP)
#         elif Target_Mode == W_x86 or Target_Mode == L_X86:
#             rip = ql.arch.regs.read(WL_X86_EIP)
#         else:
#             assert 0   
        
#         print(f"[=>] {hex(ctx.last_pc)} ===>  {hex(rip)}")
#         if rip == 0x401298:
#             trace_tagg = 1
        
#         ctx.last_pc = rip
        
#     else:
#         return 
# def get_oep():  # 这个oep没考虑tls
#     from variable import ROOTFS,pack_path
#     pe = lief.parse(rf"{ROOTFS}/{pack_path}")
#     return pe.optional_header.addressof_entrypoint + pe.optional_header.imagebase


# def Simulation_record_cross_jmp():
#     import time
#     start_time = time.time()
#     from variable import ROOTFS,pack_path,debug_level,Target_Mode

#     ql = Qiling([rf"{ROOTFS}/{pack_path}"], ROOTFS,verbose=debug_level,multithread=True)
    
#     seg_mess = get_segment_message()
#     rip = get_oep()  
    
#     start_addr = ql.loader.pe_image_address
#     mem_size = ql.loader.pe_image_size

    
#     ctx = PeEmulation()
#     handle = ql.hook_code(begin=start_addr,end=mem_size + start_addr,callback=record_cross_segment_message,user_data=ctx)
#     ctx.hook_queue["record_cross_segment_message"] = handle
#     ctx.seg_mess = seg_mess
#     ctx.last_pc = rip
#     try:
#         ql.run()
#     except Exception as e:
#         global Last_app_addr
#         print(e)
#         print(f"imagebase => {hex(ql.loader.pe_image_address)}")
#         print(hex(Last_app_addr))
#         end_time = time.time()
#         print(end_time - start_time)
#         dump_data = ql.mem.read(start_addr,mem_size)
#         fp = open("./undump.bin","wb")
#         fp.write(dump_data)
#         fp.close()



#         print("dis1.........................................................")
#         x64code = ql.mem.read(Last_app_addr-0x20,0x20)
#         from variable import capstone_Arch,capstone_Mode
#         CP = Cs(capstone_Arch, capstone_Mode)
#         for i in CP.disasm(x64code, Last_app_addr-0x20):
#             dis = format("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))  
#             print(dis)


#         print("dis2.........................................................")
#         x64code = ql.mem.read(Last_app_addr,0x20)
#         from variable import capstone_Arch,capstone_Mode
#         CP = Cs(capstone_Arch, capstone_Mode)
#         for i in CP.disasm(x64code, Last_app_addr):
#             dis = format("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))  
#             print(dis)
        
#         global RealOEP
#         RealOEP  = 0x042AF00
#         get_import_table_message(ql=ql,userdata=ctx)
        
#         global import_table_mess
#         return import_table_mess
#         # exit()