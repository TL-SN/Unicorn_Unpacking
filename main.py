import lief
import argparse
import time
from FixImportTable import fix_import_table,fix_fist_thunk
from unicorn_unpack import get_import_iat_mess_and_dump
from variable import set_debug_level,set_pack_path,set_ROOTFS,set_unpack_path,set_Target_Mode,set_src_trace,set_dependency_Arch_Mode,set_unicorn_PE,set_unpacking_mode
from variable_const import *
import os
os.system('')

def is_vaild_name(name):
    if name.find("/") != -1 or name.find("\\")  != -1:
        raise argparse.ArgumentTypeError(f"{name} is not a valid file Name") 
    return name

def init_args() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        description="binary unpacking Tools",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "inp_file_Name",
        type=str,       # 参数类型 , 使用自定义的类型检查函数
        help="=> inp your file names(only name) , your file path must in roofs/x8664_windows/bin/"
    )
    
    parser.add_argument(
        "-o",
        "--output_name",
        type=str,
        help="=> specify a output file name (only name)"
    )
    parser.add_argument(
        "-l",
        "--debug_level",
        default=0,        
        type=int,
        nargs = "?", # 设置或不设置
        help="=> set debug level (0 or 1)"
    )
    # parser.add_argument(
    #     "-k",
    #     "--kernel",
    #     default=0,        
    #     type=int,
    #     nargs = "?", # 设置或不设置
    #     help="=> set kernel Mode (0 or 1)"
    # )
    
    parser.add_argument(
        "-t",
        "--trace_src",
        default=0,        
        type=int,
        nargs = "?", # 设置或不设置
        help="=> set trace (0 or 1)"
    )
    parser.add_argument(
        "-p",
        "--set_unicorn_PE?",
        default=0,        
        type=int,
        nargs = "?", # 设置或不设置
        help="=> set dump (0 or 1)"
    )
    parser.add_argument(
        "-m",
        "--unpack_mode",
        default=1,        
        type=int,
        nargs = "?", # 设置或不设置
        help="=> set dump (1 or 2)  1=>esp unpacker 2=> cross_seg unpacker"
    )


    return parser.parse_args()


def main():
    args = init_args()
    pack_path = args.inp_file_Name        # 脱壳程序的路径
    unpack_path = args.output_name        # 脱壳后的文件生成路径 
    debug_level = args.debug_level
    src_level_trace  = args.trace_src
    unpacking_mode = args.unpack_mode
    if unpack_path == None:
        if unpack_path.find(".exe") != -1:
            unpack_path = unpack_path[:len(unpack_path)-4] + "_unicorn.exe"
        else:
            unpack_path = unpack_path + "_unicorn.exe"
    txt = '''
\033[31m#####################################################################################
#   Ok, plz set your qiling ROOTFS_path before you play me                                  #
#                                                                                           #           
#####################################################################################\033[0m
    '''
    print(txt)
    # unicorn_PE = 0

    
    # debug_level = 0  # only 0 or 1
    # pack_path = r"D:\Python\Environment\Python_3.87\install_pack_by_myself\qiling\examples\rootfs\x8664_windows\bin\Selected_x86_upx.exe"    # "./Selected_x86_upx.exe or .\Selected_x86_upx.exe are wrong!!! "
    # unpack_path = "Selected_x86_upx.unicorn.exe"
    # src_level_trace = 0               # 提供地址trace
    # unpacking_mode =1                 # mode1是esp定律，mode2是跨段跳转判断
    
    
    set_pack_path(pack_path)
    set_unpack_path(unpack_path)
    set_debug_level(debug=debug_level)
    set_dependency_Arch_Mode(Mode=W_x86)
    set_unpacking_mode(mode=unpacking_mode)
    set_src_trace(src_trace=src_level_trace)
    # handle_unicorn_PE(unicorn_PE) 待开发
    


    print("")
    print(rf"The srcFile path is {pack_path}")
    print(rf"The target file path is {unpack_path}")
    print(f"The debug level is {debug_level}")
    print("")

    # import_table_mess = test_get_import_iat_mess_and_dump()
    # import_table_mess = Simulation_record_cross_jmp()


    # 1、qiling运行至oep，然后进行dump
    import_table_mess = get_import_iat_mess_and_dump()
    
    # 2、修复dump文件的导入表
    pe_dumped = lief.parse(unpack_path)
    fix_import_table(pe_dumped,import_table_mess)

    # 3、修复firstthunk字段
    fix_fist_thunk(unpack_path,import_table_mess)
    
    print(f"the out file is {unpack_path}")
    
   
def set_some_confige():
    fp = open("./confige.txt","r")
    all_data = fp.readlines()
    ROOTFS_path = ""
    for line in all_data:
        if "ROOTFS_path" in line:
            idx = line.find("=")
            ROOTFS_path = line[idx+1:].strip()
    
    if ROOTFS_path != "":
        set_ROOTFS(path=ROOTFS_path)
    else:
        print("you should set your qiling ROOTFS_path in confige.txt")
        assert 0
    
        

if __name__ == "__main__":
    set_some_confige()
    start = time.time()
    main()
    end = time.time()
    print(f"The time consumed is {end -start}s")

    