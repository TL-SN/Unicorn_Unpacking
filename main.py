import lief
import argparse
import pathlib
from FixImportTable import fix_import_table,fix_fist_thunk
from unicorn_unpack import get_import_iat_mess_and_dump
from variable import set_debug_level,set_dump_path,set_ROOTFS,set_unpack_path,set_Target_Mode,W_x86,W_x64,set_dependency_Arch_Mode


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
        type=is_vaild_name,       # 参数类型 , 使用自定义的类型检查函数
        help="inp your file names(only name) , your file path must in roofs/x8664_windows/bin/",
    )
    
    parser.add_argument(
        "-o",
        "--output_name",
        type=is_vaild_name,
        help="specify a output file name (only name)",
    )
    parser.add_argument(
        "-l",
        "--debug_level",
        default=0,        
        type=int,
        nargs = "?", # 设置或不设置
        help="set debug level (0 or 1)",
    )

    return parser.parse_args()


def main():
    # args = init_args()
    # unpack_path = args.inp_file_Name
    # dump_path = args.output_name
    # debug_level = args.debug_level
    # if dump_path == None:
    #     if unpack_path.find(".exe") != -1:
    #         dump_path = unpack_path[:len(unpack_path)-4] + "_unicorn.exe"
    #     else:
    #         dump_path = unpack_path + "_unicorn.exe"
    txt = '''
\033[1;31;40m#####################################################################################
#   Ok, plz set your qiling ROOTFS_path、debug_level、unpack_path、dump_path        #
#   put your file in the dir of ROOTFS_path/bin/                                    #
#   Watch your path!!!:                                                             #
#       ./Selected_x86_upx.exe  x                                                   #
#       Selected_x86_upx.exe    √                                                   #
#####################################################################################\033[0m
    '''
    print(txt)
    
    debug_level = 1  # only 0 or 1
    unpack_path = "Selected_x86_upx.exe"    # "./Selected_x86_upx.exe or .\Selected_x86_upx.exe are wrong!!! "
    dump_path = "Selected_x86_upx_unicorn.exe"
    ROOTFS_path="D:/Python/Environment/Python_3.87/install_pack_by_myself/qiling/examples/rootfs/x86_windows" # set your qiling ROOTS
    set_ROOTFS(path=ROOTFS_path)
    set_unpack_path("bin/" + unpack_path)
    set_dump_path(dump_path)
    set_debug_level(debug=debug_level)
    set_dependency_Arch_Mode(Mode=W_x86)
    

    print("")
    print(rf"The srcFile path is {ROOTFS_path}/bin/{unpack_path}")
    print(rf"The target file path is {pathlib.Path.cwd()}\{dump_path}")
    print(f"The debug level is {debug_level}")
    print("")

    # 1、qiling运行至oep，然后进行dump
    # 加上个dll地址判断可能会更好
    import_table_mess = get_import_iat_mess_and_dump()
    
    # 2、修复dump文件的导入表
    pe_dumped = lief.parse(dump_path)
    fix_import_table(pe_dumped,import_table_mess)

    # 3、修复firstthunk字段
    fix_fist_thunk(dump_path,import_table_mess)
    
    print(f"the out file is {dump_path}")
    
   

if __name__ == "__main__":
    main()

    