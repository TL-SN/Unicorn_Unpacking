W_x86 = 1
W_x64 = 2


L_X86 = 16
L_X64 = 32

WL_X86_EAX = "eax"
WL_X86_EBX = "ebx"
WL_X86_ECX = "ecx"
WL_X86_EDX = "edx"
WL_X86_ESI = "esi"
WL_X86_EDI = "edi"
WL_X86_EBP = "ebp"
WL_X86_ESP = "esp"
WL_X86_EIP = "eip"


WL_X64_EAX = "rax"
WL_X64_RBX = "rbx"
WL_X64_RCX = "rcx"
WL_X64_RDX = "rdx"
WL_X64_RSI = "rsi"
WL_X64_RDI = "rdi"
WL_X64_RBP = "rbp"
WL_X64_RSP = "rsp"
WL_X64_RIP = "rip"


class iat_table:
    def __init__(self):
        self.dll_name = ""
        self.dll_base = -1
        self.dll_load_addr = -1
        self.fun_name = []
        self.fun_addr = []
        self.fun_load_addr = []

class PeEmulation:
    def __init__(self):
        self.hook_queue = {}
        self.seg_mess = []
        self.last_pc = 0