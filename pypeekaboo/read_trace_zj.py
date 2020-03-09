import os
import struct
import sys

from ctypes import Structure, c_uint64, c_uint32, c_uint16, c_uint8, sizeof


class amd64_cpu_gr(Structure):
    _fields_ = [('rdi', c_uint64),
                ('rsi', c_uint64),
                ('rsp', c_uint64),
                ('rbp', c_uint64),
                ('rbx', c_uint64),
                ('rdx', c_uint64),
                ('rcx', c_uint64),
                ('rax', c_uint64),
                ('r8', c_uint64),
                ('r9', c_uint64),
                ('r10', c_uint64),
                ('r11', c_uint64),
                ('r12', c_uint64),
                ('r13', c_uint64),
                ('r14', c_uint64),
                ('r15', c_uint64),
                ('rflags', c_uint64),
                ('rip', c_uint64)]


class amd64_cpu_simd(Structure):
    _fields_ = [('ymm0', c_uint64*4),
                ('ymm1', c_uint64*4),
                ('ymm2', c_uint64*4),
                ('ymm3', c_uint64*4),
                ('ymm4', c_uint64*4),
                ('ymm5', c_uint64*4),
                ('ymm6', c_uint64*4),
                ('ymm7', c_uint64*4),
                ('ymm8', c_uint64*4),
                ('ymm9', c_uint64*4),
                ('ymm10', c_uint64*4),
                ('ymm11', c_uint64*4),
                ('ymm12', c_uint64*4),
                ('ymm13', c_uint64*4),
                ('ymm14', c_uint64*4),
                ('ymm15', c_uint64*4)]

class fxsave_area(Structure):
    _fields_ = [('fcw', c_uint16),
                ('fsw', c_uint16),
                ('ftw', c_uint8),
                ('reserved_1', c_uint8),
                ('fop', c_uint16),
                ('fpu_ip', c_uint32),
                ('fpu_cs', c_uint16),
                ('reserved_2', c_uint16),
                ('fpu_dp', c_uint32),
                ('fpu_ds', c_uint16),
                ('reserved_3', c_uint16),
                ('mxcsr', c_uint32),
                ('mxcsr_mask', c_uint32),
                ('st_mm', c_uint64*2*8),
                ('xmm', c_uint64*2*16),
                ('padding', c_uint8*96)]


class x86_cpu_gr(Structure):
    _fields_ = [('eax', c_uint32),
                ('ecx', c_uint32),
                ('edx', c_uint32),
                ('ebx', c_uint32),
                ('esp', c_uint32),
                ('ebp', c_uint32),
                ('esi', c_uint32),
                ('edi', c_uint32),]


class regfile_amd64(Structure):
    _fields_ = [('gr', amd64_cpu_gr),
                ('simd', amd64_cpu_simd),
                ('fxsave', fxsave_area)]


class regfile_x86(Structure):
    _fields_ = [('gr', x86_cpu_gr)]


class insn_ref(Structure):
    _fields_ = [('pc', c_uint64)]


class bytes_map(Structure):
    _fields_ = [('pc', c_uint32),
                ('x86_to_x64', c_uint32),
                ('size', c_uint32),
                ('rawbytes', c_uint8 * 16)]


class mem_ref(Structure):
    _fields_ = [('length', c_uint32)]


class mem_file(Structure):
    _fields_ = [('addr', c_uint64),
               ('value', c_uint64),
               ('size', c_uint32),
               ('status', c_uint32)]

class peekaboo_insn_t():
    def __int__(self):
        self.addr = None
        self.rawbytes = None
        self.regfile = None
        self.memref = None
        self.memfile = None

class trace_read():
    def __init__(self, trace_path):
        insn_trace_path = os.path.join(trace_path, 'insn.trace')
        insn_bytemap_path = os.path.join(trace_path, 'insn.bytemap')
        regfile_path = os.path.join(trace_path, 'regfile')
        memrefs_path = os.path.join(trace_path, 'memrefs')
        memfile_path = os.path.join(trace_path, 'memfile')

        self.insn_trace = open(insn_trace_path, 'rb')
        self.insn_bytemap = open(insn_bytemap_path, 'rb')
        self.regfile = open(regfile_path, 'rb')
        self.memrefs = open(memrefs_path, 'rb')
        self.memfile = open(memfile_path, 'rb')

        self.num_insn = int(os.path.getsize(insn_trace_path) / sizeof(insn_ref))

    def get_peekaboo_insn(self, id, arch): # arch: 0 x86, 1 amd64
        id_insn = peekaboo_insn_t()

        # read pc
        insnref_entry = insn_ref()
        self.insn_trace.seek(sizeof(insn_ref) * id)
        self.insn_trace.readinto(insnref_entry)
        id_insn.addr = insnref_entry

        # read raw bytes
        bytesmap_entry = bytes_map()
        self.insn_bytemap.seek(sizeof(bytes_map) * id)
        self.insn_bytemap.readinto(bytesmap_entry)
        id_insn.rawbytes = bytesmap_entry

        # read register information
        # amd64
        if arch:
            regfile_entry = regfile_amd64()
            self.regfile.seek(sizeof(regfile_amd64) * id)
            self.regfile.readinto(regfile_entry)
            id_insn.regfile = regfile_entry

        # x86
        else:
            regfile_entry = regfile_x86()
            self.regfile.seek(sizeof(regfile_x86) * id)
            self.regfile.readinto(regfile_entry)
            id_insn.regfile = regfile_entry

        # read memory ref information
        memref_entry = mem_ref()
        self.memrefs.seek(sizeof(mem_ref) * id)
        self.memrefs.readinto(memref_entry)
        id_insn.memref = memref_entry

        # read memory information
        memref_entries = []
        for i in range(id):
            memref_entry = mem_ref()
            self.memrefs.seek(sizeof(mem_ref) * i)
            self.memrefs.readinto(memref_entry)
            memref_entries.append(memref_entry.length)

        memfile_entries = []
        for i in range(id_insn.memref.length):
            memfile_entry = mem_file()
            self.memfile.seek(sizeof(mem_file) * (sum(memref_entries) + i))
            self.memfile.readinto(memfile_entry)
            memfile_entries.append(memfile_entry)
        id_insn.memfile = memfile_entries
        return id_insn


def main():
    if len(sys.argv) != 4:
        print("Input format: trace_folder insn_id arch (x86:0 amd64:1)\nExample: python read_trace_zj.py ls-xx-xx 10 0")	
	return
    trace_path = sys.argv[1]
    insn_id = int(sys.argv[2])
    arch = int(sys.argv[3])

    x = trace_read(trace_path)

    print("number of instructions: %d"% (x.num_insn))

    insn = x.get_peekaboo_insn(insn_id, arch)

    print("\naddress information")
    print("pc: %#x" % insn.addr.pc)

    print("pc: %x" % insn.rawbytes.pc)
    print("size: %d"%insn.rawbytes.size)
    print("rawbyte: %s"%[hex(x) for x in insn.rawbytes.rawbytes][:insn.rawbytes.size])

    print("\nregister info")
    print("\teax: %#x"%insn.regfile.gr.eax)
    print("\tebx: %#x"%insn.regfile.gr.ebx)
    print("\tecx: %#x"%insn.regfile.gr.ecx)
    print("\tedx: %#x"%insn.regfile.gr.edx)
    print("\tesi: %#x"%insn.regfile.gr.esi)
    print("\tedi: %#x"%insn.regfile.gr.edi)
    print("\tesp: %#x"%insn.regfile.gr.esp)
    print("\tebp: %#x"%insn.regfile.gr.ebp)

    for j in range(insn.memref.length):
        print("\nmemory info")
        print("\taddr: %#x"%insn.memfile[j].addr)
        print("\tvalue: %d"%insn.memfile[j].value)
        print("\tsize: %#d"%insn.memfile[j].size)
        print("\tstatus: %#d\n"%insn.memfile[j].status)

if __name__ == "__main__":
    main()






