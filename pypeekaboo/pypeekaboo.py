import os
import sys

from ctypes import Structure, c_uint64, c_uint32, c_uint8, sizeof

'''
typedef struct insn_ref {
	uint64_t pc;
} insn_ref_t;
'''
class InsnRef(Structure):
    _fields_ = [('pc', c_uint64)]

'''
typedef struct bytes_map {
	uint64_t pc;
	uint32_t size;
	uint8_t rawbytes[16];
} bytes_map_t ;
'''
class BytesMap(Structure):
    _fields_ = [('pc', c_uint64), ('size', c_uint32), ('rawbytes', c_uint8*16)]

'''
typedef struct {
	uint32_t length;	/* how many refs are there*/
} memref_t;
'''
class MemRef(Structure):
    _fields_ = [('length', c_uint32)]

'''
typedef struct {
	uint64_t addr;		/* memory address */
	uint64_t value;		/* memory value */
	uint32_t size;		/* how many bits are vaild in value */
	uint32_t status; 	/* 0 for Read, 1 for write */
} memfile_t;
'''
class MemFile(Structure):
    _fields_ = [('addr', c_uint64), ('value', c_uint64), ('size', c_uint32), ('status', c_uint32)]

class PyPeekaboo(object):
    def __init__(self, trace_path):
        # ensure that path points to a directory...
        assert(os.path.isdir(trace_path))
        # ensure that the basic structure is correct
        insn_trace_path = os.path.join(trace_path, 'insn.trace')
        insn_bytemap_path = os.path.join(trace_path, 'insn.bytemap')
        regfile_path = os.path.join(trace_path, 'regfile')
        memfile_path = os.path.join(trace_path, 'memfile')
        memrefs_path = os.path.join(trace_path, 'memrefs')
        metafile_path = os.path.join(trace_path, 'metafile')
        assert(os.path.isfile(insn_trace_path))
        assert(os.path.isfile(insn_bytemap_path))
        assert(os.path.isfile(regfile_path))
        assert(os.path.isfile(memfile_path))
        assert(os.path.isfile(memrefs_path))
        assert(os.path.isfile(metafile_path))

        # open up the files
        self.insn_trace = open(insn_trace_path, 'rb')
        self.insn_bytemap = open(insn_bytemap_path, 'rb')
        self.regfile = open(regfile_path, 'rb')
        self.memfile = open(memfile_path, 'rb')
        self.memrefs = open(memrefs_path, 'rb')
        self.metafile = open(metafile_path, 'rb')

        self.num_insn = os.path.getsize(insn_trace_path) / sizeof(InsnRef)

        # parse the bytemaps
        self.bytesmap = {}
        bytesmap_entry = BytesMap()
        while self.insn_bytemap.readinto(bytesmap_entry) == sizeof(bytesmap_entry):
            self.bytesmap[bytesmap_entry.pc] = [x for x in bytesmap_entry.rawbytes][:bytesmap_entry.size]

        # generate the memfile offsets
        cur_offset = 0
        self.memfile_offsets = []
        memref_entry = MemRef()
        while self.memrefs.readinto(memref_entry) == sizeof(memref_entry):
            if memref_entry.length:
                self.memfile_offsets.append(cur_offset)
            else:
                self.memfile_offsets.append(None)
            cur_offset += sizeof(MemFile)

        # print(self.memfile_offsets)
    
    def pp(self):
        insn_ref = InsnRef()
        while self.insn_trace.readinto(insn_ref) == sizeof(InsnRef):
            rawbytes = self.bytesmap[insn_ref.pc]
            print("{}\t: {}".format(hex(insn_ref.pc), [hex(x) for x in rawbytes]))

