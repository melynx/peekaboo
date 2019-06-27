import os
import sys
import struct

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


class TraceInsn(object):
    def __init__(self):
        pass

class MemInfo(object):
    def __init__(self):
        pass

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

        self.memrefs_offsets = self.load_memrefs_offsets(trace_path)
        self.num_insn = os.path.getsize(insn_trace_path) / sizeof(InsnRef)

        # parse the bytemaps
        self.bytesmap = {}
        bytesmap_entry = BytesMap()
        while self.insn_bytemap.readinto(bytesmap_entry) == sizeof(bytesmap_entry):
            self.bytesmap[bytesmap_entry.pc] = [x for x in bytesmap_entry.rawbytes][:bytesmap_entry.size]

    def load_memrefs_offsets(self, trace_path):
        memrefs_offsets_path = os.path.join(trace_path, 'memrefs_offsets')
        if not os.path.isfile(memrefs_offsets_path):
            # memfile offsets for each insn does not exist, create them
            # generate the memfile offsets
            with open(memrefs_offsets_path, 'wb') as offset_file:
                cur_offset = 0
                memfile_offsets = []
                memref_entry = MemRef()
                while self.memrefs.readinto(memref_entry) == sizeof(memref_entry):
                    if memref_entry.length:
                        offset_file.write(struct.pack('<Q', cur_offset))
                        cur_offset += sizeof(MemFile) * memref_entry.length
                    else:
                        # 63rd bit tell us if its valid or not, 0 is valid, 1 is not
                        offset_file.write(struct.pack('<Q', 2**63))
        return open(memrefs_offsets_path, 'rb')

    def get_insn(self, insn_id):
        my_insn = TraceInsn()

        x = InsnRef()
        self.insn_trace.seek(insn_id * sizeof(InsnRef))
        assert(self.insn_trace.readinto(x) == sizeof(InsnRef))
        my_insn.addr = x.pc
        my_insn.rawbytes = self.bytesmap[x.pc]

        x = MemRef()
        self.memrefs.seek(insn_id * sizeof(MemRef))
        assert(self.memrefs.readinto(x) == sizeof(MemRef))
        my_insn.num_mem = x.length


        my_insn.mem = []
        if my_insn.num_mem:
            self.memrefs_offsets.seek(insn_id * 8)
            for _ in range(my_insn.num_mem):
                buf = self.memrefs_offsets.read(8)
                memref_offset = struct.unpack('<Q', buf)[0]
                memfile = MemFile()
                self.memfile.seek(memref_offset)
                assert(self.memfile.readinto(memfile)==sizeof(MemFile))
                print(memfile)

        return my_insn

    
    def pp(self):
        insn_ref = InsnRef()
        while self.insn_trace.readinto(insn_ref) == sizeof(InsnRef):
            rawbytes = self.bytesmap[insn_ref.pc]
            print("{}\t: {}".format(hex(insn_ref.pc), [hex(x) for x in rawbytes]))

