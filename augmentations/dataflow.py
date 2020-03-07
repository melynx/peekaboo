import argparse
import struct
import os

from tqdm import tqdm

import squirrel
import squirrel.vex_lifter as lifter
import squirrel.acorn.acorns_obj_pb2 as acorn_obj

import pypeekaboo

parser = argparse.ArgumentParser()
parser.add_argument("peekaboo_path")
parser.add_argument("--insn_id", default=None, type=int)
parser.add_argument("--debug_start", default=None, type=int)
parser.add_argument("--debug_print")
args = parser.parse_args()

class TraceDataflow(object):
    '''
    dataflow augment file is of the following format
    <num_insn 64bits> 
    <offsets to each taintrule object, size of taintrule object> (num_insn entries each 64bits*2)
    <TaintRule objects> (num_insn entries)
    '''
    def __init__(self, trace_path, num_insn):
        augment_path = os.path.join(trace_path, "dataflow.augment")
        self.augment_file = open(augment_path, "wb")
        bits = struct.pack("<Q", num_insn)
        self.augment_file.write(bits)
        self.augment_file.write(bytes(num_insn*8*2))

    def write_taintrule(self, insn_id, taintrule):
        bin_data = taintrule.SerializeToString()
        bin_size = len(bin_data)
        # get the current index
        cur_offset = self.augment_file.tell()
        self.augment_file.write(bin_data)
        # write the index
        pos = 8 + ((insn_id)  * 16)
        self.augment_file.seek(pos, 0)
        offset_size = struct.pack("<QQ", cur_offset, bin_size)
        self.augment_file.write(offset_size)
        self.augment_file.seek(0, 2)

def main():
    peekaboo = pypeekaboo.PyPeekaboo(args.peekaboo_path)
    augment = TraceDataflow(args.peekaboo_path, peekaboo.num_insn)
    #insn = peekaboo.get_insn(4)
    #print(peekaboo.arch_str)
    #print(insn.addr)
    #print(bytes(insn.rawbytes))
    #print(insn.num_mem)
    #print(insn.mem)
    #print(insn.regfile)

    if args.insn_id:
        insn_id = args.insn_id
        insn = peekaboo.get_insn(insn_id)
        bytestring = bytes(insn.rawbytes).hex()
        #print('--------')
        #print(bytestring)
        #print('--------')
        taintrule = lifter.get_flow(peekaboo.arch_str, 0x1000, bytestring)
        augment.write_taintrule(insn_id, taintrule)
        print(taintrule)
        return

    if args.debug_start:
        myrange = list(range(args.debug_start, peekaboo.num_insn))
    else:
        myrange = list(range(peekaboo.num_insn))
    for insn_id in tqdm(myrange):
        insn = peekaboo.get_insn(insn_id)
        bytestring = bytes(insn.rawbytes).hex()
        if args.debug_print:
            print('--------')
            print(bytestring)
            print('--------')
        taintrule = lifter.get_flow(peekaboo.arch_str, 0x1000, bytestring)
        augment.write_taintrule(insn_id, taintrule)

if __name__ == "__main__":
    main()
