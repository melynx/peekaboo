use std::fs;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::collections::HashMap;
use std::mem::size_of;
use std::mem::transmute;

struct PeekabooInsn {
    pc: u64,
    rawbytes: Vec<u8>,
}

struct PeekabooTrace {
    peekaboo_dir: String,
    insn_trace: File,
    bytes_hashmap: HashMap<u64, Vec<u8>>,
}

#[repr(C)]
struct BytesMapEntry {
    pc: u64,
    size: u32,
    rawbytes: [u8; 16],
}

impl PeekabooTrace {
    fn create_bytesmap(bytesmap_path: &str) -> HashMap<u64, Vec<u8>> {
        let mut bytes_hashmap: HashMap<u64, Vec<u8>> = HashMap::new();
        let mut bytesmap_file = File::open(bytesmap_path).unwrap();
        let mut buf = [0u8; size_of::<BytesMapEntry>()];
        while let Ok(n) = bytesmap_file.read(&mut buf) {
            if n == 0 { break; }
            let entry = unsafe { transmute::<[u8; size_of::<BytesMapEntry>()], BytesMapEntry>(buf) };
            bytes_hashmap.insert(entry.pc, entry.rawbytes[ .. entry.size as usize].to_vec());
        }
        bytes_hashmap
    }

    fn new(peekaboo_dir: &str) -> PeekabooTrace {
        let insn_trace_file = File::open([peekaboo_dir, "insn.trace"].iter().collect::<PathBuf>()).unwrap();
        let bytes_hashmap = PeekabooTrace::create_bytesmap([peekaboo_dir, "insn.bytemap"].iter().collect::<PathBuf>().to_str().unwrap());
        PeekabooTrace {
            peekaboo_dir: String::from(peekaboo_dir),
            insn_trace: insn_trace_file,
            bytes_hashmap: bytes_hashmap,
        }
    }

    fn num_insns(&self) -> u64 {
        let trace_index_path: PathBuf = [&self.peekaboo_dir[..], "insn.trace"].iter().collect();
        fs::metadata(trace_index_path).unwrap().len() / 8
    }

    fn get_ea(&mut self, insn_id: &u64) -> u64 {
        let mut buf = [0; 8];
        self.insn_trace.seek(SeekFrom::Start(insn_id*8)).unwrap();
        self.insn_trace.read(&mut buf).unwrap();
        u64::from_le_bytes(buf)
    }

    fn get_insn(&mut self, insn_id: &u64) -> PeekabooInsn {
        let insn_pc = self.get_ea(&insn_id);
        let insn_rawbytes = self.bytes_hashmap.get(&insn_pc).unwrap();
        PeekabooInsn {
            pc: insn_pc,
            rawbytes: insn_rawbytes.to_vec(),
        }
    }
}

fn main() {
    let mut peekaboo_trace = PeekabooTrace::new("../ls-22797-22797");
    let num_insn = peekaboo_trace.num_insns();
    println!("Num insns: {}", num_insn);
    for insn_id in 0..num_insn {
        let cur_insn = peekaboo_trace.get_insn(&insn_id);
        println!("{}: {:#x} - {:?}", insn_id, cur_insn.pc, cur_insn.rawbytes);
    };
}
