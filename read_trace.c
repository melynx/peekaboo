/* 
 * Copyright 2019 Chua Zheng Leong
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     https://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* This is a simple trace reader for reading peekaboo traces. */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <math.h>

#ifdef ASM
    // binutils-dev >= 2.29 required
    #include <dis-asm.h>
#endif

// Print how many instructions if block matches
#define PRINT_NEXT 100

#include "libpeekaboo/libpeekaboo.h"

// The instruction raw bytes you are looking for
unsigned char target_block[] = {
    /*
    "\x48\x89\xe7"
    "\xe8\x78\x0d\x00\x00"
    "\x55"
    */
    "\x48\x8d\x3c\x97"
};


// What you want to include in ouput?
// Users can edit print_filter() to modify these booleans during runtime.
bool print_disasm   = true;
bool print_memory   = false;
bool print_register = false;

// Structure
struct circular_buffer_t {
    char* buffer;
    size_t head;
    size_t size;
};
uint32_t print_next = 0;


bool print_filter(peekaboo_insn_t *insn, size_t insn_idx, const size_t num_insn)
{
    /* Return true to print this instruction. Otherwise, skip this instruction printing. */
    bool rvalue;

    // KH: If no target block, then by default print everything
    if (sizeof(target_block) == 0)
        rvalue = true;
    else
        rvalue = false;

    // If print_next, then overide return value
    if (print_next)
    {
        print_next--;
        rvalue = true;
    }

    // Detailed settings for what to print
    /*
    if (insn_idx == num_insn)
    {
        print_register  = true;
        print_memory    = true;
    }
    else
    {
        print_register  = false;
        print_memory    = false;    
    }
    */

   return rvalue;
}

static void display_usage(char *program_name)
{
    printf("Usage: %s <trace_dir>\n", program_name);
    printf("\t<trace_dir>: Path to the sub directory of a process/thread. e.g. ~/ls-31401/31401\n");
    exit(0);
}

#ifdef ASM
/* Disassemble and print instruction */
int disassemble_raw(const enum ARCH arch, const bool big_endian, uint8_t *input_buffer, const size_t input_buffer_size) 
{
    disassemble_info disasm_info = {};
    init_disassemble_info(&disasm_info, stdout, (fprintf_ftype) fprintf);
    switch(arch)
    {
        case (ARCH_AMD64):
            disasm_info.arch = bfd_arch_i386;
            disasm_info.mach = bfd_mach_x86_64;
            break;
        case (ARCH_X86):
            disasm_info.arch = bfd_arch_i386;
            disasm_info.mach = bfd_mach_i386_i386;
            break;
        case (ARCH_AARCH64):
            disasm_info.arch = bfd_arch_aarch64;
            disasm_info.mach = bfd_mach_aarch64;
            break;
        case (ARCH_AARCH32):
            disasm_info.arch = bfd_arch_aarch64;
            disasm_info.mach = bfd_mach_aarch64_ilp32;
            break;        
        default:
            perror("Arch not supported!");
            return -1;
    }
    if (big_endian)
        disasm_info.endian = BFD_ENDIAN_BIG;
    else
        disasm_info.endian = BFD_ENDIAN_LITTLE;
    disasm_info.read_memory_func = buffer_read_memory;
    disasm_info.buffer = input_buffer;
    disasm_info.buffer_vma = 0;
    disasm_info.buffer_length = input_buffer_size;
    disassemble_init_for_target(&disasm_info);

    disassembler_ftype disasm;
    disasm = disassembler(disasm_info.arch, big_endian, disasm_info.mach, NULL);

    for (size_t pc = 0; pc < input_buffer_size;) 
        pc += disasm(pc, &disasm_info);

    return 0;
}
#endif

void update_raw_byte_buffer(struct circular_buffer_t *raw_bytes_buffer_ptr, char const *cur_insn_rawbytes, const uint32_t cur_insn_size)
{
    for (size_t idx = 0; idx < cur_insn_size; idx++)
    {
        raw_bytes_buffer_ptr->buffer[raw_bytes_buffer_ptr->head] = cur_insn_rawbytes[idx];
        raw_bytes_buffer_ptr->head = (raw_bytes_buffer_ptr->head + 1) % raw_bytes_buffer_ptr->size;
    }
}

bool is_buffer_matched(struct circular_buffer_t const* raw_bytes_buffer_ptr, char *target_buffer, const uint32_t target_buffer_size)
{
    size_t cur_head = raw_bytes_buffer_ptr->head;
    bool matched = true;

    for (int64_t idx = target_buffer_size - 1; idx >= 0; idx--)
    {
        if (cur_head == 0)
            cur_head = raw_bytes_buffer_ptr->size - 1; 
        else
            cur_head--;
        uint8_t byte_in_buffer = raw_bytes_buffer_ptr->buffer[cur_head] & 0xff;
        uint8_t byte_in_target = target_buffer[idx] & 0xff;
        if (byte_in_buffer != byte_in_target)
        {
            matched = false;
            break;
        }
    }
    return matched;
}

int main(int argc, char *argv[])
{
    // Argument check
    if (argc!=2) display_usage(argv[0]);

    // Print current libpeekaboo version
    fprintf(stderr, "libpeekaboo version: %d\n", LIBPEEKABOO_VER);

    // Load trace
    char *trace_path = argv[1];
    peekaboo_trace_t mytrace;
    load_trace(trace_path, &mytrace);

    // Get and print the length of the trace
    const size_t num_insn = get_num_insn(&mytrace);
    printf("Total instructions: %ld\n", num_insn);

    uint8_t digits = (uint8_t) log10(num_insn);

    // Maintain a buffer to store rawbytes
    size_t block_size;
    if (sizeof(target_block))
        block_size = sizeof(target_block) - 1;
    else
        block_size = 0;
    struct circular_buffer_t raw_bytes_buffer;
    raw_bytes_buffer.buffer = malloc(block_size);
    if (raw_bytes_buffer.buffer == NULL) PEEKABOO_DIE("Fail to malloc circular buffer.");
    raw_bytes_buffer.head = 0;
    raw_bytes_buffer.size = block_size;
    uint64_t num_found_block = 0;

    // We print all instructions sequentially. 
    // Please note the first instruction's index is 1, instead of 0.
    for (size_t insn_idx=1; insn_idx<=num_insn; insn_idx++)
    {
        // Get instruction ptr by instruction index
        peekaboo_insn_t *insn = get_peekaboo_insn(insn_idx, &mytrace);
        
        // Update buffer and check buffer
        if (block_size)
        {
            update_raw_byte_buffer(&raw_bytes_buffer, insn->rawbytes, insn->size);
            if (is_buffer_matched(&raw_bytes_buffer, target_block, block_size))
            {
                num_found_block ++;
                print_next = PRINT_NEXT;
                printf("\n[Target block %lu] ends at 0x%"PRIx64". Print next %d instructions:\n", num_found_block, insn->addr, print_next);
            }
        }

        // Call print_filter() to decide what should be printed
        if (!print_filter(insn, insn_idx, num_insn))
        {
            free_peekaboo_insn(insn);
            continue;
        }

        // Print instruction index
        printf("[%lu] ", insn_idx);
        if (!print_memory && !print_register)
            for (uint8_t idx = (uint8_t)log10f(insn_idx); idx < digits; idx++) printf(" ");

        // Print instruction ea
        printf("0x%"PRIx64"", insn->addr);
        
        // Print Rawbytes
        printf(":\t ");
        for (uint8_t rawbyte_idx = 0; rawbyte_idx < insn->size; rawbyte_idx++)
        {
            if (insn->rawbytes[rawbyte_idx] < 16) printf("0");
            printf("%"PRIx8" ", insn->rawbytes[rawbyte_idx]);
        }

        // Print disassemble for instructions using libopcodes
        if (print_disasm) 
        {
            #ifdef ASM
            // Pretty print 
            for (uint8_t idx = insn->size; idx < 8; idx++) printf("   ");
            printf("\t");

            // Disasmble the instruction
            int rvalue = disassemble_raw((enum ARCH)mytrace.internal->arch, false, insn->rawbytes, insn->size);
            if(rvalue != 0) exit(1);
            #endif
        }
        printf("\n");

        // Print memory ops
        if (print_memory && (insn->num_mem > 0))
        {
            for (uint32_t mem_idx = 0; mem_idx < insn->num_mem; mem_idx++)
            {
                printf("\t");
                printf(insn->mem[mem_idx].status ? "Memory Write: " : "Memory Read: ");
                printf("%d bytes @ 0x%lx\n", insn->mem[mem_idx].size, insn->mem[mem_idx].addr);

                // Assert fails at this line? Delete memrefs_offsets in trace folder and try again.
                assert(insn->mem[mem_idx].status==0 || insn->mem[mem_idx].status==1);
            }
        }

        // Print GPRs
        if (print_register) regfile_pp(insn);

        // Free instruction ptr
        free_peekaboo_insn(insn);
    }

    free(raw_bytes_buffer.buffer);
    return 0;
}