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

/* This is a trace reader for reading peekaboo traces. */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <math.h>
#include <unistd.h>


#include "libpeekaboo/libpeekaboo.h"

#ifdef ASM
    // binutils-dev >= 2.29 required
    #include <dis-asm.h>
#endif

// Print how many instructions if block matches
#define PRINT_NEXT 30

#define BUFFER_SIZE 512

// The instruction raw bytes you are looking for
unsigned char* target_block = NULL;

// What you want to include in ouput?
// Users can edit print_filter() to modify these booleans during runtime.
bool print_disasm   = true;
bool print_memory   = false;
bool print_register = false;

// Start? End?
size_t loop_starts = 1;
int loop_ends = 0; // Default is 0 for printing till the end

// Target memory address 
uint64_t target_addr = (uint64_t) -1;

// Structure
struct circular_buffer_t {
    char* buffer;
    size_t head;
    size_t size;
};
uint32_t print_next = 0;


bool print_filter(peekaboo_insn_t *insn, size_t insn_idx, const size_t num_insn, const bool is_search)
{
    /* Return true to print this instruction. Otherwise, skip this instruction printing. */
    bool rvalue;

    // KH: If no target block, then by default print everything
    if (is_search)
        rvalue = false;
    else
        rvalue = true;

    if (target_addr != (uint64_t) -1)
    {
        rvalue = false;
        if (insn->num_mem > 0)
        {
            for (uint32_t mem_idx = 0; mem_idx < insn->num_mem; mem_idx++)
            {
                if (target_addr >= insn->mem[mem_idx].addr 
                    &&
                    target_addr < insn->mem[mem_idx].addr + insn->mem[mem_idx].size)
                {
                    rvalue = true;
                    break;
                }
            }
        }
    }

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

int hexchar_to_uint8(uint8_t *output_uint8_ptr, const char input_char)
{
    if (input_char >= '0' && input_char <= '9')
    {
        *output_uint8_ptr = input_char - '0';
        return 0;
    }
    if (input_char >= 'A' && input_char <= 'F')
    {
        *output_uint8_ptr = input_char - 'A' + 10;
        return 0;
    }
    if (input_char >= 'a' && input_char <= 'f')
    {
        *output_uint8_ptr = input_char - 'a' + 10;
        return 0;
    }
    return -1;
}

/* Covert hex string into uint8_t array*/
int hex_string_to_uint8_arrary(uint8_t *uint8_array, const char *hex_string)
{
    int size = 0;
    while(hex_string[0] && hex_string[1])
    {
        uint8_t output[2];
        if (hexchar_to_uint8(&output[0], hex_string[0])==0 && hexchar_to_uint8(&output[1], hex_string[1])==0)
        {
            uint8_array[size++] = output[0] * 16 + output[1];
        }
        else return -1;
        hex_string += 2;
    }
    return size;
}

#ifdef ASM
/* Disassemble and print instruction */
int disassemble_raw(const enum ARCH arch, const bool is_big_endian, uint8_t *input_buffer, const size_t input_buffer_size) 
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
    if (is_big_endian)
        disasm_info.endian = BFD_ENDIAN_BIG;
    else
        disasm_info.endian = BFD_ENDIAN_LITTLE;
    disasm_info.read_memory_func = buffer_read_memory;
    disasm_info.buffer = input_buffer;
    disasm_info.buffer_vma = 0;
    disasm_info.buffer_length = input_buffer_size;
    disassemble_init_for_target(&disasm_info);

    disassembler_ftype disasm;
    disasm = disassembler(disasm_info.arch, is_big_endian, disasm_info.mach, NULL);

    for (size_t pc = 0; pc < input_buffer_size;) 
        pc += disasm(pc, &disasm_info);

    return 0;
}
#endif

void update_raw_byte_buffer(struct circular_buffer_t *raw_bytes_buffer_ptr, 
                            char const *cur_insn_rawbytes, 
                            const uint32_t cur_insn_size)
{
    for (size_t idx = 0; idx < cur_insn_size; idx++)
    {
        raw_bytes_buffer_ptr->buffer[raw_bytes_buffer_ptr->head] = cur_insn_rawbytes[idx];
        raw_bytes_buffer_ptr->head = (raw_bytes_buffer_ptr->head + 1) % raw_bytes_buffer_ptr->size;
    }
}

bool is_buffer_matched(struct circular_buffer_t const* raw_bytes_buffer_ptr, 
                       char *target_buffer, 
                       const uint32_t target_buffer_size)
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

uint8_t digits;
void print_peekaboo_insn(peekaboo_insn_t *insn, 
                         peekaboo_trace_t *peekaboo_trace_ptr, 
                         const size_t insn_idx,
                         const bool target)
{
    // Print instruction index
    printf("[%lu] ", insn_idx);
    if (!print_memory && !print_register)
        if (target) 
        {
            for (uint8_t idx = (uint8_t)log10f(insn_idx); idx < digits - 1; idx++) printf("-");
            printf(">");
        }
        else
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
            int rvalue = disassemble_raw((enum ARCH)peekaboo_trace_ptr->internal->arch, false, insn->rawbytes, insn->size);
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

    // Print GPR
    if (print_register) regfile_pp(insn);
}

uint64_t print_back(const int64_t unprinted_size,
                peekaboo_trace_t *peekaboo_trace_ptr, 
                const size_t insn_idx)
{
    if (unprinted_size <= 0 || insn_idx < 1)
    {
        for (size_t prev_idx = ((int64_t)insn_idx - 5 > 0) ? (insn_idx - 5) : 1; prev_idx <= insn_idx; prev_idx++)
        {
            peekaboo_insn_t *prev_insn = get_peekaboo_insn(prev_idx, peekaboo_trace_ptr);
            print_peekaboo_insn(prev_insn, peekaboo_trace_ptr, prev_idx, false);
            free_peekaboo_insn(prev_insn);
        }
        return (insn_idx+1);
    }
    peekaboo_insn_t *insn = get_peekaboo_insn(insn_idx, peekaboo_trace_ptr);
    uint64_t rvalue = print_back(unprinted_size - insn->size, peekaboo_trace_ptr, insn_idx - 1);
    print_peekaboo_insn(insn, peekaboo_trace_ptr, insn_idx, true);
    free_peekaboo_insn(insn);
    return rvalue;
}

int load_pattern(const char* pattern_file_path)
{
    // Load pattern, if given.
    char buffer[BUFFER_SIZE];
    unsigned int buffer_size = 0;
    FILE* file = fopen(pattern_file_path, "rb");
    if (!file) PEEKABOO_DIE("No such pattern file %s\n", pattern_file_path);
    char c;
    const char comment_symbol = '#';
    bool line_is_commented = false;
    while (fread(&c, 1, 1, file) == 1) 
    {
        if (c == comment_symbol) line_is_commented = true;
        if (line_is_commented)
        {
            if (c == '\n') line_is_commented = false;
            continue;
        }
        if (c < '0' || c > '9')
            if (c < 'a' || c > 'f')
                if (c < 'A' || c > 'F')
                {
                    // this is not a hex char, ignore
                    continue;
                }
        buffer[buffer_size] = c;
        buffer_size++;
        if (buffer_size >= BUFFER_SIZE) PEEKABOO_DIE("Pattern too large!");
    }
    buffer[buffer_size] = 0x0;
    fclose(file);
    target_block = malloc(buffer_size/2+1);
    if (!target_block) PEEKABOO_DIE("Malloc failed.");
    int block_size = hex_string_to_uint8_arrary(target_block, buffer);
    if (block_size <= 0) PEEKABOO_DIE("Error when loading pattern from file.");
    
    return block_size;
}


void print_usage(const char* program_name)
{
    fprintf(stderr, "Usage: %s [Options] path_to_trace_dir\n", program_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -r               \tPrint register values.\n");
    fprintf(stderr, "  -m               \tPrint memory values.\n");
    fprintf(stderr, "  -s <instr id>    \tPrint trace starting from the given id.\n");
    fprintf(stderr, "  -e <instr id>    \tPrint trace till the given id.\n");
    fprintf(stderr, "  -a <memory addr> \tSearch for all instructions accessing given memory address.\n");
    fprintf(stderr, "  -p <pattern file>\tSearch for instruction patterns in trace.\n");
    fprintf(stderr, "  -h               \tPrint this help.\n");
}

int main(int argc, char *argv[])
{
    int opt;
    char *pattern_file_path;
    bool is_search = false;
    while ((opt = getopt(argc, argv, "hrms:p:e:a:")) != -1) {
        switch (opt) {
        case 'r':
            print_register = true;
            break;
        case 'm':
            print_memory = true;
            break;
        case 'p':
            pattern_file_path = optarg;
            is_search = true;
            break;
        case 's':
            loop_starts = atoi(optarg);
            if (loop_starts <= 0) PEEKABOO_DIE("Starting point must be greater than 0");
            break;
        case 'e':
            loop_ends = atoi(optarg);
            if (loop_ends <= 0) PEEKABOO_DIE("End point must be greater than 0");
            break;
        case 'a':
            if (optarg[0] == '0' && optarg[1] == 'x')
                target_addr = strtol(&optarg[2], NULL, 16);
            else
                target_addr = strtol(optarg, NULL, 16);
            break;
        case 'h':
            fprintf(stderr, "Default.\n");
            print_usage(argv[0]);
            exit(EXIT_FAILURE);
            break;
        }
    }
    // Check mandatory argument
    if (optind >= argc) 
    {
        print_usage(argv[0]);
        PEEKABOO_DIE("Missing argument: Trace path expected!\n");
    }

    // Load pattern
    int block_size = 0;
    if (is_search) block_size = load_pattern(pattern_file_path);

    // Print current libpeekaboo version
    fprintf(stderr, "libpeekaboo version: %d\n", LIBPEEKABOO_VER);

    // Load trace
    char *trace_path = argv[argc - 1];
    peekaboo_trace_t *peekaboo_trace_ptr = malloc(sizeof(peekaboo_trace_t));
    if (peekaboo_trace_ptr == NULL) PEEKABOO_DIE("Fail to malloc trace structure.");
    load_trace(trace_path, peekaboo_trace_ptr);

    // Get and print the length of the trace
    const size_t num_insn = get_num_insn(peekaboo_trace_ptr);
    digits = (uint8_t) log10(num_insn) + 2;

    // Print info for memory access search
    if (target_addr != (uint64_t) -1)
    {
        printf("Search for memory access @0x%lx\n", target_addr);
    }

    // Maintain a circular buffer to store seen rawbytes
    struct circular_buffer_t raw_bytes_buffer;
    if (block_size)
    {
        printf("Search for the following block:");
        for (size_t idx = 0; idx < block_size; idx++)
        {
            if (idx % 16 == 0) printf("\n\t");
            printf("%02hhx ", target_block[idx]);
        }
    }

    raw_bytes_buffer.head = 0;
    raw_bytes_buffer.size = (block_size > 256) ? block_size : 256;  // Fast circular buffer with size 256
    raw_bytes_buffer.buffer = malloc(raw_bytes_buffer.size);
    if (raw_bytes_buffer.buffer == NULL) PEEKABOO_DIE("Fail to malloc circular buffer.");
    uint64_t num_found_block = 0;

    // We print all instructions sequentially. 
    // Please note the first instruction's index is 1, instead of 0.
    const size_t _loop_ends = (loop_ends) ? loop_ends : num_insn;
    printf("Range: from %ld to %ld (%ld in total)\n", loop_starts, _loop_ends, num_insn);
    for (size_t insn_idx=loop_starts; insn_idx<=_loop_ends; insn_idx++)
    {
        // Get instruction ptr by instruction index
        peekaboo_insn_t *insn = get_peekaboo_insn(insn_idx, peekaboo_trace_ptr);
        
        // Buffer search
        if (block_size)
        {
            update_raw_byte_buffer(&raw_bytes_buffer, insn->rawbytes, insn->size);
            if (is_buffer_matched(&raw_bytes_buffer, target_block, block_size))
            {
                num_found_block ++;
                print_next = PRINT_NEXT;
                printf("\n[Target block %lu] ends at [%lu]0x%"PRIx64":\n", num_found_block, insn_idx, insn->addr);
                print_back(block_size, peekaboo_trace_ptr, insn_idx);
                free_peekaboo_insn(insn);
                continue;
            }
        }

        // Call print_filter() to decide what should be printed
        if (!print_filter(insn, insn_idx, num_insn, is_search))
        {
            free_peekaboo_insn(insn);
            continue;
        }

        // Body of print
        print_peekaboo_insn(insn, peekaboo_trace_ptr, insn_idx, false);

        // Free instruction ptr
        free_peekaboo_insn(insn);
    }

    if (target_block) free(target_block);
    free(raw_bytes_buffer.buffer);
    free_peekaboo_trace(peekaboo_trace_ptr);
    return 0;
}