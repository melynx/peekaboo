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
#include <string.h>


#include "libpeekaboo/libpeekaboo.h"

#ifdef ASM
    // binutils-dev >= 2.29 required
    #include <dis-asm.h>
#endif
#ifdef ASM_CAPSTONE
    #include <capstone/capstone.h>
  	csh capstone_handler;
#endif


// Print how many instructions if block matches
#define PRINT_NEXT 15

#define BUFFER_SIZE 512


// What you want to include in ouput?
// Users can edit print_filter() to modify these booleans during runtime.
bool print_memory   = false;
bool print_register = false;
uint32_t print_next = 0;

// Structure
typedef struct _insn_rawbyte_node_t {
    bool is_arbitrary;
    uint16_t *bytes;
    int size;  
    struct _insn_rawbyte_node_t *prec, *succ;
} insn_rawbyte_node_t;
typedef struct _cache_linked_list_t {
    insn_rawbyte_node_t *head, *tail;
    size_t length;
} cache_linked_list_t;
typedef struct _matched_list_node_t {
    struct _matched_list_node_t *succ;
    uint64_t addr;
    size_t cnt;
} matched_list_node_t;


bool print_filter(peekaboo_insn_t *insn, 
                  size_t insn_idx, 
                  const size_t num_insn, 
                  const bool is_search, 
                  const uint64_t target_addr,
                  const uint32_t target_addr_size)
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
                if (
                    (
                        (target_addr >= insn->mem[mem_idx].addr) 
                        && 
                        (target_addr < insn->mem[mem_idx].addr + insn->mem[mem_idx].size)
                    )
                    ||
                    (
                        (target_addr+target_addr_size-1 < insn->mem[mem_idx].addr + insn->mem[mem_idx].size)
                        &&
                        (target_addr+target_addr_size-1 >= insn->mem[mem_idx].addr)
                    )
                   )
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

int hexchar_to_uint16(uint16_t *output_uint16_ptr, const char input_char)
{
    if (input_char >= '0' && input_char <= '9')
    {
        *output_uint16_ptr = input_char - '0';
        return 0;
    }
    if (input_char >= 'A' && input_char <= 'F')
    {
        *output_uint16_ptr = input_char - 'A' + 10;
        return 0;
    }
    if (input_char >= 'a' && input_char <= 'f')
    {
        *output_uint16_ptr = input_char - 'a' + 10;
        return 0;
    }
    if (input_char == '*')
    {
        *output_uint16_ptr = 0x100;
        return 0;
    }
    if (input_char == '?')
    {
        *output_uint16_ptr = 0x101;
        return 0;
    }

    return -1;
}

/* Covert hex string into uint8_t array*/
int hex_string_to_uint16_arrary(uint16_t *uint16_array, const char *hex_string)
{
    int size = 0;
    while(hex_string[0] && hex_string[1])
    {
        // Arbitrary symbols must be in pairs
        if (hex_string[0] == '?' || hex_string[1] == '?' || hex_string[0] == '*' || hex_string[1] == '*')
            if (hex_string[0] != hex_string[1]) return -1;

        uint16_t output[2];
        if (hexchar_to_uint16(&output[0], hex_string[0])==0 && hexchar_to_uint16(&output[1], hex_string[1])==0)
        {
            uint16_array[size++] = output[0] * 16 + output[1];
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

void free_insn_rawbyte_node(insn_rawbyte_node_t *node_ptr)
{
    if (node_ptr != NULL)
    {
        if (node_ptr->bytes != NULL) free(node_ptr->bytes);
        free(node_ptr);
    }
}

void update_raw_byte_buffer(cache_linked_list_t *instr_buffer, 
                            char const *cur_insn_rawbytes, 
                            const uint32_t instr_size,
                            const size_t target_length)
{
    // Remove instr from head if buffer is full
    if (instr_buffer->length > target_length)
    {
        assert(instr_buffer->head != NULL);
        assert(instr_buffer->head != instr_buffer->tail);
        insn_rawbyte_node_t *new_head = instr_buffer->head->succ;
        assert(new_head != NULL);
        free_insn_rawbyte_node(instr_buffer->head);
        instr_buffer->head = new_head;
        instr_buffer->length -= 1;
    }

    // New instr
    insn_rawbyte_node_t *new_node = malloc(sizeof(insn_rawbyte_node_t));
    if (!new_node) PEEKABOO_DIE("Failed to malloc!");
    new_node->is_arbitrary = false;
    new_node->prec = instr_buffer->tail;
    new_node->succ = NULL;
    new_node->size = instr_size;
    new_node->bytes = malloc(sizeof(uint16_t) * instr_size);
    uint32_t idx;
    for (idx=0; idx<instr_size; idx++)
    {
        new_node->bytes[idx] = cur_insn_rawbytes[idx] & 0xFF;
    }

    // Update buffer
    if (instr_buffer->head == NULL) 
    {
        instr_buffer->head = new_node;
    }
    if (instr_buffer->tail != NULL) 
    {
        instr_buffer->tail->succ = new_node;
    }
    instr_buffer->tail = new_node;
    instr_buffer->length += 1;
}

uint32_t is_buffer_matched(cache_linked_list_t const *raw_bytes_buffer, 
                       cache_linked_list_t const *pattern)
{
    insn_rawbyte_node_t *target_node = raw_bytes_buffer->tail;
    insn_rawbyte_node_t *pattern_node = pattern->tail;
    uint32_t matched_bytes_num = 0;

    if (raw_bytes_buffer->length < pattern->length) return 0;

    uint32_t idx = pattern->length;
    for (; idx>0; idx--, pattern_node = pattern_node->prec, target_node = target_node->prec)
    {
        matched_bytes_num += target_node->size;
        if (pattern_node->is_arbitrary) continue;
        if (pattern_node->size != target_node->size) return 0;
        uint32_t byte_offset = 0;
        for (; byte_offset < pattern_node->size; byte_offset++)
        {
            if (pattern_node->bytes[byte_offset] == 0x101*16+0x101) continue; // Matched "??"
            if (pattern_node->bytes[byte_offset] != target_node->bytes[byte_offset]) return 0;
        }
    }
    return matched_bytes_num;
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
    #ifdef ASM
    {
        // Pretty print 
        for (uint8_t idx = insn->size; idx < 8; idx++) printf("   ");
        printf("\t");

        // Disasmble the instruction
        int rvalue = disassemble_raw((enum ARCH)peekaboo_trace_ptr->internal->arch, false, insn->rawbytes, insn->size);
        if(rvalue != 0) PEEKABOO_DIE("Libopcodes disasm error!\n");

        if (insn->size == 2 && insn->rawbytes[0]=='\x0f' && insn->rawbytes[1]=='\x05')
        {
            size_t trace_length = get_num_insn(peekaboo_trace_ptr);
            size_t next_insn_idx = insn_idx + 1;
            const regfile_amd64_t *regfile_ptr = (regfile_amd64_t *) insn->regfile;
            printf("%lu; rvalue=", regfile_ptr->gpr.reg_rax);
            if (next_insn_idx > trace_length)
                printf("NA");
            else
            {
                peekaboo_insn_t *next_insn = get_peekaboo_insn(next_insn_idx, peekaboo_trace_ptr);
                regfile_ptr = (regfile_amd64_t *) next_insn->regfile;
                printf("0x%lx", regfile_ptr->gpr.reg_rax);
                free_peekaboo_insn(next_insn);
            }
        }
    }
    #endif
    #ifdef ASM_CAPSTONE
    {
        // Pretty print 
        for (uint8_t idx = insn->size; idx < 8; idx++) printf("   ");
        printf("\t");

        // Disasmble the instruction
        cs_insn *capstone_insn;
        size_t count = cs_disasm(capstone_handler, insn->rawbytes, insn->size, insn->addr, 0, &capstone_insn);
        printf("%s\t%s", capstone_insn[0].mnemonic, capstone_insn[0].op_str);
        cs_free(capstone_insn, count);

        if (insn->size == 2 && insn->rawbytes[0]=='\x0f' && insn->rawbytes[1]=='\x05')
        {
            size_t trace_length = get_num_insn(peekaboo_trace_ptr);
            size_t next_insn_idx = insn_idx + 1;
            const regfile_amd64_t *regfile_ptr = (regfile_amd64_t *) insn->regfile;
            printf("%lu; rvalue=", regfile_ptr->gpr.reg_rax);
            if (next_insn_idx > trace_length)
                printf("NA");
            else
            {
                peekaboo_insn_t *next_insn = get_peekaboo_insn(next_insn_idx, peekaboo_trace_ptr);
                regfile_ptr = (regfile_amd64_t *) next_insn->regfile;
                printf("0x%lx", regfile_ptr->gpr.reg_rax);
                free_peekaboo_insn(next_insn);
            }
        }
    }
    #endif
    printf("\n");

    // Print memory ops
    if (print_memory && (insn->num_mem > 0))
    {
        for (uint32_t mem_idx = 0; mem_idx < insn->num_mem; mem_idx++)
        {
            printf("\t");
            printf(insn->mem[mem_idx].status ? "Memory Write: " : "Memory Read: ");
            printf("%d bytes @ 0x%lx\n", insn->mem[mem_idx].size, insn->mem[mem_idx].addr);

            // Memory trace broken checker
            if (!(insn->mem[mem_idx].status==0 || insn->mem[mem_idx].status==1)) 
                PEEKABOO_DIE("Abort! Broken memrefs_offsets. Remove memrefs_offsets in trace folder and try again.");
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

int append2pattern_list(cache_linked_list_t *pattern_ptr, const uint8_t *buffer, const unsigned int buffer_size)
{
    // Empty buffer, directly return
    if (buffer_size == 0) return 0;

    insn_rawbyte_node_t *new_node = malloc(sizeof(insn_rawbyte_node_t));
    if (!new_node) PEEKABOO_DIE("Failed to malloc.");
    new_node->succ = NULL;
    
    if (pattern_ptr->head == NULL)
    {
        pattern_ptr->head = new_node;
    }

    // Update tail and length
    insn_rawbyte_node_t *curr_tail_node = pattern_ptr->tail;
    if (curr_tail_node != NULL)
    {
        curr_tail_node->succ = new_node;
    }
    new_node->prec = curr_tail_node;
    pattern_ptr->tail = new_node;
    pattern_ptr->length += 1;

    new_node->bytes = malloc((buffer_size/2+1)*sizeof(uint16_t));
    if(!new_node->bytes) PEEKABOO_DIE("Failed to malloc.");
    new_node->size = hex_string_to_uint16_arrary(new_node->bytes, buffer);
    if (new_node->size <= 0) return -1; 

    // Find if abitrary
    size_t idx;
    new_node->is_arbitrary = false;
    for (idx=0; idx<new_node->size; idx++)
    {
        if (new_node->bytes[idx] == 0x100*16+0x100) // Matched "**"
        {
            new_node->is_arbitrary = true;
            new_node->size = 0;
            free(new_node->bytes);
            new_node->bytes = NULL;
            break;
        }
    }
    return 1;
}

void load_pattern(cache_linked_list_t *pattern_ptr, const char* pattern_file_path)
{
    // Init pattern
    pattern_ptr->length = 0;
    pattern_ptr->head = NULL;
    pattern_ptr->tail = NULL;

    // Load pattern, if given.
    uint8_t buffer[33];
    unsigned int buffer_size = 0;
    FILE* file = fopen(pattern_file_path, "rb");
    if (!file) PEEKABOO_DIE("No such pattern file %s\n", pattern_file_path);
    uint8_t c;
    uint32_t line_num = 0;
    bool line_is_commented = false;
    while (fread(&c, 1, 1, file) == 1) 
    {
        // Check if this is comment
        if (c == '#') 
        {
            line_is_commented = true;
            continue;
        }

        // Check if this is '\n'
        if (c == '\n')
        {   
            // Update line number 
            line_num++;

            // Reset commented
            line_is_commented = false;

            // Parse buffer
            buffer[buffer_size] = 0x0;
            if (append2pattern_list(pattern_ptr, buffer, buffer_size) < 0) PEEKABOO_DIE("Fail to parse input pattern at line %u", line_num);

            // Reset buffer to load next instruction
            buffer_size = 0;
            continue;
        } 

        // Check if commented
        if (line_is_commented) continue;

        // Parse this char
        if (c < '0' || c > '9')
            if (c < 'a' || c > 'f')
                if (c < 'A' || c > 'F')
                    if (c != '*' && c != '?') // Arbitrary matching
                    {
                        // this is not a hex char, or an arbitrary matching char
                        continue;
                    }
        buffer[buffer_size] = c;
        buffer_size++;
        if (buffer_size > 33) PEEKABOO_DIE("Pattern: Rawbytes are too long for one instruction!");
    }
    fclose(file);
}

void free_dulinked_list(cache_linked_list_t* pattern)
{
    if (pattern == NULL) return;
    uint32_t idx;
    insn_rawbyte_node_t *this_node = pattern->head;
    for (idx=0; idx<pattern->length; idx++)
    {
        insn_rawbyte_node_t *next_node = this_node->succ;
        free_insn_rawbyte_node(this_node);
        this_node = next_node;
    }
}

void print_pattern(const cache_linked_list_t* pattern)
{
    printf("Search for the following snippet (%lu instructions):\n", pattern->length);
    uint32_t instr_id;
    insn_rawbyte_node_t *this_node = pattern->head;
    for (instr_id = 0; instr_id < pattern->length; instr_id++, this_node=this_node->succ)
    {
        uint32_t byte_offset;
        bool has_arbitrary_byte = false;
        assert(this_node!=NULL);
        printf("\t");
        if (this_node->is_arbitrary)
        {
            printf("**                   \t[Any Instr.]\n");
            continue;
        }
        for(byte_offset = 0; byte_offset < this_node->size; byte_offset++)
        {
            uint16_t byte_to_print = this_node->bytes[byte_offset];
            if (byte_to_print == 0x101*16+0x101)
            {
                printf("?? ");
                has_arbitrary_byte = true;
                continue;
            }
            printf("%02hhx ", byte_to_print);
        }
        if (!has_arbitrary_byte)
        {
        #ifdef ASM_CAPSTONE
            cs_insn *capstone_insn;
            uint8_t *tmp_rawbytes = malloc(this_node->size);
            if (!tmp_rawbytes) PEEKABOO_DIE("Failed to malloc");
            uint32_t tmp_idx;
            for (tmp_idx = 0; tmp_idx < this_node->size; tmp_idx++)
            {
                tmp_rawbytes[tmp_idx] = this_node->bytes[tmp_idx] & 0xFF;
            }
            size_t count = cs_disasm(capstone_handler, tmp_rawbytes, this_node->size, 0x0, 0, &capstone_insn);
            free(tmp_rawbytes);
            if (count > 0) 
            {
                size_t k;
                for (k = this_node->size; k < 8; k++) printf("   ");
                printf("%s\t\t%s", capstone_insn[0].mnemonic, capstone_insn[00].op_str);
                cs_free(capstone_insn, count);
            }
        #endif
        }
        printf("\n");
    }
}

void print_usage(const char* program_name)
{
    fprintf(stderr, "Usage: %s [Options] path_to_trace_dir\n", program_name);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -r               \tPrint register values.\n");
    fprintf(stderr, "  -m               \tPrint memory values.\n");
    fprintf(stderr, "  -y               \tPrint syscalls. Not compatible with -p.\n");
    fprintf(stderr, "  -s <instr id>    \tPrint trace starting from the given id. Below zero for reversed order.\n");
    fprintf(stderr, "  -e <instr id>    \tPrint trace till the given id.\n");
    fprintf(stderr, "  -a <addr>[,size] \tSearch for all accesses to given memory address. Search accesses to buffer when size is given.\n");
    fprintf(stderr, "  -p <pattern file>\tSearch for instruction patterns in trace. See pattern.txt for samples. Not compatible with -c.\n");
    fprintf(stderr, "  -h               \tPrint this help.\n");
}

void append2macthed_list(matched_list_node_t **list_header, const uint64_t addr)
{

    if (*list_header == NULL)
    {
        *list_header = malloc(sizeof(matched_list_node_t));
        if (!*list_header) PEEKABOO_DIE("Malloc failed.");
        (*list_header)->addr = addr;
        (*list_header)->cnt = 1;
        (*list_header)->succ = NULL;
    }
    else
    {
        matched_list_node_t *prev_node, *node = *list_header;
        while (node)
        {
            if (node->addr == addr)
            {
                node->cnt++;
                break;
            }
            prev_node = node;
            node = prev_node->succ;
        }
        if (node == NULL)
        {
            node = malloc(sizeof(matched_list_node_t));
            if (!node) PEEKABOO_DIE("Malloc failed.");
            node->addr = addr;
            node->cnt = 1;
            node->succ = NULL;
            prev_node->succ = node;
        }
    }
}

int main(int argc, char *argv[])
{
    // Argument parsing
    int loop_starts = 1;
    int loop_ends = 0; // Default is 0 for printing till the end
    int opt;
    char *pattern_file_path;
    bool is_search = false;
    bool print_syscall_only = false;
    uint64_t target_addr = (uint64_t) -1; // Target memory address
    uint32_t target_addr_size = 1;
    bool target_addr_size_hex = false;
    char *comma_pos, *size_ptr;
    while ((opt = getopt(argc, argv, "hrms:p:e:a:y")) != -1) {
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
            if (loop_starts == 0) PEEKABOO_DIE("Starting point could not be 0. Traces always start at 1.\n");
            break;
        case 'e':
            loop_ends = atoi(optarg);
            if (loop_ends <= 0) PEEKABOO_DIE("End point must be greater than 0\n");
            break;
        case 'a':
            comma_pos = strrchr(optarg, ',');
            if (optarg[0] == '0' && optarg[1] == 'x')
                target_addr = strtol(optarg+2, NULL, 16);
            else
                target_addr = strtol(optarg, NULL, 16);
            if (comma_pos != NULL)
            {
                size_ptr = comma_pos + 1;
                if (size_ptr[0] == '0' && size_ptr[1] == 'x')
                {
                    target_addr_size = strtol(size_ptr+2, NULL, 16);
                    target_addr_size_hex = true;
                }
                else
                {
                    target_addr_size = strtol(size_ptr, NULL, 10);
                    target_addr_size_hex = false;
                }
            }
            break;
        case 'y':
            print_syscall_only = true;
            break;
        case 'h':
            print_usage(argv[0]);
            exit(EXIT_FAILURE);
            break;
        }
    }
    // Check mandatory argument
    if (optind >= argc) 
    {
        print_usage(argv[0]);
        PEEKABOO_DIE("\nMissing argument: Trace path at the end expected.\n");
    }

    // Init capstone
#ifdef ASM_CAPSTONE
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &capstone_handler) != CS_ERR_OK) PEEKABOO_DIE("Capstone init error.");
#endif

    // Print current libpeekaboo version
    fprintf(stderr, "libpeekaboo version: %d\n", LIBPEEKABOO_VER);

    // Print info for memory access search
    if (target_addr != (uint64_t) -1)
    {
        if (target_addr_size > 1)  
        {
            printf("Search for memory access to buffer at 0x%lx with size of ",target_addr);
            if (target_addr_size_hex) // Buffer size is taken 
                printf("0x%x bytes.\n", target_addr_size);
            else
                printf("%u bytes.\n", target_addr_size);
        }
        else
        {
            printf("Search for memory access @0x%lx.\n", target_addr);
        }
    }

    // Load and Print search pattern
    cache_linked_list_t pattern;
    pattern.length = 0;
    pattern.head = NULL;
    pattern.tail = NULL;
    if (is_search) load_pattern(&pattern, pattern_file_path);
    if (pattern.length) print_pattern(&pattern);

    // Load trace
    char *trace_path = argv[argc - 1];
    peekaboo_trace_t *peekaboo_trace_ptr = malloc(sizeof(peekaboo_trace_t));
    if (peekaboo_trace_ptr == NULL) PEEKABOO_DIE("Fail to malloc trace structure.");
    load_trace(trace_path, peekaboo_trace_ptr);

    // Get and print the length of the trace
    const size_t num_insn = get_num_insn(peekaboo_trace_ptr);
    digits = (uint8_t) log10(num_insn) + 2;

    // Prepare buffer for pattern searching
    cache_linked_list_t instr_buffer;
    instr_buffer.length = 0;
    instr_buffer.head = NULL;
    instr_buffer.tail = NULL;

    uint64_t num_found_block = 0;
    matched_list_node_t *matched_list_header = NULL;

    // We print instructions sequentially. 
    // Please note the first instruction's index is 1, instead of 0.
    const size_t _loop_ends = (loop_ends) ? loop_ends : num_insn;
    const size_t _loop_starts = (loop_starts < 0) ? (_loop_ends + loop_starts + 1) : loop_starts;
    printf("Range: from %lu to %lu (%lu in total)\n", _loop_starts, _loop_ends, num_insn);
    for (size_t insn_idx=_loop_starts; insn_idx<=_loop_ends; insn_idx++)
    {
        // Get instruction ptr by instruction index
        peekaboo_insn_t *insn = get_peekaboo_insn(insn_idx, peekaboo_trace_ptr);
        
        if (print_syscall_only)
        {
            if (insn->size == 2 && insn->rawbytes[0]=='\x0f' && insn->rawbytes[1]=='\x05')
            {
                print_peekaboo_insn(insn, peekaboo_trace_ptr, insn_idx, false);
            }
            free_peekaboo_insn(insn);
            continue;
        }

        // Pattern search
        if (pattern.length)
        {
            update_raw_byte_buffer(&instr_buffer, insn->rawbytes, insn->size, pattern.length);
            uint32_t matched_bytes_num = is_buffer_matched(&instr_buffer, &pattern);
            if (matched_bytes_num)
            {
                num_found_block ++;
                print_next = PRINT_NEXT;
                if (num_found_block) printf("\n");
                printf("[Target block %lu] ends at [%lu]0x%"PRIx64":\n", num_found_block, insn_idx, insn->addr);
                print_back(matched_bytes_num, peekaboo_trace_ptr, insn_idx);
                append2macthed_list(&matched_list_header, insn->addr);
                free_peekaboo_insn(insn);
                continue;
            }
        }

        // Call print_filter() to decide what should be printed
        if (!print_filter(insn, insn_idx, num_insn, is_search, target_addr, target_addr_size))
        {
            free_peekaboo_insn(insn);
            continue;
        }

        // Body of print
        print_peekaboo_insn(insn, peekaboo_trace_ptr, insn_idx, false);

        // Free instruction ptr
        free_peekaboo_insn(insn);
    }

    // Print pattern search summary and free linked list
    if (pattern.length)
    {
        printf("%lu code snippet(s) matched with the given pattern", num_found_block);
        if (num_found_block)
        {
            printf(":\n");
            matched_list_node_t *node = matched_list_header;
            while (node != NULL)
            {
                printf("  Found pattern at 0x%lx for %ld time(s)\n", node->addr, node->cnt);
                matched_list_node_t *this_node = node;
                node = node->succ;
                free(this_node);
            }
        }
    }

#ifdef ASM_CAPSTONE
	cs_close(&capstone_handler);
#endif
    if (pattern.length)
    {
        free_dulinked_list(&pattern);
        free_dulinked_list(&instr_buffer);
    }
    free_peekaboo_trace(peekaboo_trace_ptr);
    
    return 0;
}