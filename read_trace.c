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

#include "libpeekaboo.h"

void display_usage(char *program_name)
{
    printf("Usage: %s <trace_dir>\n", program_name);
    printf("\t<trace_dir>: Path to the sub directory of a process/thread. e.g. ~/ls-31401/31401\n");
    exit(0);
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

    // We print all instructions sequentially. 
    // Please note the first instruction's index is 1, instead of 0.
    for (size_t insn_idx=1; insn_idx<=num_insn; insn_idx++)
    {
        // Get instruction ptr by instruction index
        peekaboo_insn_t *insn = get_peekaboo_insn(insn_idx, &mytrace);

        // Print instruction ea
        printf("%lu: 0x%"PRIx64"", insn_idx, insn->addr);
        
        // Print length of instruction (in bytes)
        printf("\tSize: %ld", insn->size);

        // Print Rawbytes
        printf("\trawbytes: ");
        for (uint8_t rawbyte_idx = 0; rawbyte_idx < insn->size; rawbyte_idx++)
        {
            if (insn->rawbytes[rawbyte_idx] < 16) printf("0");
            printf("%"PRIx8" ", insn->rawbytes[rawbyte_idx]);
        }
        printf("\n");

        // Print memory ops
        if (insn->num_mem > 0)
        {
            for (uint32_t mem_idx = 0; mem_idx < insn->num_mem; mem_idx++)
            {
                printf("\t");
                printf(insn->mem[mem_idx].status ? "Memory Write: " : "Memory Read: ");
                assert(insn->mem[mem_idx].status==0 || insn->mem[mem_idx].status==1);
                printf("%d bytes @ 0x%lx\n", insn->mem[mem_idx].size, insn->mem[mem_idx].addr);
            }
        }

        // Print GPRs
        regfile_pp(insn);

        // Free instruction ptr
        free_peekaboo_insn(insn);
    }

    return 0;
}