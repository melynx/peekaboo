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

#include <stdio.h>
#include <stdlib.h>

#include "libpeekaboo.h"

int main(int argc, char *argv[])
{
    char *trace_path = argv[1];
    peekaboo_trace_t mytrace;
    load_trace(trace_path, &mytrace);

    const size_t num_insn = get_num_insn(&mytrace);
    printf("Total instructions: %ld\n", num_insn);
    for (size_t insn_idx=1; insn_idx<=num_insn; insn_idx++)
    {
        // Get instruction ptr by instruction index
        peekaboo_insn_t *insn = get_peekaboo_insn(insn_idx, &mytrace);

        // Print instruction ea
        printf("%lu: 0x%"PRIx64"", insn_idx, insn->addr);
        
        // Print length of instruction (in bytes)
        printf("\tsize: %ld", insn->size);

        // Print Rawbytes
        printf("\trawbytes: ");
        for (uint8_t rawbyte_idx = 0; rawbyte_idx < insn->size; rawbyte_idx++)
        {
            if (insn->rawbytes[rawbyte_idx] < 16) printf("0");
            printf("%"PRIx8" ", insn->rawbytes[rawbyte_idx]);
        }
        printf("\n");

        // Print memory access

        if (insn->num_mem > 0)
        {
            printf("Memory:");
            for (uint32_t mem_idx = 0; mem_idx < insn->num_mem; mem_idx++)
            {
                printf("\t0x%lx: 0x%lx: %d: %d", insn->mem[mem_idx].addr, insn->mem[mem_idx].value, insn->mem[mem_idx].size, insn->mem[mem_idx].status);
            }
            printf("\n");
        }


        // Print GPRs
//        regfile_pp(insn);
//        printf("\n");

        // Free instruction ptr
        free_peekaboo_insn(insn);
    }

    return 0;
}