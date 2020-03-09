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

#ifndef __LIBPEEKABOO_X86_H__
#define __LIBPEEKABOO_X86_H__

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>

#include "libpeekaboo.h"

/* Regfile */
typedef struct {
	uint32_t reg_eax;
	uint32_t reg_ecx;
	uint32_t reg_edx;
	uint32_t reg_ebx;
	uint32_t reg_esp;
	uint32_t reg_ebp;
	uint32_t reg_esi;
	uint32_t reg_edi;
} x86_cpu_gr_t;

typedef struct {
	uint16_t reg_cs;
	uint16_t reg_ss;
	uint16_t reg_ds;
	uint16_t reg_es;
	uint16_t reg_fs;
	uint16_t reg_gs;
} x86_cpu_seg_t;

typedef struct regfile_x86{
	x86_cpu_gr_t gpr;
} regfile_x86_t;

void x86_regfile_pp(regfile_x86_t *regfile);
/* End of Regfile */

#endif
