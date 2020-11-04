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

/*! @file
 *  this file is the x86-64 regfile structure & memfile structure.
 */
#ifndef __LIBPEEKABOO_AMD64_H__
#define __LIBPEEKABOO_AMD64_H__

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>

typedef struct storage_option_amd64{
	uint32_t has_simd;
	uint32_t has_fxsave;
	uint32_t has_sr;
} storage_option_amd64_t;

#include "../libpeekaboo.h"
#include "amd64_conf.h"

#define AMD64_NUM_SIMD_SLOTS 16


/* Regfile */
typedef struct {
	uint64_t reg_rdi;
	uint64_t reg_rsi;
	uint64_t reg_rsp;
	uint64_t reg_rbp;
	uint64_t reg_rbx;
	uint64_t reg_rdx;
	uint64_t reg_rcx;
	uint64_t reg_rax;
	uint64_t reg_r8;
	uint64_t reg_r9;
	uint64_t reg_r10;
	uint64_t reg_r11;
	uint64_t reg_r12;
	uint64_t reg_r13;
	uint64_t reg_r14;
	uint64_t reg_r15;
	uint64_t reg_rflags;
	uint64_t reg_rip;
} amd64_cpu_gr_t;

typedef struct {
	uint16_t reg_cs;
	uint16_t reg_ss;
	uint16_t reg_ds;
	uint16_t reg_es;
	uint16_t reg_fs;
	uint16_t reg_gs;
} amd64_cpu_seg_t;

typedef struct {
	//  simd: avx2
	uint256_t ymm0;
	uint256_t ymm1;
	uint256_t ymm2;
	uint256_t ymm3;
	uint256_t ymm4;
	uint256_t ymm5;
	uint256_t ymm6;
	uint256_t ymm7;
	uint256_t ymm8;
	uint256_t ymm9;
	uint256_t ymm10;
	uint256_t ymm11;
	uint256_t ymm12;
	uint256_t ymm13;
	uint256_t ymm14;
	uint256_t ymm15;
} amd64_cpu_simd_t;

typedef struct {
	// fp registers
	uint80_t reg_st0;
	uint80_t reg_st1;
	uint80_t reg_st2;
	uint80_t reg_st3;
	uint80_t reg_st4;
	uint80_t reg_st5;
	uint80_t reg_st6;
	uint80_t reg_st7;
} amd64_cpu_st_t;

typedef struct {
	uint16_t fcw;  // FPU control word
	uint16_t fsw;  // FPU status word
	uint8_t ftw;  // Abridged FPU tag word
	uint8_t reserved_1;
	uint16_t fop;  // FPU opcode
	uint32_t fpu_ip;  // FPU instruction pointer offset
	uint16_t fpu_cs;  // FPU instruction pointer segment selector
	uint16_t reserved_2;
	uint32_t fpu_dp;  // FPU data pointer offset
	uint16_t fpu_ds;  // FPU data pointer segment selector
	uint16_t reserved_3;
	uint32_t mxcsr;  // Multimedia extensions status and control register
	uint32_t mxcsr_mask;  // Valid bits in mxcsr
	uint128_t st_mm[8];  // 8 128-bits FP Registers
	uint128_t xmm[16];  // 16 128-bits XMM Regiters
	uint8_t padding[96]; // 416 Bytes are used. The total area should be 512 bytes.
} __attribute__((packed)) fxsave_area_t;

typedef struct regfile_amd64{
	amd64_cpu_gr_t gpr;
#ifdef _STORE_SEGMENT_REGISTER
	amd64_cpu_seg_t sr;
#endif
#ifdef _STORE_SIMD
	amd64_cpu_simd_t simd;
#endif
#ifdef _STORE_FXSAVE
	fxsave_area_t fxsave;
#endif
} regfile_amd64_t;

void amd64_regfile_pp(regfile_amd64_t *regfile);
#ifdef _STORE_SEGMENT_REGISTER
void amd64_sr_pp(amd64_cpu_seg_t *regfile_sr);
#endif
/* End of Regfile */

#endif
