/*! @file
 *  this file is the x86-64 regfile structure.
 */

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

typedef uint64_t    UINT64_T;

typedef union {
    uint64_t r;
    uint32_t w[2];
    uint16_t hw[4];
    uint8_t b[8];
} UINT64_REG_T;

typedef union {
    uint8_t b[10];
} UINT80_T;

typedef union {
    UINT64_T r[4];
} UINT256_T;


typedef struct {
    UINT64_T reg_rdi;
	UINT64_T reg_rsi;
	UINT64_T reg_rsp;
	UINT64_T reg_rbp;
	UINT64_REG_T reg_rbx;
	UINT64_REG_T reg_rdx;
	UINT64_REG_T reg_rcx;
	UINT64_REG_T reg_rax;
	UINT64_T reg_r8;
	UINT64_T reg_r9;
	UINT64_T reg_r10;
	UINT64_T reg_r11;
	UINT64_T reg_r12;
	UINT64_T reg_r13;
	UINT64_T reg_r14;
	UINT64_T reg_r15;
	UINT64_T reg_rflags;
	UINT64_T reg_rip;
} CPU_GR_T;

typedef struct {
    UINT64_T reg_cs;
    UINT64_T reg_ss;
    UINT64_T reg_ds;
    UINT64_T reg_es;
    UINT64_T reg_fs;
    UINT64_T reg_gs;
} CPU_SEG_T;

typedef struct {
    //  simd: avx2
    UINT256_T ymm0;
    UINT256_T ymm1;
    UINT256_T ymm2;
    UINT256_T ymm3;
    UINT256_T ymm4;
    UINT256_T ymm5;
    UINT256_T ymm6;
    UINT256_T ymm7;
    UINT256_T ymm8;
    UINT256_T ymm9;
    UINT256_T ymm10;
    UINT256_T ymm11;
    UINT256_T ymm12;
    UINT256_T ymm13;
    UINT256_T ymm14;
    UINT256_T ymm15;
} CPU_SIMD_T;

typedef struct {
    // fp registers
    UINT80_T reg_st0;
    UINT80_T reg_st1;
    UINT80_T reg_st2;
    UINT80_T reg_st3;
    UINT80_T reg_st4;
    UINT80_T reg_st5;
    UINT80_T reg_st6;
    UINT80_T reg_st7;
} CPU_ST_T;



typedef struct {
	CPU_GR_T 	gpr;
	CPU_SIMD_T 	simd;
	CPU_SEG_T 	seg;
	CPU_ST_T 	fpr;
} regfile_amd64_t;
