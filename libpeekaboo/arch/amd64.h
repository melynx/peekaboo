/*! @file
 *  this file is the x86-64 regfile structure & memfile structure.
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

typedef union {
    UINT64_T r[2];
} UINT128_T;

/* Regfile */

typedef struct {
	UINT64_T reg_rdi;
	UINT64_T reg_rsi;
	UINT64_T reg_rsp;
	UINT64_T reg_rbp;
	UINT64_T reg_rbx;
	UINT64_T reg_rdx;
	UINT64_T reg_rcx;
	UINT64_T reg_rax;
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
  UINT128_T st_mm[8];  // 8 128-bits FP Registers
  UINT128_T xmm[16];  // 16 128-bits XMM Regiters
  uint8_t padding[96]; // 416 Bytes are used. The total area should be 512 bytes.
} __attribute__((packed)) FXSAVE_AREA_T;

typedef struct {
	CPU_GR_T 	gpr;
	CPU_SIMD_T 	simd;
	CPU_SEG_T 	seg;
	CPU_ST_T 	fpr;
	FXSAVE_AREA_T	fxsave;
} regfile_amd64_t;

/* End of Regfile */

/* Memfile */

typedef struct {
	uint64_t addr;		/* memory address */
	uint64_t value;		/* memory value */
	uint32_t size;		/* how many bits are vaild in value */
	uint32_t status; 	/* 0 for Read, 1 for write */
} mem_ref_t;

typedef struct {
	uint32_t length;	/* how many refs are there*/
	mem_ref_t *ref;
} memfile_amd64_t;
/* End of Memfile */