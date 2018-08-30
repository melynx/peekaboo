/*! @file
 *  This file is the x86-64 regfile structure.
 */

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

typedef uint64_t    UINT64_T;

typedef union {
    uint64_t r;
    uint32_t e[2];
    uint16_t x[4];
    uint8_t b[8];
} UINT64_REG_T;

typedef union {
    uint8_t b[10];
} UINT80_T;

typedef union {
    uint64_t r[4];
} UINT256_T;


typedef struct {
    UINT64_T REG_RDI;
	UINT64_T REG_RSI;
	UINT64_T REG_RSP;
	UINT64_T REG_RBP;
	UINT64_REG_T REG_RBX;
	UINT64_REG_T REG_RDX;
	UINT64_REG_T REG_RCX;
	UINT64_REG_T REG_RAX;
	UINT64_T REG_R8;
	UINT64_T REG_R9;
	UINT64_T REG_R10;
	UINT64_T REG_R11;
	UINT64_T REG_R12;
	UINT64_T REG_R13;
	UINT64_T REG_R14;
	UINT64_T REG_R15;
	UINT64_T REG_RFLAGS;
	UINT64_T REG_RIP;
} CPU_GR_t;

typedef struct {
    UINT64_T REG_CS;
    UINT64_T REG_SS;
    UINT64_T REG_DS;
    UINT64_T REG_ES;
    UINT64_T REG_FS;
    UINT64_T REG_GS;
} CPU_SEG_t;

typedef struct {
    //  SIMD: AVX2
    UINT256_T YMM0;
    UINT256_T YMM1;
    UINT256_T YMM2;
    UINT256_T YMM3;
    UINT256_T YMM4;
    UINT256_T YMM5;
    UINT256_T YMM6;
    UINT256_T YMM7;
    UINT256_T YMM8;
    UINT256_T YMM9;
    UINT256_T YMM10;
    UINT256_T YMM11;
    UINT256_T YMM12;
    UINT256_T YMM13;
    UINT256_T YMM14;
    UINT256_T YMM15;
} CPU_SIMD_t;

typedef struct {
    // FP Registers
    UINT80_T REG_ST0;
    UINT80_T REG_ST1;
    UINT80_T REG_ST2;
    UINT80_T REG_ST3;
    UINT80_T REG_ST4;
    UINT80_T REG_ST5;
    UINT80_T REG_ST6;
    UINT80_T REG_ST7;
} CPU_ST_t;
