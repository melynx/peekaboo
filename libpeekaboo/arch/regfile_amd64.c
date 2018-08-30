/*! @file
 *  This file is the x86-64 regfile structure.
 */

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

typedef uint8_t     UINT8;
typedef uint64_t    UINT64;
typedef union {
    uint64_t r;
    uint32_t e[2];
    uint16_t x[4];
    uint8_t b[8];
} UINT64_REG_T;

typedef union {
    uint8_t b[10];
} UINT80;

typedef union {
    uint64_t r[4];
} UINT256;


typedef struct {
    UINT64 REG_RDI;
	UINT64 REG_RSI;
	UINT64 REG_RSP;
	UINT64 REG_RBP;
	UINT64_REG_T REG_RBX;
	UINT64_REG_T REG_RDX;
	UINT64_REG_T REG_RCX;
	UINT64_REG_T REG_RAX;
	UINT64 REG_R8;
	UINT64 REG_R9;
	UINT64 REG_R10;
	UINT64 REG_R11;
	UINT64 REG_R12;
	UINT64 REG_R13;
	UINT64 REG_R14;
	UINT64 REG_R15;
	UINT64 REG_RFLAGS;
	UINT64 REG_RIP;
} CPU_GR_t;

typedef struct {
    UINT64 REG_CS;
    UINT64 REG_SS;
    UINT64 REG_DS;
    UINT64 REG_ES;
    UINT64 REG_FS;
    UINT64 REG_GS;
} CPU_SEG_t;

typedef struct {
    //  SIMD: AVX2
    UINT256 YMM0;
    UINT256 YMM1;
    UINT256 YMM2;
    UINT256 YMM3;
    UINT256 YMM4;
    UINT256 YMM5;
    UINT256 YMM6;
    UINT256 YMM7;
    UINT256 YMM8;
    UINT256 YMM9;
    UINT256 YMM10;
    UINT256 YMM11;
    UINT256 YMM12;
    UINT256 YMM13;
    UINT256 YMM14;
    UINT256 YMM15;
} CPU_SIMD_t;

typedef struct {
    // FP Registers
    UINT80 REG_ST0;
    UINT80 REG_ST1;
    UINT80 REG_ST2;
    UINT80 REG_ST3;
    UINT80 REG_ST4;
    UINT80 REG_ST5;
    UINT80 REG_ST6;
    UINT80 REG_ST7;
} CPU_ST_t;

