#ifndef __LIBPEEKABOO_COMMON_H__
#define __LIBPEEKABOO_COMMON_H__

// Bunch of type definitions for register sizes
typedef union {
	uint64_t r;
	uint32_t w[2];
	uint16_t hw[4];
	uint8_t b[8];
} uint64_reg_t;

typedef union {
	uint8_t b[10];
} uint80_t;

typedef union {
	uint64_t r[4];
} uint256_t;

typedef union {
	uint64_t r[2];
} uint128_t;

enum ARCH {
	ARCH_AARCH32,
	ARCH_AARCH64,
	ARCH_X86,
	ARCH_AMD64
};
// end of type definitions

#endif