#ifndef COMPEL_RELOCATIONS_H__
#define COMPEL_RELOCATIONS_H__

#include <stdint.h>

static inline uint32_t riscv_b_imm(uint32_t val)
{
	return (val & 0x00001000) << 19 | (val & 0x000007e0) << 20 | (val & 0x0000001e) << 7 | (val & 0x00000800) >> 4;
}

static inline uint32_t riscv_i_imm(uint32_t val)
{
	return val << 20;
}

static inline uint32_t riscv_u_imm(uint32_t val)
{
	return val & 0xfffff000;
}

static inline uint32_t riscv_j_imm(uint32_t val)
{
	return (val & 0x00100000) << 11 | (val & 0x000007fe) << 20 | (val & 0x00000800) << 9 | (val & 0x000ff000);
}

#endif /* COMPEL_RELOCATIONS_H__ */