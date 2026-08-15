#include "port_state.h"

/*
 * Port of _Multiply in engine/math/multiply_divide.asm.
 *
 * Performs 24-bit × 8-bit multiplication using shift-and-add algorithm.
 *
 * Inputs (memory-mapped):
 *   hMultiplicand (0xFF96-0xFF98): 24-bit multiplicand (big-endian)
 *   hMultiplier   (0xFF99):        8-bit multiplier
 *
 * Outputs:
 *   hProduct      (0xFF95-0xFF98): 32-bit product (big-endian)
 *
 * Algorithm: shift-and-add. Multiplier is shifted right each iteration;
 * if carry was set (bit was 1), add multiplicand to product. Then
 * shift multiplicand left. Repeat 8 times.
 */
__attribute__((noinline, used)) void
port_multiply(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;

	/* Load multiplicand (24-bit) */
	port_u32 multiplicand = 0;
	multiplicand |= (port_u32)memory[0xFF96] << 16;
	multiplicand |= (port_u32)memory[0xFF97] << 8;
	multiplicand |= (port_u32)memory[0xFF98];

	/* Load multiplier (8-bit) */
	port_u8 multiplier = memory[0xFF99];

	/* Initialize product to 0 (32-bit) */
	port_u32 product = 0;

	/* 8-bit shift-and-add multiplication */
	for (port_u8 i = 0; i < 8; i++) {
		/* Check LSB of multiplier (equivalent to SRL + JR NC) */
		if (multiplier & 0x01) {
			product += multiplicand;
		}

		/* Shift multiplier right */
		multiplier >>= 1;

		/* Shift multiplicand left (24-bit) */
		multiplicand <<= 1;
	}

	/* Store 32-bit product (big-endian) */
	memory[0xFF95] = (port_u8)(product >> 24);
	memory[0xFF96] = (port_u8)(product >> 16);
	memory[0xFF97] = (port_u8)(product >> 8);
	memory[0xFF98] = (port_u8)product;
}

/*
 * Port of _Divide in engine/math/multiply_divide.asm.
 *
 * Performs 32-bit ÷ 8-bit division using restoring division algorithm.
 *
 * Inputs (memory-mapped):
 *   hDividend (0xFF95-0xFF98): 32-bit dividend (big-endian)
 *   hDivisor  (0xFF99):        8-bit divisor
 *
 * Outputs:
 *   hQuotient  (0xFF95-0xFF98): 32-bit quotient (big-endian)
 *   hRemainder (0xFF99):        8-bit remainder (overwrites divisor)
 *
 * Algorithm: Restoring division. For each bit position from MSB to LSB:
 *   - Shift remainder left, bring down next dividend bit
 *   - Subtract divisor from remainder
 *   - If no borrow (remainder >= divisor), set quotient bit and keep new remainder
 *   - If borrow (remainder < divisor), restore remainder and clear quotient bit
 * Repeat 32 times (or until dividend exhausted).
 */
__attribute__((noinline, used)) void
port_divide(struct cpu_register_state *state, port_u8 *memory)
{
	(void)state;

	/* Load 32-bit dividend (big-endian) */
	port_u32 dividend = 0;
	dividend |= (port_u32)memory[0xFF95] << 24;
	dividend |= (port_u32)memory[0xFF96] << 16;
	dividend |= (port_u32)memory[0xFF97] << 8;
	dividend |= (port_u32)memory[0xFF98];

	/* Load 8-bit divisor */
	port_u8 divisor = memory[0xFF99];

	/* Initialize quotient and remainder */
	port_u32 quotient = 0;
	port_u8 remainder = 0;

	/* Restoring division: 32 iterations for 32-bit dividend */
	for (port_u8 i = 0; i < 32; i++) {
		/* Shift remainder left by 1 */
		remainder <<= 1;

		/* Bring down next bit of dividend (MSB first) */
		if (dividend & 0x80000000) {
			remainder |= 1;
		}

		/* Shift dividend left for next iteration */
		dividend <<= 1;

		/* Try subtracting divisor from remainder */
		if (remainder >= divisor) {
			remainder -= divisor;
			quotient = (quotient << 1) | 1;
		} else {
			quotient = (quotient << 1) | 0;
		}
	}

	/* Store 32-bit quotient (big-endian) */
	memory[0xFF95] = (port_u8)(quotient >> 24);
	memory[0xFF96] = (port_u8)(quotient >> 16);
	memory[0xFF97] = (port_u8)(quotient >> 8);
	memory[0xFF98] = (port_u8)quotient;

	/* Store 8-bit remainder (overwrites divisor) */
	memory[0xFF99] = remainder;
}