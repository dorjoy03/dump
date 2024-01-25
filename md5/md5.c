/*
 * Copyright (c) 2024 Dorjoy Chowdhury
 * SPDX-License-Identifier: BSD-2-Clause
 */

/*
 * Derived from the RSA Data Security, Inc. MD5 Message-Digest Algorithm
 * Ref: https://www.rfc-editor.org/rfc/rfc1321.txt
 * Mostly similar code like in the rfc with some changes of my own
 */

#include <stdint.h>

#include "md5.h"

#define S11 7
#define S12 12
#define S13 17
#define S14 22

#define S21 5
#define S22 9
#define S23 14
#define S24 20

#define S31 4
#define S32 11
#define S33 16
#define S34 23

#define S41 6
#define S42 10
#define S43 15
#define S44 21

#define F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~(z))))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~(z))))

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define FF(a, b, c, d, x, s, ac) { \
		(a) += F((b), (c), (d)) + (x) + (ac); \
		(a) = ROTATE_LEFT((a), (s)); \
		(a) += (b); \
	}

#define GG(a, b, c, d, x, s, ac) { \
		(a) += G((b), (c), (d)) + (x) + (ac); \
		(a) = ROTATE_LEFT((a), (s)); \
		(a) += (b); \
	}

#define HH(a, b, c, d, x, s, ac) { \
		(a) += H((b), (c), (d)) + (x) + (ac); \
		(a) = ROTATE_LEFT((a), (s)); \
		(a) += (b); \
	}

#define II(a, b, c, d, x, s, ac) { \
		(a) += I((b), (c), (d)) + (x) + (ac); \
		(a) = ROTATE_LEFT((a), (s)); \
		(a) += (b); \
	}

static uint8_t PADDING[64] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void
md5_init(struct md5_ctx *ctx) {
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
	ctx->count = 0;
}

static void
md5_transform(uint32_t state[4], uint8_t block[64])
{
	uint32_t a = state[0];
	uint32_t b = state[1];
	uint32_t c = state[2];
	uint32_t d = state[3];

	uint32_t x[16];
	x[0] = ((uint32_t) block[0]) | ((uint32_t) block[1] << 8) | ((uint32_t) block[2] << 16) | ((uint32_t) block[3] << 24);
	x[1] = ((uint32_t) block[4]) | ((uint32_t) block[5] << 8) | ((uint32_t) block[6] << 16) | ((uint32_t) block[7] << 24);
	x[2] = ((uint32_t) block[8]) | ((uint32_t) block[9] << 8) | ((uint32_t) block[10] << 16) | ((uint32_t) block[11] << 24);
	x[3] = ((uint32_t) block[12]) | ((uint32_t) block[13] << 8) | ((uint32_t) block[14] << 16) | ((uint32_t) block[15] << 24);
	x[4] = ((uint32_t) block[16]) | ((uint32_t) block[17] << 8) | ((uint32_t) block[18] << 16) | ((uint32_t) block[19] << 24);
	x[5] = ((uint32_t) block[20]) | ((uint32_t) block[21] << 8) | ((uint32_t) block[22] << 16) | ((uint32_t) block[23] << 24);
	x[6] = ((uint32_t) block[24]) | ((uint32_t) block[25] << 8) | ((uint32_t) block[26] << 16) | ((uint32_t) block[27] << 24);
	x[7] = ((uint32_t) block[28]) | ((uint32_t) block[29] << 8) | ((uint32_t) block[30] << 16) | ((uint32_t) block[31] << 24);
	x[8] = ((uint32_t) block[32]) | ((uint32_t) block[33] << 8) | ((uint32_t) block[34] << 16) | ((uint32_t) block[35] << 24);
	x[9] = ((uint32_t) block[36]) | ((uint32_t) block[37] << 8) | ((uint32_t) block[38] << 16) | ((uint32_t) block[39] << 24);
	x[10] = ((uint32_t) block[40]) | ((uint32_t) block[41] << 8) | ((uint32_t) block[42] << 16) | ((uint32_t) block[43] << 24);
	x[11] = ((uint32_t) block[44]) | ((uint32_t) block[45] << 8) | ((uint32_t) block[46] << 16) | ((uint32_t) block[47] << 24);
	x[12] = ((uint32_t) block[48]) | ((uint32_t) block[49] << 8) | ((uint32_t) block[50] << 16) | ((uint32_t) block[51] << 24);
	x[13] = ((uint32_t) block[52]) | ((uint32_t) block[53] << 8) | ((uint32_t) block[54] << 16) | ((uint32_t) block[55] << 24);
	x[14] = ((uint32_t) block[56]) | ((uint32_t) block[57] << 8) | ((uint32_t) block[58] << 16) | ((uint32_t) block[59] << 24);
	x[15] = ((uint32_t) block[60]) | ((uint32_t) block[61] << 8) | ((uint32_t) block[62] << 16) | ((uint32_t) block[63] << 24);

	/* Round 1 */
	FF(a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
	FF(d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
	FF(c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
	FF(b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
	FF(a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
	FF(d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
	FF(c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
	FF(b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
	FF(a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
	FF(d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
	FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
	FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
	FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
	FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
	FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
	FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

	/* Round 2 */
	GG(a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
	GG(d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
	GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
	GG(b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
	GG(a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
	GG(d, a, b, c, x[10], S22,  0x2441453); /* 22 */
	GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
	GG(b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
	GG(a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
	GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
	GG(c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
	GG(b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
	GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
	GG(d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
	GG(c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
	GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

	/* Round 3 */
	HH(a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
	HH(d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
	HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
	HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
	HH(a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
	HH(d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
	HH(c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
	HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
	HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
	HH(d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
	HH(c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
	HH(b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
	HH(a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
	HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
	HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
	HH(b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

	/* Round 4 */
	II(a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
	II(d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
	II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
	II(b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
	II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
	II(d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
	II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
	II(b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
	II(a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
	II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
	II(c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
	II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
	II(a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
	II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
	II(c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
	II(b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;

	return;
}

void
md5_update(struct md5_ctx *ctx, uint8_t *input, uint64_t input_len)
{
	uint8_t buf_index = ctx->count & 0x3F;
	uint64_t input_left = input_len;
	uint8_t *tmp = input;

	if (buf_index > 0) {
		for (uint8_t i = buf_index; i < 64 && input_left > 0; ++i) {
			ctx->buffer[i] = *tmp;
			--input_left;
			++tmp;
			if (i == 63)
				md5_transform(ctx->state, ctx->buffer);
		}
	}

	uint64_t block_count = input_left >> 6; // input_left / 64
	for (uint64_t i = 0; i < block_count; ++i) {
		md5_transform(ctx->state, tmp);
		input_left -= 64;
		tmp += 64;
	}

	// At this point, input_left should be less than 64
	for (uint8_t i = 0; i < input_left; ++i) {
		ctx->buffer[i] = *tmp;
		++tmp;
	}

	ctx->count += input_len;
	return;
}

void
md5_final(struct md5_ctx *ctx, uint8_t digest[16])
{
	uint64_t total_bits = ctx->count << 3; // (byte count * 8) bits
	uint8_t index = ctx->count & 0x3F;
	uint8_t pad_len = index < 56 ? (56 - index) : (120 - index);
	md5_update(ctx, PADDING, pad_len);

	uint8_t bits_count[8];
	bits_count[0] = (uint8_t) (total_bits & 0xFF);
	bits_count[1] = (uint8_t) ((total_bits >> 8) & 0xFF);
	bits_count[2] = (uint8_t) ((total_bits >> 16) & 0xFF);
	bits_count[3] = (uint8_t) ((total_bits >> 24) & 0xFF);
	bits_count[4] = (uint8_t) ((total_bits >> 32) & 0xFF);
	bits_count[5] = (uint8_t) ((total_bits >> 40) & 0xFF);
	bits_count[6] = (uint8_t) ((total_bits >> 48) & 0xFF);
	bits_count[7] = (uint8_t) ((total_bits >> 56) & 0xFF);
	md5_update(ctx, bits_count, 8);

	digest[0] = (uint8_t) (ctx->state[0] & 0xFF);
	digest[1] = (uint8_t) ((ctx->state[0] >> 8) & 0xFF);
	digest[2] = (uint8_t) ((ctx->state[0] >> 16) & 0xFF);
	digest[3] = (uint8_t) ((ctx->state[0] >> 24) & 0xFF);

	digest[4] = (uint8_t) (ctx->state[1] & 0xFF);
	digest[5] = (uint8_t) ((ctx->state[1] >> 8) & 0xFF);
	digest[6] = (uint8_t) ((ctx->state[1] >> 16) & 0xFF);
	digest[7] = (uint8_t) ((ctx->state[1] >> 24) & 0xFF);

	digest[8] = (uint8_t) (ctx->state[2] & 0xFF);
	digest[9] = (uint8_t) ((ctx->state[2] >> 8) & 0xFF);
	digest[10] = (uint8_t) ((ctx->state[2] >> 16) & 0xFF);
	digest[11] = (uint8_t) ((ctx->state[2] >> 24) & 0xFF);

	digest[12] = (uint8_t) (ctx->state[3] & 0xFF);
	digest[13] = (uint8_t) ((ctx->state[3] >> 8) & 0xFF);
	digest[14] = (uint8_t) ((ctx->state[3] >> 16) & 0xFF);
	digest[15] = (uint8_t) ((ctx->state[3] >> 24) & 0xFF);

	return;
}
