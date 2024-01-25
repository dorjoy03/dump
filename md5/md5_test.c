/*
 * Copyright (c) 2024 Dorjoy Chowdhury
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#include "md5.h"

void uint8t_cmp(uint8_t got[16], uint8_t exp[16])
{
	for (int i = 0; i < 16; ++i)
		assert(got[i] == exp[i]);

	return;
}

int main()
{
	uint8_t digest[16];
	struct md5_ctx ctx;

	{
		md5_init(&ctx);
		md5_update(&ctx, (uint8_t *) "", 0);
		md5_final(&ctx, digest);
		// d41d8cd98f00b204e9800998ecf8427e
		uint8_t exp[16] = {0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e};
		uint8t_cmp(digest, exp);
	}


	{
		md5_init(&ctx);
		md5_update(&ctx, (uint8_t *) "a", 1);
		md5_final(&ctx, digest);
		// 0cc175b9c0f1b6a831c399e269772661
		uint8_t exp[16] = {0x0c, 0xc1, 0x75, 0xb9, 0xc0, 0xf1, 0xb6, 0xa8, 0x31, 0xc3, 0x99, 0xe2, 0x69, 0x77, 0x26, 0x61};
		uint8t_cmp(digest, exp);
	}

	{
		md5_init(&ctx);
		md5_update(&ctx, (uint8_t *) "abc", 3);
		md5_final(&ctx, digest);
		// 900150983cd24fb0d6963f7d28e17f72
		uint8_t exp[16] = {0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72};
		uint8t_cmp(digest, exp);
	}

	{
		md5_init(&ctx);
		md5_update(&ctx, (uint8_t *) "message digest", 14);
		md5_final(&ctx, digest);
		// f96b697d7cb7938d525a2f31aaf161d0
		uint8_t exp[16] = {0xf9, 0x6b, 0x69, 0x7d, 0x7c, 0xb7, 0x93, 0x8d, 0x52, 0x5a, 0x2f, 0x31, 0xaa, 0xf1, 0x61, 0xd0};
		uint8t_cmp(digest, exp);
	}

	{
		md5_init(&ctx);
		md5_update(&ctx, (uint8_t *) "abcdefghijklmnopqrstuvwxyz", 26);
		md5_final(&ctx, digest);
		// c3fcd3d76192e4007dfb496cca67e13b
		uint8_t exp[16] = {0xc3, 0xfc, 0xd3, 0xd7, 0x61, 0x92, 0xe4, 0x00, 0x7d, 0xfb, 0x49, 0x6c, 0xca, 0x67, 0xe1, 0x3b};
		uint8t_cmp(digest, exp);
	}

	{
		md5_init(&ctx);
		md5_update(&ctx, (uint8_t *) "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62);
		md5_final(&ctx, digest);
		// d174ab98d277d9f5a5611c2c9f419d9f
		uint8_t exp[16] = {0xd1, 0x74, 0xab, 0x98, 0xd2, 0x77, 0xd9, 0xf5, 0xa5, 0x61, 0x1c, 0x2c, 0x9f, 0x41, 0x9d, 0x9f};
		uint8t_cmp(digest, exp);
	}

	{
		md5_init(&ctx);
		md5_update(&ctx, (uint8_t *) "12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80);
		md5_final(&ctx, digest);
		// 57edf4a22be3c955ac49da2e2107b67a
		uint8_t exp[16] = {0x57, 0xed, 0xf4, 0xa2, 0x2b, 0xe3, 0xc9, 0x55, 0xac, 0x49, 0xda, 0x2e, 0x21, 0x07, 0xb6, 0x7a};
		uint8t_cmp(digest, exp);
	}

	{
		md5_init(&ctx);
		md5_update(&ctx,  (uint8_t *) "owiefjskaflaskjfqiouwepeowfjslfasldfjsladfjasljfewoiuroweriugdvjdssssssssssssssssssuewr;jfsaklfasfiohbvckjhvgasdfjsdkfjefeeyyyyyyyyyyyyyyyyyyyyyyyyyyyyfggggggggggggggggggggggggggggggggggggggggggggggggggggggggdsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafkljjjjjjjjdasdfdsssssssssssssssssssssssssssssfljka;llfdsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaasterrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrtwqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqowiefjskaflaskjfqiouwepeowfjslfasldfjsladfjasljfewoiuroweriugdvjdssssssssssssssssssuewr;jfsaklfasfiohbvckjhvgasdfjsdkfjefeeyyyyyyyyyyyyyyyyyyyyyyyyyyyyfggggggggggggggggggggggggggggggggggggggggggggggggggggggggdsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaafkljjjjjjjjdasdfdsssssssssssssssssssssssssssssfljka;llfdsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaasterrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrtwqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", 1224);
		md5_final(&ctx, digest);
		// 8b6ab066c0d88f61e468010d8e8ab467
		uint8_t exp[16] = {0x8b, 0x6a, 0xb0, 0x66, 0xc0, 0xd8, 0x8f, 0x61, 0xe4, 0x68, 0x01, 0x0d, 0x8e, 0x8a, 0xb4, 0x67};
		uint8t_cmp(digest, exp);
	}

	printf("All tests passed\n");

	return 0;
}
