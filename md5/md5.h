#ifndef MD5_H
#define MD5_H

#include <stdint.h>

struct md5_ctx {
	uint32_t state[4];  // A = state[0], B = state[1], C = state[2], D = state[3]
	uint64_t count;     // byte count
	uint8_t buffer[64]; // holding area for bytes that don't make it into 64 byte chunks
};

void md5_init(struct md5_ctx *ctx);
void md5_update(struct md5_ctx *ctx, uint8_t *input, uint64_t input_len);
void md5_final(struct md5_ctx *ctx, uint8_t digest[16]);

#endif /* MD5_H */
