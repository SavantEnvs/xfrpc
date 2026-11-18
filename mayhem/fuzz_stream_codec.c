// Fuzzes the payload codecs: snappy decompression, snappy and AES-128-CFB round trips.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "harness_common.h"
#include "crypto_stream.h"
#include "vendor/snappy/snappy.h"

#define MAX_OUT (1u << 20)

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	mayhem_quiet_logging();
	return 0;
}

static void decompress_raw(const uint8_t *in, size_t in_len, size_t out_size)
{
	uint8_t *out = malloc(out_size ? out_size : 1);
	if (!out)
		return;
	size_t out_len = out_size;
	xfrpc_decompress(in, in_len, out, out_size, &out_len);
	free(out);
}

static void snappy_round_trip(const uint8_t *in, size_t len)
{
	uint8_t *comp = malloc(snappy_max_compressed_length(len));
	uint8_t *back = malloc(len);
	size_t comp_len = 0, back_len = 0;
	if (comp && back && xfrpc_compress(in, len, comp, &comp_len) == 0) {
		if (xfrpc_decompress(comp, comp_len, back, len, &back_len) != 0 ||
		    back_len != len || memcmp(back, in, len) != 0)
			abort();
	}
	free(comp);
	free(back);
}

static void cfb(const uint8_t *iv, const uint8_t *in, size_t len, int round_trip)
{
	uint8_t key[16];
	if (crypto_derive_key("mayhem-token", key) != 0)
		return;
	uint8_t *work = malloc(len);
	if (!work)
		return;
	memcpy(work, in, len);

	struct crypto_ctx *reader = crypto_ctx_new_reader(key);
	if (reader && round_trip) {
		struct crypto_ctx *writer = crypto_ctx_new_writer(key);
		uint8_t wiv[16];
		if (writer && crypto_get_iv(writer, wiv) == 0 &&
		    crypto_encrypt(writer, work, len) == 0 &&
		    crypto_set_iv(reader, wiv) == 0 &&
		    crypto_decrypt(reader, work, len) == 0 &&
		    memcmp(work, in, len) != 0)
			abort();
		crypto_ctx_free(writer);
	} else if (reader && crypto_set_iv(reader, iv) == 0) {
		crypto_decrypt(reader, work, len);
	}
	crypto_ctx_free(reader);
	free(work);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 20)
		return -1;
	uint8_t mode = data[0] % 4;
	/* Two bytes size the output buffer, the way proxy_tcp.c sizes it from the input length. */
	size_t out_size = (((size_t)data[1] << 8) | data[2]) * 4;
	data += 3;
	size -= 3;
	if (out_size > MAX_OUT)
		out_size = MAX_OUT;

	switch (mode) {
	case 0:
		decompress_raw(data, size, out_size);
		break;
	case 1:
		snappy_round_trip(data, size);
		break;
	case 2:
		cfb(data, data + 16, size - 16, 0);
		break;
	default:
		cfb(NULL, data, size, 1);
		break;
	}
	return 0;
}
