// Fuzzes the frp wire-protocol-v2 framing, ServerHello parsing, key derivation and AEAD stream reader.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "harness_common.h"
#include "aead_stream.h"
#include "msg.h"
#include "wire_v2.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	mayhem_quiet_logging();
	return 0;
}

static void consume_frames(const uint8_t *buf, size_t len)
{
	while (len > 0) {
		uint16_t type = 0;
		const uint8_t *payload = NULL;
		uint32_t plen = 0;
		int n = wire_v2_parse_frame(buf, len, &type, &payload, &plen);
		if (n <= 0)
			return;
		if (type == WIRE_V2_FRAME_MESSAGE) {
			uint8_t *v1 = NULL;
			size_t v1_len = 0;
			if (wire_v2_payload_to_v1(payload, plen, &v1, &v1_len) == 0)
				free(v1);
		}
		buf += n;
		len -= (size_t)n;
	}
}

static void server_hello(const uint8_t *json, size_t jlen)
{
	char alg[64] = {0};
	char err[256] = {0};
	if (wire_v2_parse_server_hello_json(json, jlen, alg, sizeof(alg), err, sizeof(err)) != 0)
		return;

	uint8_t transcript[32];
	uint8_t c2s[AEAD_KEY_SIZE], s2c[AEAD_KEY_SIZE];
	wire_v2_hash_transcript(json, jlen, json, jlen, transcript);
	derive_v2_control_keys(json, jlen, transcript, alg, c2s, s2c);
}

static void aead_stream(const uint8_t *data, size_t size)
{
	static const uint8_t key[AEAD_KEY_SIZE] = {
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
	};
	struct aead_reader r;
	if (aead_reader_init(&r, key) != 0)
		return;
	/* The first byte is the chunk size the stream arrives in. */
	size_t chunk = size ? (size_t)data[0] + 1 : 1;
	if (size)
		data++, size--;
	while (size > 0) {
		size_t n = size < chunk ? size : chunk;
		if (aead_reader_feed(&r, data, n) != 0)
			break;
		r.pt_len = 0;
		data += n;
		size -= n;
	}
	aead_reader_free(&r);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 2)
		return -1;
	uint8_t which = data[0] % 5;
	data++;
	size--;

	switch (which) {
	case 0:
		consume_frames(data, size);
		break;
	case 1:
		server_hello(data, size);
		break;
	case 2: {
		uint8_t *v1 = NULL;
		size_t v1_len = 0;
		if (wire_v2_payload_to_v1(data, (uint32_t)size, &v1, &v1_len) == 0)
			free(v1);
		break;
	}
	case 3:
		aead_stream(data, size);
		break;
	default: {
		/* Round trip: whatever the encoder produces, the parser must accept. */
		if (size - 1 > 64 * 1024)
			return -1;
		uint8_t *frame = NULL;
		size_t flen = 0;
		uint16_t type = (uint16_t)(data[0] % 3);
		if (wire_v2_encode_frame(type, data + 1, (uint32_t)(size - 1), &frame, &flen) != 0)
			break;
		uint16_t rtype = 0;
		const uint8_t *payload = NULL;
		uint32_t plen = 0;
		int n = wire_v2_parse_frame(frame, flen, &rtype, &payload, &plen);
		if (n != (int)flen || rtype != type || plen != size - 1 ||
		    memcmp(payload, data + 1, plen) != 0)
			abort();
		free(frame);
		break;
	}
	}
	return 0;
}
