// Fuzzes the STUN Binding Response parser (nathole.c: stun_extract_addr -> stun_parse_response) on a
// UDP reply, making the three calls the STUN query loop makes on each response. nathole.c is
// included because both functions are static.
#include "nathole.c"
#include "harness_common.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	mayhem_quiet_logging();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	/* The caller receives into a 1024-byte buffer (stun_do_request's resp_buf_len); recvfrom()
	 * truncates a longer reply to that, so do the same. */
	uint8_t resp[1024];
	if (size > sizeof(resp))
		size = sizeof(resp);
	memcpy(resp, data, size);

	/* A reply to our request echoes the random transaction ID we sent; take it from the reply. */
	uint8_t txid[STUN_TXID_LEN] = {0};
	if (size >= 8 + STUN_TXID_LEN)
		memcpy(txid, resp + 8, STUN_TXID_LEN);

	char mapped[64], other[64];
	if (stun_extract_addr(resp, size, txid, STUN_ATTR_XOR_MAPPED_ADDR, mapped, sizeof(mapped)) != 0)
		stun_extract_addr(resp, size, txid, STUN_ATTR_MAPPED_ADDR, mapped, sizeof(mapped));
	stun_extract_addr(resp, size, txid, STUN_ATTR_OTHER_ADDR, other, sizeof(other));
	return 0;
}
