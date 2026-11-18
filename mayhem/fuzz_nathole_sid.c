// Fuzzes the XTCP hole-punch packet decoder (nathole.c: nathole_decode_sid), which xtcp_client.c and
// xtcp_visitor.c call on every UDP datagram recvfrom()'d from any peer during hole punching. The
// datagram is AES-128-CFB with no MAC, so a peer controls the decrypted plaintext completely; the
// fuzz input IS that plaintext ([type:1][len:8 BE][json]). Each input is encrypted with nathole.c's
// own aes_cfb_encrypt under a fixed secret key and handed to nathole_decode_sid as the datagram, so
// the fuzzer works on the plaintext parser instead of on ciphertext. nathole.c is included because
// the encryption helpers are static.
#include "nathole.c"
#include "harness_common.h"

static const char *k_secret = "mayhem-fuzz-secret";
static uint8_t k_key[16];

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	mayhem_quiet_logging();
	derive_nathole_key(k_secret, k_key);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	/* Both callers recvfrom() into a 2048-byte buffer, which truncates longer datagrams; the
	 * ciphertext carries a 16-byte IV, so at most 2032 plaintext bytes reach the decoder. CFB is
	 * a stream mode, so truncating the plaintext is the same as truncating the datagram. */
	uint8_t dgram[2048];
	if (size > sizeof(dgram) - 16)
		size = sizeof(dgram) - 16;
	int n = aes_cfb_encrypt(data, size, k_key, dgram, sizeof(dgram));
	if (n < 0)
		return 0;

	struct nathole_sid_msg msg;
	memset(&msg, 0, sizeof(msg));
	if (nathole_decode_sid(dgram, (size_t)n, k_secret, &msg) == 0)
		nathole_sid_msg_free(&msg);
	return 0;
}
