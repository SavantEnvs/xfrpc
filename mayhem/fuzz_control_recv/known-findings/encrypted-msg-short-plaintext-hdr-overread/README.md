# handle_control_work: heap over-read of the message header on a decrypted frame

`control.c:1155` (`handle_control_work`) reads `msg->length` from the buffer `handle_enc_msg`/`decrypt_data` returned
(`crypto.c:461`, a `calloc(enclen + 1)` sized from the encrypted length), and ASan reports a `READ of size 8`
past the end of that heap block for a short encrypted frame that decrypts to a header-sized buffer.
The frame is parsed before it is authenticated, so frps (or anyone on path) controls it.

Reproduce: `/mayhem/fuzz_control_recv-standalone mayhem/fuzz_control_recv/known-findings/encrypted-msg-short-plaintext-hdr-overread/reproducer.bin`
(first byte = flags: bit0 tcp_mux, bit1 wire v2, bit2 already logged in; the rest is what the server sent).
