# process_login_response: attacker-controlled message length used for malloc and memcpy

`control.c:1235` does `int data_len = (int)msg_hton(mhdr->length); malloc(data_len + 1); memcpy(json_str, mhdr->data, data_len)`.
The 64-bit length comes straight from the frps message header, so a LoginResp header whose length has
low 32 bits above 0x7fffffff, which truncate to a negative `int` and `malloc` receives a gigantic size (ASan
`allocation-size-too-big`); a length that fits `int` but exceeds the bytes received is an out-of-bounds `memcpy`.
The header's length is never checked against the data actually buffered on this path.

Reproduce: `/mayhem/fuzz_control_recv-standalone mayhem/fuzz_control_recv/known-findings/login-resp-length-underflow-malloc/reproducer.bin`
(first byte = flags: bit0 tcp_mux, bit1 wire v2, bit2 already logged in; the rest is what the server sent).
