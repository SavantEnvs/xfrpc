// Fuzzes handle_socks5() (proxy_tcp.c): the SOCKS5 greeting and CONNECT request a socks5 proxy reads
// from its work connection (tcpmux.c with tcp_mux, socks5_proxy_s2c_cb without).
#include "harness_proxy.h"

static struct proxy_service ps;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	mayhem_proxy_init();
	ps.proxy_name = "socks5";
	ps.proxy_type = "socks5";
	ps.service_type = NO_XDPI;
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	return mayhem_run_payload(data, size, &ps, handle_socks5);
}
