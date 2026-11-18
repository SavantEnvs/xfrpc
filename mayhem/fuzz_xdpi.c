// Fuzzes handle_xdpi() (proxy_tcp.c) and xdpi_engine() (client.c): the first bytes of a work
// connection, checked against the proxy's service_type before it connects to the local service
// (tcpmux.c with tcp_mux, xdpi_proxy_s2c_cb without).
#include "harness_proxy.h"

static struct proxy_service ps;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	mayhem_proxy_init();
	ps.proxy_name = "xdpi";
	ps.proxy_type = "tcp";
	ps.local_ip = "127.0.0.1";
	ps.local_port = 22;
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 4)
		return -1;
	/* byte 0: the configured service type; the caller takes this path only when it is not NO_XDPI. */
	ps.service_type = (enum xdpi_service_type)(1 + data[0] % SERVICE_HTTPS);
	return mayhem_run_payload(data + 1, size - 1, &ps, handle_xdpi);
}
