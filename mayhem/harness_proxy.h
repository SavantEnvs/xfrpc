// Shared setup for the work-connection payload harnesses (fuzz_socks5, fuzz_xdpi). The payload frps
// relays on a work connection is handed to the handler through a socketless bufferevent, chunk by
// chunk, as tcpmux.c (tcp_mux = 1) or the work connection's read callback (tcp_mux = 0) does.
// control.c is included so main_ctl can be set up with an offline resolver.
#include "control.c"
#include "login.c"
#include "harness_common.h"

#include <errno.h>
#include <event2/dns.h>

/* Socket mock: every outgoing connection is refused, so no input makes the target reach a real
 * address (Mayhem runs targets without a network; this makes every host behave the same). */
int connect(int fd, const struct sockaddr *addr, socklen_t len)
{
	(void)fd;
	(void)addr;
	(void)len;
	errno = ECONNREFUSED;
	return -1;
}

static struct bufferevent *mayhem_ctl_bev;

static void mayhem_proxy_init(void)
{
	mayhem_quiet_logging();
	mayhem_load_default_config();
	main_ctl = calloc(1, sizeof(*main_ctl));
	if (!main_ctl)
		abort();
	main_ctl->connect_base = event_base_new();
	if (!main_ctl->connect_base)
		abort();
	/* init_main_control() would load nameservers from resolv.conf; with none, lookups fail offline. */
	main_ctl->dnsbase = evdns_base_new(main_ctl->connect_base, 0);
	if (!main_ctl->dnsbase)
		abort();
	mayhem_ctl_bev = bufferevent_socket_new(main_ctl->connect_base, -1, 0);
	if (!mayhem_ctl_bev)
		abort();
	main_ctl->connect_bev = mayhem_ctl_bev;
	/* A socket bufferevent freezes the end of its input and the start of its output; this one has no socket. */
	evbuffer_unfreeze(bufferevent_get_input(mayhem_ctl_bev), 0);
	evbuffer_unfreeze(bufferevent_get_output(mayhem_ctl_bev), 1);
}

typedef void (*mayhem_handler)(struct proxy_client *, struct bufferevent *, uint32_t);

/* Input: byte 0 = flags (bit 0: tcp_mux), byte 1 = chunk size - 1, then the payload. */
static int mayhem_run_payload(const uint8_t *data, size_t size, struct proxy_service *ps,
			      mayhem_handler handle)
{
	if (size < 3)
		return -1;
	struct common_conf *c = get_common_config();
	c->tcp_mux = data[0] & 1;
	size_t chunk = (size_t)data[1] + 1;
	data += 2;
	size -= 2;

	struct proxy_client *pc = new_proxy_client();
	if (!pc)
		abort();
	pc->base = main_ctl->connect_base;
	pc->ctl_bev = mayhem_ctl_bev;
	pc->ps = ps;

	struct evbuffer *in = bufferevent_get_input(mayhem_ctl_bev);
	while (size > 0) {
		size_t n = size < chunk ? size : chunk;
		if (evbuffer_add(in, data, n) != 0)
			abort();
		handle(pc, mayhem_ctl_bev, (uint32_t)n);
		/* The caller counts the whole chunk as processed. */
		evbuffer_drain(in, evbuffer_get_length(in));
		data += n;
		size -= n;
	}

	clear_all_proxy_client();
	struct evbuffer *out = bufferevent_get_output(mayhem_ctl_bev);
	evbuffer_drain(out, evbuffer_get_length(out));
	/* Run the deferred callbacks and finalizers the freed bufferevents left behind. */
	event_base_loop(main_ctl->connect_base, EVLOOP_NONBLOCK);
	return 0;
}
