// Fuzzes the control-connection receive path: bytes frps sends are handed to recv_cb() through a
// socketless bufferevent, covering the yamux/tcpmux framing, login response, v1 and v2 dispatch.
// control.c is included so its static state can be reset between inputs.
#include "control.c"
#include "login.c"
#include "harness_common.h"
#include "harness_login.h"

static struct bufferevent *ctl_bev;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	mayhem_quiet_logging();
	mayhem_load_default_config();
	mayhem_init_login_offline();
	init_main_control();
	ctl_bev = bufferevent_socket_new(main_ctl->connect_base, -1, 0);
	if (!ctl_bev)
		abort();
	main_ctl->connect_bev = ctl_bev;
	/* A socket bufferevent freezes the end of its input and the start of its output; this one has no socket. */
	evbuffer_unfreeze(bufferevent_get_input(ctl_bev), 0);
	evbuffer_unfreeze(bufferevent_get_output(ctl_bev), 1);
	static uint8_t ch[] = "{\"version\":\"0.1\"}";
	v2_ch_json = ch;
	v2_ch_json_len = sizeof(ch) - 1;
	return 0;
}

static void reset_state(int tcp_mux, int v2, int logged_in)
{
	handle_tcp_mux(NULL, 0, NULL);
	clear_all_proxy_client();
	tmux_stream_release(&main_ctl->stream);
	memset(&abandon_stream, 0, sizeof(abandon_stream));
	reset_session_id();
	memset(&main_ctl->stream, 0, sizeof(main_ctl->stream));
	init_tmux_stream(&main_ctl->stream, get_next_session_id(), ESTABLISHED);
	free_crypto_resources();
	aead_reader_free(&v2_ar);
	aead_writer_free(&v2_aw);
	evbuffer_drain(bufferevent_get_output(ctl_bev), evbuffer_get_length(bufferevent_get_output(ctl_bev)));
	evbuffer_drain(bufferevent_get_input(ctl_bev), evbuffer_get_length(bufferevent_get_input(ctl_bev)));

	is_login = logged_in;
	xfrpc_status = false;
	v2_got_hello = 0;
	v2_aead_ready = 0;

	struct common_conf *c = get_common_config();
	c->tcp_mux = tcp_mux;
	free(c->wire_protocol);
	c->wire_protocol = strdup(v2 ? "v2" : "v1");
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 2)
		return -1;
	uint8_t flags = data[0];
	data++;
	size--;

	reset_state(flags & 1, (flags >> 1) & 1, (flags >> 2) & 1);

	if (evbuffer_add(bufferevent_get_input(ctl_bev), data, size) != 0)
		return -1;
	recv_cb(ctl_bev, NULL);
	return 0;
}
