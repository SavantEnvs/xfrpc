// Known-answer probe for the functional oracle (mayhem/test.sh): runs real xfrpc code on fixed
// inputs and prints the results, which test.sh compares to golden text.
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "client.h"
#include "config.h"
#include "crypto_stream.h"
#include "login.h"
#include "msg.h"
#include "tcpmux.h"
#include "wire_v2.h"

static void hex(const char *label, const uint8_t *p, size_t n)
{
	printf("%s=", label);
	for (size_t i = 0; i < n; i++)
		printf("%02x", p[i]);
	printf("\n");
}

static int kat_config(const char *path)
{
	load_config(path);
	struct common_conf *c = get_common_config();
	printf("server_addr=%s\nserver_port=%d\ntcp_mux=%d\nheartbeat_interval=%d\n",
	       c->server_addr, c->server_port, c->tcp_mux, c->heartbeat_interval);
	printf("token=%s\n", c->auth_token ? c->auth_token : "(none)");
	struct proxy_service *ps = get_proxy_service("ssh");
	if (!ps) {
		printf("proxy ssh: missing\n");
		return 0;
	}
	printf("proxy=%s type=%s local_ip=%s local_port=%d remote_port=%d\n", ps->proxy_name,
	       ps->proxy_type, ps->local_ip, ps->local_port, ps->remote_port);
	return 0;
}

static int kat_json(void)
{
	struct login_resp *lr = login_resp_unmarshal(
		"{\"version\":\"0.61.0\",\"run_id\":\"abcdef0123456789\",\"error\":\"\"}");
	printf("login_resp version=%s run_id=%s error=%s\n", lr->version, lr->run_id, lr->error);
	login_resp_free(lr);

	struct new_proxy_response *np = new_proxy_resp_unmarshal(
		"{\"run_id\":\"r1\",\"proxy_name\":\"web\",\"remote_addr\":\"0.0.0.0:8080\",\"error\":\"\"}");
	printf("new_proxy run_id=%s name=%s remote_port=%d error=%s\n", np->run_id, np->proxy_name,
	       np->remote_port, np->error);
	new_proxy_resp_free(np);

	struct start_work_conn_resp *sw = start_work_conn_resp_unmarshal(
		"{\"proxy_name\":\"ssh\",\"src_addr\":\"1.2.3.4\",\"src_port\":1234}");
	printf("start_work_conn proxy_name=%s\n", sw->proxy_name);
	free(sw->proxy_name);
	free(sw);

	struct udp_packet *up = udp_packet_unmarshal(
		"{\"c\":\"aGVsbG8=\",\"l\":{\"IP\":\"10.0.0.1\",\"Port\":53},\"r\":{\"IP\":\"10.0.0.2\",\"Port\":5353}}");
	printf("udp content=%s laddr=%s:%d raddr=%s:%d\n", up->content, up->laddr->addr,
	       up->laddr->port, up->raddr->addr, up->raddr->port);
	udp_packet_free(up);

	printf("bad_json=%s\n", login_resp_unmarshal("{not json") ? "parsed" : "rejected");
	return 0;
}

static int kat_wire(void)
{
	uint8_t *frame = NULL;
	size_t flen = 0;
	if (wire_v2_encode_message(TypeReqWorkConn, "{}", 2, &frame, &flen) != 0)
		return 1;
	hex("req_work_conn_frame", frame, flen);

	uint16_t type = 0;
	const uint8_t *payload = NULL;
	uint32_t plen = 0;
	int n = wire_v2_parse_frame(frame, flen, &type, &payload, &plen);
	printf("parse n=%d type=%u plen=%u\n", n, type, plen);

	uint8_t *v1 = NULL;
	size_t v1_len = 0;
	if (wire_v2_payload_to_v1(payload, plen, &v1, &v1_len) != 0)
		return 1;
	hex("v1", v1, v1_len);
	free(v1);
	free(frame);

	static const uint8_t partial[] = {0, 16, 0, 0, 0, 0, 0, 9, 'x'};
	printf("partial=%d\n", wire_v2_parse_frame(partial, sizeof(partial), &type, &payload, &plen));
	static const uint8_t bad_flags[] = {0, 16, 0, 1, 0, 0, 0, 0};
	printf("bad_flags=%d\n", wire_v2_parse_frame(bad_flags, sizeof(bad_flags), &type, &payload, &plen));

	char alg[64] = {0}, err[64] = {0};
	static const char sh[] = "{\"selected\":{\"crypto\":{\"algorithm\":\"aes-256-gcm\"}}}";
	int rc = wire_v2_parse_server_hello_json((const uint8_t *)sh, strlen(sh), alg, sizeof(alg), err, sizeof(err));
	printf("server_hello rc=%d alg=%s\n", rc, alg);
	static const char bad[] = "{\"selected\":{\"crypto\":{\"algorithm\":\"rc4\"}}}";
	rc = wire_v2_parse_server_hello_json((const uint8_t *)bad, strlen(bad), alg, sizeof(alg), err, sizeof(err));
	printf("server_hello_bad rc=%d\n", rc);

	uint8_t digest[32];
	wire_v2_hash_transcript((const uint8_t *)"ch", 2, (const uint8_t *)"sh", 2, digest);
	hex("transcript", digest, sizeof(digest));
	return 0;
}

static int kat_codec(void)
{
	uint8_t key[16];
	crypto_derive_key("token", key);
	hex("key", key, sizeof(key));

	static const uint8_t iv[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
	uint8_t buf[11] = "hello world";
	struct crypto_ctx *r = crypto_ctx_new_reader(key);
	crypto_set_iv(r, iv);
	crypto_decrypt(r, buf, sizeof(buf));
	hex("cfb_decrypt_hello_world", buf, sizeof(buf));
	crypto_ctx_free(r);

	/* snappy: varint length 5, literal tag, "hello" */
	static const uint8_t comp[] = {0x05, 0x10, 'h', 'e', 'l', 'l', 'o'};
	uint8_t out[32];
	size_t out_len = 0;
	int rc = xfrpc_decompress(comp, sizeof(comp), out, sizeof(out), &out_len);
	printf("snappy rc=%d len=%zu text=%.*s\n", rc, out_len, (int)out_len, out);
	rc = xfrpc_decompress(comp, sizeof(comp), out, 4, &out_len);
	printf("snappy_small_buffer rc=%d\n", rc);

	uint8_t c2[64];
	size_t c2_len = 0;
	rc = xfrpc_compress((const uint8_t *)"hello hello hello hello", 23, c2, &c2_len);
	hex("snappy_compressed", c2, c2_len);
	return rc;
}

static int kat_mux(void)
{
	struct tcp_mux_header h;
	tcp_mux_encode(TMUX_DATA, SYN, 5, 300, &h);
	hex("mux_data_syn", (const uint8_t *)&h, sizeof(h));
	printf("validate=%d\n", validate_tcp_mux_protocol(&h));
	tcp_mux_encode(WINDOW_UPDATE, ACK, 7, 0, &h);
	hex("mux_window_ack", (const uint8_t *)&h, sizeof(h));
	h.version = 9;
	printf("validate_bad_version=%d\n", validate_tcp_mux_protocol(&h));
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2)
		return 2;
	if (!strcmp(argv[1], "config") && argc == 3)
		return kat_config(argv[2]);
	if (!strcmp(argv[1], "json"))
		return kat_json();
	if (!strcmp(argv[1], "wire"))
		return kat_wire();
	if (!strcmp(argv[1], "codec"))
		return kat_codec();
	if (!strcmp(argv[1], "mux"))
		return kat_mux();
	return 2;
}
