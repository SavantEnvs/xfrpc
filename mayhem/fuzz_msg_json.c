// Fuzzes the JSON message parsers that decode what frps sends to the client.
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "login.c"
#include "harness_common.h"
#include "harness_login.h"
#include "msg.h"

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	mayhem_quiet_logging();
	mayhem_load_default_config();
	mayhem_init_login_offline();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 2)
		return -1;

	uint8_t which = data[0] % 6;
	size_t jlen = size - 1;
	char *json = malloc(jlen + 1);
	if (!json)
		return -1;
	memcpy(json, data + 1, jlen);
	json[jlen] = '\0';

	switch (which) {
	case 0: {
		struct new_proxy_response *r = new_proxy_resp_unmarshal(json);
		if (r)
			new_proxy_resp_free(r);
		break;
	}
	case 1: {
		struct login_resp *r = login_resp_unmarshal(json);
		if (r) {
			login_resp_check(r);
			login_resp_free(r);
		}
		break;
	}
	case 2: {
		struct start_work_conn_resp *r = start_work_conn_resp_unmarshal(json);
		if (r) {
			free(r->proxy_name);
			free(r);
		}
		break;
	}
	case 3: {
		struct control_response *r = control_response_unmarshal(json);
		if (r)
			control_response_free(r);
		break;
	}
	case 4: {
		struct udp_packet *r = udp_packet_unmarshal(json);
		if (r)
			udp_packet_free(r);
		break;
	}
	default: {
		struct nathole_resp_msg *r = nathole_resp_unmarshal(json);
		if (r)
			nathole_resp_msg_free(r);
		break;
	}
	}

	free(json);
	return 0;
}
