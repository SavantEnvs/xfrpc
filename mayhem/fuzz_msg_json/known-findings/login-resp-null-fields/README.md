# login_resp_unmarshal: NULL passed to strdup when run_id/version/error are JSON null

`msg.c:668`, same root cause as `new-proxy-resp-null-proxy-name`: `json_object_get_string()` returns NULL for a
JSON null and the result goes straight into `strdup`.

Reproduce: `/mayhem/fuzz_msg_json-standalone mayhem/fuzz_msg_json/known-findings/login-resp-null-fields/reproducer.bin`
