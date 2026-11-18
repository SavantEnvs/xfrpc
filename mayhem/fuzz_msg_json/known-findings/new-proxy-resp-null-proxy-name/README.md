# new_proxy_resp_unmarshal: NULL passed to strdup when `proxy_name` is JSON null

`msg.c:612` calls `strdup(json_object_get_string(j_proxy_name))`; for a JSON `null` value json-c returns NULL,
so a NewProxyResp from the server like `{"proxy_name":null}` passes NULL to `strdup` (UBSan `nonnull-attribute`,
a NULL dereference in libc without UBSan). The same pattern is at `msg.c:668` for a LoginResp whose
`run_id`/`version`/`error` are null.

Reproduce: `/mayhem/fuzz_msg_json-standalone mayhem/fuzz_msg_json/known-findings/new-proxy-resp-null-proxy-name/reproducer.bin`
(first byte selects the parser, the rest is the JSON).
