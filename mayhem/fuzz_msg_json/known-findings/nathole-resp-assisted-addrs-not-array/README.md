# parse_json_string_array: json_object_array_length() on a non-array aborts

`msg.c:1219` only checks that the key exists, then calls `json_object_array_length(jarr)`. When the server
sends `"assisted_addrs":0` (or any non-array value), json-c's `assert(json_object_is_type(jso, json_type_array))`
fires and the client aborts. Reached from `nathole_resp_unmarshal` (`msg.c:1274`).

Reproduce: `/mayhem/fuzz_msg_json-standalone mayhem/fuzz_msg_json/known-findings/nathole-resp-assisted-addrs-not-array/reproducer.bin`
