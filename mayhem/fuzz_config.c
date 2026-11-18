// Raw file-input target: loads an xfrpc config with the real loader (a ".toml" file name selects the TOML parser, anything else INI).
// Built twice: fuzz_config parses its input as named, fuzz_config_toml (-DMAYHEM_FORCE_TOML) copies it to a
// /tmp/*.toml scratch file first, so the TOML parser engages whatever name the fuzzer gives the input.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "harness_common.h"
#include "visitor.h"

#ifdef MAYHEM_FORCE_TOML
static char toml_path[] = "/tmp/fuzz_config_XXXXXX.toml";

static void remove_toml_copy(void)
{
	unlink(toml_path);
}

/* Copies <src> to a fresh /tmp/*.toml file (removed at exit, which the loader may call on bad input). */
static const char *toml_copy(const char *src)
{
	FILE *in = fopen(src, "rb");
	if (!in)
		return NULL;
	int fd = mkstemps(toml_path, 5);
	if (fd < 0) {
		fclose(in);
		return NULL;
	}
	atexit(remove_toml_copy);
	char buf[65536];
	size_t n;
	while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
		if (write(fd, buf, n) != (ssize_t)n) {
			fclose(in);
			close(fd);
			return NULL;
		}
	}
	fclose(in);
	close(fd);
	return toml_path;
}
#endif

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s <config-file>\n", argv[0]);
		return 2;
	}
	const char *path = argv[1];
#ifdef MAYHEM_FORCE_TOML
	path = toml_copy(path);
	if (!path) {
		perror("fuzz_config_toml");
		return 2;
	}
#endif
	mayhem_quiet_logging();
	load_config(path);
	free_all_proxy_services();
	free_all_visitor_confs();
	free_common_config();
	return 0;
}
