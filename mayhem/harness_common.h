// Shared one-time setup for the in-process harnesses.
#ifndef MAYHEM_HARNESS_COMMON_H
#define MAYHEM_HARNESS_COMMON_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/mman.h>

#include "config.h"
#include "debug.h"

/* Loads a minimal INI config through an anonymous memfd, so no file is written anywhere. */
static void mayhem_load_default_config(void)
{
	static const char ini[] =
		"[common]\n"
		"server_addr = 127.0.0.1\n"
		"server_port = 7000\n"
		"token = mayhem-token\n"
		"[ssh]\n"
		"type = tcp\n"
		"local_ip = 127.0.0.1\n"
		"local_port = 22\n"
		"remote_port = 6000\n";
	int fd = memfd_create("xfrpc.ini", 0);
	if (fd < 0)
		abort();
	if (write(fd, ini, sizeof(ini) - 1) != (ssize_t)(sizeof(ini) - 1))
		abort();
	char path[64];
	snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
	load_config(path);
	close(fd);
}

static void mayhem_quiet_logging(void)
{
	debugconf.debuglevel = LOG_EMERG;
	debugconf.log_stderr = 0;
}

#endif
