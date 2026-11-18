// Sets up the login state without init_login(), which exits unless the host has a non-loopback
// network interface with a MAC address (Mayhem runs targets with no network at all).
// Include after login.c, whose static c_login this fills in.
#ifndef MAYHEM_HARNESS_LOGIN_H
#define MAYHEM_HARNESS_LOGIN_H

static void mayhem_init_login_offline(void)
{
	c_login = calloc(1, sizeof(*c_login));
	if (!c_login)
		abort();
	c_login->version = strdup(PROTOCOL_VERESION);
	c_login->os = strdup("Linux");
	c_login->arch = strdup("x86_64");
	c_login->run_id = strdup("02:00:00:00:00:01");
	c_login->pool_count = 1;
	if (!c_login->version || !c_login->os || !c_login->arch || !c_login->run_id)
		abort();
}

#endif
