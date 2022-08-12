/**
 * @file lcz_shell_login.c
 *
 * Copyright (c) 2022 Laird Connectivity
 *
 * SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
 */

/**************************************************************************************************/
/* Includes                                                                                       */
/**************************************************************************************************/
#include <logging/log.h>
LOG_MODULE_REGISTER(lcz_shell_login, CONFIG_LCZ_SHELL_LOGIN_LOG_LEVEL);

#include <zephyr.h>
#include <init.h>
#include <shell/shell.h>
#include <shell/shell_uart.h>
#if defined(CONFIG_SHELL_LOGIN_ENABLE_ATTRIBUTES)
#include "attr.h"
#endif
#include "lcz_shell_login.h"

/**************************************************************************************************/
/* Local Constant, Macro and Type Definitions                                                     */
/**************************************************************************************************/
#define SHELL_PROMPT_LOGGED_OUT "login: "
#define SHELL_PROMPT_LOGGED_IN "uart:~$ "
#define SHELL_LOGIN_COMMAND "login"
#define SHELL_DEFAULT_PASSWORD "zephyr"

/**************************************************************************************************/
/* Local Function Prototypes                                                                      */
/**************************************************************************************************/
static void set_shell_logged_in(const struct shell *shell, bool logged_in, bool init);
static int cmd_login(const struct shell *shell, size_t argc, char **argv);
static int cmd_logout(const struct shell *shell, size_t argc, char **argv);
#if defined(CONFIG_SHELL_LOGIN_ENABLE_ATTRIBUTES)
static int cmd_passwd(const struct shell *shell, size_t argc, char **argv);
#endif
static bool is_passwd_set(void);
static int lcz_shell_login_init(const struct device *device);

/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/
static char *password;
static bool user_logged_in;

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/
static void set_shell_logged_in(const struct shell *shell, bool logged_in, bool init)
{
	if (logged_in) {
		shell_obscure_set(shell, false);
		shell_set_root_cmd(NULL);
		shell_prompt_change(shell, SHELL_PROMPT_LOGGED_IN);
		shell_print(shell, "\n");
		if (init) {
#if defined(CONFIG_SHELL_LOG_BACKEND)
			z_shell_log_backend_enable(shell->log_backend, (void *)shell,
						   LOG_LEVEL_DBG);
#endif
		} else {
			log_backend_activate(shell->log_backend->backend,
					     shell->log_backend->backend->cb->ctx);
		}
	} else {
		shell_set_root_cmd(SHELL_LOGIN_COMMAND);
		shell_obscure_set(shell, true);
		shell_prompt_change(shell, SHELL_PROMPT_LOGGED_OUT);
		shell_print(shell, "\n");
		log_backend_deactivate(shell->log_backend->backend);
	}
	user_logged_in = logged_in;
}

static int verify_password(char *passwd)
{
	return strcmp(passwd, password);
}

static int cmd_login(const struct shell *shell, size_t argc, char **argv)
{
	static uint32_t attempts;

	if (verify_password(argv[1]) != 0) {
		shell_error(shell, "Invalid password!");
		attempts++;
		if (attempts > 3) {
			k_sleep(K_SECONDS(attempts));
		}
		return -EINVAL;
	}

	/* clear history so password not visible there */
	z_shell_history_purge(shell->history);
	set_shell_logged_in(shell, true, false);
	attempts = 0;
	return 0;
}

static int cmd_logout(const struct shell *shell, size_t argc, char **argv)
{
	if (!is_passwd_set()) {
		shell_error(shell, "Password not set!");
		return -EINVAL;
	}
	set_shell_logged_in(shell, false, false);
	return 0;
}

#if defined(CONFIG_SHELL_LOGIN_ENABLE_ATTRIBUTES)
static int cmd_passwd(const struct shell *shell, size_t argc, char **argv)
{
	int ret;
	char *pwd;

	pwd = argv[1];
	ret = attr_set(ATTR_ID_shell_password, ATTR_TYPE_STRING, (void *)pwd, strlen(pwd), NULL);
	if (ret < 0) {
		shell_error(shell, "Could not set password [%d]", ret);
	} else {
		shell_print(shell, "Ok");
	}

	return ret;
}
#endif

static bool is_passwd_set(void)
{
	return strcmp(password, SHELL_DEFAULT_PASSWORD) != 0;
}

static int lcz_shell_login_init(const struct device *device)
{
	const struct shell *shell;

	ARG_UNUSED(device);

#if defined(CONFIG_SHELL_LOGIN_INIT_USING_KCONFIG)
	password = CONFIG_SHELL_LOGIN_PASSWORD;
#else
	password = (char *)attr_get_quasi_static(ATTR_ID_shell_password);
#endif

	shell = shell_backend_uart_get_ptr();
	/* work around to ensure user typed password is obscured */
	set_shell_logged_in(shell, true, true);
	set_shell_logged_in(shell, false, true);

	if (!is_passwd_set()) {
		set_shell_logged_in(shell, true, false);
		LOG_WRN("Shell password not set, enable shell by default.");
	}

	return 0;
}

/**************************************************************************************************/
/* Global Function Definitions                                                                    */
/**************************************************************************************************/
bool lcz_shell_login_is_logged_in(void)
{
	return user_logged_in;
}

#if defined(CONFIG_SHELL_LOGIN_ENABLE_ATTRIBUTES)
SHELL_CMD_ARG_REGISTER(passwd, NULL, "Set shell password", cmd_passwd, 2, 0);
#endif

SHELL_CMD_ARG_REGISTER(login, NULL, "<password>", cmd_login, 2, 0);

SHELL_CMD_REGISTER(logout, NULL, "Log out.", cmd_logout);

SYS_INIT(lcz_shell_login_init, APPLICATION, CONFIG_SHELL_LOGIN_INIT_PRIORITY);
