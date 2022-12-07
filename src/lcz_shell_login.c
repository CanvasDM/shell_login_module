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
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(lcz_shell_login, CONFIG_LCZ_SHELL_LOGIN_LOG_LEVEL);

#include <zephyr.h>
#include <zephyr/init.h>
#include <zephyr/shell/shell.h>
#include <zephyr/shell/shell_uart.h>
#include <zephyr/logging/log_ctrl.h>
#if defined(CONFIG_SHELL_LOGIN_ENABLE_ATTRIBUTES)
#include <attr.h>
#endif
#include <lcz_memfault.h>

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
static void session_expired_work_handler(struct k_work *Item);

/**************************************************************************************************/
/* Local Data Definitions                                                                         */
/**************************************************************************************************/
static char *password;
static bool user_logged_in;
static struct k_work_delayable session_expired_work;

/**************************************************************************************************/
/* Local Function Definitions                                                                     */
/**************************************************************************************************/
static void session_expired_work_handler(struct k_work *Item)
{
	if (is_passwd_set()) {
		LOG_WRN("Login session expired");
		set_shell_logged_in(shell_backend_uart_get_ptr(), false, false);
	} else {
		LOG_WRN("Shell password is not set, cannot expire session.");
	}
}

static void set_shell_logged_in(const struct shell *shell, bool logged_in, bool init)
{
	uint8_t session_timeout;

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

	if (user_logged_in && is_passwd_set() && !init) {
#if defined(CONFIG_SHELL_SESSION_TIMEOUT)
		session_timeout = CONFIG_SHELL_SESSION_TIMEOUT;
#else
		session_timeout = *(uint8_t *)attr_get_quasi_static(ATTR_ID_shell_session_timeout);
#endif
		LOG_WRN("Login session will expire in %d minutes", session_timeout);
		k_work_reschedule(&session_expired_work, K_MINUTES(session_timeout));
	} else {
		k_work_cancel_delayable(&session_expired_work);
	}
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
		LOG_ERR("Invalid password!");
		MFLT_METRICS_ADD(shell_login_fail, 1);
		attempts++;
		if (attempts > 3) {
			k_sleep(K_SECONDS(attempts));
		}
		return -EINVAL;
	}

#if defined(CONFIG_SHELL_HISTORY)
	/* clear history so password not visible there */
	z_shell_history_purge(shell->history);
#endif
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
		LOG_INF("Set shell password");
		MFLT_METRICS_ADD(shell_passwd_change, 1);
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

	k_work_init_delayable(&session_expired_work, session_expired_work_handler);

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
