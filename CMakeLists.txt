#
# Copyright (c) 2022 Laird Connectivity LLC
#
# SPDX-License-Identifier: LicenseRef-LairdConnectivity-Clause
#
if(CONFIG_LCZ_SHELL_LOGIN)

zephyr_include_directories(include)
zephyr_sources(src/lcz_shell_login.c)

endif()
