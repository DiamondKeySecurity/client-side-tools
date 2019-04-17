// Copyright (c) 2019  Diamond Key Security, NFP
// 
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; version 2
// of the License only.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program; if not, If not, see <https://www.gnu.org/licenses/>.
//
// Script to import CrypTech code into DKS HSM folders.
//
#ifndef CRYPTECH_DEVICE_CTY_H
#define CRYPTECH_DEVICE_CTY_H

#include <stdint.h>


#define CTY_CLIENT_SERIAL_DEVICE_ENVVAR         "CRYPTECH_CTY_CLIENT_SERIAL_DEVICE"
#define CTY_CLIENT_SERIAL_SPEED_ENVVAR          "CRYPTECH_CTY_CLIENT_SERIAL_SPEED"


int open_cryptech_device_cty();
int close_cryptech_device_cty();
int cty_write(char *cmd);
int cty_read(char *result_buffer, int *read_count, int result_max);
int cty_read_wait(char *result_buffer, int *read_count, int result_max, int max_retries);
int cty_login(char *pin);
int cty_logout();
int cty_setmasterkey(char *pin, char *masterkey);

#endif