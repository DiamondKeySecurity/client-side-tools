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
#ifndef CRYPTECH_DEVICE_H
#define CRYPTECH_DEVICE_H

#include <stdint.h>

int init_cryptech_device(char *pin, uint32_t handle);
int close_cryptech_device(uint32_t handle);

uint32_t get_random_handle();

int setup_backup_destination(uint32_t handle);

#endif