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
#ifndef SERIAL_H_DIAMONDKEY
#define SERIAL_H_DIAMONDKEY

#include <hal.h>

hal_error_t serial_init(const char * const device, const uint32_t speed);

hal_error_t serial_close(void);

hal_error_t serial_send_char(const uint8_t c);

hal_error_t serial_recv_char(uint8_t * const c);

int serial_get_fd(void);


#endif