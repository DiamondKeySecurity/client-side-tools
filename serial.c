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

// This defines a simple serial interface. For Mac and Linux builds,
// we can just use the rpc_serial implementation given by HAL. We
// can't use it directly because it acts as a singleton for all serial
// connections to an HSM, and we use it as a secondary connection
// to a CrypTech device

#define fd serial_fd
#define hal_serial_init serial_init
#define hal_serial_close serial_close
#define hal_serial_send_char serial_send_char
#define hal_serial_recv_char _serial_recv_char_
#define hal_serial_get_fd serial_get_fd

#include <rpc_serial.c>

hal_error_t serial_recv_char(uint8_t * const c)
{
    // we allow timing out
    if (read(fd, c, 1) != 1)
	    return HAL_ERROR_IO_TIMEOUT;
    return HAL_OK;
}

#undef fd
#undef hal_serial_init
#undef hal_serial_close
#undef hal_serial_send_char
#undef hal_serial_recv_char
#undef hal_serial_get_fd
