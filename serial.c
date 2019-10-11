// Copyright (c) 2019  Diamond Key Security, NFP
// 
// Copyright (c) 2019  Diamond Key Security, NFP
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
// - Redistributions of source code must retain the above copyright notice,
//   this list of conditions and the following disclaimer.
//
// - Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in the
//   documentation and/or other materials provided with the distribution.
//
// - Neither the name of the Diamond Key Security nor the names of its contributors may
//   be used to endorse or promote products derived from this software
//   without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
// TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
// PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
// TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
