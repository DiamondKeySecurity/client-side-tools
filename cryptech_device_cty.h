// Copyright (c) 2019  Diamond Key Security, NFP
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
