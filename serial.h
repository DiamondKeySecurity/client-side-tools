// Copyright (c) 2019 Diamond Key Security, NFP  All rights reserved.
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