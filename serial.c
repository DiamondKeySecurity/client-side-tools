// Copyright (c) 2019 Diamond Key Security, NFP  All rights reserved.
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
