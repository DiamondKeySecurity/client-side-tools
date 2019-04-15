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
#define hal_serial_recv_char serial_recv_char
#define hal_serial_get_fd serial_get_fd

#include <rpc_serial.c>

#undef fd
#undef hal_serial_init
#undef hal_serial_close
#undef hal_serial_send_char
#undef hal_serial_recv_char
#undef hal_serial_get_fd
