// Copyright (c) 2019 Diamond Key Security, NFP  All rights reserved.
//
#ifndef CRYPTECH_DEVICE_CTY_H
#define CRYPTECH_DEVICE_CTY_H

#include <stdint.h>


#define CTY_CLIENT_SERIAL_DEVICE_ENVVAR         "CRYPTECH_CTY_CLIENT_SERIAL_DEVICE"
#define CTY_CLIENT_SERIAL_SPEED_ENVVAR          "CRYPTECH_CTY_CLIENT_SERIAL_SPEED"


int open_cryptech_device_cty(char *pin);
int close_cryptech_device();


#endif