// Copyright (c) 2019 Diamond Key Security, NFP  All rights reserved.
//
#ifndef CRYPTECH_DEVICE_H
#define CRYPTECH_DEVICE_H

#include <stdint.h>

int init_cryptech_device(char *pin, uint32_t handle);
int close_cryptech_device(uint32_t handle);

uint32_t get_random_handle();

int setup_backup_destination(uint32_t handle);

#endif