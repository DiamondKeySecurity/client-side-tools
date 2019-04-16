// Copyright (c) 2019 Diamond Key Security, NFP  All rights reserved.
//

#include "cryptech_device_cty.h"
#include "serial.h"

#include <hal_internal.h>
#include <string.h>
#include <stdio.h>
#include <termios.h>
#include <unistd.h>

// check(op) - Copyright (c) 2016, NORDUnet A/S
#define check(op)                                               \
    do {                                                        \
        hal_error_t err = (op);                                 \
        if (err) {                                              \
            printf("%s: %s\r\n", #op, hal_error_string(err));     \
            return err;                                         \
        }                                                       \
    } while (0)

int open_cryptech_device_cty()
{
    const char *device = getenv(CTY_CLIENT_SERIAL_DEVICE_ENVVAR);
    const char *speed_ = getenv(CTY_CLIENT_SERIAL_SPEED_ENVVAR);
    uint32_t    speed  = HAL_CLIENT_SERIAL_DEFAULT_SPEED;

    if (device == NULL)
        device = HAL_CLIENT_SERIAL_DEFAULT_DEVICE;

    if (speed_ != NULL)
        speed = (uint32_t) strtoul(speed_, NULL, 10);

    int r = serial_init(device, speed);
    if (r != 0) return r;

    // changed so we don't block on reads
    struct termios tty;

    if (tcgetattr(serial_get_fd(), &tty) < 0) {
        return HAL_ERROR_IO_OS_ERROR;
    }

    tty.c_cc[VMIN] = 0;
    tty.c_cc[VTIME] = 5; // wait upto 3 seconds before timing out

    if (tcsetattr(serial_get_fd(), TCSANOW, &tty) < 0)
        return HAL_ERROR_IO_OS_ERROR;

    return HAL_OK;
}

int strendswith(char *str, const char *ending)
{
    int str_len = strlen(str);
    int ending_len = strlen(ending);

    if (ending_len > str_len) return 0;

    return strcmp(&str[str_len - ending_len], ending) == 0;
}

int cty_logout()
{
    char read_buffer[1024];
    int read_count, MAX_RETRIES = 10;

    // make sure the device has been logged out
    check(cty_write("\rlogout\r\r"));

    // wait for the username prompt
    check(cty_read_wait(read_buffer, &read_count, sizeof(read_buffer), MAX_RETRIES));
    if (strendswith(read_buffer, "Username: ") == 0)
        return HAL_ERROR_NOT_READY;

    return HAL_OK;
}

int cty_login(char *pin)
{
    char read_buffer[1024];
    int read_count, MAX_RETRIES = 10, PASSWORD_WAIT = 60;

    // make sure the device has been logged out
    check(cty_logout());

    // log in using the wheel account

    // send the user name
    check(cty_write("wheel\r"));

    // wait for the password prompt
    check(cty_read_wait(read_buffer, &read_count, sizeof(read_buffer), MAX_RETRIES));
    if (strendswith(read_buffer, "Password: ") == 0)
        return HAL_ERROR_NOT_READY;

    // send the pin
    check(cty_write(pin));
    check(cty_write("\r"));

    // wait for the cryptech prompt
    check(cty_read_wait(read_buffer, &read_count, sizeof(read_buffer), PASSWORD_WAIT));
    if (strendswith(read_buffer, "cryptech> ") == 0)
        return HAL_ERROR_PIN_INCORRECT;

    return HAL_OK;
}

int cty_setmasterkey(char *pin, char *masterkey)
{
    int MAX_RETRIES = 60;
    char read_buffer[1024];
    int read_count;

    // make sure the device has been logged in
    check(cty_login(pin));

    // get the command to send
    char cmd[256];
    if (masterkey != NULL)
    {
        snprintf(cmd, sizeof(cmd)/sizeof(char), "masterkey set %s\r", masterkey);
    }
    else
    {
        strcpy(cmd, "masterkey set\r");
    }

    // send the command
    check(cty_write(cmd));

    // if the outout contains failed, then it didn't work
    check(cty_read_wait(read_buffer, &read_count, sizeof(read_buffer), MAX_RETRIES));
    if (strstr(read_buffer, "Failed") != NULL) return HAL_ERROR_MASTERKEY_FAIL;

    // show the master key
    printf("%s", read_buffer);

    // make sure the device has been logged out
    return cty_logout();
}

int cty_write(char *cmd)
{
    if(cmd == NULL) return HAL_ERROR_BAD_ARGUMENTS;

    // write the command to the CTY
    int len = strlen(cmd);

    for (int i = 0; i < len; ++i)
    {
        int rval = serial_send_char(cmd[i]);
        if (rval != 0) return rval;
    }
}

int cty_read(char *result_buffer, int *read_count, int result_max)
// reads data until result_max or a timeout on the stream
{
    if(result_buffer == NULL || read_count == NULL) return HAL_ERROR_BAD_ARGUMENTS;

    // read data until the stream timesout
    int i = 0;
    result_buffer[0] = 0; // mark the end of the string in case there is an error

    int rval = HAL_OK;

    while ((rval = serial_recv_char(&result_buffer[i])) == HAL_OK &&
           i < result_max-1) 
    {
        ++i;
        result_buffer[i] = 0; // mark the end of the string
    }

    *read_count = i;

    // if we just timed out, that's ok. We just ran out of data
    if (rval == HAL_ERROR_IO_TIMEOUT) return HAL_OK;
    else return rval;
}

int cty_read_wait(char *result_buffer, int *read_count, int result_max, int max_retries)
{
    int current_try = 0;
    int rval;

    if(result_buffer == NULL || read_count == NULL) return HAL_ERROR_BAD_ARGUMENTS;

    while ((rval = cty_read(result_buffer, read_count, result_max)) == HAL_OK &&
           *read_count == 0 &&
           current_try < max_retries)
    {
        ++current_try;   
    }

    // return timeout if we didn't get anything
    if (read_count == 0 && rval == HAL_OK)
    {
        return HAL_ERROR_IO_TIMEOUT;
    }

    return rval;
}

int close_cryptech_device_cty()
{
    return serial_close();
}