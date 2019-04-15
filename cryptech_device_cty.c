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
    tty.c_cc[VTIME] = 100; // wait upto 10 seconds before timing out

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

int cty_login(char *pin)
{
    char *result;
    const int MAX_TIMEOUTS = 10;
    int r, timeouts = 0;

    check(cty_write("\rlogout\r\r"));
    while((r = cty_read(&result, "Username: ")) != HAL_OK)
    {
        if (r != HAL_ERROR_IO_TIMEOUT)
        {
            return r;
        }
        else
        {
            if(strendswith(result, "Password: "))
            {
                // must free after the compare but before the check
                free(result);

                check(cty_write("\r"));
            }
            else
            {
                // we haven't gotten the prompt that we want yet
                free(result);                    
            }

            ++timeouts;
            if(timeouts > MAX_TIMEOUTS)
            {
                return r;
            }
        }
        
    }

    check(cty_write("wheel\r"));

    check(cty_read(&result, "Password: "));
    free(result);

    check(cty_write(pin));
    check(cty_write("\r"));

    check(cty_read(&result, "cryptech> "));
    free(result);

    return 0;
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

int cty_read(char **result, const char *prompt)
{
    if(result == NULL) return HAL_ERROR_BAD_ARGUMENTS;

    int rval = HAL_OK;

    // get the output until prompt
    int prompt_len = strlen(prompt);
    int prompt_index = 0;

    int buffer_length = 32;
    int i = 0;
    char *output = malloc(buffer_length);
    if(output == NULL)
    {
        return HAL_ERROR_ALLOCATION_FAILURE;
    }
    output[0] = 0; // mark the end of the string incase there is an error

    while (prompt_index < prompt_len)
    {
        // make sure the buffer is big enough
        if(i >= (buffer_length-1))
        {
            buffer_length *= 2;

            char *new_output = realloc(output, buffer_length);
            if(new_output == NULL)
            {
                free(output);
                return HAL_ERROR_ALLOCATION_FAILURE;
            }
            output = new_output;
        }

        int rval = serial_recv_char(&output[i]);

        if(rval != 0)
        {
            if (i > 0)
            {
                rval = HAL_ERROR_IO_TIMEOUT;
                goto read_done;
            }

            free(output);
            return rval;
        }

        // check to see if we're getting the cryptech prompt
        if(output[i] == prompt[prompt_index])
        {
            ++prompt_index;
        }
        else
        {
            prompt_index = 0;
        }
        
        ++i;
        output[i] = 0;
    }

read_done:
    *result = output;

    printf("%s\r\n", output);

    return rval;
}

int close_cryptech_device_cty()
{
    return serial_close();
}