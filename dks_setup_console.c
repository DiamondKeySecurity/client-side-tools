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
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>
#include <stdbool.h>
#include <poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <tls.h>

#include <dks.h>
#include <dks_transfer.h>

#include "cryptech_device.h"
#include "cryptech_device_cty.h"

pthread_mutex_t active_lock;
pthread_mutex_t write_lock;
FILE *gfp_temp_file;

// Define data type that will be passed to thread
typedef struct __ThreadArguments {
    struct tls *tls;
    int socket;

    bool project_active;
    bool can_write;
} ThreadArguments;

// finish reading a data from a socket to
char *get_special_command(struct tls *tls, char *input_from_tls)
{
    // we'll use a growable buffer to hold our new string and avoid buffer overflows
    int buffer_size = 1024;
    char *buffer = malloc(sizeof(char) * buffer_size);
    char *memory_error = "Unable to receive data from the HSM because this computer is out of memory\r\n";
    char *error_msg;

    // used to receive more data from TLS in the case that we haven't received up to the '\r'
    char recv_buffer[256];
    
    if (buffer == NULL)
    {
        error_msg = memory_error;
        goto error_condition;
    }

    int index = 0;

    buffer[index++] = 0x11; // we must add this because it wasn't put in memory

    // read all of previous input and get more data from the buffer until we 
    char *p = input_from_tls;
    
    do
    {
        while (*p != '\0')
        {
            if(*p == '\r')
            {
                // mark the end
                buffer[index] = 0;

                // nothing else should follow this so ignore everything else
                return buffer;
            }
            else
            {
                buffer[index++] = *p;
            }

            if(index == buffer_size)
            {
                // we need to regrow the buffer
                buffer_size *= 2;
                char *new_buffer = realloc(buffer, buffer_size);
                if(new_buffer == NULL)
                {
                    error_msg = memory_error;
                    goto error_condition;
                }
                buffer = new_buffer;
            }
            ++p;
        }

        bzero(recv_buffer, 256);
        ssize_t len;
        if((len = tls_read(tls, recv_buffer, 255)) < 0)
        {
            error_msg = "data not read\r\n";
            goto error_condition;
        }
        p = recv_buffer;
    } while (true);

error_condition:
    printf("%s", error_msg);
    free(buffer);
    return NULL;
}

void SendHSMUpdate(ThreadArguments *args, char *command)
{
    // skip command code and ':RECV:'
    char *file_to_send = &command[10];

    // send the file
    dks_send_file(args->tls, file_to_send);
}

void SendSetupJSON(ThreadArguments *args, char *command)
{
    // get pin and masterkey from options
    // skip command code and ':RECV:{'
    char *masterkey = &command[11];
    char *pin;
    char *device_index;

    char *ptr = masterkey;

    // find the end of the master key option
    while (*ptr != '}') ptr++;
    *ptr = 0;

    // get the beginning of the pin
    pin = ptr + 2;

    // find the end of the pin option
    while (*ptr != '}') ptr++;
    *ptr = 0;

    // get the beginning of the device_index
    device_index = ptr + 2;    

    // find the end of the device_index option
    while (*ptr != '}') ptr++;
    *ptr = 0;

    int device;
    sscanf(device_index, "%i", &device);

    int rval = 0;
    if (strcmp(masterkey, "None") != 0)
    {
        rval = open_cryptech_device_cty();

        if (rval == 0)
        {
            if (strlen(masterkey) == 0)
            {
                // random master key
                rval = cty_setmasterkey(pin, NULL);
            }
            else
            {       
                // user has a master key to use
                rval = cty_setmasterkey(pin, masterkey);
            }
        }

        // make sure we've logged out
        cty_logout();

        rval = close_cryptech_device_cty();
    }

    if (rval != 0)
    {
        printf("Unable to set master key.");
        dks_send_file_none(args->tls);
        return;
    }

    uint32_t handle = get_random_handle();

    rval = init_cryptech_device(pin, handle);

    if (rval != 0)
    {
        printf("Unable to log into CrypTech device.\r\n");
        printf("Did you run 'eval $(cryptech_probe)' before running this command?\r\n");
        dks_send_file_none(args->tls);
    }
    else
    {
        char *setup_json;
        rval = setup_backup_destination(handle, device, &setup_json);

        if (rval == 0)
        {
            dks_send_file_mem(args->tls, setup_json, strlen(setup_json));

            free (setup_json);
        }
        else
        {
            printf("Unable to get KEKEK.\r\nPlease check that the master key is correct.\r\n");
            dks_send_file_none(args->tls);
        }

        close_cryptech_device(handle);   
    }
}

void RecvKEKEKFromHSM(ThreadArguments *args, char *command)
{
    // get pin and masterkey from options
    // skip command code and ':RECV:{'
    char *masterkey = &command[11];
    char *pin;
    char *num_bytes_to_receive_string;

    char *ptr = masterkey;

    // free any temporary files
    if(gfp_temp_file != NULL)
    {
        fclose(gfp_temp_file);
        gfp_temp_file = NULL;
    }

    // find the end of the master key option
    while (*ptr != '}') ptr++;
    *ptr = 0;

    // get the beginning of the pin
    pin = ptr + 2;

    // find the end of the pin option
    while (*ptr != '}') ptr++;
    *ptr = 0;

    // get the beginning of the num_bytes_to_receive
    num_bytes_to_receive_string = ptr + 2;    

    // find the end of the num_bytes_to_receive option
    while (*ptr != '}') ptr++;
    *ptr = 0;

    int num_bytes_to_receive;
    sscanf(num_bytes_to_receive_string, "%i", &num_bytes_to_receive); 

    // get the data
    char *setup_json = dks_recv_from_hsm(args->tls, num_bytes_to_receive);

    if (setup_json == NULL)
    {
        printf("\ndks_setup_console: Unable to receive data from HSM\r\n");
    }
    else
    {
        int rval = 0;
        if (strcmp(masterkey, "None") != 0)
        {
            rval = open_cryptech_device_cty();

            if (rval == 0)
            {
                if (strlen(masterkey) == 0)
                {
                    // random master key
                    rval = cty_setmasterkey(pin, NULL);
                }
                else
                {       
                    // user has a master key to use
                    rval = cty_setmasterkey(pin, masterkey);
                }
            }

            // make sure we've logged out
            cty_logout();

            rval = close_cryptech_device_cty();
        }

        if (rval != 0)
        {
            printf("Unable to set master key.");
            dks_send_file_none(args->tls);
            return;
        }

        uint32_t handle = get_random_handle();

        rval = init_cryptech_device(pin, handle);

        if (rval != 0)
        {
            printf("Unable to log into CrypTech device.\r\n");
            printf("Did you run 'eval $(cryptech_probe)' before running this command?\r\n");
            dks_send_file_none(args->tls);
        }
        else
        {
            FILE *export_json;
            rval = cryptech_export_keys(handle, setup_json, &export_json);
            if (rval == 0)
            {
                // keep export data in a temporary file that we can access when the
                // HSM ask for it
                gfp_temp_file = export_json;
            }           

            close_cryptech_device(handle);
        }

        free (setup_json);
    }
}

void RecvExportDataFromHSM(ThreadArguments *args, char *command)
{
    // get pin and masterkey from options
    // skip command code and ':RECV:{'
    char *pin = &command[11];
    char *num_bytes_to_receive_string;

    char *ptr = pin;

    // find the end of the pin key option
    while (*ptr != '}') ptr++;
    *ptr = 0;

    // get the beginning of the num_bytes_to_receive
    num_bytes_to_receive_string = ptr + 2;

    // find the end of the num_bytes_to_receive option
    while (*ptr != '}') ptr++;
    *ptr = 0;

    int num_bytes_to_receive;
    sscanf(num_bytes_to_receive_string, "%i", &num_bytes_to_receive); 

    // get the data
    char *json = dks_recv_from_hsm(args->tls, num_bytes_to_receive);

    if (json == NULL)
    {
        printf("\ndks_setup_console: Unable to receive data from HSM\r\n");
    }
    else
    {
        uint32_t handle = get_random_handle();

        int rval = init_cryptech_device(pin, handle);

        if (rval != 0)
        {
            printf("Unable to log into CrypTech device.\r\n");
            printf("Did you run 'eval $(cryptech_probe)' before running this command?\r\n");
            dks_send_file_none(args->tls);
        }
        else
        {
            char *setup_json;
            rval = import_keys(handle, json);

            if (rval == 0)
            {
                printf("Backup complete\r\n");
            }
            else
            {
                printf("Unable to save export data to CrypTech device.\r\n");
            }

            close_cryptech_device(handle);
        }
    }
    free (json);
}

void SendExportData(ThreadArguments *args, char *command)
{
    if (gfp_temp_file == NULL)
    {
        printf("Export data not found.\r\n");
        dks_send_file_none(args->tls);
    }
    else
    {
        printf("Sending data to HSM.\r\n");
        dks_send_file_fp(args->tls, gfp_temp_file);

        fseek(gfp_temp_file, 0, SEEK_SET);

        FILE *fp = fopen("/home/douglas/Documents/test.json", "wt");
        int c;
        while ((c = fgetc(gfp_temp_file)) != EOF)
        {
            fputc(c, fp);
        }
        fclose(fp);

        fclose(gfp_temp_file);
        gfp_temp_file = NULL;
    }
}

void handle_special_command(ThreadArguments *args, char *command)
{
    // make sure nothing else gets sent during our transfer
    pthread_mutex_lock(&write_lock);
    args->can_write = false;
    pthread_mutex_unlock(&write_lock);

    // get the code
    int code = (command[0] << 24) + 
               (command[1] << 16) + 
               (command[2] << 8) + 
               command[3];

    if (code == MGMTCODE_RECEIVEHSM_UPDATE)
    {
        SendHSMUpdate(args, command);
    }
    else if (code == MGMTCODE_RECEIVE_RMT_KEKEK)
    {
        SendSetupJSON(args, command);
    }
    else if (code == MGMTCODE_SEND_LCL_KEKEK)
    {
        RecvKEKEKFromHSM(args, command);
    }
    else if (code == MGMTCODE_SEND_EXPORT_DATA)
    {
        RecvExportDataFromHSM(args, command);
    }
    else if (code == MGMTCODE_RECEIVE_IMPORT_DATA)
    {
        SendExportData(args, command);
    }

    // allow other things during transfer
    pthread_mutex_lock(&write_lock);
    args->can_write = true;
    pthread_mutex_unlock(&write_lock);    

    free(command);
}

// Incoming Data listening thread
void *socketDataListeningThread(void *vargs)
{
    ssize_t len = 0;
    char recv_buffer[1024];

    ThreadArguments *args = (ThreadArguments *)vargs;

    struct pollfd pfd;
    pfd.fd = args->socket;
    pfd.events = POLLIN;

    bool active;

    pthread_mutex_lock(&active_lock);
    active = args->project_active;
    pthread_mutex_unlock(&active_lock);

    while(args->project_active)
    {
        bzero(recv_buffer, 1024);

        poll(&pfd, 1, -1);

        if(pfd.revents & POLLIN) 
        {
            if((len = tls_read(args->tls, recv_buffer, 1023)) < 0)
            {
                printf("data not read\n\n");
                pthread_mutex_lock(&active_lock);
                args->project_active = false;
                pthread_mutex_unlock(&active_lock);
            }
            else
            {
                // search for 0xFF in the buffer
                char *b = recv_buffer;
                while (*b != '\0')
                {
                    if(*b == 0x11)
                    {
                        *b++ = '\0'; // mark the end of the line here so we can print any data before it

                        // the next character will be 0xEF
                        break;
                    }

                    ++b; // go to the next character
                }

                printf("%s", recv_buffer);

                // we need to flush stdout otherwise, it won't show any data until it gets a new line
                fflush(stdout);

                // a special character is in the buffer
                if (*b == 0x12)
                {
                    // get the complete line
                    char *special_command = get_special_command(args->tls, b);

                    handle_special_command(args, special_command);
                }
            }
        }

        pthread_mutex_lock(&active_lock);
        active = args->project_active;
        pthread_mutex_unlock(&active_lock);
    }
}

// set keyboard input to be non-buffered and do not echo
void SetRawKeyboardInput(struct termios *oldAttributes)
{
    struct termios attr;

    // get a copy of the current settings so we can reset later
    tcgetattr(STDIN_FILENO, oldAttributes);

    // get another copy for setting the new state
    tcgetattr(STDIN_FILENO, &attr);

    // make raw
    cfmakeraw(&attr);
	
    // set
    tcsetattr(STDIN_FILENO, TCSANOW, &attr);
}

// set stdin to saved attributes
void ResetKeyboardInput(struct termios *oldAttributes)
{
    tcsetattr(STDIN_FILENO, TCSANOW, oldAttributes);
}

// Linux implementation that can handle escape characters
int ReadKey(char *buffer, int max_len)
{
    int c = getchar();
    int num_written = 0;

    // This may be different on Windows, but we will need to
    // send the same sequence to the CTY no matter what

    // check for escape characters
    if(c == 27)
    {
        // check for an arrow key
        c = getchar();
        if(c == 91) // we got an arror key escape sequence
        {
            c = getchar();
            if(max_len >= 3)
            {
                // send the escape sequence for the  arrow key
                buffer[0] = 27;
                buffer[1] = 91;
                buffer[2] = c;

                num_written = 3;
            }
        }
    }
    else if (c == 3) return 0;
    else if(max_len > 0)
    {
        buffer[0] = c;
        num_written++;
    }

    return num_written;
}

int main(int argc, char **argv)
{
    struct tls *tls = NULL;
    struct tls_config *config = NULL;
    char *initial_msg = "\r";
    char buf[2];
    struct sockaddr_in server;
    struct pollfd pfd;
    int sock;
    int rval = 0;

    hsm_info_t *hsm_info = NULL;

    gfp_temp_file = NULL;

    if (pthread_mutex_init(&active_lock, NULL) != 0) 
    { 
        printf("Unable to create mutex lock.\n"); 
        return 1; 
    }
    if (pthread_mutex_init(&write_lock, NULL) != 0) 
    { 
        printf("Unable to create mutex lock.\n"); 
        return 1; 
    }        

    // get the configuration from the config file
    hsm_conf_result_t conf_result = LoadHSMInfo(&hsm_info, HSM_PORT_CTY);
    switch(conf_result)
    {
        case HSMCONF_FAILED_FILENOTFOUND:
            printf("\r\n Unable to load configuration file. The file either does not exist or is inaccessible.\r\n");
            return 1;
        case HSMCONF_FAILED_FORMAT:
            printf("\r\n There was reading configuration file. Please check the files format.\r\n");
            return 1;
    }
	
    tls_init();

    tls = tls_client();

    config = tls_config_new();

    tls_config_insecure_noverifycert(config);
    tls_config_insecure_noverifyname(config);

    tls_configure(tls, config);

    sock = socket(AF_INET, SOCK_STREAM, 0);

    server.sin_port = htons(hsm_info->port);
    server.sin_addr.s_addr = inet_addr(hsm_info->ip_addr);
    server.sin_family = AF_INET;

    printf("Connecting to %s...\n", hsm_info->ip_addr);
    if(connect(sock, (struct sockaddr *) &server, sizeof(server)) < 0) {
        printf("Unable to connect to remote host.\n");
        rval = 1;
        goto FREE_CONNECTION_DATA;
    }

    printf("Connected ...\n");
    if(tls_connect_socket(tls, sock, hsm_info->servername) < 0) {
        printf("Unable to establish secure socket connection.\n");
        printf("%s\n", tls_error(tls));
        rval = 1;
        goto FREE_CONNECTION_DATA;
    }

    printf("Connected TLS...\n");
    tls_write(tls, initial_msg, strlen(initial_msg));

    ThreadArguments args;
    args.tls = tls;
    args.project_active = true;
    args.socket =sock;
    args.can_write = true;

    // create our thread to listen for data from the socket
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, socketDataListeningThread, &args);

    struct termios originalSTDINAttr;
    SetRawKeyboardInput(&originalSTDINAttr);

    bool active;
    pthread_mutex_lock(&active_lock);
    active = args.project_active;
    pthread_mutex_unlock(&active_lock);

    while(active)
    {
        char buffer[3];
        int len;

        len = ReadKey(buffer, 3);
        if(len == 0)
        {
            pthread_mutex_lock(&active_lock);
            args.project_active = false;
            pthread_mutex_unlock(&active_lock);
            break;
        }

        if(buffer[0] == '\b') buffer[0] = 8;
        if(buffer[0] == '\n') buffer[0] = '\r';

        pthread_mutex_lock(&write_lock);
        if(args.can_write)
            tls_write(tls, buffer, len);
        pthread_mutex_unlock(&write_lock);

        pthread_mutex_lock(&active_lock);
        active = args.project_active;
        pthread_mutex_unlock(&active_lock);
    }

    ResetKeyboardInput(&originalSTDINAttr);

    close(sock);

    tls_close(tls);
FREE_CONNECTION_DATA:
    tls_free(tls);
    tls_config_free(config);
    FreeHSMInfo(&hsm_info);

    pthread_mutex_destroy(&active_lock); 
    pthread_mutex_destroy(&write_lock); 

    printf("\n\n");

    return rval;
}
