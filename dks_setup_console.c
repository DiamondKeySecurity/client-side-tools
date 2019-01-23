// Copyright (c) 2018, 2019 Diamond Key Security, NFP  All rights reserved.
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

#include <tls.h>

#include <dks.h>

pthread_mutex_t active_lock;
pthread_mutex_t write_lock;

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

void handle_special_command(ThreadArguments *args, char *command)
{
    // get the code
    int code = (command[0] << 24) + 
               (command[1] << 16) + 
               (command[2] << 8) + 
               command[3];

    if (code == MGMTCODE_RECEIVEHSM_UPDATE)
    {
        char buffer[1024];

        // make sure nothing else gets sent during our transfer
        pthread_mutex_lock(&write_lock);
        args->can_write = false;
        pthread_mutex_unlock(&write_lock);

        // skip command code and ':RECV:'
        char *file_to_send = &command[10];

        FILE *fp = fopen(file_to_send, "rb");

        if(fp != NULL)
        {
            printf("\r\nSending file %s to HSM\r\n", file_to_send);

            // get the size of the file
            fseek(fp, 0, SEEK_END);
            long file_len = ftell(fp);
            fseek(fp, 0, SEEK_SET);

            // send the file size
            sprintf(buffer, "%ld\r", file_len);

            tls_write(args->tls, buffer, strlen(buffer));

            int remaining = file_len;

            // send the file
            int read_count;
            do
            {
                read_count = 1024;
                if(read_count > remaining) read_count = remaining;

                int n = fread(buffer, read_count, 1, fp);

                if(n > 0)
                {
                    // send to the HSM
                    tls_write(args->tls, buffer, read_count);
                }

                remaining -= read_count;

            } while (remaining > 0);

            fclose(fp);
        }
        else
        {
            printf("\r\nUnable to open (%s).\r\n", file_to_send);

            // send 0 which means the file wasn't found
            sprintf(buffer, "0\r0000000");

            tls_write(args->tls, buffer, strlen(buffer));            
        }

        pthread_mutex_lock(&write_lock);
        args->can_write = true;
        pthread_mutex_unlock(&write_lock);        
    }

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
