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
#include <stdio.h> 
#include <stdlib.h> 
#include <time.h> 

#include <hal.h>

#include "libs/base64.c/base64.h"

// check(op) - Copyright (c) 2016, NORDUnet A/S
#define check(op)                                               \
    do {                                                        \
        hal_error_t err = (op);                                 \
        if (err) {                                              \
            printf("%s: %s\r\n", #op, hal_error_string(err));     \
            return err;                                         \
        }                                                       \
    } while (0)

static const unsigned char const_0x010001[] = { 0x01, 0x00, 0x01 };

// Internal Functions --------------------------------------------------
char *create_setup_json_string(hal_uuid_t kekek_uuid, uint8_t *kekek_public_key, unsigned int pub_key_len, int device_index);
char uuid_to_string(hal_uuid_t uuid, char *buffer);
char *split_b64_string(const char *b64data);


// Function Implementations --------------------------------------------
int init_cryptech_device(char *pin, uint32_t handle)
{
    hal_client_handle_t client = {handle};
    hal_user_t user = HAL_USER_WHEEL;

    check(hal_rpc_client_init());

    check(hal_rpc_login(client, user, pin, strlen(pin)));
    check(hal_rpc_is_logged_in(client, user));
    
    return 0;
}

int close_cryptech_device(uint32_t handle)
{
    hal_client_handle_t client = {handle};

    hal_rpc_logout(client);

    check(hal_rpc_client_close());
    
    return 0;
}

int seeded = 0;

uint32_t get_random_handle()
{
    uint32_t handle = 0;

    // make sure the number generator has been seeded
    if (seeded == 0)
    {
        seeded = 1;
        srand(time(0));
    }

    for (int i = 0; i < 32; ++i)
    {
        int bit = rand() % 2;
        handle += bit < i;
    }

    return handle;
}

int setup_backup_destination(uint32_t handle, int device_index, char **json_result)
{
    if (json_result == NULL) return HAL_ERROR_BAD_ARGUMENTS;

    *json_result = NULL;
    // """
    // Set up backup HSM for subsequent import.
    // Generates an RSA keypair with appropriate usage settings
    // to use as a key-encryption-key-encryption-key (KEKEK), and
    // writes the KEKEK to a JSON file for transfer to primary HSM.
    // """
    
    hal_client_handle_t client = {handle};
    hal_session_handle_t session = {0};

    hal_uuid_t result_kekek_uuid;
    uint8_t *result_kekek_public_key = NULL;
    size_t pub_key_len;

    const int MAX_UUIDS = 64;
    hal_uuid_t uuids[MAX_UUIDS];
    hal_uuid_t previous_uuid;
    memset(&previous_uuid, 0, sizeof(previous_uuid));

    unsigned n, state = 0;


    // First try to find an exisiting KEKEK on the device
    check(hal_rpc_pkey_match(client,
                             session,
                             HAL_KEY_TYPE_RSA_PRIVATE,
                             HAL_CURVE_NONE,
                             HAL_KEY_FLAG_USAGE_KEYENCIPHERMENT | HAL_KEY_FLAG_TOKEN,
                             HAL_KEY_FLAG_USAGE_KEYENCIPHERMENT | HAL_KEY_FLAG_TOKEN,
                             NULL, // const hal_pkey_attribute_t *attributes,
                             0,    // const unsigned attributes_len,
                             &state,
                             uuids,
                             &n,
                             MAX_UUIDS,
                             &previous_uuid));

    for (unsigned i = 0; i < n; ++i)
    {
        hal_pkey_handle_t kekek;

        hal_key_type_t kekek_type;
        hal_key_flags_t kekek_flags;

        check(hal_rpc_pkey_open(client,
                                session,
                                &kekek,
                                &uuids[i]));

        check(hal_rpc_pkey_get_key_type(kekek, &kekek_type));
        check(hal_rpc_pkey_get_key_flags(kekek, &kekek_flags));

        if (kekek_type == HAL_KEY_TYPE_RSA_PRIVATE &&
           (kekek_flags & HAL_KEY_FLAG_USAGE_KEYENCIPHERMENT) != 0)
        {
            printf("\r\nAttempting to use existing KEYENCIPHERMENT key.\r\n");
            memcpy(&result_kekek_uuid, &uuids[i], sizeof(hal_uuid_t));

            pub_key_len = hal_rpc_pkey_get_public_key_len(kekek);
            result_kekek_public_key = (uint8_t *)malloc(pub_key_len);
            size_t der_len;

            hal_error_t result = hal_rpc_pkey_get_public_key(kekek, result_kekek_public_key, &der_len, pub_key_len);

            check(hal_rpc_pkey_close(kekek));

            if(result != 0)
            {
                // prevent a memory leak
                free(result_kekek_public_key);
                
                // don't stop here. See if there's another acceptable key.
                // If not, the next step will create another one
                result_kekek_public_key = NULL;
                printf("\r\nThe existing KEYENCIPHERMENT key is not usable.\r\n");
            }
            
            break;
        }

        check(hal_rpc_pkey_close(kekek));
    }

    // try to generate a key
    if (result_kekek_public_key == NULL)
    {
        printf("\r\nAttempting to generate a new KEYENCIPHERMENT key.\r\n");
        hal_pkey_handle_t kekek;
        hal_uuid_t name;

        const uint8_t *public_exponent = const_0x010001;
        size_t public_exponent_len = sizeof(const_0x010001);        

        check(hal_rpc_pkey_generate_rsa(client,
                                        session,
                                        &kekek,
                                        &name,
                                        2048,
                                        public_exponent,
                                        public_exponent_len,
                                        HAL_KEY_FLAG_USAGE_KEYENCIPHERMENT | HAL_KEY_FLAG_TOKEN));

        memcpy(&result_kekek_uuid, &name, sizeof(hal_uuid_t));

        pub_key_len = hal_rpc_pkey_get_public_key_len(kekek);
        result_kekek_public_key = (uint8_t *)malloc(pub_key_len);
        size_t der_len;

        hal_error_t result = hal_rpc_pkey_get_public_key(kekek, result_kekek_public_key, &der_len, pub_key_len);

        check(hal_rpc_pkey_close(kekek));

        if(result != 0)
        {
            // prevent a memory leak
            free(result_kekek_public_key);
            check(result);
        }
    }

    *json_result = create_setup_json_string(result_kekek_uuid, result_kekek_public_key, (unsigned int)pub_key_len, device_index);

    if (result_kekek_public_key != NULL)
    {
        free(result_kekek_public_key);

        return 0;
    }

    if (*json_result == NULL) return HAL_ERROR_ALLOCATION_FAILURE;

    return 1;
}

char *split_b64_string(const char *b64data)
{
    const int CHARS_IN_ROW = 76;
    unsigned int len = strlen(b64data);

    int rows = (len / CHARS_IN_ROW) + 1;
    char *splitbuffer = malloc(((CHARS_IN_ROW + 12) * rows) + 1); // '        "..",\n
    if (splitbuffer == NULL) return NULL;
    splitbuffer[0] = 0;
    int count = 0;
    int index = 0;

    for (unsigned int i = 0; i < len; ++i)
    {
        if (count == 0)
        {
            if (index > 0) strcat(splitbuffer, "\",\n");
            strcat(splitbuffer, "        \"");
            index = strlen(splitbuffer);
        }
        splitbuffer[index++] = b64data[i];
        count = (count + 1) % 76;
    }
    strcat(splitbuffer, "\"");

    return splitbuffer;
}

//4700438d-4ac9-4561-823e-4f74c38de219
// buffer must be at least 40 characters
char uuid_to_string(hal_uuid_t uuid, char *buffer)
{
    // sorry for implementing this this way, but it was so easy.
    sprintf(buffer, "%x%x%x%x-%x%x-%x%x-%x%x-%x%x%x%x%x%x",
            (unsigned int)uuid.uuid[0],
            (unsigned int)uuid.uuid[1],
            (unsigned int)uuid.uuid[2],
            (unsigned int)uuid.uuid[3],
            (unsigned int)uuid.uuid[4],
            (unsigned int)uuid.uuid[5],
            (unsigned int)uuid.uuid[6],
            (unsigned int)uuid.uuid[7],
            (unsigned int)uuid.uuid[8],
            (unsigned int)uuid.uuid[9],
            (unsigned int)uuid.uuid[10],
            (unsigned int)uuid.uuid[11],
            (unsigned int)uuid.uuid[12],
            (unsigned int)uuid.uuid[13],
            (unsigned int)uuid.uuid[14],
            (unsigned int)uuid.uuid[15]
            );
}

char *create_setup_json_string(hal_uuid_t kekek_uuid, uint8_t *kekek_public_key, unsigned int pub_key_len, int device_index)
{
    unsigned int b64size = b64e_size(pub_key_len)+1;

    // make sure the allocation was successful
    unsigned char *b64data = malloc(b64size);
    if(b64data == NULL) return NULL;

    // encode the public key
    unsigned int num_bytes = b64_encode((const unsigned char *)kekek_public_key, pub_key_len, b64data);

    // split b64 like the way CrypTech does it in Python
    char *public_key_string = split_b64_string(b64data);
    free(b64data);
    if(public_key_string == NULL) return NULL;

    char kekek_uuid_string[40];
    uuid_to_string(kekek_uuid, kekek_uuid_string);

    // create our json
    const char *format = "{\n    \"device_index\": %i,\n    \"comment\": \"KEKEK public key\",\n    \"kekek_pubkey\": [\n%s\n    ],\n    \"kekek_uuid\": \"%s\"\n}";

    int buffer_size = snprintf(NULL, 0, format, device_index, public_key_string, kekek_uuid_string) + 1;

    char *json_result = malloc(buffer_size);

    snprintf(json_result, buffer_size, format, device_index, public_key_string, kekek_uuid_string);

    // free remaining temporary data
    free(public_key_string);

    return json_result;
}