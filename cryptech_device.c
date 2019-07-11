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
#include <hal_internal.h>
#include <slip_internal.h>

#include "libs/base64.c/base64.h"
#include "djson.h"

#define CK_PTR                                          *
#define CK_DEFINE_FUNCTION(returnType, name)            returnType name
#define CK_DECLARE_FUNCTION(returnType, name)           returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name)   returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name)          returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR                                        NULL
#endif

#include "pkcs11t.h"

// check(op) - Copyright (c) 2016, NORDUnet A/S
#define check(op)                                               \
    do {                                                        \
        hal_error_t err = (op);                                 \
        if (err) {                                              \
            printf("%s: %s\r\n", #op, hal_error_string(err));     \
            return err;                                         \
        }                                                       \
    } while (0)

#define dks_json_throw(a) { rval = a; goto finished; }

#define dks_json_check(a) { result = (a); if (result != DJSON_OK) dks_json_throw(HAL_ERROR_BAD_ARGUMENTS); }

static const unsigned char const_0x010001[] = { 0x01, 0x00, 0x01 };

// Internal Functions --------------------------------------------------
char *create_setup_json_string(hal_uuid_t kekek_uuid, uint8_t *kekek_public_key, unsigned int pub_key_len, int device_index);
hal_error_t add_cached_attributes_to_json(const hal_pkey_handle_t pkey, FILE *fp);
char *uuid_to_string(hal_uuid_t uuid, char *buffer);
hal_uuid_t string_to_uuid(char *name);

char *binary_to_split_b64(const uint8_t *binary_data, size_t binary_data_len);
char *split_b64_string(const char *b64data);
diamond_json_error_t djson_ext_join_decodeb64string(diamond_json_ptr_t *json_ptr, char **decoded_result, unsigned int *result_len);
hal_error_t dks_hal_rpc_client_transport_init(void);

// Function Implementations --------------------------------------------
int init_cryptech_device(char *pin, uint32_t handle)
{
    hal_client_handle_t client = {handle};
    hal_user_t user = HAL_USER_WHEEL;

    check(dks_hal_rpc_client_transport_init());

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

int cmp_uuid(char *uuid1, char *uuid2)
{
    return memcmp(uuid1, uuid2, sizeof(hal_uuid_t)) == 0;
}

int cryptech_export_keys(uint32_t handle, char *setup_json, FILE **export_json)
{
    if (export_json == NULL || setup_json == NULL) return HAL_ERROR_BAD_ARGUMENTS;

    FILE *fp;
    if (*export_json != NULL)
    {
        fp = *export_json;
    }
    else
    {  
        *export_json = NULL;

        fp = tmpfile();
        if(fp == NULL)
        {
            printf("\r\nUnable to create tmp file.\r\n");
            return HAL_ERROR_ALLOCATION_FAILURE;
        }
    }
    // copy KEKEK info to export_json
    char *s = setup_json;
    while (*s != '}' && *s != 0) fputc(*s++, fp);

    // add key data
    hal_client_handle_t client = {handle};
    hal_session_handle_t session = {0};

    diamond_json_ptr_t json_ptr;
    diamond_json_error_t result = DJSON_OK;
    diamond_json_node_t pool[8];
    int rval = HAL_OK;

    const int MAX_UUIDS = 64;
    hal_uuid_t uuids[MAX_UUIDS];

    const size_t der_max = 1024 * 8;   // overkill
    const size_t pkcs8_max = 1024 * 8; // overkill
    const size_t kek_max = 512 * 8;

    char pkcs8[pkcs8_max];
    char kek[kek_max];
    char der[der_max];


    dks_json_check(djson_start_parser(setup_json, &json_ptr, pool, sizeof(pool)/sizeof(diamond_json_node_t)));

    // get the KEKEK
    dks_json_check(djson_parse_until(&json_ptr, "kekek_pubkey", DJSON_TYPE_Array));

    hal_pkey_handle_t kekek;
    hal_uuid_t kekek_uuid;
    char *kekek_data = NULL;
    int kekek_len;
    dks_json_check(djson_ext_join_decodeb64string(&json_ptr, &kekek_data, &kekek_len));

    check(hal_rpc_pkey_load(client,
                            session,
                            &kekek,
                            &kekek_uuid,
                            kekek_data, kekek_len,
                            HAL_KEY_FLAG_USAGE_KEYENCIPHERMENT));

    char temp_buffer[40];
    printf("Loaded KEYENCIPHERMENT as '%s'.\r\n", uuid_to_string(kekek_uuid, temp_buffer));

    hal_uuid_t previous_uuid;
    memset(&previous_uuid, 0, sizeof(previous_uuid));

    unsigned n = 0, state = 0, first = 1;

    fputs(",\"keys\": [ ", fp);

    int isfirstuuid = 1;
    hal_uuid_t first_uuid;

    // loop through all keys on the device
    do
    {
        // First try to find an exisiting KEKEK on the device
        check(hal_rpc_pkey_match(client,
                                 session,
                                 HAL_KEY_TYPE_NONE,
                                 HAL_CURVE_NONE,
                                 HAL_KEY_FLAG_EXPORTABLE,
                                 HAL_KEY_FLAG_EXPORTABLE,
                                 NULL, // const hal_pkey_attribute_t *attributes,
                                 0,    // const unsigned attributes_len,
                                 &state,
                                 uuids,
                                 &n,
                                 MAX_UUIDS,
                                 &previous_uuid));

        for (int i = 0; i < n; ++i)
        {
            if (isfirstuuid) {
                memcpy(&first_uuid, &uuids[i], sizeof(hal_uuid_t));
                isfirstuuid = 0;
            }
            else if (cmp_uuid((char *)&first_uuid, (char *)&uuids[i]) == 1)
            {
                n = 0;
                break;
            }
            // start the object
            if (first) { fputs("{ ", fp); first = 0; }
            else { fputs(", { ", fp); }

            // write the data
            char uuid_buffer[64];
            char uuid_sub_buffer[40];
            char flags_buffer[32];

            hal_pkey_handle_t pkey;
            hal_key_type_t pkey_type;
            hal_key_flags_t pkey_flags;

            check(hal_rpc_pkey_open(client,
                                    session,
                                    &pkey,
                                    &uuids[i]));

            check(hal_rpc_pkey_get_key_type(pkey, &pkey_type));
            check(hal_rpc_pkey_get_key_flags(pkey, &pkey_flags));

            snprintf(uuid_buffer, 64, ",\"uuid\": \"%s\" ", uuid_to_string(uuids[i], uuid_sub_buffer));
            snprintf(flags_buffer, 32, ",\"flags\": %u ", pkey_flags);

            if (pkey_type == HAL_KEY_TYPE_RSA_PRIVATE || pkey_type == HAL_KEY_TYPE_EC_PRIVATE)
            {
                fputs("\"comment\": \"Encrypted private key\" ", fp);

                size_t pkcs8_len, kek_len;

                check(hal_rpc_pkey_export(pkey,
                                          kekek,
                                          pkcs8, &pkcs8_len, pkcs8_max,
                                          kek,   &kek_len,   kek_max));

                char *pkcs8_splitb64 = binary_to_split_b64(pkcs8, pkcs8_len);
                char *kek_splitb64 = binary_to_split_b64(kek, kek_len);

                fputs(", \"pkcs8\": [ ", fp);
                fputs(pkcs8_splitb64, fp);
                fputs(" ]", fp);

                fputs(", \"kek\": [ ", fp);
                fputs(kek_splitb64, fp);
                fputs(" ]", fp);

                fputs(uuid_buffer, fp);
                fputs(flags_buffer, fp);

                free(pkcs8_splitb64);
                free(kek_splitb64);
            }
            else if (pkey_type == HAL_KEY_TYPE_RSA_PUBLIC || pkey_type == HAL_KEY_TYPE_EC_PUBLIC)
            {
                fputs("\"comment\": \"Public key\" ", fp);

                size_t der_len;
                check(hal_rpc_pkey_get_public_key(pkey,
                                                  der, &der_len, der_max));

                char *spki_splitb64 = binary_to_split_b64(der, der_len);

                fputs(", \"spki\": [ ", fp);
                fputs(spki_splitb64, fp);
                fputs(" ]", fp);

                fputs(uuid_buffer, fp);
                fputs(flags_buffer, fp);

                free(spki_splitb64);
            }

            fputs(", \"attributes\": { ", fp);
            check(add_cached_attributes_to_json(pkey, fp));
            fputs(" }", fp);

            // close
            fputc('}', fp);

            check(hal_rpc_pkey_close(pkey));

            printf("Key '%s' processed.\r\n", uuid_sub_buffer);
        }

        // save the last uuid for more searches
        if (n > 0)
            memcpy(&previous_uuid, &uuids[n-1], sizeof(hal_uuid_t));
    } while (n == MAX_UUIDS);
    
    // finish the json
    fputs("] }", fp);

finished:
    if(kekek_data != NULL)
    {
        check(hal_rpc_pkey_delete(kekek));
        free(kekek_data);
    }
    if (rval != HAL_OK) fclose(fp);
    else *export_json = fp;

    return rval;
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
    }

    if (*json_result == NULL) return HAL_ERROR_ALLOCATION_FAILURE;

    return 0;
}

int import_keys(uint32_t handle, char *json_string)
{
    if (json_string == NULL) return HAL_ERROR_BAD_ARGUMENTS;

    int rval = HAL_OK;
    
    hal_client_handle_t client = {handle};
    hal_session_handle_t session = {0};

    // pool of nodes. must be the maximum depth
    diamond_json_node_t pool[8];
    diamond_json_ptr_t json_ptr;

    char *pkcs8 = NULL;
    unsigned int pkcs8_len;
    char *kek = NULL;
    unsigned int kek_len;
    char *spki = NULL;
    unsigned int spki_len;
    char *attr_json = NULL;

    // get the KEKEK
    char kekek_uuid_buffer[40], *json_search_ptr = json_string;
    char *kekek_uuid_s = djson_find_element("kekek_uuid", kekek_uuid_buffer, 40, &json_search_ptr);

    if (kekek_uuid_s == NULL)
    {
        printf("\r\n'kekek_uuid' not found in export JSON.\r\n");
        return HAL_ERROR_ASSERTION_FAILED;
    }

    // starting JSON parser before opening KEKEK just incase there is an error
    diamond_json_error_t result = djson_start_parser(json_string, &json_ptr, pool, sizeof(pool)/sizeof(diamond_json_node_t));
    if (result != DJSON_OK) return HAL_ERROR_BAD_ARGUMENTS;

    result = djson_parse_until(&json_ptr, "keys", DJSON_TYPE_Array);
    if (result != DJSON_OK) return HAL_ERROR_BAD_ARGUMENTS;

    // open the KEKEK
    hal_pkey_handle_t kekek;
    hal_uuid_t kekek_uuid = string_to_uuid(kekek_uuid_s);

    check(hal_rpc_pkey_open(client, session, &kekek, &kekek_uuid));

    // parse the JSON
    while (1)
    {
        char *uuid_string = NULL;
        int flags;

        // should be an object
        dks_json_check(djson_goto_next_element(&json_ptr));

        diamond_json_type_t json_type;
        dks_json_check(djson_get_type_current(&json_ptr, &json_type));

        if (json_type == DJSON_TYPE_ArrayEnd) break; // finished looking at all keys
        else if (json_type != DJSON_TYPE_Object) dks_json_throw(HAL_ERROR_BAD_ARGUMENTS);

        // go to the first element
        dks_json_check(djson_goto_next_element(&json_ptr));
        dks_json_check(djson_get_type_current(&json_ptr, &json_type));

        // parse a key object
        while (json_type != DJSON_TYPE_ObjectEnd)
        {
            char *name;
            dks_json_check(djson_get_name_current(&json_ptr, &name));

            if (strcmp(name, "pkcs8") == 0 && json_type == DJSON_TYPE_Array)
            {
                dks_json_check(djson_ext_join_decodeb64string(&json_ptr, &pkcs8, &pkcs8_len));
            }
            else if (strcmp(name, "kek") == 0 && json_type == DJSON_TYPE_Array)
            {
                dks_json_check(djson_ext_join_decodeb64string(&json_ptr, &kek, &kek_len));
            }
            else if (strcmp(name, "spki") == 0 && json_type == DJSON_TYPE_Array)
            {
                dks_json_check(djson_ext_join_decodeb64string(&json_ptr, &spki, &spki_len));
            }
            else if (strcmp(name, "attributes") == 0 && json_type == DJSON_TYPE_Object)
            {
                dks_json_check(djson_skip_save_object(&json_ptr, &attr_json));
            }
            else if (strcmp(name, "uuid") == 0 && json_type == DJSON_TYPE_String)
            {
                dks_json_check(djson_get_string_value_current(&json_ptr, &uuid_string));
            }
            else if (strcmp(name, "flags") == 0 && json_type == DJSON_TYPE_Primitive)
            {
                dks_json_check(djson_get_integer_primitive_current(&json_ptr, &flags));
            }
            else if (strcmp(name, "comment") == 0 && json_type == DJSON_TYPE_String) { printf("\r\n"); }
            else
            {
                dks_json_throw(HAL_ERROR_BAD_ARGUMENTS);
            }

            dks_json_check(djson_pass(&json_ptr));

            dks_json_check(djson_get_type_current(&json_ptr, &json_type));
        }

        // we know have all of our data from JSON
        hal_uuid_t uuid = string_to_uuid(uuid_string);

        hal_pkey_handle_t new_pkey = {0};
        hal_uuid_t new_uuid;

        // make sure we can parse the attributes before continuing
        // pool of nodes. must be the maximum depth
        diamond_json_node_t attr_pool[8];
        diamond_json_ptr_t attr_json_ptr;

        if(attr_json != NULL)
        {
            // starting JSON parser before opening KEKEK just incase there is an error
            dks_json_check(djson_start_parser(attr_json, &attr_json_ptr, attr_pool, sizeof(attr_pool)/sizeof(diamond_json_node_t)));
            if (result != DJSON_OK) return HAL_ERROR_BAD_ARGUMENTS;
        }

        if (pkcs8 != NULL && kek != NULL)
        {
            check(hal_rpc_pkey_import(client,
                                      session,
                                      &new_pkey,
                                      &new_uuid,
                                      kekek,
                                      pkcs8, pkcs8_len,
                                      kek, kek_len,
                                      flags));

            char temp_buffer[40];
            printf("Imported %s as %s", uuid_string, uuid_to_string(new_uuid, temp_buffer));
        }
        else if (spki != NULL)
        {
            check(hal_rpc_pkey_load(client,
                                    session,
                                    &new_pkey,
                                    &new_uuid,
                                    spki, spki_len,
                                    flags));

            char temp_buffer[40];
            printf("Loaded %s as %s", uuid_string, uuid_to_string(new_uuid, temp_buffer));
        }
        else
        {
            dks_json_throw(HAL_ERROR_BAD_ARGUMENTS);
        }
        
        // save the attributes
        if(attr_json != NULL)
        {
            diamond_json_type_t curr_attr_type;
            dks_json_check(djson_goto_next_element(&attr_json_ptr));
            dks_json_check(djson_get_type_current(&attr_json_ptr, &curr_attr_type));

            while (curr_attr_type != DJSON_TYPE_ObjectEnd)
            {
                // igore all none array types
                if (curr_attr_type == DJSON_TYPE_Array ||
                    curr_attr_type == DJSON_TYPE_Primitive)
                {
                    char *decoded_data = NULL;
                    unsigned int data_len;
                    char *attr_name;

                    dks_json_check(djson_get_name_current(&attr_json_ptr, &attr_name));

                    hal_pkey_attribute_t pkey_attr;
                    pkey_attr.type = atoi(attr_name);

                    unsigned char bool_value;
                    unsigned int uint_value;


                    if(curr_attr_type == DJSON_TYPE_Array)
                    {
                        dks_json_check(djson_ext_join_decodeb64string(&attr_json_ptr, &decoded_data, &data_len));
                        pkey_attr.value = decoded_data;
                        pkey_attr.length = data_len;
                    }
                    else
                    {
                        int int_value;
                        diamond_primitive_value_t prim_type;

                        if (djson_get_integer_primitive_current(&attr_json_ptr, &int_value) == DJSON_OK)
                        {
                            if (int_value == 0 || int_value == 1)
                            {
                                bool_value = (unsigned char)int_value;
                                pkey_attr.value = &bool_value;
                                pkey_attr.length = sizeof(bool_value);
                            }
                            else
                            {
                                uint_value = (unsigned int)int_value;
                                pkey_attr.value = &uint_value;
                                pkey_attr.length = sizeof(uint_value);
                            }
                        }
                        else
                        {
                            pkey_attr.value = NULL;
                            pkey_attr.length = 0xFFFFFFFF;
                        }
                    }                  


                    check(hal_rpc_pkey_set_attributes(new_pkey,
                                                      &pkey_attr,
                                                      1));
                    free(decoded_data);
                }

                // get the next element
                dks_json_check(djson_goto_next_element(&attr_json_ptr));
                dks_json_check(djson_get_type_current(&attr_json_ptr, &curr_attr_type));
            }
        }

        // close the new pkey
        check(hal_rpc_pkey_close(new_pkey));

        // free temporary data
        free(pkcs8);
        free(kek);
        free(spki);
        free(attr_json);
        pkcs8 = NULL;
        kek = NULL;
        spki = NULL;
        attr_json = NULL;
    }

finished:
    check(hal_rpc_pkey_close(kekek));
    free(pkcs8);
    free(kek);
    free(spki);
    free(attr_json);

    return rval;
}

diamond_json_error_t djson_ext_join_decodeb64string(diamond_json_ptr_t *json_ptr, char **decoded_result,
                                                    unsigned int *result_len)
{
    *decoded_result = NULL;
    char *b64data;
    char *decoded_data;
    
    diamond_json_error_t result = djson_join_string_array(json_ptr, &b64data);
    if (result != DJSON_OK) return result;

    unsigned int b64data_len = strlen(b64data);

    unsigned int decoded_size = b64d_size(b64data_len);

    // make sure the allocation was successful
    decoded_data = malloc(decoded_size);
    if(decoded_data == NULL) return DJSON_ERROR_MEMORY;

    *result_len = b64_decode(b64data, b64data_len, decoded_data);

    *decoded_result = decoded_data;

    return result;
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
        splitbuffer[index] = 0;
        count = (count + 1) % 76;
    }
    strcat(splitbuffer, "\"");

    return splitbuffer;
}

//4700438d-4ac9-4561-823e-4f74c38de219
// buffer must be at least 40 characters
char *uuid_to_string(hal_uuid_t uuid, char *buffer)
{
    // sorry for implementing this this way, but it was so easy.
    sprintf(buffer, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
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

    return buffer;
}

hal_uuid_t string_to_uuid(char *name)
{
    // sorry for implementing this this way, but it was so easy.
    hal_uuid_t uuid;
    char temp[3];
    temp[2] = 0;
    int i = 0, j = 0;

    while (*name != 0 && j < 16)
    {
        if ((*name >= '0' && *name <= '9') ||
            (*name >= 'a' && *name <= 'f') ||
            (*name >= 'A' && *name <= 'F'))
        {
            temp[i++] = *name;
            if(i == 2)
            {
                unsigned int t;
                sscanf(temp, "%x", &t);
                uuid.uuid[j++] = (char)t;
                i = 0;
            }
        }
        ++name;
    }
    return uuid;
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

hal_error_t add_cached_attributes_to_json(const hal_pkey_handle_t pkey, FILE *fp)
{
    // what are the attributes that we want to read from the CrypTech device
    const uint32_t cached_attributes[] = { CKA_CLASS, CKA_TOKEN, CKA_PRIVATE, CKA_LABEL, CKA_APPLICATION,
                                           CKA_VALUE, CKA_OBJECT_ID, CKA_CERTIFICATE_TYPE,
                                           CKA_SERIAL_NUMBER, CKA_OWNER, CKA_ATTR_TYPES,
                                           CKA_TRUSTED, CKA_CERTIFICATE_CATEGORY, CKA_JAVA_MIDP_SECURITY_DOMAIN,
                                           CKA_CHECK_VALUE, CKA_KEY_TYPE, CKA_SUBJECT, CKA_ID, CKA_SENSITIVE,
                                           CKA_ENCRYPT, CKA_DECRYPT, CKA_WRAP, CKA_UNWRAP, CKA_SIGN,
                                           CKA_SIGN_RECOVER, CKA_VERIFY, CKA_VERIFY_RECOVER, CKA_DERIVE,
                                           CKA_MODULUS, CKA_MODULUS_BITS,
                                           CKA_PUBLIC_EXPONENT, CKA_EXTRACTABLE, CKA_LOCAL, CKA_NEVER_EXTRACTABLE,
                                           CKA_ALWAYS_SENSITIVE, CKA_KEY_GEN_MECHANISM, CKA_MODIFIABLE,
                                           CKA_EC_PARAMS, CKA_EC_POINT, CKA_ALWAYS_AUTHENTICATE, 
                                           CKA_WRAP_WITH_TRUSTED };

    const uint32_t optional_attributes[] = { CKA_ISSUER, CKA_SERIAL_NUMBER, CKA_AC_ISSUER, CKA_URL,
                                             CKA_HASH_OF_SUBJECT_PUBLIC_KEY, CKA_HASH_OF_ISSUER_PUBLIC_KEY,
                                             CKA_START_DATE, CKA_END_DATE, CKA_OTP_FORMAT, CKA_OTP_LENGTH,
                                             CKA_OTP_TIME_INTERVAL, CKA_OTP_USER_FRIENDLY_MODE,
                                             CKA_OTP_CHALLENGE_REQUIREMENT, CKA_OTP_TIME_REQUIREMENT,
                                             CKA_OTP_COUNTER_REQUIREMENT, CKA_OTP_PIN_REQUIREMENT,
                                             CKA_OTP_COUNTER, CKA_OTP_TIME, CKA_OTP_USER_IDENTIFIER,
                                             CKA_OTP_SERVICE_IDENTIFIER, CKA_OTP_SERVICE_LOGO,
                                             CKA_OTP_SERVICE_LOGO_TYPE, CKA_GOSTR3410_PARAMS, 
                                             CKA_GOSTR3411_PARAMS, CKA_GOST28147_PARAMS };

    
    const int num_cached_attributes = sizeof(cached_attributes) /  sizeof(unsigned int);
    const int num_optional_attributes = sizeof(optional_attributes) /  sizeof(unsigned int);

    // the buffer size is much larger than needed for most cases, but larger than 2048
    // can cause a RPC packet overflow error
    const size_t attributes_buffer_len = 2048;
    unsigned char attributes_buffer[attributes_buffer_len];

    int first = 1;

    char buffer[4096]; // lazy waste of memory

    for (int i = 0; i < num_cached_attributes; ++i)
    {
        hal_pkey_attribute_t attr_get = { .type = cached_attributes[i] };

        hal_error_t err;
        if ((err = hal_rpc_pkey_get_attributes(pkey,
                                        &attr_get,
                                        1,
                                        attributes_buffer,
                                        attributes_buffer_len)) == HAL_OK)
        {
            if (!first) { fputc(',', fp);}
            else first = 0; 

            char *attr_data = binary_to_split_b64(attr_get.value, attr_get.length);
            snprintf(buffer, 4095, "\"%u\":[%s]", attr_get.type, attr_data);

            fputs(buffer, fp);
        }       
    }

    for (int i = 0; i < num_optional_attributes; ++i)
    {
        hal_pkey_attribute_t attr_get = { .type = optional_attributes[i] };

        hal_error_t err;
        if ((err = hal_rpc_pkey_get_attributes(pkey,
                                        &attr_get,
                                        1,
                                        attributes_buffer,
                                        attributes_buffer_len)) == HAL_OK)
        {
            if (attr_get.length > 0)
            {
                if (!first) { fputc(',', fp);}
                else first = 0; 

                char *attr_data = binary_to_split_b64(attr_get.value, attr_get.length);
                snprintf(buffer, 4095, "\"%u\":[%s]", attr_get.type, attr_data);

                fputs(buffer, fp);
            }
        }       
    }    
    return HAL_OK;
}

char *binary_to_split_b64(const uint8_t *binary_data, size_t binary_data_len)
{
    unsigned int b64size = b64e_size(binary_data_len)+1;

    // make sure the allocation was successful
    unsigned char *b64data = malloc(b64size);
    if(b64data == NULL) return NULL;

    // encode the public key
    unsigned int num_bytes = b64_encode((const unsigned char *)binary_data, binary_data_len, b64data);

    // split b64 like the way CrypTech does it in Python
    char *splitb64 = split_b64_string(b64data);
    
    free(b64data);

    return splitb64;
}

// --------------------------------------------------------------------------------
// Taken from rpc_client_serial.c with modifications
/*
 * rpc_client_serial.c
 * -------------------
 * Remote procedure call transport over serial line with SLIP framing.
 *
 * Copyright (c) 2016, NORDUnet A/S All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * - Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * - Neither the name of the NORDUnet nor the names of its contributors may
 *   be used to endorse or promote products derived from this software
 *   without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
hal_error_t dks_hal_rpc_client_transport_init(void)
{
    const char *device = getenv(HAL_CLIENT_SERIAL_DEVICE_ENVVAR);
    const char *speed_ = getenv(HAL_CLIENT_SERIAL_SPEED_ENVVAR);
    uint32_t    speed  = HAL_CLIENT_SERIAL_DEFAULT_SPEED;

    if (device == NULL)
        return HAL_ERROR_RPC_TRANSPORT;

    if (speed_ != NULL)
        speed = (uint32_t) strtoul(speed_, NULL, 10);

    return hal_serial_init(device, speed);
}
// --------------------------------------------------------------------------------
