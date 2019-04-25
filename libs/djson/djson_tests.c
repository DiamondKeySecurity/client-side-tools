// Copyright (c) 2019 Diamond Key Security, NFP
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

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#include "djson.h"

char *loadfile(char *filename)
{
    FILE *fp = fopen(filename, "rt");

    // get the size of the file
    fseek(fp, 0, SEEK_END);
    int length = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *buffer = malloc(length+1);

    if (buffer == NULL) return NULL;

    for (int i = 0; i < length; ++i)
    {
        buffer[i] = fgetc(fp);
    }

    buffer[length] = 0; // null terminator

    return buffer;
}

#define check(a) if(a != DJSON_OK) { printf("Error: %i", (int)a); exit(1); }

int main()
{
    char *json_string = loadfile("sample.json");

    // pool of nodes. must be the maximum depth
    diamond_json_node_t pool[8];
    diamond_json_ptr_t json_ptr;

    diamond_json_error_t result = djson_start_parser(json_string, &json_ptr, pool, sizeof(pool)/sizeof(diamond_json_node_t));
    check(result);

    while (result == DJSON_OK)
    {
        char *name, *value;
        diamond_json_type_t type;
        djson_get_type_current(&json_ptr, &type);
        djson_get_name_current(&json_ptr, &name);
        djson_get_string_value_current(&json_ptr, &value);

        printf("\n--------------------\nType:%i\n", (int)type);
        if(name != NULL) printf("Name:%s\n", name);
        if(value != NULL) printf("Value:%s\n", value);

        result = djson_goto_next_element(&json_ptr);
    }
    check(result);

    free (json_string);
}