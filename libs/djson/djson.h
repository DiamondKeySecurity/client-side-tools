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
#ifndef _DIAMOND_JSON_HEADER
#define _DIAMOND_JSON_HEADER

typedef enum 
{
    DJSON_OK = 0,
    DJSON_ERROR_PARSER = 1,
    DJSON_ERROR_NO_PARENT_NODE = 2,
    DJSON_ERROR_BAD_ARGUMENTS = 3,
    DJSON_ERROR_FILE_EMPTY = 4,
    DJSON_ERROR_UNENDING_STRING = 5,
    DJSON_ERROR_NEWLINE_IN_STRING = 6,
    DJSON_ERROR_ELEMENT_HAS_NO_NAME = 7,
    DJSON_ERROR_INVALID_STRING = 8,
    DJSON_ERROR_UNEXPECTED_EOF = 9,
    DJSON_ERROR_UNEXPECTED_END_OF_OBJECT = 10,
    DJSON_ERROR_UNEXPECTED_END_OF_ARRAY = 11,
    DJSON_ERROR_UNEXPECTED_OBJECT = 12,
    DJSON_ERROR_UNEXPECTED_ARRAY = 13,
    DJSON_ERROR_UNEXPECTED_COMMA = 14,
    DJSON_ERROR_INVALID_SYNTAX = 15,
    DJSON_ERROR_UNEXPECTED_STRING = 16,
    DJSON_ERROR_NOT_A_STRING = 17,
    DJSON_ERROR_NOT_A_PRIMITIVE = 18,
    DJSON_ERROR_NOT_A_NUMBER = 19,
    DJSON_ERROR_NOT_AN_OBJECT = 20,
    DJSON_ERROR_NODEPOOL_EMPTY = 21,
    DJSON_ERROR_MEMORY = 22,
    DJSON_EOF
} diamond_json_error_t;

typedef enum _diamond_json_type
{
    // the value of this node is a string in quotes
    DJSON_TYPE_String,

    // the value of this node is an array
    DJSON_TYPE_Array,

    // the value of this node is an object
    DJSON_TYPE_Object,

    // the value of this node is a non-string primitive (null, number, or bool)
    DJSON_TYPE_Primitive,

    // this node marks the end of an array ']'
    DJSON_TYPE_ArrayEnd,

    // this node marks the end of an object '}'
    DJSON_TYPE_ObjectEnd,

    // Parser error
    DJSON_TYPE_Undefined
} diamond_json_type_t;

typedef enum _diamond_primitive_value
{
    DJSON_PRIMITIVE_true,
    DJSON_PRIMITIVE_false,
    DJSON_PRIMITIVE_null,
    DJSON_PRIMITIVE_integer,
    DJSON_PRIMITIVE_real,
    DJSON_PRIMITIVE_NotAPrimitive,
} diamond_primitive_value_t;

typedef struct _diamond_json_node
{
    // the type of this node
    diamond_json_type_t type;

    // parsed name of this object
    char *name;

    // parsed value, for strings only.
    // For all other types, this will be NULL
    char *string_value;

    // if the node is a primitive, this is the
    // value. string_value will be null
    diamond_primitive_value_t primitive_value;

    // if the primitive is a number, store the
    // value here
    union {
        int int_value;
        float real_value;
    } primitive_number;

    // parent element
    struct _diamond_json_node *parent;
} diamond_json_node_t;

typedef struct _diamond_json_ptr
{
    // pointer to the beginning of the json
    // file.
    char *json_data;

    // the current node
    diamond_json_node_t *current_element;

    // pool of nodes that the parser can use
    diamond_json_node_t *node_pool;

    // size of the pool of nodes,
    // must be greater than or equal to the
    // depth of the deepest node
    int node_pool_size;

    // how many nodes in the node pool are
    // currently being used
    int nodes_used;

    // pointer to the next thing in the string to be read
    char *ptr;
} diamond_json_ptr_t;

// starts the parser and parses the first element
diamond_json_error_t djson_start_parser(char *json_data, diamond_json_ptr_t *json_ptr,
                                        diamond_json_node_t *pool, int pool_size);

// gets the type of the current element
diamond_json_error_t djson_get_type_current(diamond_json_ptr_t *json_ptr, diamond_json_type_t *result);

// gets the name of the current element
diamond_json_error_t djson_get_name_current(diamond_json_ptr_t *json_ptr, char **result);

// gets the value of the current element, if it is a string type
diamond_json_error_t djson_get_string_value_current(diamond_json_ptr_t *json_ptr, char **result);

// gets the value of the current element, if it is a primitive type
diamond_json_error_t djson_get_primitive_value_current(diamond_json_ptr_t *json_ptr, diamond_primitive_value_t *result);

// gets the value of the current element, if it is a number type
diamond_json_error_t djson_get_integer_primitive_current(diamond_json_ptr_t *json_ptr, int *result);

// gets the value of the current element, if it is a number type
diamond_json_error_t djson_get_real_primitive_current(diamond_json_ptr_t *json_ptr, float *result);

// returns 1 if the current element is a number
int djson_is_current_a_number(diamond_json_ptr_t *json_ptr);

// goes to the next sibling if the node has siblings and no children
diamond_json_error_t djson_goto_next_element(diamond_json_ptr_t *json_ptr);

// parse the json until it finds an element with the name and type
diamond_json_error_t djson_parse_until(diamond_json_ptr_t *json_ptr, char *name, diamond_json_type_t type);

// goto the next element skipping any children of the current element
diamond_json_error_t djson_pass(diamond_json_ptr_t *json_ptr);

// parses an array of strings and joins all of the strings together.
diamond_json_error_t djson_join_string_array(diamond_json_ptr_t *json_ptr, char **results);

// skips the current json object and all children and returns an unaltered string of the json skipped
// This method will create a buffer to hold the string. Must use with "free(object_json);"
diamond_json_error_t djson_skip_save_object(diamond_json_ptr_t *json_ptr, char **object_json);

// utility function that returns the value of a JSON token
char *djson_find_element(const char *name, char *buffer, int maxlen, char **json_data);

#endif