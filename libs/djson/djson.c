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
#include <string.h>

#include "djson.h"

// Internal function declataion
diamond_json_error_t _djson_get_node_from_pool(diamond_json_ptr_t *json_ptr, diamond_json_node_t **node);
diamond_json_error_t _djson_read_string(char **ptr, char **result);
diamond_json_error_t _djson_read_primitive(char **ptr, char *result, int result_len);
diamond_json_error_t _djson_set_node_primitive(diamond_json_node_t *node, char *primitive_value);
char *_djson_get_next_non_whitespace(char *string);
int _djson_isNumeric(char c);
int _djson_isAlpha(char c);
diamond_json_type_t _djson_type_lookahead(char next_char);
int _djson_isNumber(char *s);

// Function Implementation ---------------------------------------

// starts the parser and parses the first element
diamond_json_error_t djson_start_parser(char *json_data, diamond_json_ptr_t *json_ptr,
                                        diamond_json_node_t *pool, int pool_size)
{
    json_ptr->node_pool = pool;
    json_ptr->node_pool_size = pool_size;
    json_ptr->nodes_used = 0;
    json_ptr->json_data = json_data;
    json_ptr->current_element = NULL;
    json_ptr->ptr = json_data;

    return djson_goto_next_element(json_ptr);
}


// gets the type of the current element
diamond_json_error_t djson_get_type_current(diamond_json_ptr_t *json_ptr, diamond_json_type_t *result)
{
    if (json_ptr == NULL || json_ptr->current_element == NULL) return DJSON_ERROR_BAD_ARGUMENTS;

    *result = json_ptr->current_element->type;

    return DJSON_OK;
}

// gets the name of the current element
diamond_json_error_t djson_get_name_current(diamond_json_ptr_t *json_ptr, char **result)
{
    *result = NULL;
    if (json_ptr == NULL || json_ptr->current_element == NULL) return DJSON_ERROR_BAD_ARGUMENTS;

    if (json_ptr->current_element->name == NULL) return DJSON_ERROR_ELEMENT_HAS_NO_NAME;

    *result = json_ptr->current_element->name;

    return DJSON_OK;
}

// gets the value of the current element, if it is a primitive type
diamond_json_error_t djson_get_string_value_current(diamond_json_ptr_t *json_ptr, char **result)
{
    *result = NULL;
    if (json_ptr == NULL || json_ptr->current_element == NULL) return DJSON_ERROR_BAD_ARGUMENTS;

    if (json_ptr->current_element->type != DJSON_TYPE_String || 
        json_ptr->current_element->string_value == NULL) return DJSON_ERROR_NOT_A_STRING;

    *result = json_ptr->current_element->string_value;

    return DJSON_OK;
}

diamond_json_error_t djson_get_primitive_value_current(diamond_json_ptr_t *json_ptr, diamond_primitive_value_t *result)
{
    *result = DJSON_PRIMITIVE_NotAPrimitive;
    if (json_ptr == NULL || json_ptr->current_element == NULL) return DJSON_ERROR_BAD_ARGUMENTS;

    if (json_ptr->current_element->type != DJSON_TYPE_Primitive || 
        json_ptr->current_element->primitive_value == DJSON_PRIMITIVE_NotAPrimitive) return DJSON_ERROR_NOT_A_PRIMITIVE;

    *result = json_ptr->current_element->primitive_value;

    return DJSON_OK;
}

diamond_json_error_t djson_get_integer_primitive_current(diamond_json_ptr_t *json_ptr, int *result)
{
    *result = 0;
    if (json_ptr == NULL || json_ptr->current_element == NULL) return DJSON_ERROR_BAD_ARGUMENTS;

    if (json_ptr->current_element->type != DJSON_TYPE_Primitive || 
        json_ptr->current_element->primitive_value == DJSON_PRIMITIVE_NotAPrimitive) return DJSON_ERROR_NOT_A_PRIMITIVE;

    if (json_ptr->current_element->primitive_value == DJSON_PRIMITIVE_integer)
        *result = json_ptr->current_element->primitive_number.int_value;
    else if (json_ptr->current_element->primitive_value == DJSON_PRIMITIVE_real)
        *result = (int)json_ptr->current_element->primitive_number.real_value;
    else return DJSON_ERROR_NOT_A_NUMBER;

    return DJSON_OK;
}

diamond_json_error_t djson_get_real_primitive_current(diamond_json_ptr_t *json_ptr, float *result)
{
    *result = 0;
    if (json_ptr == NULL || json_ptr->current_element == NULL) return DJSON_ERROR_BAD_ARGUMENTS;

    if (json_ptr->current_element->type != DJSON_TYPE_Primitive || 
        json_ptr->current_element->primitive_value == DJSON_PRIMITIVE_NotAPrimitive) return DJSON_ERROR_NOT_A_PRIMITIVE;

    if (json_ptr->current_element->primitive_value == DJSON_PRIMITIVE_integer)
        *result = (float)json_ptr->current_element->primitive_number.int_value;
    else if (json_ptr->current_element->primitive_value == DJSON_PRIMITIVE_real)
        *result = json_ptr->current_element->primitive_number.real_value;
    else return DJSON_ERROR_NOT_A_NUMBER;

    return DJSON_OK;
}

int djson_is_current_a_number(diamond_json_ptr_t *json_ptr)
{
    return (json_ptr != NULL && json_ptr->current_element != NULL &&
            json_ptr->current_element->type == DJSON_TYPE_Primitive && 
            (json_ptr->current_element->primitive_value == DJSON_PRIMITIVE_integer ||
             json_ptr->current_element->primitive_value == DJSON_PRIMITIVE_real));

}


int _djson_pop_top_element(diamond_json_ptr_t *json_ptr)
{
    if (json_ptr->current_element == NULL)
    {
        return 0;
    }
    else
    {
        json_ptr->current_element = json_ptr->current_element->parent;
        --json_ptr->nodes_used;

        return 1;
    }
}


diamond_json_error_t djson_goto_next_element(diamond_json_ptr_t *json_ptr)
{
    // check for the end of the string
    if (json_ptr == NULL || json_ptr->ptr == NULL) return DJSON_ERROR_BAD_ARGUMENTS;

    char *ptr = _djson_get_next_non_whitespace(json_ptr->ptr);
    if (*ptr == 0)
    {
        return DJSON_EOF;
    }

    if(json_ptr->current_element != NULL &&
       json_ptr->current_element->type != DJSON_TYPE_Array &&
       json_ptr->current_element->type != DJSON_TYPE_Object)
    {
        // if ObjectEnd or ArrayEnd, pop parent too
        int pop_parent = json_ptr->current_element->type == DJSON_TYPE_ObjectEnd ||
                         json_ptr->current_element->type == DJSON_TYPE_ArrayEnd;

        // pop the last element to reveal parent
        if (_djson_pop_top_element(json_ptr) == 0) return DJSON_ERROR_PARSER;

        // we just finished an array or list so pop the parent too
        if (pop_parent)
        {
            if (_djson_pop_top_element(json_ptr) == 0) return DJSON_ERROR_PARSER;

            // read past comma if this was part of a greater list
            if (*ptr == ',')
            {
                if (json_ptr->current_element != NULL &&
                    (json_ptr->current_element->type == DJSON_TYPE_Object ||
                     json_ptr->current_element->type == DJSON_TYPE_Array))
                {
                    ptr = _djson_get_next_non_whitespace(ptr+1);

                    if (*ptr == 0) return DJSON_ERROR_UNEXPECTED_EOF;
                }
                else
                {
                    return DJSON_ERROR_UNEXPECTED_COMMA;
                }
            }
        }
    }

    // get a new node from the pool
    diamond_json_node_t *node;
    diamond_json_error_t result = _djson_get_node_from_pool(json_ptr, &node);
    if (result != DJSON_OK) return result;

    // set our new node
    node->parent = json_ptr->current_element;
    json_ptr->current_element = node;

    // checkout the next element
    diamond_json_type_t lookahead = _djson_type_lookahead(*ptr);

    if (lookahead == DJSON_TYPE_Undefined)
        return DJSON_ERROR_PARSER;

    if (node->parent == NULL)
    // if no parent then this is the first element
    {
        // first element must be an array or object
        if (lookahead == DJSON_TYPE_Array ||
            lookahead == DJSON_TYPE_Object)
        {
            node->type = lookahead;

            // move off the current character
            json_ptr->ptr = ptr + 1;
        }
        else
        {
            return DJSON_ERROR_INVALID_SYNTAX;
        }
    }
    else
    {
        diamond_json_node_t *parent = node->parent;

        char primitive_buffer[128]; // primitive max 127 characters for long numbers

        switch (lookahead)
        {
            case DJSON_TYPE_Object:
            case DJSON_TYPE_Array:
                if (parent->type == DJSON_TYPE_Array)
                {
                    node->type = lookahead;

                    // move off the current character
                    json_ptr->ptr = ptr + 1;
                }
                else
                {
                    if (lookahead == DJSON_TYPE_Object) return DJSON_ERROR_UNEXPECTED_OBJECT;
                    else return DJSON_ERROR_UNEXPECTED_ARRAY;
                }
                break;
            case DJSON_TYPE_ObjectEnd:
                if (parent->type == DJSON_TYPE_Object)
                {
                    node->type = lookahead;

                    // move off the current character
                    json_ptr->ptr = ptr + 1;
                }
                else
                {
                    return DJSON_ERROR_UNEXPECTED_END_OF_OBJECT;
                }
                break;
            case DJSON_TYPE_ArrayEnd:
                if (parent->type == DJSON_TYPE_Array)
                {
                    node->type = lookahead;

                    // move off the current character
                    json_ptr->ptr = ptr + 1;
                }
                else
                {
                    return DJSON_ERROR_UNEXPECTED_END_OF_ARRAY;
                }
                break;
            case DJSON_TYPE_String:
                if (parent->type == DJSON_TYPE_Object)
                {
                    // should be the "name" : value

                    // get the name
                    diamond_json_error_t result = _djson_read_string(&ptr, &(node->name));
                    if (result != DJSON_OK) return result;

                    // get the ':'
                    ptr = _djson_get_next_non_whitespace(ptr);
                    if (*ptr == 0) return DJSON_ERROR_UNEXPECTED_EOF;
                    else if (*ptr != ':') return DJSON_ERROR_INVALID_SYNTAX;

                    // get the value
                    ptr = _djson_get_next_non_whitespace(ptr+1);
                    if (*ptr == 0) return DJSON_ERROR_UNEXPECTED_EOF;
                    
                    node->type = _djson_type_lookahead(*ptr);

                    switch (node->type)
                    {
                        case DJSON_TYPE_Array:
                        case DJSON_TYPE_Object:
                            // move off the current character
                            json_ptr->ptr = ptr + 1;
                            break;
                        case DJSON_TYPE_ArrayEnd:
                            return DJSON_ERROR_UNEXPECTED_END_OF_ARRAY;
                        case DJSON_TYPE_ObjectEnd:
                            return DJSON_ERROR_UNEXPECTED_END_OF_OBJECT;
                        case DJSON_TYPE_Undefined:
                            return DJSON_ERROR_INVALID_SYNTAX;
                        case DJSON_TYPE_String:
                            result = _djson_read_string(&ptr, &(node->string_value));
                            if (result != DJSON_OK) return result;

                            // prepar for the next object. we really just need to make sure we
                            // have eaten the comma
                            ptr = _djson_get_next_non_whitespace(ptr);
                            if (*ptr == 0) return DJSON_ERROR_UNEXPECTED_EOF;
                            else if (*ptr == ',') ptr = ptr + 1;

                            json_ptr->ptr = ptr;
                            break;
                        case DJSON_TYPE_Primitive:
                            result = _djson_read_primitive(&ptr, primitive_buffer, sizeof(primitive_buffer)/sizeof(char));
                            if (result != DJSON_OK) return result;

                            result = _djson_set_node_primitive(node, primitive_buffer);
                            if (result != DJSON_OK) return result;

                            // prepar for the next object. we really just need to make sure we
                            // have eaten the comma
                            ptr = _djson_get_next_non_whitespace(ptr);
                            if (*ptr == 0) return DJSON_ERROR_UNEXPECTED_EOF;
                            else if (*ptr == ',') ptr = ptr + 1;

                            json_ptr->ptr = ptr;
                            break;
                    }
                }
                else if (parent->type == DJSON_TYPE_Array)
                {
                    // should be "value",

                    // get the value
                    diamond_json_error_t result = _djson_read_string(&ptr, &(node->string_value));
                    if (result != DJSON_OK) return result;

                    // get the ','
                    ptr = _djson_get_next_non_whitespace(ptr);
                    if (*ptr == 0) return DJSON_ERROR_UNEXPECTED_EOF;
                    else if (*ptr != ',' && *ptr != ']') return DJSON_ERROR_INVALID_SYNTAX;

                    node->type = lookahead;
                    
                    if(*ptr == ',') json_ptr->ptr = ptr + 1;
                    else json_ptr->ptr = ptr;
                }
                else
                {
                    return DJSON_ERROR_UNEXPECTED_STRING;
                }
                break;
            case DJSON_TYPE_Primitive:
                if (parent->type == DJSON_TYPE_Array)
                {
                    // should be value,
                    // get the value
                    result = _djson_read_primitive(&ptr, primitive_buffer, sizeof(primitive_buffer)/sizeof(char));
                    if (result != DJSON_OK) return result;

                    result = _djson_set_node_primitive(node, primitive_buffer);
                    if (result != DJSON_OK) return result;

                    // get the ','
                    ptr = _djson_get_next_non_whitespace(ptr);
                    if (*ptr == 0) return DJSON_ERROR_UNEXPECTED_EOF;
                    else if (*ptr != ',' && *ptr != ']') return DJSON_ERROR_INVALID_SYNTAX;

                    node->type = lookahead;
                    
                    if(*ptr == ',') json_ptr->ptr = ptr + 1;
                    else json_ptr->ptr = ptr;
                }
                else
                {
                    return DJSON_ERROR_UNEXPECTED_STRING;
                }
                break;         
        }
    }

    return DJSON_OK;
}

diamond_json_error_t djson_parse_until(diamond_json_ptr_t *json_ptr, char *name, diamond_json_type_t type)
{
    char *_name;
    diamond_json_type_t _type;
    diamond_json_error_t result;

    do
    {
        result = djson_goto_next_element(json_ptr);
        if (result != DJSON_OK) return result;

        djson_get_name_current(json_ptr, &_name);
        djson_get_type_current(json_ptr, &_type);
    } while ((_name == NULL) || (strcmp(_name, name) != 0) || (_type != type));

    return DJSON_OK;
}

diamond_json_error_t djson_pass(diamond_json_ptr_t *json_ptr)
// goto the next element skipping any children of the current element
{
    diamond_json_type_t _type;
    djson_get_type_current(json_ptr, &_type);

    if (_type != DJSON_TYPE_Array &&
        _type != DJSON_TYPE_Object)
    {
        // these types don't have children
        return djson_goto_next_element(json_ptr);
    }

    int objects = 0, arrays = 0;
    
    do
    {
        if (_type == DJSON_TYPE_Array) arrays++;
        else if (_type == DJSON_TYPE_ArrayEnd) arrays--;
        else if (_type == DJSON_TYPE_Object) objects++;
        else if (_type == DJSON_TYPE_ObjectEnd) objects--;

        diamond_json_error_t result = djson_goto_next_element(json_ptr);
        if (result != DJSON_OK)
        {
            return result;
        }

        djson_get_type_current(json_ptr, &_type);
    } while (arrays > 0 || objects > 0);

    return DJSON_OK;
}

diamond_json_error_t djson_skip_save_object(diamond_json_ptr_t *json_ptr, char **object_json)
// skips the current json object and all children and returns an unaltered string of the json skipped
{
    if (json_ptr == NULL || json_ptr->current_element == NULL) return DJSON_ERROR_BAD_ARGUMENTS;
    else if (json_ptr->current_element->type != DJSON_TYPE_Object) return DJSON_ERROR_NOT_AN_OBJECT;

    // find the start. we move off the start so we need to go back and find it
    char *ptr = json_ptr->ptr;

    // do some pointer magic
    while ((ptr > json_ptr->json_data) && *ptr != '{') --ptr;
    if (*ptr != '{') return DJSON_ERROR_INVALID_SYNTAX;

    char *start = ptr;

    // count the first one
    int num_objects = 1;
    int len = 1;

    do
    {
        ++ptr;
        if (*ptr == '{') ++num_objects;
        else if (*ptr == '}') --num_objects;
        ++len;
    } while (*ptr != 0 && num_objects > 0);

    if (*ptr == 0) return DJSON_ERROR_UNEXPECTED_EOF;

    // create buffer and copy
    *object_json = malloc(len + 1);
    strncpy(*object_json, start, len);
    (*object_json)[len] = 0; // null terminate

    // update the main pointer
    json_ptr->ptr = ptr;

    return djson_goto_next_element(json_ptr);
}

diamond_json_error_t djson_join_string_array(diamond_json_ptr_t *json_ptr, char **results)
// destructively joins all of the strings in an array to get one contatenated string
{
    *results = NULL;
    diamond_json_error_t result = DJSON_OK;
    char *result_string = NULL;
    diamond_json_type_t type;
    char *s;

    // get the first part
    result = djson_goto_next_element(json_ptr);
    if (result != DJSON_OK) return result;

    result = djson_get_type_current(json_ptr, &type);
    if (result != DJSON_OK) return result;

    while (type != DJSON_TYPE_ArrayEnd)
    {
        if (type != DJSON_TYPE_String) return DJSON_ERROR_BAD_ARGUMENTS;

        // just get the first one
        if (result_string == NULL)
        {
            result = djson_get_string_value_current(json_ptr, &result_string);
            if (result != DJSON_OK) return result;

            s = result_string + strlen(result_string);
        }
        else
        {
            // get the next string
            char *new_string;
            result = djson_get_string_value_current(json_ptr, &new_string);
            if (result != DJSON_OK) return result;

            // attach the strings, they may overlap so don't use strcpy
            while (*new_string != 0) *s++ = *new_string++;
            *s = 0; // terminate string
        }

        // get the next part
        result = djson_goto_next_element(json_ptr);
        if (result != DJSON_OK) return result;

        result = djson_get_type_current(json_ptr, &type);
        if (result != DJSON_OK) return result;
    }

    *results = result_string;

    return result;
}

// searches a json string pointed to by json_data and returns the value
// json_data will be updated to point after this element for additional
// searches. Element must be <string> : <string or primitive>
char *djson_find_element(const char *name, char *buffer, int maxlen, char **json_data)
{
    char *ptr = *json_data;

    char *element = strstr(ptr, name);

    if (element == NULL) return NULL;
 

    // we found the element. Now get the value
    ptr = element + strlen(name);

    ptr = _djson_get_next_non_whitespace(ptr+1); // skip the quotation mark
    if (*ptr != ':') return NULL; // format error

    // goto the value
    ptr = _djson_get_next_non_whitespace(ptr+1);

    diamond_json_type_t lookahead = _djson_type_lookahead(*ptr);

    // check to make sure this is a valid type
    if (lookahead != DJSON_TYPE_String && lookahead != DJSON_TYPE_Primitive) return NULL;

    // if string, skip the initial '"'
    if (lookahead == DJSON_TYPE_String) ptr++;

    int i = 0;
    while (*ptr != 0 && *ptr != ' ' && *ptr != '"' && *ptr != '\t' && *ptr != '\r' && *ptr != '\n' && *ptr != ',' && i < maxlen-1)
    {
        buffer[i++] = *ptr;
        ++ptr;
    }
    buffer[i] = 0;

    // update the ptr
    *json_data = ptr;

    return buffer;
}

// Internal functions -----------------------------------------------------

diamond_json_type_t _djson_type_lookahead(char next_char)
{
    switch (next_char)
    {
        case '{':
            return DJSON_TYPE_Object;
        case '}':
            return DJSON_TYPE_ObjectEnd;
        case '[':
            return DJSON_TYPE_Array;
        case ']':
            return DJSON_TYPE_ArrayEnd;
        case '"':
            return DJSON_TYPE_String;
    }

    if (_djson_isAlpha(next_char) || _djson_isNumeric(next_char))
    {
        // probably
        return DJSON_TYPE_Primitive;
    }
    else
    {
        return DJSON_TYPE_Undefined;
    }
    
}

diamond_json_error_t _djson_get_node_from_pool(diamond_json_ptr_t *json_ptr, diamond_json_node_t **node)
{
    if ((node == NULL) || (json_ptr == NULL)) return DJSON_ERROR_BAD_ARGUMENTS;

    if (json_ptr->nodes_used < json_ptr->node_pool_size)
    {
        *node = &(json_ptr->node_pool[json_ptr->nodes_used++]);

        (*node)->name = NULL;
        (*node)->parent = NULL;
        (*node)->string_value = NULL;
        (*node)->primitive_value = DJSON_PRIMITIVE_NotAPrimitive;

        return DJSON_OK;
    }
    else
    {
        return DJSON_ERROR_NODEPOOL_EMPTY;
    }
}

// reads the string pointed by pointer until '"' to get a string.
// will return NULL if the string is empty. The final '"' will be
// changed to '\0'. ptr will be updated to point to the next
// character after the end of the string
diamond_json_error_t _djson_read_string(char **ptr, char **result)
{
    char *string = *ptr; // get the beginning of our string
    char *s = string;
    int size = 0;

    // all strings should start with "
    if (*s != '"') return DJSON_ERROR_INVALID_STRING;

    // go to the next character
    ++s;

    // skip the first "
    string = s;

    // search for the end of the string
    while (*s != '"' && *s != '\n' && *s != 0) { ++size; ++s; }

    // check for errors
    if (*s == '\n') return DJSON_ERROR_NEWLINE_IN_STRING;
    else if (*s == 0) return DJSON_ERROR_UNENDING_STRING;

    // mark the end of our string
    *s = 0;

    // set ptr to just after our string
    *ptr = s + 1;

    // result is null on the empty string
    if (size == 0) *result = NULL;

    // set the result
    *result = string;

    return DJSON_OK;
}

// reads the out a primitive until a whitespace character or a comma.
// ptr will be updated to point to the next character after the end
// primitive
diamond_json_error_t _djson_read_primitive(char **ptr, char *result, int result_len)
{
    char *string = *ptr; // get the beginning of our string
    char *s = string;
    int len = 0;

    // search for the end of the string
    while (*s != 0 && *s != ' ' && *s != '\t' && *s != '\r' && *s != '\n' &&
           *s != ',' && *s != ']' && *s != '[' && *s != '{' && *s != '}') { ++len; ++s; }

    if (*s == 0) return DJSON_ERROR_UNEXPECTED_EOF;

    if (len > result_len) len = result_len;

    // don't mark the end of our string because we could destroy important structural data

    // set ptr to just after our string
    *ptr = s;

    // set the result
    strncpy(result, string, len);

    // null terminate result
    result[len] = 0;

    // make sure this is a valid primitive
    if ((strcmp(result, "true") != 0) &&
        (strcmp(result, "false") != 0) &&
        (strcmp(result, "null") != 0) &&
        (_djson_isNumber(result) == 0))
    {
        return DJSON_ERROR_INVALID_SYNTAX;
    }

    return DJSON_OK;
}

diamond_json_error_t _djson_set_node_primitive(diamond_json_node_t *node, char *primitive_value)
{
    if (node == NULL || primitive_value == NULL) return DJSON_ERROR_BAD_ARGUMENTS;

    if (strcmp(primitive_value, "true") == 0)
    {
        node->primitive_value = DJSON_PRIMITIVE_true;
    }
    else if (strcmp(primitive_value, "false") == 0)
    {
        node->primitive_value = DJSON_PRIMITIVE_false;        
    }
    else if (strcmp(primitive_value, "null") == 0)
    {
        node->primitive_value = DJSON_PRIMITIVE_null;        
    }
    else if (_djson_isNumber(primitive_value))
    {
        if (strstr(primitive_value, ".") != NULL)
        {
            node->primitive_value = DJSON_PRIMITIVE_real;
            sscanf(primitive_value, "%f", &(node->primitive_number.real_value));
        }
        else
        {
            node->primitive_value = DJSON_PRIMITIVE_integer;
            sscanf(primitive_value, "%i", &(node->primitive_number.int_value));
        }
    }
    else return DJSON_ERROR_INVALID_SYNTAX;

    node->type = DJSON_TYPE_Primitive;
    return DJSON_OK;
}

// goes through a string and returns a pointer to the first non-whitespace character
char *_djson_get_next_non_whitespace(char *string)
{
    char *s = string;
    while (*s != 0 && (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')) ++s;

    return s;
}

int _djson_isNumeric(char c)
{
    return ((c >= '0' && c <= '9') || c == '-' || c == '+');
}

int _djson_isAlpha(char c)
{
    return ((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z'));
}

int _djson_isNumber(char *s)
{
    int decimal_found = 0;

    // this will check for leading '+' or '-'
    if (!_djson_isNumeric(*s)) return 0;
    ++s;

    while (*s != 0)
    {
        if (*s == '.')
        {
            // there can only be one decimal point
            if (decimal_found == 0) decimal_found = 1;
            else return 0;
        }
        else if (*s < '0' || *s > '9') return 0;

        ++s;
    }

    return 1;
}