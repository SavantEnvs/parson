/* Fuzz schema validation and the object/array mutation API: input is split at NUL bytes into
 * three parts — a JSON document, a JSON schema, and a dot-path / key name. The document and
 * schema are parsed, json_validate()d, then the path drives the dot-path getters/setters/removal
 * and the plain object/array mutators, and the result is serialized. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "parson.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *s, *doc, *schema_txt, *path, *p;
    JSON_Value *root, *schema;
    JSON_Object *obj;
    JSON_Array *arr;

    s = (char *)malloc(size + 3);
    if (s == NULL) {
        return 0;
    }
    memcpy(s, data, size);
    s[size] = s[size + 1] = s[size + 2] = '\0';
    doc = s;
    p = doc + strlen(doc);
    schema_txt = (p < s + size) ? p + 1 : p;
    p = schema_txt + strlen(schema_txt);
    path = (p < s + size) ? p + 1 : p;

    root = json_parse_string_with_comments(doc);
    schema = json_parse_string(schema_txt);
    if (root != NULL && schema != NULL) {
        json_validate(schema, root);
        json_validate(root, schema);
    }

    obj = json_value_get_object(root);
    if (obj != NULL) {
        JSON_Value *got = json_object_dotget_value(obj, path);
        (void)json_object_dotget_string(obj, path);
        (void)json_object_dotget_string_len(obj, path);
        (void)json_object_dotget_number(obj, path);
        (void)json_object_dothas_value(obj, path);
        (void)json_object_dothas_value_of_type(obj, path, JSONArray);
        (void)json_object_has_value(obj, path);
        (void)json_object_get_value(obj, path);
        if (got != NULL && schema != NULL) {
            json_validate(schema, got);
        }
        if (schema != NULL) {
            JSON_Value *c = json_value_deep_copy(schema);
            if (c != NULL && json_object_dotset_value(obj, path, c) != JSONSuccess) {
                json_value_free(c);
            }
        }
        json_object_dotset_string(obj, path, "x");
        json_object_dotset_number(obj, path, 1.5);
        json_object_set_boolean(obj, path, 1);
        json_object_dotset_null(obj, path);
        if (json_object_get_count(obj) > 0) {
            const char *name = json_object_get_name(obj, 0);
            if (name != NULL) {
                char *dup = strdup(name);
                if (dup != NULL) {
                    json_object_remove(obj, dup);
                    free(dup);
                }
            }
        }
        json_object_dotremove(obj, path);
        {
            char *out = json_serialize_to_string_pretty(root);
            json_free_serialized_string(out);
        }
        json_object_clear(obj);
    }

    arr = json_value_get_array(root);
    if (arr != NULL) {
        size_t n = json_array_get_count(arr);
        json_array_append_string(arr, path);
        json_array_replace_number(arr, n / 2, 2.0);
        if (n > 0) {
            json_array_remove(arr, (n - 1) / 2);
        }
        {
            char *out = json_serialize_to_string(root);
            json_free_serialized_string(out);
        }
        json_array_clear(arr);
    }

    json_value_free(schema);
    json_value_free(root);
    free(s);
    return 0;
}
