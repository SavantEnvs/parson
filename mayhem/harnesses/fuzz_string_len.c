/* Fuzz the length-delimited (binary-safe) string API: json_value_init_string_with_len (the only
 * caller of is_valid_utf8), json_object_set_string_with_len, json_array_append_string_with_len,
 * then serialize the result (string escaping of arbitrary bytes) and re-parse it.
 * The input is copied into an exact-size heap buffer with NO trailing NUL, matching the API's
 * contract (pointer + length), so over-reads past `len` are visible to ASan. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "parson.h"

static void roundtrip(const JSON_Value *v) {
    char *out = json_serialize_to_string(v);
    if (out != NULL) {
        JSON_Value *re = json_parse_string(out);
        if (re != NULL && json_value_get_type(re) == JSONString) {
            (void)json_value_get_string_len(re);
        }
        json_value_free(re);
        json_free_serialized_string(out);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    JSON_Value *v;
    JSON_Value *root;
    char *buf = (char *)malloc(size ? size : 1);
    if (buf == NULL) {
        return 0;
    }
    if (size) {
        memcpy(buf, data, size);
    }

    v = json_value_init_string_with_len(buf, size);
    if (v != NULL) {
        roundtrip(v);
        (void)json_value_get_string_len(v);
        json_value_free(v);
    }

    root = json_value_init_object();
    if (root != NULL) {
        JSON_Object *o = json_value_get_object(root);
        json_object_set_string_with_len(o, "k", buf, size);
        json_object_dotset_string_with_len(o, "a.b", buf, size);
        roundtrip(root);
        json_value_free(root);
    }

    root = json_value_init_array();
    if (root != NULL) {
        JSON_Array *a = json_value_get_array(root);
        json_array_append_string_with_len(a, buf, size);
        json_array_replace_string_with_len(a, 0, buf, size);
        roundtrip(root);
        json_value_free(root);
    }

    free(buf);
    return 0;
}
