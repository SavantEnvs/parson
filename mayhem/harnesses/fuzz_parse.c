/* Fuzz the JSON text parser (plain and with comments), then serialize (plain + pretty),
 * re-parse the output, deep-copy and compare. Input: arbitrary bytes, treated as a C string
 * (json_parse_string's contract is a NUL-terminated string, so bytes after an embedded NUL are
 * not seen by the parser). */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "parson.h"

static void exercise(JSON_Value *v) {
    char *out;
    size_t sz;
    JSON_Value *copy;
    if (v == NULL) {
        return;
    }
    out = json_serialize_to_string(v);
    if (out != NULL) {
        JSON_Value *re = json_parse_string(out);
        json_value_free(re);
        json_free_serialized_string(out);
    }
    out = json_serialize_to_string_pretty(v);
    if (out != NULL) {
        JSON_Value *re = json_parse_string(out);
        json_value_free(re);
        json_free_serialized_string(out);
    }
    sz = json_serialization_size(v);
    if (sz > 0) {
        char *buf = (char *)malloc(sz);
        if (buf != NULL) {
            json_serialize_to_buffer(v, buf, sz);
            free(buf);
        }
    }
    copy = json_value_deep_copy(v);
    if (copy != NULL) {
        json_value_equals(v, copy);
        json_value_free(copy);
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    JSON_Value *v;
    char *s = (char *)malloc(size + 1);
    if (s == NULL) {
        return 0;
    }
    memcpy(s, data, size);
    s[size] = '\0';

    v = json_parse_string(s);
    exercise(v);
    json_value_free(v);

    v = json_parse_string_with_comments(s);
    exercise(v);
    json_value_free(v);

    free(s);
    return 0;
}
