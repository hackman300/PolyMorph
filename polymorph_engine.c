/*
 * PolyMorph Engine - High-Performance Payload Transformation Library
 * For Red Team research: testing AV/EDR evasion effectiveness of known payloads
 *
 * Compile: gcc -shared -fPIC -O2 -o polymorph_engine.so polymorph_engine.c -lm
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>

/* ─── Entropy Analysis ─────────────────────────────────────────────────── */

double calc_entropy(const uint8_t *data, size_t len) {
    if (len == 0) return 0.0;
    uint64_t freq[256] = {0};
    for (size_t i = 0; i < len; i++) freq[data[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / (double)len;
            entropy -= p * log2(p);
        }
    }
    return entropy;
}

/* ─── Bad Character Analysis ───────────────────────────────────────────── */

int find_bad_chars(const uint8_t *data, size_t len,
                   const uint8_t *bad, size_t bad_len,
                   uint8_t *out_offsets, size_t max_out) {
    int found = 0;
    for (size_t i = 0; i < len && (size_t)found < max_out; i++) {
        for (size_t j = 0; j < bad_len; j++) {
            if (data[i] == bad[j]) {
                out_offsets[found++] = (uint8_t)(i & 0xFF);
                break;
            }
        }
    }
    return found;
}

/* ─── XOR Rolling-Key Encoder ──────────────────────────────────────────── */

void xor_encode(const uint8_t *in, size_t len, uint8_t *out,
                const uint8_t *key, size_t key_len) {
    for (size_t i = 0; i < len; i++)
        out[i] = in[i] ^ key[i % key_len];
}

/* Additive key mutation: each successive key byte shifts by delta */
void xor_rolling_encode(const uint8_t *in, size_t len, uint8_t *out,
                         uint8_t seed, uint8_t delta) {
    uint8_t k = seed;
    for (size_t i = 0; i < len; i++) {
        out[i] = in[i] ^ k;
        k = (uint8_t)(k + delta);
    }
}

/* ─── Bit-Level Transforms ─────────────────────────────────────────────── */

void bit_not(const uint8_t *in, size_t len, uint8_t *out) {
    for (size_t i = 0; i < len; i++) out[i] = ~in[i];
}

void bit_rotate_left(const uint8_t *in, size_t len, uint8_t *out, int n) {
    n = ((n % 8) + 8) % 8;
    for (size_t i = 0; i < len; i++)
        out[i] = (uint8_t)((in[i] << n) | (in[i] >> (8 - n)));
}

void bit_rotate_right(const uint8_t *in, size_t len, uint8_t *out, int n) {
    bit_rotate_left(in, len, out, 8 - n);
}

void byte_swap_pairs(const uint8_t *in, size_t len, uint8_t *out) {
    memcpy(out, in, len);
    for (size_t i = 0; i + 1 < len; i += 2) {
        uint8_t tmp = out[i]; out[i] = out[i+1]; out[i+1] = tmp;
    }
}

/* ─── Encoding / Representation ────────────────────────────────────────── */

/* Standard hex encoding → "deadbeef..." */
size_t hex_encode(const uint8_t *in, size_t len, char *out) {
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i*2]   = h[in[i] >> 4];
        out[i*2+1] = h[in[i] & 0x0F];
    }
    out[len*2] = '\0';
    return len * 2;
}

/* Custom base64 with caller-supplied 64-char alphabet */
static const char *B64_STD =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t custom_base64_encode(const uint8_t *in, size_t len,
                             char *out, const char *alphabet) {
    if (!alphabet) alphabet = B64_STD;
    size_t out_len = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t group = ((uint32_t)in[i] << 16)
                       | (i+1 < len ? (uint32_t)in[i+1] << 8 : 0)
                       | (i+2 < len ? (uint32_t)in[i+2]      : 0);
        out[out_len++] = alphabet[(group >> 18) & 0x3F];
        out[out_len++] = alphabet[(group >> 12) & 0x3F];
        out[out_len++] = (i+1 < len) ? alphabet[(group >> 6) & 0x3F] : '=';
        out[out_len++] = (i+2 < len) ? alphabet[group & 0x3F]        : '=';
    }
    out[out_len] = '\0';
    return out_len;
}

/* ─── NOP Sled Insertion ───────────────────────────────────────────────── */
/*
 * Inserts a NOP-like byte (or user-supplied byte) every `freq` bytes.
 * Returns new length. out must be pre-allocated to at least
 *   len + ceil(len / freq) bytes.
 */
size_t insert_nops(const uint8_t *in, size_t len, uint8_t *out,
                   size_t freq, uint8_t nop_byte) {
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        if (freq > 0 && i > 0 && i % freq == 0)
            out[j++] = nop_byte;
        out[j++] = in[i];
    }
    return j;
}

/* ─── Byte Substitution (single-byte Caesar-style) ─────────────────────── */

void byte_add(const uint8_t *in, size_t len, uint8_t *out, uint8_t delta) {
    for (size_t i = 0; i < len; i++)
        out[i] = (uint8_t)(in[i] + delta);
}

void byte_sub(const uint8_t *in, size_t len, uint8_t *out, uint8_t delta) {
    byte_add(in, len, out, (uint8_t)(256 - delta));
}

/* ─── Reverse ───────────────────────────────────────────────────────────── */

void reverse_bytes(const uint8_t *in, size_t len, uint8_t *out) {
    for (size_t i = 0; i < len; i++)
        out[i] = in[len - 1 - i];
}

/* ─── Frequency / Uniqueness Stats ─────────────────────────────────────── */

/* Byte diversity: 0-255 unique bytes as a ratio (0.0 – 1.0) */
double byte_diversity(const uint8_t *data, size_t len) {
    if (len == 0) return 0.0;
    uint8_t seen[256] = {0};
    for (size_t i = 0; i < len; i++) seen[data[i]] = 1;
    int count = 0;
    for (int i = 0; i < 256; i++) count += seen[i];
    return (double)count / 256.0;
}

/* Most frequent byte value */
uint8_t most_frequent_byte(const uint8_t *data, size_t len) {
    uint64_t freq[256] = {0};
    for (size_t i = 0; i < len; i++) freq[data[i]]++;
    uint8_t best = 0;
    for (int i = 1; i < 256; i++)
        if (freq[i] > freq[best]) best = (uint8_t)i;
    return best;
}

/* Null-byte count */
size_t count_nulls(const uint8_t *data, size_t len) {
    size_t n = 0;
    for (size_t i = 0; i < len; i++) if (data[i] == 0x00) n++;
    return n;
}

/* ─── Evasion Score Heuristic ───────────────────────────────────────────── */
/*
 * Very rough heuristic (0-100). Higher = harder to detect by naive sigs:
 *   - High entropy → +30
 *   - High byte diversity → +25
 *   - Few null bytes → +20
 *   - No long repeating runs → +25
 */
int evasion_score(const uint8_t *data, size_t len) {
    if (len == 0) return 0;

    double ent  = calc_entropy(data, len);
    double div  = byte_diversity(data, len);
    double null_ratio = (double)count_nulls(data, len) / (double)len;

    /* Run detection: longest run of same byte */
    size_t max_run = 1, cur_run = 1;
    for (size_t i = 1; i < len; i++) {
        if (data[i] == data[i-1]) { cur_run++; if (cur_run > max_run) max_run = cur_run; }
        else cur_run = 1;
    }
    double run_penalty = (double)max_run / (double)len;

    int score = 0;
    score += (int)(ent / 8.0 * 30.0);           /* 0-30 */
    score += (int)(div * 25.0);                  /* 0-25 */
    score += (int)((1.0 - null_ratio) * 20.0);   /* 0-20 */
    score += (int)((1.0 - run_penalty) * 25.0);  /* 0-25 */
    if (score > 100) score = 100;
    return score;
}

/* ─── C-Array Export ────────────────────────────────────────────────────── */

size_t to_c_array(const uint8_t *data, size_t len,
                  char *out, size_t out_size, const char *var_name) {
    size_t pos = 0;
    pos += snprintf(out + pos, out_size - pos,
                    "unsigned char %s[] = {\n    ", var_name);
    for (size_t i = 0; i < len && pos < out_size - 20; i++) {
        pos += snprintf(out + pos, out_size - pos, "0x%02x", data[i]);
        if (i + 1 < len) {
            pos += snprintf(out + pos, out_size - pos, ",");
            if ((i + 1) % 12 == 0)
                pos += snprintf(out + pos, out_size - pos, "\n    ");
            else
                pos += snprintf(out + pos, out_size - pos, " ");
        }
    }
    pos += snprintf(out + pos, out_size - pos,
                    "\n};\nsize_t %s_len = %zu;\n", var_name, len);
    return pos;
}
