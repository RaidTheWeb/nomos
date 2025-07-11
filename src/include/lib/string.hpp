#ifndef _LIB__STRING_HPP
#define _LIB__STRING_HPP

#include <stddef.h>
#include <stdint.h>

namespace NLib {

extern "C" {
    void *memcpy(void *dest, void *src, size_t n);
    void *memset(void *dest, int c, size_t n);
    void *memmove(void *dest, void *src, size_t n);
    int memcmp(void *s1, void *s2, size_t n);
    size_t strlen(const char *str);
    size_t strnlen(const char *str, size_t n);
    char *strcpy(char *dest, char *src);
    char *strncpy(char *dest, char *src, size_t n);
    int strcmp(const char *s1, const char *s2);
    int strncmp(const char *s1, const char *s2, size_t n);
    char *strchr(char *str, int c);
    char *strstr(const char *haystack, const char *needle);
    char *strdup(const char *str);
    char *strndup(const char *str, size_t n);

    // Non-standard.
    char *strtrim(char *str);
}

}

#endif
