#ifndef _STD__STDDEF_H
#define _STD__STDDEF_H

typedef __SIZE_TYPE__ size_t;
typedef __INT64_TYPE__ ssize_t;
typedef __INT64_TYPE__ off_t;

#ifdef __cplusplus
#define NULL 0
#else
#define NULL ((void *)0)
#endif

#define offsetof(TYPE, MEMBER) __builtin_offsetof (TYPE, MEMBER)

#endif
