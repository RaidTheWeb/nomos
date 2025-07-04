#ifndef _STD__STDDEF_H
#define _STD__STDDEF_H

typedef __SIZE_TYPE__ size_t;
typedef signed long long ssize_t;
typedef signed long int off_t;

#ifdef __cplusplus
#define NULL 0
#else
#define NULL ((void *)0)
#endif

#define offsetof(TYPE, MEMBER) __builtin_offsetof (TYPE, MEMBER)

#endif
