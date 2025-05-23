#ifndef _STD__STDATOMIC_H
#define _STD__STDATOMIC_H

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    memory_order_relaxed = __ATOMIC_RELAXED,
    memory_order_consume = __ATOMIC_CONSUME,
    memory_order_acquire = __ATOMIC_ACQUIRE,
    memory_order_release = __ATOMIC_RELEASE,
    memory_order_acq_rel = __ATOMIC_ACQ_REL,
    memory_order_seq_cst = __ATOMIC_SEQ_CST
} memory_order;


#define atomic_compare_exchange_weak_explicit(PTR, VAL, DES, SUC, FAIL) \
    __extension__ \
    ({ \
        __auto_type __atomic_compare_exchange_ptr = (PTR); \
        __typeof__ ((void)0, *__atomic_compare_exchange_ptr)__atomic_compare_exchange_tmp = (DES); \
        __atomic_compare_exchange(__atomic_compare_exchange_ptr, (VAL), &__atomic_compare_exchange_tmp, 1, (SUC), (FAIL)); \
    })

#define atomic_compare_exchange_strong_explicit(PTR, VAL, DES, SUC, FAIL) \
    __extension__ \
    ({ \
        __auto_type __atomic_compare_exchange_ptr = (PTR); \
        __typeof__ ((void)0, *__atomic_compare_exchange_ptr)__atomic_compare_exchange_tmp = (DES); \
        __atomic_compare_exchange(__atomic_compare_exchange_ptr, (VAL), &__atomic_compare_exchange_tmp, 0, (SUC), (FAIL)); \
    })

#define atomic_compare_exchange_strong(PTR, VAL, DES) \
    atomic_compare_exchange_strong_explicit(PTR, VAL, DES, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)

#endif
