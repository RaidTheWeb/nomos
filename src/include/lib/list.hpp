#ifndef _LIB__LIST_HPP
#define _LIB__LIST_HPP

#include <mm/slab.hpp>

namespace NLib {
    template <typename T>
    class SingleList {
        private:
            struct node {
                T data;
                struct node *next;
            };

            struct node *head;
        public:
            SingleList(void);

            struct node *push(T data) {
                struct node *node = NMem::allocator.alloc(sizeof(struct node));
                node->data = data;

                node->next = this->head;
                this->head = node;
                return node;
            }

            T pop(void) {
                T data = this->head->data;
                this->head = this->head->next;
            }

            void foreach(void (*callback)(T data));
    };
}

#endif
