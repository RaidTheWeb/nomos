#ifndef _SCHED__RBTREE_HPP
#define _SCHED__RBTREE_HPP

#ifdef __x86_64__
#include <arch/x86_64/sync.hpp>
#endif

#include <lib/sync.hpp>

namespace NSched {
    // Red-Black tree for fair task queue.
    class RBTree {
        private:
            enum colour {
                RED,
                BLACK
            };

        public:
            struct node {
                uintptr_t parent = 0; // Parent + Colour.
                struct node *left = NULL;
                struct node *right = NULL;
                uint8_t pad[64 - (sizeof(uintptr_t) + (sizeof(struct node *) * 2))]; // Cache alignment. We *could* have used __attribute__((aligned(64))) here, but then aligned new would have to be implemented.

                struct node *getparent(void) {
                    return (struct node *)(this->parent & ~0b11); // Colour is stored within lower bit, we use this to extract only the parent from the node property.
                }

                enum colour getcolour(void) {
                    return (enum colour)(this->parent & 0b01); // Extract colour from last bit.
                }

                // Pack parent of node, given the parent. Uses original colour.
                void packparent(struct node *parent) {
                    this->parent = (uintptr_t)parent | this->getcolour();
                }

                // Pack colour of node, given the colour. Uses original parent.
                void packcolour(enum colour colour) {
                    this->parent = (uintptr_t)this->getparent() | colour;
                }
            };

            template <typename T>
            static T *getentry(struct node *node) {
                return reinterpret_cast<T *>(
                    reinterpret_cast<uint8_t *>(node) - offsetof(T, node)
                );
            }

            NArch::IRQSpinlock lock;
        private:

            size_t nodecount = 0;
            struct node *root = NULL; // Tree root.

            void rebalance(struct node *node);
            void reerase(struct node *child, struct node *parent);

            void rotateleft(struct node *node);
            void rotateright(struct node *node);
            void transplant(struct node *u, struct node *v);
        public:
            RBTree(void) { };

            // Insert into Red-Black tree using cmp to compare left child against right child, for traversal (Unlocked).
            void _insert(struct node *node, int (*cmp)(struct node *, struct node *));

            // Remove a node (Unlocked).
            void _erase(struct node *node);

            // Get first node (Unlocked).
            struct node *_first(void);

            // Get next node (Unlocked).
            struct node *_next(struct node *node);

            // Get previous node (Unlocked).
            struct node *_prev(struct node *node);

            // Get last node (Unlocked).
            struct node *_last(void);

            struct node *_sibling(struct node *node);

            // Insert into Red-Black tree using cmp to compare left child against right child, for traversal.
            void insert(struct node *node, int (*cmp)(struct node *, struct node *)) {
                NLib::ScopeIRQSpinlock guard(&this->lock);
                this->_insert(node, cmp);
            }

            // Remove a node.
            void erase(struct node *node) {
                NLib::ScopeIRQSpinlock guard(&this->lock);
                this->_erase(node);
            }

            // Get first node.
            struct node *first(void) {
                NLib::ScopeIRQSpinlock guard(&this->lock);
                return this->_first();
            }

            // Get last node.
            struct node *last(void) {
                NLib::ScopeIRQSpinlock guard(&this->lock);
                return this->_last();
            }

            // Get next node.
            struct node *next(struct node *node) {
                NLib::ScopeIRQSpinlock guard(&this->lock);
                return this->_next(node);
            }

            struct node *prev(struct node *node) {
                NLib::ScopeIRQSpinlock guard(&this->lock);
                return this->_prev(node);
            }

            // Count the number of nodes within the Red-Black tree.
            size_t count(void);
    };
}

#endif