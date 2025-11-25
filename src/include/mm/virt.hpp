#ifndef _MM__VIRT_HPP
#define _MM__VIRT_HPP

#ifdef __x86_64__
#include <arch/x86_64/sync.hpp>
#endif
#include <stddef.h>
#include <stdint.h>

namespace NMem {
    namespace Virt {

        enum flags {
            VIRT_RW         = (1 << 0), // Region is writeable.
            VIRT_USER       = (1 << 1), // Region is unprivileged.
            VIRT_NX         = (1 << 2), // Region is non-executable.
            VIRT_SWAPPED    = (1 << 3), // Region is swapped out to disk.
            VIRT_DIRTY      = (1 << 4), // Region has been modified (and is thus, dirty). Automatic.
            VIRT_SHARED     = (1 << 5)  // Region is shared between processses (no CoW!).
        };

        // Address ordered AVL tree for managing the allocations of an address space.
        // Big block splits into needed, and free parts of the block.
        // This type of tree is good because it's O(log n) for any operation.

        // Each "node" indicates
        struct vmanode {
            uintptr_t start; // Start of range.
            uintptr_t end; // End of range.
            uintptr_t maxend; // Maximum end address.
            uint8_t flags; // Collection of flags for this region.
            bool used; // Allocated?
            int8_t height;
            // Tree structure, branches between left and right.
            struct vmanode *left;
            struct vmanode *right;
        };

        // Helper function for the height of a node, NULL nodes have a default 0 height.
        static inline int height(struct vmanode *node) {
            return node ? node->height : 0;
        }

        // Helper function to determine balance factor by the different between the heights of a subtree.
        static inline int balancefactor(struct vmanode *node) {
            return node ? height(node->left) - height(node->right) : 0;
        }

        // Distinguished from the architecture-specific VMM address space, because this is for the AVL tree.
        class VMASpace {
            private:

                struct vmanode *root = NULL; // Root node in tree.
                uintptr_t base; // Start of the address space (typically zero).
                uintptr_t top; // End of the address space (typically a generic upper limit).

            public:
                VMASpace(uintptr_t base, uintptr_t top);
                ~VMASpace(void);
            private:

                void updatenode(struct vmanode *node);

                // Ideally, the tree must always be balanced to maintain O(log n) time complexity. These functions swivel the trees to balance the subtrees.
                struct vmanode *rotateright(struct vmanode *y);
                // Ditto.
                struct vmanode *rotateleft(struct vmanode *x);

                // Balance left-heavy or right-heavy subtrees to keep O(log n) performance.
                struct vmanode *balancenode(struct vmanode *node);

                // Find a free node for the size and alignment, returns the output address.
                struct vmanode *findfree(struct vmanode *node, size_t size, size_t align, uintptr_t *out);

                // Insert a new node into the root tree.
                struct vmanode *insert(struct vmanode *root, struct vmanode *node);

                // Remove a node from a root tree, by allocation start address.
                struct vmanode *remove(struct vmanode *root, uintptr_t start);

                // Initialise new node.
                struct vmanode *newnode(uintptr_t start, uintptr_t end, bool used);

                // Recursively destroy nodes in tree.
                void destroytree(struct vmanode *node);

                // Find the node that contains a specific desired region.
                struct vmanode *containing(struct vmanode *root, uintptr_t start, uintptr_t end);

                // Validate nodes.
                void validate(struct vmanode *root, uintptr_t *last);

                // Find adjacent nodes.
                void findadj(struct vmanode *root, struct vmanode *target, struct vmanode **prev, struct vmanode **next);

            public:
                struct vmanode *getroot(void) {
                    return this->root;
                }

                // Traverse nodes in order, calling callback.
                void traverse(struct vmanode *root, void (*callback)(struct vmanode *node));

                void traversedata(struct vmanode *root, void (*callback)(struct vmanode *node, void *data), void *data);

                // Allocate an aligned region within address space.
                void *alloc(size_t size, uint8_t flags);

                void setflags(uintptr_t start, uintptr_t end, uint8_t flags);

                // Forcibly occupy this area of memory. Useful for areas of memory that we should avoid (kernel sections, regions of actual RAM). We only want to be allocating where we could not be having anything useful.
                void *reserve(uintptr_t start, uintptr_t end, uint8_t flags);

                // Free an aligned region with address space.
                void free(void *ptr, size_t size);

                void dump(void);
                void validate(void);
        };
    }
}

#endif
