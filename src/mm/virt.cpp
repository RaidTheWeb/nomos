
#ifdef __x86_64__
#include <arch/x86_64/vmm.hpp>
#endif

#include <mm/slab.hpp>
#include <mm/virt.hpp>
#include <lib/align.hpp>
#include <lib/assert.hpp>
#include <util/kprint.hpp>

#define MAX(a, b) ((a) > (b) ? (a) : (b))

namespace NMem {
    namespace Virt {

        struct vmanode *VMASpace::rotateright(struct vmanode *y) {
            struct vmanode *x = y->left;
            struct vmanode *t2 = x->right; // t2 is irrelevant to the swivel.

            //      y             x
            //     /             / \
            //    x       ->    z   y
            //   / \               /
            //  z   t2           t2

            x->right = y; // Swivel to make the left node the parent of node.
            y->left = t2; // Make the previous right node the left node of the current node.

            // Update nodes.
            this->updatenode(y); // Start with y because it's the lower one.
            this->updatenode(x); // Update x next, because it has to take the update of y into account.
            return x; // Return new parent node.
        }

        struct vmanode *VMASpace::rotateleft(struct vmanode *x) {
            struct vmanode *y = x->right;
            struct vmanode *t2 = y->left;

            //   x                y
            //    \              / \
            //     y      ->    x   z
            //    / \            \
            //  t2   z            t2

            y->left = x; // Swivel to make x into the left child of y.
            x->right = t2; // Make t2 the right child of x.

            this->updatenode(x); // Start with lower subtree x.
            this->updatenode(y); // Update y next, because it's higher up in the tree.

            return y; // Return new parent node.
        }

        struct vmanode *VMASpace::balancenode(struct vmanode *node) {
            int bf = balancefactor(node);

            if (bf > 1) { // If the difference is positive, the left side is "heavier" than the right. We have a left-left or left-right case.
                if (balancefactor(node->left) < 0) { // Check for left-right.
                    node->left = this->rotateleft(node->left);
                }
                return this->rotateright(node);
            }

            if (bf < -1) { // If the difference is negative, the right side is "heavier" than the left. We have a right-right or right-left case.
                if (balancefactor(node->right) > 0) { // Check for right-left.
                    node->right = this->rotateright(node->right);
                }
                return this->rotateleft(node);
            }

            return node; // If everything is perfect, we can just return the node as is.
        }

        void VMASpace::updatenode(struct vmanode *node) {
            if (!node) {
                return; // Don't try to update a non-allocated node.
            }

            // Maintain the height and maximum end for child nodes. Makes sure the parent node reflects the information about the children.

            // 1 + the height of whichever child node has a larger height.
            node->height = 1 + MAX(height(node->left), height(node->right));

            node->maxend = node->end; // Max end is now the current end.

            // Below, we set the parent node's maximum end to the heighest maximum end of its children.
            // We want to use this to keep a record of whatever this tree branch of capable of handling, to quickly skip over during the allocation process.
            if (node->left && node->left->maxend > node->maxend) {
                node->maxend = node->left->maxend;
            }

            if (node->right && node->right->maxend > node->maxend) {
                node->maxend = node->right->maxend;
            }
        }

        struct vmanode *VMASpace::findfree(struct vmanode *node, size_t size, size_t align, uintptr_t *out) {
            if (!node) {
                return NULL;
            }

            if (!node->used) { // If this particular node is free, we should be checking if it'll satisfy the requirements for the allocation (this will be called in both the top-level and recursed states).
                uintptr_t alignedstart = NLib::alignup(node->start, align);
                uintptr_t end = alignedstart + size;

                if (end <= node->end) { // Ideal node, fits within the region.
                    *out = alignedstart;
                    return node; // We return our node, and dump an address into the out pointer.
                }
            }

            struct vmanode *left = this->findfree(node->left, size, align, out);
            return left ? left : this->findfree(node->right, size, align, out); // Otherwise: we'll traverse down the right side.
        }

        struct vmanode *VMASpace::insert(struct vmanode *root, struct vmanode *node) {
            if (!root) {
                return node; // Can't insert the node into tree if the tree isn't real.
            }

            if (node->start < root->end && node->end > root->start) {
                assert(false, "VMA insertion would create overlap.\n");
            }

            if (node->start < root->start) { // Ordering! The lower address should be stored to the left of the root.
                root->left = this->insert(root->left, node);
            } else {
                root->right = this->insert(root->right, node); // While the higher address is stored to the right.
            }

            this->updatenode(root); // Prepare for rebalance.
            return this->balancenode(root); // Rebalance.
        }

        struct vmanode *VMASpace::remove(struct vmanode *root, uintptr_t start) {
            if (!root) {
                return NULL; // Don't even attempt it.
            }

            if (start < root->start) { // Lower address is found in left hand side (as is the insert logic).
                root->left = this->remove(root->left, start); // Recurse down the tree, until we find the node that matches this start address exactly.
            } else if (start > root->start) { // Higher addresses are found in right hand side (Ditto.)
                root->right = this->remove(root->right, start); // Ditto.
            } else { // Matches our range allocation.
                if (!root->left || !root->right) { // Possesses one or no children, no more nodes to search, remove it.
                    struct vmanode *tmp = root->left ? root->left : root->right; // Figure out whatever is left.
                    delete root;
                    return tmp; // Return NULL or remaining child.
                }

                // Otherwise: Two children exist, we'll have to manage this.
                struct vmanode *tmp = root->right;
                while (tmp->left) {
                    tmp = tmp->left; // Traverse the entirety of the left hand side to the right child of root.
                }

                // Copy data to root, then delete the right hand side.
                root->start = tmp->start;
                root->end = tmp->end;
                root->used = tmp->used;
                root->flags = tmp->flags;

                root->right = this->remove(root->right, tmp->start);
            }

            this->updatenode(root); // Force update on root (recalculate based on children, we removed something, so the heights and max end may have changed).
            return this->balancenode(root); // Rebalance root, based on updates.
        }

        struct vmanode *VMASpace::newnode(uintptr_t start, uintptr_t end, bool used) {
            // Allocate and initialise new VMA node.
            struct vmanode *node = new struct vmanode;
            node->start = start;
            node->end = end;
            node->maxend = end;
            node->used = used;
            node->height = 1;
            node->left = NULL;
            node->right = NULL;
            node->flags = 0;
            return node;
        }

        void VMASpace::destroytree(struct vmanode *node) {
            if (!node) {
                return; // Don't try anything on a NULL node (we call this regardless of whether the branch exists or not.
            }

            this->destroytree(node->left);
            this->destroytree(node->right);

            delete node;// Finally, destroy the node allocation.
        }

        void VMASpace::findadj(struct vmanode *root, struct vmanode *target, struct vmanode **prev, struct vmanode **next) {
            *prev = NULL;
            *next = NULL;

            struct vmanode *current = root;

            while (current) {
                if (current != target) {
                    if (current->end == target->start && !current->used) {
                        *prev = current; // End of this node is the beginning of our target, this means it's the node before it.
                    } else if (target->end == current->start && !current->used) {
                        *next = current; // Start of this node is the end of our target, this means it's the node after it.
                    }
                }

                if (target->start < current->start) {
                    current = current->left;
                } else {
                    current = current->right;
                }
            }
        }

        VMASpace::VMASpace(uintptr_t base, uintptr_t top) {
            this->base = base;
            this->top = top;
            this->root = this->newnode(base, top, false); // Start with the initial node, this one consumes the entire address space.
        }

        VMASpace::~VMASpace(void) {
            this->destroytree(this->root); // Destroy root of tree.
            this->root = NULL; // NULL root.
        }

        void VMASpace::setflags(uintptr_t start, uintptr_t end, uint8_t flags) {
            this->free((void *)start, end - start); // Free size of region before remapping (in case it's only marking part of an area).

            this->alloc(end - start, flags);
        }

        void *VMASpace::alloc(size_t size, uint8_t flags) {
            assert(size && NArch::PAGESIZE, "Attempting to allocate zero aligned/zero size VMA region.\n");

            uintptr_t allocaddr = 0;
            size_t alignsize = NLib::alignup(size, NArch::PAGESIZE);

            assert(this->root, "Root is NULL.\n");

            // Find a suitable node for this allocation.
            struct vmanode *node = this->findfree(this->root, alignsize, NArch::PAGESIZE, &allocaddr);

            if (!node) {
                this->dump();
            }
            assertarg(node, "OOM for VMA allocation of size %lu and %lu alignment.\n", size, NArch::PAGESIZE);

            struct vmanode *nodes[3];
            size_t count = 0;

            if (node->start < allocaddr) { // Allocation does not begin at start of the node region, therefore, allocate a node for the space before.
                nodes[count++] = this->newnode(node->start, allocaddr, false);
            }

            // Allocate for the region we allocate.
            nodes[count] = this->newnode(allocaddr, allocaddr + alignsize, true);
            nodes[count]->flags = flags;
            count++;

            if (allocaddr + alignsize < node->end) { // Allocation does not end at the end of the node region, therefore, allocate a node for the space after.
                nodes[count++] = this->newnode(allocaddr + alignsize, node->end, false);
            }

            // Remove entire origin node.
            this->root = this->remove(this->root, node->start);

            for (size_t i = 0; i < count; i++) {
                // Put prepared nodes back in, after we removed the old origin node.
                this->root = this->insert(this->root, nodes[i]);
            }

            assert(this->root, "Root is NULL.\n");

            return (void *)allocaddr; // Return pointer to brand new virtual address space!
        }


        void VMASpace::traverse(struct vmanode *root, void (*callback)(struct vmanode *node)) {
            if (!root) {
                return; // We're done here.
            }

            // Debug output in order:
            // Left child of Node.
            // Node
            // Right child of Node.
            this->traverse(root->left, callback);
            callback(root);
            this->traverse(root->right, callback);
        }

        void VMASpace::traversedata(struct vmanode *root, void (*callback)(struct vmanode *node, void *data), void *data) {
            if (!root) {
                return; // We're done here.
            }

            this->traversedata(root->left, callback, data);
            callback(root, data);
            this->traversedata(root->right, callback, data);
        }

        void VMASpace::validate(struct vmanode *root, uintptr_t *last) {
            if (!root) {
                return; // We're done here.
            }

            this->validate(root->left, last);

            if (root->start >= root->end) {
                assert(false, "Invalid node range.\n");
            }

            if (root->start < *last) {
                assert(false, "Overlapping regions.\n");
            }

            *last = root->end;

            if (balancefactor(root) > 1) {
                assert(false, "Unbalanced node.\n");
            }

            this->validate(root->right, last);
        }

        void VMASpace::validate(void) {
            uintptr_t last = 0;
            this->validate(this->root, &last);
            NUtil::printf("Valid AVL tree.\n");
        }

        static void printnode(struct vmanode *node) {
            NUtil::printf("[%p->%p] %s\n", node->start, node->end, node->used ? "Used" : "Free");
            // Print flags.
            NUtil::printf(" Flags: %s%s%s\n",
                (node->flags & NMem::Virt::VIRT_RW) ? "RW" : "RO",
                (node->flags & NMem::Virt::VIRT_USER) ?"|USER" : "",
                (node->flags & NMem::Virt::VIRT_NX) ? "|NX" : ""
            );
        }

        void VMASpace::dump(void) {
            NUtil::printf("Dumping VMA AVL tree:\n");
            NUtil::printf(" Start               End                 State\n");
            this->traverse(this->root, printnode);
        }

        struct vmanode *VMASpace::containing(struct vmanode *root, uintptr_t start, uintptr_t end) {
            while (root) {
                if (start >= root->start && end <= root->end) {
                    return root; // This node contains the region.
                }

                if (start < root->start) { // Lower address, which means we should traverse the left subtree.
                    root = root->left;
                } else {
                    root = root->right; // Otherwise, higher address, we should traverse the right subtree.
                }
            }

            return NULL;
        }

        void *VMASpace::reserve(uintptr_t start, uintptr_t end, uint8_t flags) {
            // Find the node that contains this region.
            struct vmanode *node = this->containing(this->root, start, end);
            assertarg(node, "No VMA node exists to contain %p->%p.\n", start, end);

            // Identical logic to alloc(), but we utilise the containing node instead of a found suitable node. This will still create holes for free allocation spaces, around the reserved regions.

            struct vmanode *nodes[3];
            size_t count = 0;

            if (node->start < start) {
                // If the node starts before our reserved region, we need to create a free node for that region.
                nodes[count++] = this->newnode(node->start, start, false);
            }

            // Create node for reserved region.
            nodes[count] = this->newnode(start, end, true);
            nodes[count]->flags = flags;
            count++;

            if (end < node->end) {
                // If the node ends after our reserved region, we need to create a free node for that region.
                nodes[count++] = this->newnode(end, node->end, false);
            }

            this->root = this->remove(this->root, node->start);

            for (size_t i = 0; i < count; i++) {
                this->root = this->insert(this->root, nodes[i]);
            }

            return (void *)start;
        }

        void VMASpace::free(void *ptr, size_t size) {
            if (!ptr || !size) {
                return; // Don't attempt to free zero pointer or zero size.
            }

            uintptr_t start = NLib::aligndown((uintptr_t)ptr, NArch::PAGESIZE);
            uintptr_t end = NLib::alignup(start + size, NArch::PAGESIZE);

            struct vmanode *tofree = NULL;
            struct vmanode *current = this->root;

            while (current) {
                if (start >= current->start && end <= current->end && current->used) {
                    tofree = current; // This is our node!
                    break;
                }

                if (start < current->start) {
                    current = current->left;
                } else {
                    current = current->right;
                }
            }

            assert(tofree, "Attempting to free a node that doesn't exist within VMA.\n");

            tofree->used = false; // Set to free.
            this->updatenode(tofree); // Recompute balancing prerequisites.

            struct vmanode *prev = NULL;
            struct vmanode *next = NULL;
            this->findadj(this->root, tofree, &prev, &next); // Call the helper function to find adjacent nodes within the tree.

            // These will be replaced if there are adjacent nodes, and we'll use that to know if we should modify the origin region.
            struct vmanode *merged = tofree;
            bool changed = false;
            uintptr_t mergedstart = tofree->start;
            uintptr_t mergedend = tofree->end;

            if (prev) {
                mergedstart = prev->start;
                this->root = this->remove(this->root, prev->start); // Remove this node, we're treating it as the start of the new region.
            }

            if (next) {
                mergedend = next->end;
                this->root = this->remove(this->root, next->start); // Remove this node, we're treating it as the end of the new region.
            }

            if (mergedstart != tofree->start || mergedend != tofree->end) { // Did we find any adjacent node?
                this->root = this->remove(this->root, tofree->start); // If so, OBLITERATE ourselves.
                merged = this->newnode(mergedstart, mergedend, false); // Initialise the new node that occupies our new region.
                changed = true; // Have we made a new node?
            }

            if (changed) {
                // Insert this new node.
                this->root = this->insert(this->root, merged);
            }
        }
    }
}
