
#ifdef __x86_64__
#include <arch/x86_64/vmm.hpp>
#endif

#include <fs/vfs.hpp>
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
                // Case 1: Node with zero or one child
                if (!root->left) {
                    struct vmanode *tmp = root->right;
                    delete root;
                    return tmp;
                }
                if (!root->right) {
                    struct vmanode *tmp = root->left;
                    delete root;
                    return tmp;
                }

                // Case 2: Node with two children
                // Find the in-order successor (minimum in right subtree)
                struct vmanode *successor = this->findmin(root->right);

                // Copy successor's data to root (in-place replacement)
                root->start = successor->start;
                root->end = successor->end;
                root->used = successor->used;
                root->flags = successor->flags;
                root->backingfile = successor->backingfile;
                root->fileoffset = successor->fileoffset;
                // Don't copy maxend or height - they'll be recalculated

                // Recursively remove the successor from right subtree
                root->right = this->remove(root->right, successor->start);
            }

            this->updatenode(root); // Force update on root (recalculate based on children, we removed something, so the heights and max end may have changed).
            return this->balancenode(root); // Rebalance root, based on updates.
        }

        struct vmanode *VMASpace::findmin(struct vmanode *node) {
            if (!node) {
                return NULL;
            }
            while (node->left) {
                node = node->left;
            }
            return node;
        }

        struct vmanode *VMASpace::findmax(struct vmanode *node) {
            if (!node) {
                return NULL;
            }
            while (node->right) {
                node = node->right;
            }
            return node;
        }

        struct vmanode *VMASpace::findsuccessor(struct vmanode *root, uintptr_t start) {
            struct vmanode *current = root;
            struct vmanode *target = NULL;
            struct vmanode *successor = NULL;

            // First find the target node
            while (current) {
                if (current->start == start) {
                    target = current;
                    break;
                }
                if (start < current->start) {
                    current = current->left;
                } else {
                    current = current->right;
                }
            }

            if (!target) {
                return NULL;
            }

            // If right subtree exists, successor is leftmost node in right subtree
            if (target->right) {
                return this->findmin(target->right);
            }

            // Otherwise, successor is the lowest ancestor whose left child is also ancestor of target
            current = root;
            while (current) {
                if (start < current->start) {
                    successor = current;
                    current = current->left;
                } else if (start > current->start) {
                    current = current->right;
                } else {
                    break;
                }
            }

            return successor;
        }

        struct vmanode *VMASpace::findpredecessor(struct vmanode *root, uintptr_t start) {
            struct vmanode *current = root;
            struct vmanode *target = NULL;
            struct vmanode *predecessor = NULL;

            // First find the target node
            while (current) {
                if (current->start == start) {
                    target = current;
                    break;
                }
                if (start < current->start) {
                    current = current->left;
                } else {
                    current = current->right;
                }
            }

            if (!target) {
                return NULL;
            }

            // If left subtree exists, predecessor is rightmost node in left subtree
            if (target->left) {
                return this->findmax(target->left);
            }

            // Otherwise, predecessor is the lowest ancestor whose right child is also ancestor of target
            current = root;
            while (current) {
                if (start < current->start) {
                    current = current->left;
                } else if (start > current->start) {
                    predecessor = current;
                    current = current->right;
                } else {
                    break;
                }
            }

            return predecessor;
        }

        struct vmanode *VMASpace::findexact(struct vmanode *root, uintptr_t start) {
            while (root) {
                if (start == root->start) {
                    return root;
                }
                if (start < root->start) {
                    root = root->left;
                } else {
                    root = root->right;
                }
            }
            return NULL;
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
            node->backingfile = NULL;
            node->fileoffset = 0;
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

        void VMASpace::mergeadjacent(uintptr_t start, uintptr_t end) {
            // Keep track of the current region being processed.
            uintptr_t currentstart = start;
            uintptr_t currentend = end;

            // Try to merge with predecessor (node immediately before).
            struct vmanode *pred = this->findpredecessor(this->root, currentstart);
            if (pred && !pred->used && pred->end == currentstart) {
                struct vmanode *current = this->findexact(this->root, currentstart);
                if (!current) {
                    return; // Safety check.
                }

                uintptr_t predstart = pred->start;
                uintptr_t currentend_val = current->end;
                uint8_t flags = current->flags;

                this->root = this->remove(this->root, predstart);
                this->root = this->remove(this->root, currentstart);

                // Insert merged node.
                struct vmanode *merged = this->newnode(predstart, currentend_val, false);
                merged->flags = flags;
                this->root = this->insert(this->root, merged);

                currentstart = predstart;
                currentend = currentend_val;
            }

            // Try to merge with successor (node immediately after).
            // Must re-find after potential previous merge.
            struct vmanode *succ = this->findsuccessor(this->root, currentstart);
            if (succ && !succ->used && currentend == succ->start) {
                struct vmanode *current = this->findexact(this->root, currentstart);
                if (!current) {
                    return; // Safety check.
                }

                uintptr_t succstart = succ->start;
                uintptr_t succend = succ->end;
                uint8_t flags = current->flags;

                this->root = this->remove(this->root, currentstart);
                this->root = this->remove(this->root, succstart);

                // Insert merged node.
                struct vmanode *merged = this->newnode(currentstart, succend, false);
                merged->flags = flags;
                this->root = this->insert(this->root, merged);
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

        struct vmanode *VMASpace::findcontaining(uintptr_t addr) {
            struct vmanode *current = this->root;
            while (current) {
                if (addr >= current->start && addr < current->end) {
                    return current; // This node contains the address.
                }

                if (addr < current->start) {
                    current = current->left;
                } else {
                    current = current->right;
                }
            }
            return NULL;
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

            int bf = balancefactor(root);
            if (bf > 1 || bf < -1) {
                assert(false, "Unbalanced node.\n");
            }

            this->validate(root->right, last);
        }

        bool VMASpace::verifyavl(struct vmanode *node) {
            if (!node) {
                return true;
            }

            // Verify height is correct.
            int leftheight = height(node->left);
            int rightheight = height(node->right);
            int expectedheight = 1 + MAX(leftheight, rightheight);

            if (node->height != expectedheight) {
                NUtil::printf("Height mismatch at node [%p->%p]: expected %d, got %d\n", node->start, node->end, expectedheight, node->height);
                return false;
            }

            // Verify balance factor is within bounds.
            int bf = balancefactor(node);
            if (bf < -1 || bf > 1) {
                NUtil::printf("Invalid balance factor at node [%p->%p]: %d\n", node->start, node->end, bf);
                return false;
            }

            // Verify maxend is correct
            uintptr_t expectedmaxend = node->end;
            if (node->left && node->left->maxend > expectedmaxend) {
                expectedmaxend = node->left->maxend;
            }
            if (node->right && node->right->maxend > expectedmaxend) {
                expectedmaxend = node->right->maxend;
            }

            if (node->maxend != expectedmaxend) {
                NUtil::printf("Maxend mismatch at node [%p->%p]: expected %p, got %p\n", node->start, node->end, expectedmaxend, node->maxend);
                return false;
            }

            // Verify left children have lower addresses.
            if (node->left && node->left->start >= node->start) {
                NUtil::printf("BST violation: left child [%p->%p] >= parent [%p->%p]\n", node->left->start, node->left->end, node->start, node->end);
                return false;
            }

            // Verify right children have higher addresses.
            if (node->right && node->right->start <= node->start) {
                NUtil::printf("BST violation: right child [%p->%p] <= parent [%p->%p]\n", node->right->start, node->right->end, node->start, node->end);
                return false;
            }

            // Recursively verify subtrees.
            return this->verifyavl(node->left) && this->verifyavl(node->right);
        }

        void VMASpace::validate(void) {
            uintptr_t last = 0;
            this->validate(this->root, &last);
            if (!this->verifyavl(this->root)) {
                assert(false, "AVL tree verification failed.\n");
            }
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
            if (!node) {
                this->dump();
                NUtil::printf("VMA reserve failed: no containing node for region [%p->%p].\n", start, end);
                return NULL;
            }

            if (node->used) {
                return NULL;
            }

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

        void VMASpace::protect(uintptr_t start, uintptr_t end, uint8_t flags) {
            struct vmanode *node = this->containing(this->root, start, end);
            if (!node) {
                return;
            }

            struct vmanode *nodes[3];
            size_t count = 0;

            if (node->start < start) {
                nodes[count] = this->newnode(node->start, start, node->used);
                nodes[count]->flags = node->flags;
                count++;
            }

            nodes[count] = this->newnode(start, end, node->used);
            nodes[count]->flags = flags;
            // Preserve shared flag if it was set.
            if (node->flags & VIRT_SHARED) {
                nodes[count]->flags |= VIRT_SHARED;
            }
            count++;

            if (end < node->end) {
                nodes[count] = this->newnode(end, node->end, node->used);
                nodes[count]->flags = node->flags;
                count++;
            }

            this->root = this->remove(this->root, node->start);

            for (size_t i = 0; i < count; i++) {
                this->root = this->insert(this->root, nodes[i]);
            }
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

            if (!tofree) {
                return;
            }

            if (tofree->start != start || tofree->end != end) {
                struct vmanode *nodes[3];
                size_t count = 0;

                if (tofree->start < start) {
                    nodes[count] = this->newnode(tofree->start, start, tofree->used);
                    nodes[count]->flags = tofree->flags;
                    count++;
                }

                // Mark freed region as free.
                nodes[count] = this->newnode(start, end, false);
                nodes[count]->flags = tofree->flags;
                count++;

                if (end < tofree->end) {
                    nodes[count] = this->newnode(end, tofree->end, tofree->used);
                    nodes[count]->flags = tofree->flags;
                    count++;
                }

                this->root = this->remove(this->root, tofree->start);

                for (size_t i = 0; i < count; i++) {
                    this->root = this->insert(this->root, nodes[i]);
                }

                // Now find the middle node we just inserted and merge it with adjacent free nodes.
                tofree = NULL;
                current = this->root;
                while (current) {
                    if (current->start == start && current->end == end) {
                        tofree = current;
                        break;
                    }
                    if (start < current->start) {
                        current = current->left;
                    } else {
                        current = current->right;
                    }
                }

                if (!tofree) {
                    NUtil::printf("[vma/free]: WARNING: couldn't re-find freed node\n");
                    return;
                }
                this->mergeadjacent(start, end);
            } else {
                tofree->used = false; // Set to free.
                this->mergeadjacent(tofree->start, tofree->end);
            }
        }
    }
}
