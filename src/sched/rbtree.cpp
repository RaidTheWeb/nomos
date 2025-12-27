#include <sched/rbtree.hpp>
#include <std/stdatomic.h>
#include <std/stddef.h>

namespace NSched {
    void RBTree::_insert(struct node *node, int (*cmp)(struct node *, struct node *)) {
        struct node *y = NULL;
        struct node *x = this->root;

        while (x != NULL) {
            y = x;
            if (cmp(node, x) < 0) {
                x = x->left;
            } else {
                x = x->right;
            }
        }

        node->packparent(y);
        if (y == NULL) {
            this->root = node;
        } else if (cmp(node, y) < 0) {
            y->left = node;
        } else {
            y->right = node;
        }

        node->left = NULL;
        node->right = NULL;
        node->packcolour(colour::RED);

        this->rebalance(node);

        __atomic_add_fetch(&this->nodecount, 1, memory_order_seq_cst);
    }

    void RBTree::_erase(struct node *z) {
        struct node *y = z;
        struct node *x = NULL;
        struct node *x_parent = NULL;
        enum colour y_original_colour = y->getcolour();

        if (z->left == NULL) {
            x = z->right;
            this->transplant(z, z->right);
            x_parent = z->getparent();
        } else if (z->right == NULL) {
            x = z->left;
            this->transplant(z, z->left);
            x_parent = z->getparent();
        } else {
            y = this->_next(z);
            y_original_colour = y->getcolour();
            x = y->right;

            if (y->getparent() == z) {
                x_parent = y;
            } else {
                x_parent = y->getparent();
                this->transplant(y, y->right);
                y->right = z->right;
                if (y->right) y->right->packparent(y);
            }

            this->transplant(z, y);
            y->left = z->left;
            y->left->packparent(y);
            y->packcolour(z->getcolour());
        }

        if (y_original_colour == colour::BLACK) {
            this->reerase(x, x_parent);
        }

        __atomic_sub_fetch(&this->nodecount, 1, memory_order_seq_cst);
    }

    void RBTree::transplant(struct node *u, struct node *v) {
        if (u->getparent() == NULL) {
            this->root = v;
        } else if (u == u->getparent()->left) {
            u->getparent()->left = v;
        } else {
            u->getparent()->right = v;
        }
        if (v != NULL) {
            v->packparent(u->getparent());
        }
    }

    void RBTree::rotateleft(struct node *x) {
        struct node *y = x->right;
        struct node *t2 = y->left;

        x->right = t2;

        if (y->left) {
            y->left->packparent(x);
        }

        y->packparent(x->getparent());

        if (!x->getparent()) {
            this->root = y; // Has no parent, this will be the top level node.
        } else if (x == x->getparent()->left) { // We are the left path of the parent.
            x->getparent()->left = y;
        } else {
            x->getparent()->right = y;
        }

        y->left = x;
        x->packparent(y); // Y is now the new parent node.
    }

    void RBTree::rotateright(struct node *y) {
        struct node *x = y->left;
        struct node *t2 = x->right;

        y->left = t2;

        if (x->right) {
            x->right->packparent(y);
        }

        x->packparent(y->getparent());

        if (!y->getparent()) {
            this->root = x;
        } else if (y == y->getparent()->right) { // We are the right path of the parent.
            y->getparent()->right = x;
        } else {
            y->getparent()->left = x;
        }

        x->right = y;
        y->packparent(x); // X is now the parent node.
    }

    struct RBTree::node *RBTree::_first(void) {

        struct node *n = this->root;
        if (!n) {
            return NULL; // With no root, there is no node.
        }

        while (n->left) {
            n = n->left; // Traverse left branch.
        }
        return n;
    }

    struct RBTree::node *RBTree::_last(void) {
        // Same as _first(), but we traverse the right branch instead.

        struct node *n = this->root;
        if (!n) {
            return NULL; // With no root, there is no node.
        }

        while (n->right) {
            n = n->right; // Traverse right branch.
        }
        return n;
    }

    struct RBTree::node *RBTree::_next(struct node *node) {

        if (node->right) {
            struct node *n = node->right;
            while (n->left) {
                n = n->left;
            }
            return n;
        }

        struct node *parent = node->getparent();
        while (parent && node == parent->right) {
            node = parent;
            parent = parent->getparent();
        }
        return parent;
    }

    struct RBTree::node *RBTree::_prev(struct node *node) {

        if (node->left) {
            struct node *n = node->left;
            while (n->right) {
                n = n->right;
            }
            return n;
        }

        struct node *parent = node->getparent();
        while (parent && node == parent->left) {
            node = parent;
            parent = parent->getparent();
        }
        return parent;
    }

    void RBTree::rebalance(struct node *z) {
        while (z->getparent() && z->getparent()->getcolour() == colour::RED) {
            if (z->getparent() == z->getparent()->getparent()->left) {
                struct node *y = z->getparent()->getparent()->right;
                if (y && y->getcolour() == colour::RED) {
                    z->getparent()->packcolour(colour::BLACK);
                    y->packcolour(colour::BLACK);
                    z->getparent()->getparent()->packcolour(colour::RED);
                    z = z->getparent()->getparent();
                } else {
                    if (z == z->getparent()->right) {
                        z = z->getparent();
                        this->rotateleft(z);
                    }
                    z->getparent()->packcolour(colour::BLACK);
                    z->getparent()->getparent()->packcolour(colour::RED);
                    this->rotateright(z->getparent()->getparent());
                }
            } else {
                struct node *y = z->getparent()->getparent()->left;
                if (y && y->getcolour() == colour::RED) {
                    z->getparent()->packcolour(colour::BLACK);
                    y->packcolour(colour::BLACK);
                    z->getparent()->getparent()->packcolour(colour::RED);
                    z = z->getparent()->getparent();
                } else {
                    if (z == z->getparent()->left) {
                        z = z->getparent();
                        this->rotateright(z);
                    }
                    z->getparent()->packcolour(colour::BLACK);
                    z->getparent()->getparent()->packcolour(colour::RED);
                    this->rotateleft(z->getparent()->getparent());
                }
            }
        }
        this->root->packcolour(colour::BLACK);
    }

    void RBTree::reerase(struct node *x, struct node *x_parent) {
        struct node *w;
        while (x != this->root && (x == NULL || x->getcolour() == colour::BLACK)) {
            if (x == x_parent->left) {
                w = x_parent->right;
                if (w->getcolour() == colour::RED) {
                    w->packcolour(colour::BLACK);
                    x_parent->packcolour(colour::RED);
                    this->rotateleft(x_parent);
                    w = x_parent->right;
                }
                if ((w->left == NULL || w->left->getcolour() == colour::BLACK) &&
                    (w->right == NULL || w->right->getcolour() == colour::BLACK)) {
                    w->packcolour(colour::RED);
                    x = x_parent;
                    x_parent = x->getparent();
                } else {
                    if (w->right == NULL || w->right->getcolour() == colour::BLACK) {
                        if (w->left) {
                            w->left->packcolour(colour::BLACK);
                        }
                        w->packcolour(colour::RED);
                        this->rotateright(w);
                        w = x_parent->right;
                    }
                    w->packcolour(x_parent->getcolour());
                    x_parent->packcolour(colour::BLACK);
                    if (w->right) {
                        w->right->packcolour(colour::BLACK);
                    }
                    this->rotateleft(x_parent);
                    x = this->root;
                }
            } else {
                w = x_parent->left;
                if (w->getcolour() == colour::RED) {
                    w->packcolour(colour::BLACK);
                    x_parent->packcolour(colour::RED);
                    this->rotateright(x_parent);
                    w = x_parent->left;
                }
                if ((w->right == NULL || w->right->getcolour() == colour::BLACK) &&
                    (w->left == NULL || w->left->getcolour() == colour::BLACK)) {
                    w->packcolour(colour::RED);
                    x = x_parent;
                    x_parent = x->getparent();
                } else {
                    if (w->left == NULL || w->left->getcolour() == colour::BLACK) {
                        if (w->right) {
                            w->right->packcolour(colour::BLACK);
                        }
                        w->packcolour(colour::RED);
                        this->rotateleft(w);
                        w = x_parent->left;
                    }
                    w->packcolour(x_parent->getcolour());
                    x_parent->packcolour(colour::BLACK);
                    if (w->left) {
                        w->left->packcolour(colour::BLACK);
                    }
                    this->rotateright(x_parent);
                    x = this->root;
                }
            }
        }
        if (x) {
            x->packcolour(colour::BLACK);
        }
    }

    size_t RBTree::count(void) {
        // Lockless return of cached value.
        return __atomic_load_n(&this->nodecount, memory_order_seq_cst);
    }

}