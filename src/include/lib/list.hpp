#ifndef _LIB__LIST_HPP
#define _LIB__LIST_HPP

#include <lib/assert.hpp>
#include <mm/slab.hpp>

namespace NLib {

    template<typename T>
    class CircularBuffer {
        private:
            T *buffer = NULL;
            size_t capacity = 0;
            size_t head = 0;
            size_t tail = 0;
            size_t count = 0;
        public:
            CircularBuffer(size_t size) {
                this->capacity = size;
                this->buffer = new T[size];
            }

            ~CircularBuffer(void) {
                delete[] this->buffer;
            }

            T *data(void) {
                return &this->buffer[this->head]; // Return data from offset.
            }

            void push(T item) {
                if (this->count < this->capacity) {
                    this->buffer[this->tail] = item;
                    this->tail = (this->tail + 1) % this->capacity;
                    this->count++;
                }
            }

            T popback(void) {
                if (this->count > 0) {
                    T item = this->buffer[this->tail];
                    this->tail = (this->tail - 1) % this->capacity;
                    this->count--;
                    return item;
                }
                return T();
            }

            T pop(void) {
                if (this->count > 0) {
                    T item = this->buffer[this->head];
                    this->head = (this->head + 1) % this->capacity;
                    this->count--;
                    return item;
                }
                return T();
            }

            T peek(size_t idx) {
                if (idx < this->count) {
                    size_t actualidx = (this->head + idx) % this->capacity;
                    return this->buffer[actualidx];
                }
                return T();
            }

            size_t size(void) {
                return this->count;
            }

            size_t available(void) {
                return this->capacity - this->count;
            }

            bool empty(void) {
                return !this->count;
            }

            bool full(void) {
                return this->count == this->capacity;
            }

            void clear(void) {
                this->head = 0;
                this->tail = 0;
                this->count = 0;
            }
    };

    template<typename T>
    class Vector {
        private:
            T *data = NULL;
            size_t size = 0;
            size_t capacity = 0;

            bool realloc(size_t newcap) {
                this->data = (T *)NMem::allocator.realloc(this->data, newcap * sizeof(T));
                if (!this->data) {
                    return false;
                }
                if (newcap > this->capacity) {
                    NLib::memset((void *)((uintptr_t)this->data + this->capacity * sizeof(T)), 0, (newcap - this->capacity) * sizeof(T)); // Zero new allocation, so NULL is correct.
                }
                this->capacity = newcap;
                return true;
            }

        public:
            Vector(void) = default;

            ~Vector(void) {
                this->clear();
                delete[] this->data;
            }

            T &operator[](size_t idx) {
                return this->data[idx];
            }

            T &front(void) {
                return this->data[0];
            }

            T &back(void) {
                return this->data[this->size - 1];
            }

            T *getdata(void) {
                return this->data;
            }

            bool empty(void) {
                return !this->size;
            }

            size_t getsize(void) {
                return this->size;
            }

            size_t getcapacity(void) {
                return this->capacity;
            }

            bool reserve(size_t newcap) {
                if (newcap > this->capacity) {
                    return this->realloc(newcap);
                }
                return true;
            }

            bool resize(size_t newsize) {
                if (newsize > this->size) {
                    if (!reserve(newsize)) {
                        return false;
                    }
                }

                this->size = newsize;
                return true;
            }

            void shrink(void) {
                if (this->size < this->capacity) {
                    this->realloc(this->size);
                }
            }

            void clear(void) {
                this->size = 0;
            }

            void push(T &val) {
                if (this->size >= this->capacity) {
                    this->reserve(this->capacity ? this->capacity * 2 : 1);
                }
                this->data[this->size++] = val;
            }
    };

    template<typename K, typename T>
    class KVHashMap {
        private:
            struct entry {
                K key;
                T value;
                struct entry *next = NULL;
            };

            struct entry **buckets = NULL;
            size_t bucketcount = 0;
            size_t itemcount = 0;
            size_t load = 0;

            // FNV-1a hash function.
            size_t hash(uint8_t *key, size_t count) const {
                const size_t prime = 16777619;
                size_t hash = 2166136261u;

                for (size_t i = 0; i < sizeof(K); i++) {
                    hash ^= (size_t)key[i];
                    hash *= prime;
                }
                return hash % count;
            }

            void rehash(size_t newsize) {
                struct entry **newbuckets = new struct entry *[newsize];
                NLib::memset(newbuckets, 0, sizeof(struct entry *) * newsize);

                for (size_t i = 0; i < this->bucketcount; i++) {
                    struct entry *entry = this->buckets[i];
                    while (entry) {
                        struct entry *next = entry->next;
                        size_t newidx = this->hash((uint8_t *)&entry->key, newsize);
                        entry->next = newbuckets[newidx];
                        newbuckets[newidx] = entry;
                        entry = next;
                    }
                }

                delete[] this->buckets; // Remove old buckets.

                // Update with new bucket list.
                this->buckets = newbuckets;
                this->bucketcount = newsize;
                this->load = (newsize * 3) / 4; // Update load factor.
            }
        public:
            KVHashMap(size_t size = 16) {
                this->bucketcount = size;
                this->itemcount = 0;
                this->buckets = new struct entry *[this->bucketcount];
                NLib::memset(this->buckets, 0, sizeof(struct entry *) * this->bucketcount);
                this->load = (this->bucketcount * 3) / 4;
            }

            ~KVHashMap(void) {
                this->clear(); // Free all entries.
                delete[] this->buckets;
            }

            void insert(K key, T val) {
                if (this->itemcount >= this->load) { // If we have too many items, we'll want to rehash for more buckets.
                    this->rehash(this->bucketcount * 2); // Simply double the size.
                }

                size_t idx = this->hash((uint8_t *)&key, this->bucketcount);
                struct entry *entry = this->buckets[idx];

                // Loop through bucket to find an existing key.
                while (entry) {
                    if (entry->key == key) { // If the key already exists, we should just update the value.
                        entry->value = val;
                        return;
                    }
                    entry = entry->next;
                }

                struct entry *current = this->buckets[idx]; // Get current bucket at this index.
                this->buckets[idx] = new struct entry;
                this->buckets[idx]->key = key;
                this->buckets[idx]->value = val;
                this->buckets[idx]->next = current; // Point the bucket to our previous current bucket, while also setting values.
                this->itemcount++;
            }

            bool remove(K key) {
                size_t idx = this->hash((uint8_t *)&key, this->bucketcount);
                struct entry **entry = &this->buckets[idx];

                while (*entry) {
                    if ((*entry)->key == key) {
                        struct entry *todel = *entry;
                        *entry = todel->next; // Skip this entry, we're deleting it.
                        delete todel;

                        this->itemcount--;
                        return true; // Item was found.
                    }
                    entry = &(*entry)->next; // Skip to next one.
                }
                return false; // If we couldn't find a matching pair, we return false.
            }

            T *find(K key) {
                size_t idx = this->hash((uint8_t *)&key, this->bucketcount);
                struct entry *entry = this->buckets[idx];

                while (entry) {
                    if (entry->key == key) {
                        return &entry->value; // Return a reference to the value, we found it.
                    }
                    entry = entry->next;
                }
                return NULL;
            }

            // Clear all entries within this hash map.
            void clear(void) {
                for (size_t i = 0; i < this->bucketcount; i++) {
                    struct entry *entry = this->buckets[i];
                    while (entry) {
                        struct entry *next = entry->next;
                        delete entry;
                        entry = next;
                    }
                    this->buckets[i] = NULL;
                }
                this->itemcount = 0;
            }

            size_t size(void) {
                return this->itemcount;
            }

            size_t capacity(void) {
                return this->bucketcount;
            }

            class Iterator {
                private:
                    KVHashMap *map = NULL;
                    size_t bucket = 0;
                    struct entry *current = NULL;

                    // Locate the next beginning of a bucket.
                    void getnext(void) {
                        while (!this->current && ++this->bucket < map->bucketcount) {
                            this->current = this->map->buckets[this->bucket];
                        }
                    }
                public:
                    Iterator(KVHashMap *map, size_t bucket, struct entry *entry) {
                        this->map = map;
                        this->bucket = bucket;
                        this->current = entry;
                        if (this->bucket < this->map->bucketcount && !this->current) {
                            this->getnext();
                        }
                    }

                    bool valid(void) {
                        return this->current;
                    }

                    K &key(void) {
                        return this->current->key;
                    }

                    T *value(void) {
                        return &this->current->value;
                    }

                    void next(void) {
                        if (this->current) {
                            this->current = this->current->next;
                            if (!this->current) { // Reached the end of the bucket.
                                this->getnext();
                            }
                        }
                    }
            };

            // Get an iterator for the hashmap's entries.
            Iterator begin(void) {
                return Iterator(this, 0, this->buckets[0]);
            }
    };

    template<typename T>
    class HashMap {
        private:
            struct entry {
                const char *key = NULL;
                T value;
                struct entry *next = NULL;
            };

            struct entry **buckets = NULL;
            size_t bucketcount = 0;
            size_t itemcount = 0;
            size_t load = 0;

            // FNV-1a hash function.
            size_t hash(const char *key, size_t count) const {
                const size_t prime = 16777619;
                size_t hash = 2166136261u;

                size_t len = strlen(key);
                for (size_t i = 0; i < len; i++) {
                    hash ^= (size_t)key[i];
                    hash *= prime;
                }
                return hash % count;
            }

            void rehash(size_t newsize) {
                struct entry **newbuckets = new struct entry *[newsize];
                NLib::memset(newbuckets, 0, sizeof(struct entry *) * newsize);

                for (size_t i = 0; i < this->bucketcount; i++) {
                    struct entry *entry = this->buckets[i];
                    while (entry) {
                        struct entry *next = entry->next;
                        size_t newidx = this->hash(entry->key, newsize);
                        entry->next = newbuckets[newidx];
                        newbuckets[newidx] = entry;
                        entry = next;
                    }
                }

                delete[] this->buckets; // Remove old buckets.

                // Update with new bucket list.
                this->buckets = newbuckets;
                this->bucketcount = newsize;
                this->load = (newsize * 3) / 4; // Update load factor.
            }
        public:
            HashMap(size_t size = 16) {
                this->bucketcount = size;
                this->itemcount = 0;
                this->buckets = new struct entry *[this->bucketcount];
                NLib::memset(this->buckets, 0, sizeof(struct entry *) * this->bucketcount);
                this->load = (this->bucketcount * 3) / 4;
            }

            ~HashMap(void) {
                this->clear(); // Free all entries.
                delete[] this->buckets;
            }

            void insert(const char *key, T& val) {
                if (this->itemcount >= this->load) { // If we have too many items, we'll want to rehash for more buckets.
                    this->rehash(this->bucketcount * 2); // Simply double the size.
                }

                size_t idx = this->hash(key, this->bucketcount);
                struct entry *entry = this->buckets[idx];

                // Loop through bucket to find an existing key.
                while (entry) {
                    if (!NLib::strcmp(entry->key, key)) { // If the key already exists, we should just update the value.
                        entry->value = val;
                        return;
                    }
                    entry = entry->next;
                }

                struct entry *current = this->buckets[idx]; // Get current bucket at this index.
                this->buckets[idx] = new struct entry;
                this->buckets[idx]->key = key;
                this->buckets[idx]->value = val;
                this->buckets[idx]->next = current; // Point the bucket to our previous current bucket, while also setting values.
                this->itemcount++;
            }

            bool remove(const char *key) {
                size_t idx = this->hash(key, this->bucketcount);
                struct entry **entry = &this->buckets[idx];

                while (*entry) {
                    if (!NLib::strcmp((*entry)->key, key)) {
                        struct entry *todel = *entry;
                        *entry = todel->next; // Skip this entry, we're deleting it.
                        delete todel;

                        this->itemcount--;
                        return true; // Item was found.
                    }
                    entry = &(*entry)->next; // Skip to next one.
                }
                return false; // If we couldn't find a matching pair, we return false.
            }

            T *find(const char *key) {
                size_t idx = this->hash(key, this->bucketcount);
                struct entry *entry = this->buckets[idx];

                while (entry) {
                    if (!NLib::strcmp(entry->key, key)) {
                        return &entry->value; // Return a reference to the value, we found it.
                    }
                    entry = entry->next;
                }
                return NULL;
            }

            // Clear all entries within this hash map.
            void clear(void) {
                for (size_t i = 0; i < this->bucketcount; i++) {
                    struct entry *entry = this->buckets[i];
                    while (entry) {
                        struct entry *next = entry->next;
                        delete entry;
                        entry = next;
                    }
                    this->buckets[i] = NULL;
                }
                this->itemcount = 0;
            }

            size_t size(void) {
                return this->itemcount;
            }

            size_t capacity(void) {
                return this->bucketcount;
            }

            class Iterator {
                private:
                    HashMap *map = NULL;
                    size_t bucket = 0;
                    struct entry *current = NULL;

                    // Locate the next beginning of a bucket.
                    void getnext(void) {
                        while (!this->current && ++this->bucket < map->bucketcount) {
                            this->current = this->map->buckets[this->bucket];
                        }
                    }
                public:
                    Iterator(HashMap *map, size_t bucket, struct entry *entry) {
                        this->map = map;
                        this->bucket = bucket;
                        this->current = entry;
                        if (this->bucket < this->map->bucketcount && !this->current) {
                            this->getnext();
                        }
                    }

                    bool valid(void) {
                        return this->current;
                    }

                    const char *key(void) {
                        return this->current->key;
                    }

                    T *value(void) {
                        return &this->current->value;
                    }

                    void next(void) {
                        if (this->current) {
                            this->current = this->current->next;
                            if (!this->current) { // Reached the end of the bucket.
                                this->getnext();
                            }
                        }
                    }
            };

            // Get an iterator for the hashmap's entries.
            Iterator begin(void) {
                return Iterator(this, 0, this->buckets[0]);
            }
    };

    template <typename T>
    class SingleList {
        private:
            struct node {
                T data;
                struct node *next;
            };

            struct node *head = NULL;
        public:
            struct node *push(T data) {
                struct node *node = (struct node *)NMem::allocator.alloc(sizeof(struct node));
                assert(node, "Failed to allocate memory for node.\n");
                node->data = data;

                node->next = this->head;
                this->head = node;
                return node;
            }

            bool empty(void) {
                return this->head == NULL;
            }

            T pop(void) {
                assert(!this->empty(), "Pop from empty list.\n");
                T data = this->head->data;
                struct node *node = this->head;
                this->head = this->head->next;
                delete node;
                return data;
            }

            void foreach(void (*callback)(T *data)) {
                struct node *node = this->head;
                while (node) {
                    callback(&node->data);
                    node = node->next;
                }
            }

            class Iterator {
                private:
                    struct node *node = NULL;
                public:
                    Iterator(struct node *node) {
                        this->node = node;
                    }

                    T *get(void) {
                        return &node->data;
                    }

                    bool valid(void) {
                        return this->node;
                    }

                    void next(void) {
                        this->node = node->next;
                    }
            };


            Iterator begin(void) {
                return Iterator(this->head);
            }
    };

    template <typename T>
    class DoubleList {
        private:
            struct node {
                T data;
                struct node *next;
                struct node *prev;
            };

            size_t length = 0;
            struct node *head = NULL;
            struct node *tail = NULL;
        public:
            class Iterator {
                private:
                    struct node *node = NULL;
                public:
                    Iterator(struct node *node) {
                        this->node = node;
                    }

                    T *get(void) {
                        return &node->data;
                    }

                    bool valid(void) {
                        return this->node;
                    }

                    void next(void) {
                        this->node = node->next;
                    }

                    void prev(void) {
                        this->node = node->prev;
                    }
            };

            ~DoubleList(void) {
                this->destroy();
            }

            Iterator begin(void) {
                return Iterator(this->head);
            }

            Iterator end(void) {
                return Iterator(this->tail);
            }

            struct node *push(T data) {
                struct node *node = (struct node *)NMem::allocator.alloc(sizeof(struct node));
                assert(node, "Failed to allocate memory for node.\n");
                node->data = data;

                node->next = this->head;
                node->prev = NULL;
                if (this->head) {
                    this->head->prev = node;
                    this->head = node;
                } else {
                    this->head = node;
                    this->tail = node;
                }
                this->length++;
                return node;
            }

            struct node *pushback(T data) {
                struct node *node = (struct node *)NMem::allocator.alloc(sizeof(struct node));
                assert(node, "Failed to allocate memory for node.\n");
                node->data = data;
                node->next = NULL;
                if (this->tail) {
                    this->tail->next = node;
                    node->prev = this->tail;
                    this->tail = node;
                } else {
                    node->prev = NULL;
                    this->head = node;
                    this->tail = node;
                }
                this->length++;
                return node;
            }

            bool empty(void) {
                return !this->head && this->head == this->tail;
            }

            size_t size(void) {
                return this->length;
            }

            T front(void) {
                assert(!this->empty(), "Attempting to get front of empty list.\n");
                return this->head->data;
            }

            T back(void) {
                assert(!this->empty(), "Attempting to get back of empty list.\n");
                return this->tail->data;
            }

            T pop(void) {
                assert(!this->empty(), "Pop from empty list.\n");
                T data = this->head->data;
                struct node *node = this->head;
                if (this->head == this->tail) {
                    this->head = NULL;
                    this->tail = NULL;
                } else {
                    this->head = this->head->next;
                    this->head->prev = NULL;
                }
                this->length--;

                delete node;
                return data;
            }

            T popback(void) {
                assert(!this->empty(), "Pop from empty list.\n");

                struct node *node = this->tail;

                T data = this->tail->data;
                if (this->head == this->tail) {
                    this->head = NULL;
                    this->tail = NULL;
                } else {
                    this->tail = this->tail->prev;
                    this->tail->next = NULL;
                }
                this->length--;

                delete node;
                return data;
            }

            void unlink(struct node *node) {
                assert(!this->empty(), "Somehow unlinking node within empty list.\n");
                assert(node, "Unlinking NULL node.\n");

                if (node->prev) {
                    node->prev->next = node->next; // Cause previous to skip us.
                }

                if (node->next) {
                    node->next->prev = node->prev; // Cause next to skip us.
                }

                if (node == this->head) {
                    this->head = node->next; // Adjust head.
                }

                this->length--;
            }

            void destroy(void) {
                struct node *node = this->head;
                while (node) {
                    struct node *next = node->next;
                    delete node;
                    node = next;
                }
            }

            void foreach(void (*callback)(T *data)) {
                struct node *node = this->head;
                while (node) {
                    struct node *next = node->next;
                    callback(&node->data);
                    node = next;
                }
            }

            // Iterate through all nodes, with comparison to udata.
            void forcmp(void (*callback)(T *data, void *udata), void *udata) {
                struct node *node = this->head;
                while (node) {
                    struct node *next = node->next;
                    callback(&node->data, udata);
                    node = next;
                }
            }

            // Find node, with comparison to udata.
            T find(bool (*callback)(T *data, void *udata), void *udata) {
                struct node *node = this->head;
                while (node) {
                    struct node *next = node->next;
                    if (callback(&node->data, udata)) {
                        return node->data;
                    }
                    node = next;
                }
                return { 0 };
            }

            // Remove a specific node by its data, using a comparison function, allows the passing of a specific value to compare against.
            bool remove(bool (*callback)(T data, void *udata), void *udata) {
                struct node *node = this->head;
                while (node) {
                    struct node *next = node->next;
                    if (callback(node->data, udata)) {
                        this->unlink(node); // Remove specific node.
                        return true;
                    }
                    node = next;
                }
                return false;
            }
    };
}

#endif
