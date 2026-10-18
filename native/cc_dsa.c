#include "cc_dsa.h"
#include <stdlib.h>
#include <string.h>

struct CCMessage {
    uint64_t id;
    char *json;
    size_t references;
};

struct CCNode {
    CCMessage *message;
    struct CCNode *next;
};

struct CCList {
    CCNode *head;
    CCNode *tail;
    size_t size;
};

struct CCEntry {
    CCNode *node;
    struct CCEntry *next;
};

struct CCIndex {
    CCEntry **buckets;
    CCEntry **tails;
    size_t capacity;
};

static size_t allocations = 0;

static void *allocate(size_t size) {
    void *pointer = calloc(1, size);
    if (pointer) ++allocations;
    return pointer;
}

static void release(void *pointer) {
    if (pointer) {
        free(pointer);
        --allocations;
    }
}

static char *copy_text(const char *text) {
    size_t size;
    char *copy;
    if (!text) return NULL;
    size = strlen(text) + 1;
    copy = allocate(size);
    if (copy) memcpy(copy, text, size);
    return copy;
}

unsigned cc_abi_version(void) { return 1; }
size_t cc_live_allocations(void) { return allocations; }

CCMessage *cc_message_new(uint64_t id, const char *json) {
    CCMessage *message;
    if (!id || !json) return NULL;
    message = allocate(sizeof(*message));
    if (!message) return NULL;
    message->json = copy_text(json);
    if (!message->json) { release(message); return NULL; }
    message->id = id;
    message->references = 1;
    return message;
}

void cc_message_retain(CCMessage *message) {
    if (message) ++message->references;
}

void cc_message_release(CCMessage *message) {
    if (message && --message->references == 0) {
        release(message->json);
        release(message);
    }
}

uint64_t cc_message_id(const CCMessage *message) { return message ? message->id : 0; }
const char *cc_message_json(const CCMessage *message) { return message ? message->json : NULL; }

int cc_message_update(CCMessage *message, const char *json) {
    char *replacement;
    if (!message || !json) return 0;
    replacement = copy_text(json);
    if (!replacement) return 0;
    release(message->json);
    message->json = replacement;
    return 1;
}

CCList *cc_list_new(void) { return allocate(sizeof(CCList)); }

void cc_list_free(CCList *list) {
    CCNode *node, *next;
    if (!list) return;
    node = list->head;
    while (node) {
        next = node->next;
        cc_message_release(node->message);
        release(node);
        node = next;
    }
    release(list);
}

/* Tail pointer gives O(1) append/enqueue; no history traversal occurs here. */
CCNode *cc_list_append(CCList *list, CCMessage *message) {
    CCNode *node;
    if (!list || !message) return NULL;
    node = allocate(sizeof(*node));
    if (!node) return NULL;
    node->message = message;
    cc_message_retain(message);
    if (list->tail) list->tail->next = node;
    else list->head = node;
    list->tail = node;
    ++list->size;
    return node;
}

/* Transfer the front node's message reference to the caller before freeing it. */
CCMessage *cc_list_pop_front(CCList *list) {
    CCNode *node;
    CCMessage *message;
    if (!list || !list->head) return NULL;
    node = list->head;
    message = node->message;
    list->head = node->next;
    if (!list->head) list->tail = NULL;
    --list->size;
    release(node);
    return message;
}

CCNode *cc_list_head(const CCList *list) { return list ? list->head : NULL; }
CCNode *cc_list_tail(const CCList *list) { return list ? list->tail : NULL; }
size_t cc_list_size(const CCList *list) { return list ? list->size : 0; }
CCNode *cc_node_next(const CCNode *node) { return node ? node->next : NULL; }
CCMessage *cc_node_message(const CCNode *node) { return node ? node->message : NULL; }

CCIndex *cc_index_new(size_t capacity) {
    CCIndex *index;
    if (!capacity || capacity > 4096) return NULL;
    index = allocate(sizeof(*index));
    if (!index) return NULL;
    index->buckets = allocate(capacity * sizeof(*index->buckets));
    index->tails = allocate(capacity * sizeof(*index->tails));
    if (!index->buckets || !index->tails) { cc_index_free(index); return NULL; }
    index->capacity = capacity;
    return index;
}

void cc_index_free(CCIndex *index) {
    size_t bucket;
    CCEntry *entry, *next;
    if (!index) return;
    for (bucket = 0; bucket < index->capacity; ++bucket) {
        entry = index->buckets[bucket];
        while (entry) {
            next = entry->next;
            release(entry);
            entry = next;
        }
    }
    release(index->buckets);
    release(index->tails);
    release(index);
}

size_t cc_index_bucket(const CCIndex *index, uint64_t id) {
    return index ? (size_t)(id % index->capacity) : 0;
}

CCNode *cc_index_find(const CCIndex *index, uint64_t id,
                      uint64_t *probes, size_t limit, size_t *count) {
    CCEntry *entry;
    size_t visited = 0;
    if (count) *count = 0;
    if (!index) return NULL;
    entry = index->buckets[cc_index_bucket(index, id)];
    while (entry) {
        uint64_t candidate = entry->node->message->id;
        if (probes && visited < limit) probes[visited] = candidate;
        ++visited;
        if (count) *count = visited;
        if (candidate == id) return entry->node;
        entry = entry->next;
    }
    return NULL;
}

/* The caller checks duplicate IDs first. Bucket tails keep insertion O(1). */
int cc_index_insert(CCIndex *index, CCNode *node) {
    size_t bucket;
    CCEntry *entry;
    if (!index || !node) return 0;
    entry = allocate(sizeof(*entry));
    if (!entry) return 0;
    entry->node = node;
    bucket = cc_index_bucket(index, node->message->id);
    if (index->tails[bucket]) index->tails[bucket]->next = entry;
    else index->buckets[bucket] = entry;
    index->tails[bucket] = entry;
    return 1;
}

CCEntry *cc_index_bucket_head(const CCIndex *index, size_t bucket) {
    return index && bucket < index->capacity ? index->buckets[bucket] : NULL;
}
CCEntry *cc_entry_next(const CCEntry *entry) { return entry ? entry->next : NULL; }
CCNode *cc_entry_node(const CCEntry *entry) { return entry ? entry->node : NULL; }
