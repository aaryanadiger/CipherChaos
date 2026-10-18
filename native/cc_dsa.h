#ifndef CC_DSA_H
#define CC_DSA_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#define CC_API __declspec(dllexport)
#else
#define CC_API __attribute__((visibility("default")))
#endif

/* C owns the message JSON, list nodes, queue links, and hash chains.
 * The caller serializes access and keeps a list alive while indexing its nodes. */
typedef struct CCMessage CCMessage;
typedef struct CCNode CCNode;
typedef struct CCList CCList;
typedef struct CCEntry CCEntry;
typedef struct CCIndex CCIndex;

CC_API unsigned cc_abi_version(void);
CC_API CCMessage *cc_message_new(uint64_t id, const char *json);
CC_API void cc_message_retain(CCMessage *message);
CC_API void cc_message_release(CCMessage *message);
CC_API uint64_t cc_message_id(const CCMessage *message);
CC_API const char *cc_message_json(const CCMessage *message);
CC_API int cc_message_update(CCMessage *message, const char *json);

/* One linked-list primitive supports history append and FIFO enqueue/dequeue. */
CC_API CCList *cc_list_new(void);
CC_API void cc_list_free(CCList *list);
CC_API CCNode *cc_list_append(CCList *list, CCMessage *message);
CC_API CCMessage *cc_list_pop_front(CCList *list);
CC_API CCNode *cc_list_head(const CCList *list);
CC_API CCNode *cc_list_tail(const CCList *list);
CC_API size_t cc_list_size(const CCList *list);
CC_API CCNode *cc_node_next(const CCNode *node);
CC_API CCMessage *cc_node_message(const CCNode *node);

/* Separate chaining: every entry points at the actual history node. */
CC_API CCIndex *cc_index_new(size_t capacity);
CC_API void cc_index_free(CCIndex *index);
CC_API int cc_index_insert(CCIndex *index, CCNode *node);
CC_API CCNode *cc_index_find(const CCIndex *index, uint64_t id,
                           uint64_t *probes, size_t limit, size_t *count);
CC_API size_t cc_index_bucket(const CCIndex *index, uint64_t id);
CC_API CCEntry *cc_index_bucket_head(const CCIndex *index, size_t bucket);
CC_API CCEntry *cc_entry_next(const CCEntry *entry);
CC_API CCNode *cc_entry_node(const CCEntry *entry);
CC_API size_t cc_live_allocations(void);

#endif
