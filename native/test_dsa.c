/* Standalone C checks: no Python interpreter or GUI is involved. */
#include "cc_dsa.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    CCList *queue = cc_list_new();
    CCList *history = cc_list_new();
    CCIndex *index = cc_index_new(8);
    uint64_t ids[] = {1, 9, 17};
    uint64_t probes[3];
    size_t count, i;
    CCMessage *message, *front;
    CCNode *node;
    assert(queue && history && index);
    assert(cc_list_pop_front(queue) == NULL);
    for (i = 0; i < 3; ++i) {
        message = cc_message_new(ids[i], "{\"status\":\"Queued\"}");
        assert(message);
        node = cc_list_append(history, message);
        assert(node && cc_index_insert(index, node));
        assert(cc_list_append(queue, message));
        cc_message_release(message);
    }
    assert(cc_list_size(queue) == 3);
    assert(cc_list_size(history) == 3);
    node = cc_index_find(index, 17, probes, 3, &count);
    assert(node == cc_list_tail(history));
    assert(count == 3 && probes[0] == 1 && probes[1] == 9 && probes[2] == 17);
    assert(cc_index_find(index, 25, probes, 3, &count) == NULL && count == 3);
    assert(cc_index_bucket(index, 17) == 1);
    assert(cc_entry_node(cc_index_bucket_head(index, 1)) == cc_list_head(history));
    assert(cc_node_next(cc_list_head(history)) != NULL);

    /* Both lists own references to the same record, so updates are shared. */
    message = cc_node_message(cc_list_head(history));
    assert(message == cc_node_message(cc_list_head(queue)));
    assert(cc_message_update(message, "{\"status\":\"Delivered\"}"));
    assert(strstr(cc_message_json(cc_node_message(cc_list_head(queue))), "Delivered"));
    for (i = 0; i < 3; ++i) {
        front = cc_list_pop_front(queue);
        assert(front && cc_message_id(front) == ids[i]);
        cc_message_release(front);
    }
    assert(cc_list_size(queue) == 0);
    assert(!cc_list_head(queue) && !cc_list_tail(queue));
    /* Dequeue did not delete history or its hash references. */
    assert(cc_index_find(index, 17, NULL, 0, &count) == cc_list_tail(history));
    cc_index_free(index);
    cc_list_free(history);
    cc_list_free(queue);
    assert(cc_live_allocations() == 0);
    puts("C checks passed: FIFO, linked history, collisions, shared records, memory cleanup.");
    return 0;
}
