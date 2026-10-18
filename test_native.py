"""Verify C ownership and the Python/native boundary, including lifetimes."""
import gc
from pathlib import Path
import tempfile
import unittest
from structures import FIFOQueue, MessageStore, NativeMessage, LIBRARY_PATH, _call


class NativeDSATest(unittest.TestCase):
    def test_c_backing_shared_updates_and_proxy_lifetime(self):
        self.assertTrue(LIBRARY_PATH.exists())
        with tempfile.TemporaryDirectory() as directory:
            store = MessageStore(Path(directory) / 'history.json')
            record = store.add({'id': 17, 'text': 'नमस्ते', 'status': 'Queued'})
            queue = FIFOQueue()
            queue.enqueue(record)
            self.assertIsInstance(queue.peek(), NativeMessage)
            self.assertEqual(queue.peek().native_address, store.history.tail.value.native_address)
            self.assertEqual(store.index.buckets[1][0].native_address, store.history.tail.native_address)
            store.update(17, status='Delivered')
            self.assertEqual(queue.peek()['status'], 'Delivered')
            popped = queue.dequeue()
            self.assertEqual(popped['text'], 'नमस्ते')
            self.assertEqual(store.index.lookup(17)[0]['status'], 'Delivered')
            del store, queue
            gc.collect()
            self.assertEqual(popped['text'], 'नमस्ते')

    def test_uint64_ids_and_immutable_index_keys(self):
        queue = FIFOQueue()
        queue.enqueue({'id': 2**64 - 1, 'text': 'Largest valid ID'})
        self.assertEqual(queue.peek()['id'], 2**64 - 1)
        with self.assertRaises(ValueError):
            queue.peek()['id'] = 1
        for invalid in (0, -1, True, 2**64):
            with self.assertRaises(ValueError):
                queue.enqueue({'id': invalid})

    def test_stale_queue_node_is_rejected_instead_of_dereferenced(self):
        queue = FIFOQueue()
        queue.enqueue({'id': 1})
        node = queue.front
        queue.dequeue()
        with self.assertRaises(RuntimeError):
            _ = node.value

    def test_native_allocations_return_to_baseline(self):
        gc.collect()
        baseline = _call('cc_live_allocations')

        def exercise():
            with tempfile.TemporaryDirectory() as directory:
                store = MessageStore(Path(directory) / 'history.json')
                queue = FIFOQueue()
                for number in range(1, 41):
                    queue.enqueue(store.add({'id': number, 'text': str(number)}))
                while queue.peek():
                    queue.dequeue()
                self.assertEqual(store.index.lookup(33)[1], [1, 9, 17, 25, 33])
        exercise()
        gc.collect()
        self.assertEqual(_call('cc_live_allocations'), baseline)


if __name__ == '__main__':
    unittest.main()
