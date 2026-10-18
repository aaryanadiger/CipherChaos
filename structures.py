"""The actual data structures used by the application, not display-only copies."""
from dataclasses import dataclass
from pathlib import Path
import json
import threading


@dataclass
class Node:
    value: dict
    next: object = None


class FIFOQueue:
    """Linked queue: enqueue/dequeue O(1). Failed deliveries stay at the front."""
    def __init__(self):
        self.front = self.rear = None
        self.size = 0

    def enqueue(self, value):
        node = Node(value)
        if self.rear:
            self.rear.next = node
        else:
            self.front = node
        self.rear = node
        self.size += 1

    def peek(self):
        return self.front.value if self.front else None

    def dequeue(self):
        if not self.front:
            raise IndexError("Queue is empty")
        value = self.front.value
        self.front = self.front.next
        if not self.front:
            self.rear = None
        self.size -= 1
        return value

    def __iter__(self):
        node = self.front
        while node:
            yield node.value
            node = node.next


class LinkedHistory:
    """Append O(1) using tail; traversal O(n)."""
    def __init__(self):
        self.head = self.tail = None
        self.size = 0

    def append(self, value):
        node = Node(value)
        if self.tail:
            self.tail.next = node
        else:
            self.head = node
        self.tail = node
        self.size += 1
        return node

    def __iter__(self):
        node = self.head
        while node:
            yield node.value
            node = node.next


class HashIndex:
    """Separate chaining; buckets hold references to actual linked history nodes.

    Eight fixed buckets intentionally make collisions visible in a small demo.
    Lookup is O(1 + load factor) on average, O(n) worst case.
    """
    def __init__(self, capacity=8):
        self.buckets = [[] for _ in range(capacity)]

    def bucket(self, msg_id):
        return msg_id % len(self.buckets)

    def insert(self, node):
        self.buckets[self.bucket(node.value['id'])].append(node)

    def lookup(self, msg_id):
        probes = []
        for node in self.buckets[self.bucket(msg_id)]:
            probes.append(node.value['id'])
            if node.value['id'] == msg_id:
                return node.value, probes
        return None, probes


class MessageStore:
    """JSON is disk persistence; linked list and hash table are rebuilt on load."""
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.RLock()
        self.history = LinkedHistory()
        self.index = HashIndex()
        if self.path.exists():
            for value in json.loads(self.path.read_text(encoding='utf-8')):
                self.index.insert(self.history.append(value))

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix('.tmp')
        temp.write_text(json.dumps(list(self.history), indent=2), encoding='utf-8')
        temp.replace(self.path)

    def add(self, value):
        with self.lock:
            if self.index.lookup(value['id'])[0] is not None:
                raise ValueError('Duplicate message ID')
            self.index.insert(self.history.append(value))
            self.save()

    def update(self, msg_id, **fields):
        with self.lock:
            value, _ = self.index.lookup(msg_id)
            if value is None:
                raise KeyError(msg_id)
            value.update(fields)
            self.save()

    def snapshot(self):
        with self.lock:
            return [dict(value) for value in self.history]
