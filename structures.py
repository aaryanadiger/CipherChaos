"""ctypes bridge to the C queue, history, and hash index.

C owns records and pointers. Python handles JSON persistence and presentation.
There is no Python implementation of the three data structures as a fallback.
"""
from collections.abc import MutableMapping
import ctypes as ct
from pathlib import Path
import json
import threading
import weakref
from build_native import build

_NATIVE_LOCK = threading.RLock()
LIBRARY_PATH = build()
_lib = ct.CDLL(str(LIBRARY_PATH))
_P = ct.c_void_p
_U64 = ct.c_uint64
_SIZE = ct.c_size_t


def _bind(name, result, *arguments):
    function = getattr(_lib, name)
    function.restype = result
    function.argtypes = list(arguments)
    return function


_bind('cc_abi_version', ct.c_uint)
_bind('cc_live_allocations', _SIZE)
_bind('cc_message_new', _P, _U64, ct.c_char_p)
_bind('cc_message_retain', None, _P)
_bind('cc_message_release', None, _P)
_bind('cc_message_id', _U64, _P)
_bind('cc_message_json', ct.c_char_p, _P)
_bind('cc_message_update', ct.c_int, _P, ct.c_char_p)
_bind('cc_list_new', _P)
_bind('cc_list_free', None, _P)
_bind('cc_list_append', _P, _P, _P)
_bind('cc_list_pop_front', _P, _P)
_bind('cc_list_head', _P, _P)
_bind('cc_list_tail', _P, _P)
_bind('cc_list_size', _SIZE, _P)
_bind('cc_node_next', _P, _P)
_bind('cc_node_message', _P, _P)
_bind('cc_index_new', _P, _SIZE)
_bind('cc_index_free', None, _P)
_bind('cc_index_insert', ct.c_int, _P, _P)
_bind('cc_index_find', _P, _P, _U64, ct.POINTER(_U64), _SIZE, ct.POINTER(_SIZE))
_bind('cc_index_bucket', _SIZE, _P, _U64)
_bind('cc_index_bucket_head', _P, _P, _SIZE)
_bind('cc_entry_next', _P, _P)
_bind('cc_entry_node', _P, _P)
if _lib.cc_abi_version() != 1:
    raise RuntimeError('Unsupported native library. Rebuild with python build_native.py --force.')


def _call(name, *arguments):
    with _NATIVE_LOCK:
        return getattr(_lib, name)(*arguments)


def _required(pointer):
    if not pointer:
        raise MemoryError('The C DSA library could not allocate memory.')
    return pointer


def _identifier(value):
    if type(value) is not int or not 0 < value < 2**64:
        raise ValueError('Message ID must be an unsigned 64-bit positive integer.')
    return value


def _encode(value):
    return json.dumps(dict(value), ensure_ascii=False, separators=(',', ':')).encode('utf-8')


# This weak cache preserves proxy identity, not message indexing or storage.
# Message lookup always runs cc_index_find in C.
_messages = weakref.WeakValueDictionary()


class NativeMessage(MutableMapping):
    """A live view of one C-owned JSON record, shared by queue and history."""
    def _read(self):
        return json.loads(_call('cc_message_json', self.native_address))

    def __getitem__(self, key):
        return self._read()[key]

    def __iter__(self):
        return iter(self._read())

    def __len__(self):
        return len(self._read())

    def update(self, *args, **kwargs):
        with _NATIVE_LOCK:
            record = self._read()
            record.update(*args, **kwargs)
            if _identifier(record.get('id')) != _call('cc_message_id', self.native_address):
                raise ValueError('A stored message ID cannot be changed.')
            if not _call('cc_message_update', self.native_address, _encode(record)):
                raise MemoryError('Could not update the C message record.')

    def __setitem__(self, key, value):
        self.update({key: value})

    def __delitem__(self, key):
        if key == 'id':
            raise ValueError('A stored message ID cannot be removed.')
        with _NATIVE_LOCK:
            record = self._read()
            del record[key]
            if not _call('cc_message_update', self.native_address, _encode(record)):
                raise MemoryError('Could not update the C message record.')


def _message(pointer, owned=False):
    _required(pointer)
    with _NATIVE_LOCK:
        existing = _messages.get(pointer)
        if existing is not None:
            if owned:
                _call('cc_message_release', pointer)
            return existing
        value = NativeMessage()
        value.native_address = pointer
        if not owned:
            _call('cc_message_retain', pointer)
        value._cleanup = weakref.finalize(value, _call, 'cc_message_release', pointer)
        _messages[pointer] = value
        return value


def _as_message(value):
    if isinstance(value, NativeMessage):
        return value
    return _message(_call('cc_message_new', _identifier(value['id']), _encode(value)), owned=True)


class Node:
    """Borrow a C node while retaining its owning list's lifetime."""
    def __init__(self, owner, pointer):
        self.owner, self.native_address = owner, pointer
        self.version = owner.version

    def _check(self):
        if self.version != self.owner.version:
            raise RuntimeError('The queue changed. Read its front or rear again.')

    @property
    def value(self):
        self._check()
        return _message(_call('cc_node_message', self.native_address))

    @property
    def next(self):
        self._check()
        pointer = _call('cc_node_next', self.native_address)
        return Node(self.owner, pointer) if pointer else None


class LinkedHistory:
    """Append and traversal delegate to C-owned linked nodes."""
    def __init__(self):
        self.native_address = _required(_call('cc_list_new'))
        self.version = 0
        self._cleanup = weakref.finalize(self, _call, 'cc_list_free', self.native_address)

    @property
    def head(self):
        pointer = _call('cc_list_head', self.native_address)
        return Node(self, pointer) if pointer else None

    @property
    def tail(self):
        pointer = _call('cc_list_tail', self.native_address)
        return Node(self, pointer) if pointer else None

    @property
    def size(self):
        return _call('cc_list_size', self.native_address)

    def append(self, value):
        value = _as_message(value)
        pointer = _required(_call('cc_list_append', self.native_address, value.native_address))
        return Node(self, pointer)

    def __iter__(self):
        pointer = _call('cc_list_head', self.native_address)
        version = self.version
        while pointer:
            if version != self.version:
                raise RuntimeError('Queue changed during traversal.')
            value = _message(_call('cc_node_message', pointer))
            pointer = _call('cc_node_next', pointer)
            yield value


class FIFOQueue(LinkedHistory):
    """C linked list with append at REAR and removal at FRONT, both O(1)."""
    front = LinkedHistory.head
    rear = LinkedHistory.tail

    def enqueue(self, value):
        self.append(value)

    def peek(self):
        node = self.front
        return node.value if node else None

    def dequeue(self):
        pointer = _call('cc_list_pop_front', self.native_address)
        if not pointer:
            raise IndexError('Queue is empty')
        self.version += 1
        return _message(pointer, owned=True)


class HashIndex:
    """C bucket array with C collision chains referencing history nodes."""
    def __init__(self, history, capacity=8):
        if not 1 <= capacity <= 4096:
            raise ValueError('Hash capacity must be between 1 and 4096.')
        self.history = history  # C index borrows nodes, so keep the list alive.
        self.capacity = capacity
        self.native_address = _required(_call('cc_index_new', capacity))
        self._cleanup = weakref.finalize(self, _call, 'cc_index_free', self.native_address)

    def bucket(self, msg_id):
        return _call('cc_index_bucket', self.native_address, _identifier(msg_id))

    def insert(self, node):
        if node.owner is not self.history:
            raise ValueError('Hash entries must reference this index\'s history.')
        node._check()
        if self.lookup(node.value['id'])[0] is not None:
            raise ValueError('Duplicate message ID')
        if not _call('cc_index_insert', self.native_address, node.native_address):
            raise MemoryError('Could not allocate a C hash entry.')

    def lookup(self, msg_id):
        msg_id = _identifier(msg_id)
        count = _SIZE()
        with _NATIVE_LOCK:
            pointer = _call('cc_index_find', self.native_address, msg_id, None, 0, ct.byref(count))
            # Allocate only the visited chain length, not the entire history.
            probes = (_U64 * count.value)()
            _call('cc_index_find', self.native_address, msg_id, probes, count.value, ct.byref(count))
            value = Node(self.history, pointer).value if pointer else None
            return value, list(probes)

    @property
    def buckets(self):
        # A display snapshot; the authoritative array and chains remain in C.
        snapshot = []
        for bucket in range(self.capacity):
            nodes = []
            pointer = _call('cc_index_bucket_head', self.native_address, bucket)
            while pointer:
                nodes.append(Node(self.history, _call('cc_entry_node', pointer)))
                pointer = _call('cc_entry_next', pointer)
            snapshot.append(nodes)
        return snapshot


class MessageStore:
    """JSON persistence around native history and hash index, guarded per store."""
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.RLock()
        self.history = LinkedHistory()
        self.index = HashIndex(self.history)
        if self.path.exists():
            for value in json.loads(self.path.read_text(encoding='utf-8')):
                self.index.insert(self.history.append(value))

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix('.tmp')
        temp.write_text(json.dumps(self.snapshot(), indent=2), encoding='utf-8')
        temp.replace(self.path)

    def add(self, value):
        with self.lock:
            if self.index.lookup(value['id'])[0] is not None:
                raise ValueError('Duplicate message ID')
            node = self.history.append(value)
            self.index.insert(node)
            self.save()
            return node.value

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
