import json
from pathlib import Path
import tempfile
import unittest
from urllib.error import HTTPError
from structures import FIFOQueue, MessageStore
from network import Receiver, prepare, deliver, begin_pairing, finish_pairing, fetch, canonical


class StructuresTest(unittest.TestCase):
    def test_fifo_empty_transition_and_order(self):
        q = FIFOQueue()
        for number in (1, 2, 3):
            q.enqueue({'id': number})
        self.assertEqual([q.dequeue()['id'] for _ in range(3)], [1, 2, 3])
        self.assertIsNone(q.front)
        self.assertIsNone(q.rear)
        q.enqueue({'id': 4})
        self.assertEqual(q.peek()['id'], 4)

    def test_collision_node_identity_and_reload(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'history.json'
            store = MessageStore(path)
            for msg_id in (1, 9, 17):
                store.add({'id': msg_id, 'text': str(msg_id), 'status': 'Queued'})
            found, probes = store.index.lookup(17)
            self.assertEqual(probes, [1, 9, 17])
            self.assertIs(found, store.history.tail.value)
            store.update(17, status='Delivered')
            self.assertEqual(store.history.tail.value['status'], 'Delivered')
            loaded = MessageStore(path)
            self.assertEqual([x['id'] for x in loaded.history], [1, 9, 17])
            self.assertEqual(loaded.index.lookup(17)[0]['status'], 'Delivered')
            with self.assertRaises(ValueError):
                store.add({'id': 17})


class DeliveryTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.store = MessageStore(self.directory / 'received.json')
        self.receiver = Receiver(self.directory / 'receiver', self.store, port=0)
        self.receiver.start()
        self.config = dict(self.receiver.config,
            url=f'http://127.0.0.1:{self.receiver.server.server_port}')

    def tearDown(self):
        self.receiver.stop()
        self.temp.cleanup()

    def packet(self, msg_id=1):
        return prepare({'id': msg_id, 'text': 'Hello pendulum! नमस्ते'}, self.config)[0]

    def test_real_delivery_decryption_and_idempotent_retry(self):
        packet = self.packet()
        self.assertEqual(deliver(packet, self.config)['status'], 'received')
        self.assertEqual(deliver(packet, self.config)['status'], 'already_received')
        self.assertEqual(self.store.history.size, 1)
        self.assertEqual(self.store.history.head.value['text'], 'Hello pendulum! नमस्ते')
        self.assertNotIn('plaintext', deliver(packet, self.config))
        loaded = MessageStore(self.store.path)
        self.assertEqual(loaded.index.lookup(1)[0]['status'], 'Received')

    def test_ciphertext_tampering_rejected_without_history(self):
        packet = self.packet()
        packet['ciphertext'] = 'AAAA' + packet['ciphertext'][4:]
        with self.assertRaises(HTTPError) as error:
            deliver(packet, self.config)
        self.assertEqual(error.exception.code, 400)
        error.exception.close()
        self.assertEqual(self.store.history.size, 0)

    def test_wrong_token_and_hmac_rejected(self):
        packet = self.packet()
        for field in ('token', 'secret'):
            with self.assertRaises(HTTPError) as error:
                deliver(packet, dict(self.config, **{field: 'wrong'}))
            self.assertEqual(error.exception.code, 401)
            error.exception.close()
        self.assertEqual(self.store.history.size, 0)

    def test_fingerprint_mismatch_blocks_preparation(self):
        with self.assertRaises(ValueError):
            prepare({'id': 1, 'text': 'hello'}, dict(self.config, fingerprint='0' * 64))

    def test_conflicting_id_rejected(self):
        deliver(self.packet(), self.config)
        with self.assertRaises(HTTPError) as error:
            deliver(self.packet(), self.config)
        self.assertEqual(error.exception.code, 409)
        error.exception.close()
        self.assertEqual(self.store.history.size, 1)

    def test_fifo_delivery_integration(self):
        outgoing = FIFOQueue()
        for msg_id in (10, 11, 12):
            outgoing.enqueue({'id': msg_id, 'text': str(msg_id)})
        while outgoing.peek():
            packet, _ = prepare(outgoing.peek(), self.config)
            deliver(packet, self.config)
            outgoing.dequeue()
        self.assertEqual([x['id'] for x in self.store.history], [10, 11, 12])


class PairingTest(unittest.TestCase):
    setUp = DeliveryTest.setUp
    tearDown = DeliveryTest.tearDown

    def test_pair_once_and_send_multiple_messages_after_restart(self):
        self.receiver.allow_pairing()
        pair = begin_pairing(self.config['url'])
        self.assertEqual(pair['code'], self.receiver.pending_pair()['code'])
        self.assertIsNone(finish_pairing(pair))
        self.receiver.approve_pair(pair['session'])
        config = finish_pairing(pair)
        self.assertNotEqual(config['token'], self.config['token'])
        self.assertEqual(self.receiver.pending_pair(), None)
        for msg_id in (101, 102):
            packet, _ = prepare({'id': msg_id, 'text': f'Message {msg_id}'}, config)
            self.assertEqual(deliver(packet, config)['status'], 'received')
        self.receiver.stop()
        self.receiver = Receiver(self.directory / 'receiver', self.store, port=0)
        self.receiver.start()
        config['url'] = self.receiver.config['url']
        packet, _ = prepare({'id': 103, 'text': 'After restart'}, config)
        self.assertEqual(deliver(packet, config)['status'], 'received')

    def test_closed_and_expired_pairing(self):
        with self.assertRaises(HTTPError) as error:
            begin_pairing(self.config['url'])
        self.assertEqual(error.exception.code, 403)
        error.exception.close()
        self.receiver.allow_pairing()
        pair = begin_pairing(self.config['url'])
        self.receiver.pair['expires'] = 0
        with self.assertRaises(ValueError):
            self.receiver.approve_pair(pair['session'])
        with self.assertRaises(HTTPError) as error:
            finish_pairing(pair)
        self.assertEqual(error.exception.code, 410)
        error.exception.close()

    def test_wrong_claim_cannot_get_credentials_and_claim_is_single_use(self):
        self.receiver.allow_pairing()
        pair = begin_pairing(self.config['url'])
        self.receiver.approve_pair(pair['session'])
        with self.assertRaises(HTTPError) as error:
            finish_pairing(dict(pair, claim='incorrect'))
        self.assertEqual(error.exception.code, 401)
        error.exception.close()
        self.assertIsNotNone(finish_pairing(pair))
        with self.assertRaises(HTTPError) as error:
            finish_pairing(pair)
        self.assertEqual(error.exception.code, 410)
        error.exception.close()

    def test_reject_and_pending_request_cannot_be_replaced(self):
        self.receiver.allow_pairing()
        pair = begin_pairing(self.config['url'])
        with self.assertRaises(HTTPError) as error:
            begin_pairing(self.config['url'])
        self.assertEqual(error.exception.code, 409)
        error.exception.close()
        self.assertEqual(self.receiver.pending_pair()['session'], pair['session'])
        self.receiver.reject_pair()
        with self.assertRaises(HTTPError) as error:
            finish_pairing(pair)
        self.assertEqual(error.exception.code, 410)
        error.exception.close()

    def test_attempt_limit(self):
        self.receiver.allow_pairing()
        for _ in range(5):
            with self.assertRaises(HTTPError) as error:
                fetch(self.config['url'] + '/pair/start', canonical({'client_nonce': 'short'}))
            self.assertEqual(error.exception.code, 400)
            error.exception.close()
        with self.assertRaises(HTTPError) as error:
            begin_pairing(self.config['url'])
        self.assertEqual(error.exception.code, 429)
        error.exception.close()


if __name__ == '__main__':
    unittest.main()
