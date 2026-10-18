"""Desktop integration checks using real Tk widgets and localhost delivery."""
from pathlib import Path
import gc
import tempfile
import time
import unittest
from app import App


class MessagingWindowTest(unittest.TestCase):
    def setUp(self):
        gc.collect()
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name)
        self.apps = []

    def tearDown(self):
        for app in reversed(self.apps):
            app.busy = False
            app.close()
        self.apps.clear()
        del app
        gc.collect()
        self.temp.cleanup()

    def app(self, role, name):
        app = App(role, self.directory / name, 0)
        app.withdraw()
        self.apps.append(app)
        return app

    def until(self, predicate):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            for app in self.apps:
                app.update()
            if predicate():
                return
            time.sleep(0.02)
        self.fail('GUI operation timed out')

    def test_messaging_and_lab_share_queue_history_and_inbox(self):
        app = self.app('demo', 'demo')
        app.deiconify()
        app.update()
        self.assertTrue(app.message.frame.winfo_viewable())
        self.assertLessEqual(app.message.winfo_rooty() + app.message.winfo_height(), app.winfo_rooty() + app.winfo_height())
        self.assertLessEqual(app.retry_button.winfo_rootx() + app.retry_button.winfo_width(), app.winfo_rootx() + app.winfo_width())
        app.withdraw()
        self.assertEqual(app.lab_window.state(), 'withdrawn')
        app.open_inbox()
        app.lab_message.insert('1.0', 'First from lab')
        app.add_button.invoke()
        self.assertEqual(app.outgoing.size, 1)
        self.assertIn('First from lab', app.chat.get('1.0', 'end'))
        app.message.insert('1.0', 'Second from messaging')
        app.send_button.invoke()
        self.until(lambda: not app.busy)
        self.assertEqual([v['text'] for v in app.received.snapshot()],
                         ['First from lab', 'Second from messaging'])
        self.assertEqual(app.outgoing.size, 0)
        self.assertIn('Delivered', app.chat.get('1.0', 'end'))
        self.assertIn('Second from messaging', app.inbox_text.get('1.0', 'end'))
        self.assertEqual(app.lab_window.state(), 'withdrawn')
        app.open_lab()
        app.update()
        self.assertEqual(app.lab_window.state(), 'normal')
        app.lab_window.withdraw()
        app.message.insert('1.0', 'Lab stays hidden')
        app.send_button.invoke()
        self.until(lambda: not app.busy)
        self.assertEqual(len(app.received.snapshot()), 3)
        self.assertEqual(app.lab_window.state(), 'withdrawn')

    def test_failed_send_stays_visible_and_retry_delivers(self):
        app = self.app('demo', 'demo')
        token = app.config['token']
        app.config['token'] = 'incorrect'
        app.message.insert('1.0', 'Retry this message')
        app.send_button.invoke()
        self.until(lambda: not app.busy)
        self.assertEqual(app.outgoing.size, 1)
        self.assertIn('Retry pending', app.chat_status.get())
        self.assertIn('Retry this message', app.chat.get('1.0', 'end'))
        app.config['token'] = token
        app.retry_button.invoke()
        self.until(lambda: not app.busy)
        self.assertEqual(app.outgoing.size, 0)
        self.assertEqual(app.received.snapshot()[0]['text'], 'Retry this message')

    def test_pairing_in_messaging_window_then_send_without_lab(self):
        receiver = self.app('receiver', 'receiver')
        sender = self.app('sender', 'sender')
        receiver.allow_button.invoke()
        sender.url.set(receiver.receiver.config['url'])
        sender.connect_button.invoke()
        self.until(lambda: receiver.pending_session and 'Code:' in sender.pair_status.get())
        self.assertIn(receiver.receiver.pending_pair()['code'], sender.pair_status.get())
        receiver.approve_button.invoke()
        self.until(lambda: not sender.pairing)
        self.assertTrue(sender.config_path.exists())
        sender.message.insert('1.0', 'Clean window delivery')
        sender.send_button.invoke()
        self.until(lambda: not sender.busy and 'Clean window delivery' in receiver.chat.get('1.0', 'end'))
        self.assertFalse(receiver.message.frame.winfo_manager())
        self.assertEqual(sender.lab_window.state(), 'withdrawn')
        self.assertEqual(receiver.lab_window.state(), 'withdrawn')

    def test_pending_native_queue_reloads_and_shares_history_after_restart(self):
        app = self.app('demo', 'restart')
        app.config['token'] = 'incorrect'
        app.message.insert('1.0', 'Survives native restart')
        app.send_button.invoke()
        self.until(lambda: not app.busy)
        self.assertEqual(app.outgoing.size, 1)
        app.close()
        self.apps.remove(app)
        del app
        gc.collect()
        app = self.app('demo', 'restart')
        record = app.outgoing.peek()
        history_record, _ = app.sent.index.lookup(record['id'])
        self.assertEqual(record.native_address, history_record.native_address)
        app.retry_button.invoke()
        self.until(lambda: not app.busy)
        self.assertEqual(app.outgoing.size, 0)
        self.assertEqual(app.received.snapshot()[0]['text'], 'Survives native restart')


if __name__ == '__main__':
    unittest.main()
