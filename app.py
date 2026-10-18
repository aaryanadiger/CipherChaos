"""CipherChaos: visible, functioning DSA messaging demonstration."""
import argparse
import json
import math
from pathlib import Path
import queue
import threading
import time
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from structures import FIFOQueue, MessageStore
from network import Receiver, prepare, deliver, validate_url, begin_pairing, finish_pairing

ROOT = Path(__file__).resolve().parent


class App(tk.Tk):
    def __init__(self, role, data_dir, port):
        super().__init__()
        self.title('CipherChaos | Secure Messaging & DSA Lab')
        self.geometry('1180x820')
        self.minsize(960, 700)
        self.role, self.data_dir, self.port = role, data_dir, port
        self.sent = MessageStore(data_dir / 'sent.json')
        self.received = MessageStore(data_dir / 'received.json')
        self.outgoing = FIFOQueue()
        for record in self.sent.snapshot():
            if record['status'] != 'Delivered':
                self.outgoing.enqueue(record)
        self.config_path = data_dir / 'connection.json'
        self.config = json.loads(self.config_path.read_text()) if self.config_path.exists() else None
        self.receiver = None
        self.prepared = {}
        self.table_snapshots = {}
        self.events = queue.Queue()
        self.busy = False
        self.pairing = False
        self.pair_cancel = threading.Event()
        self.pending_session = None
        self.phase = 0
        self.status = tk.StringVar(value='Ready. Add messages to watch the data structures change.')
        self.url = tk.StringVar(value=(self.config or {}).get('url', ''))
        self.view = tk.StringVar(value='Sent')
        self.lookup_id = tk.StringVar()
        self.pair_status = tk.StringVar(value=(
            'Saved connection loaded. Messages authenticate automatically.' if self.config else
            'Pair once, then send messages without further approval.'))
        self.build()
        self.protocol('WM_DELETE_WINDOW', self.close)
        if role in ('demo', 'receiver'):
            self.start_receiver(local_demo=role == 'demo')
        self.refresh()
        self.poll_timer = self.after(100, self.poll)
        self.animation_timer = self.after(40, self.animate)

    def build(self):
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('TButton', padding=7)
        style.configure('Treeview', rowheight=28)
        header = ttk.Frame(self, padding=12)
        header.pack(fill='x')
        ttk.Label(header, text='CipherChaos', font=('Segoe UI', 23, 'bold')).pack(side='left')
        ttk.Label(header, text='  Secure messaging • Queue • Linked list • Hash table',
                  font=('Segoe UI', 11)).pack(side='left', padx=10)
        ttk.Label(header, text='Mode: ' + self.role.upper()).pack(side='right')
        connection = ttk.LabelFrame(self, text='Connection', padding=8)
        connection.pack(fill='x', padx=12)
        row = ttk.Frame(connection)
        row.pack(fill='x')
        ttk.Label(row, text='Receiver URL').pack(side='left')
        ttk.Entry(row, textvariable=self.url, width=44).pack(side='left', padx=8)
        self.connect_button = ttk.Button(row, text='Connect / pair', command=self.connect)
        self.connect_button.pack(side='left', padx=3)
        self.allow_button = ttk.Button(row, text='Allow pairing (2 min)', command=self.allow_pairing)
        self.allow_button.pack(side='left', padx=3)
        pairing_row = ttk.Frame(connection)
        pairing_row.pack(fill='x', pady=(6, 0))
        ttk.Label(pairing_row, textvariable=self.pair_status, wraplength=650).pack(side='left', fill='x', expand=True)
        self.approve_button = ttk.Button(pairing_row, text='Approve matching code', command=self.approve_pair)
        self.approve_button.pack(side='left', padx=3)
        self.reject_button = ttk.Button(pairing_row, text='Reject / cancel', command=self.cancel_pair)
        self.reject_button.pack(side='left', padx=3)
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill='both', expand=True, padx=12, pady=10)
        compose = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(compose, text='1  Compose & FIFO queue')
        top = ttk.Frame(compose)
        top.pack(fill='x')
        self.pendulum = tk.Canvas(top, width=230, height=160, bg='#eef3f8', highlightthickness=0)
        self.pendulum.pack(side='right', padx=(15, 0))
        message_frame = ttk.Frame(top)
        message_frame.pack(side='left', fill='both', expand=True)
        ttk.Label(message_frame, text='Message to deliver', font=('Segoe UI', 12, 'bold')).pack(anchor='w')
        self.message = scrolledtext.ScrolledText(message_frame, height=4, wrap='word', font=('Segoe UI', 12))
        self.message.pack(fill='x', pady=6)
        ttk.Label(message_frame, text='Pendulum: visual demonstration only. Input uses fresh OS-random samples.').pack(anchor='w')
        buttons = ttk.Frame(compose)
        buttons.pack(fill='x', pady=12)
        self.add_button = ttk.Button(buttons, text='① Enqueue message', command=self.enqueue)
        self.add_button.pack(side='left', padx=3)
        self.prepare_button = ttk.Button(buttons, text='② Prepare front (encrypt)', command=lambda: self.work('prepare'))
        self.prepare_button.pack(side='left', padx=3)
        self.deliver_button = ttk.Button(buttons, text='③ Deliver front', command=lambda: self.work('deliver'))
        self.deliver_button.pack(side='left', padx=3)
        self.all_button = ttk.Button(buttons, text='Send entire queue', command=lambda: self.work('all'))
        self.all_button.pack(side='left', padx=3)
        ttk.Label(compose, text='Real queue: enqueue at REAR → encrypt FRONT → deliver → dequeue only after acknowledgment.').pack(anchor='w')
        self.queue_diagram = self.text_box(compose, height=4)
        self.queue_table = self.table(compose, ('id', 'message', 'status'))
        history = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(history, text='2  Linked-list history')
        self.selector(history)
        ttk.Label(history, text='HEAD → Node(message, next) → … → TAIL → None | append O(1), traverse O(n)').pack(anchor='w', pady=8)
        self.list_diagram = self.text_box(history, height=5)
        self.history_table = self.table(history, ('id', 'message', 'status', 'time'))
        hashes = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(hashes, text='3  Hash-table lookup')
        self.selector(hashes)
        ttk.Label(hashes, text='hash(id) = id % 8 | separate chaining | bucket entries reference the same history nodes').pack(anchor='w', pady=8)
        self.hash_diagram = self.text_box(hashes, height=12)
        lookup = ttk.Frame(hashes)
        lookup.pack(fill='x', pady=8)
        ttk.Label(lookup, text='Message ID').pack(side='left')
        ttk.Entry(lookup, textvariable=self.lookup_id, width=24).pack(side='left', padx=8)
        ttk.Button(lookup, text='Find through hash table', command=self.lookup).pack(side='left')
        self.lookup_result = self.text_box(hashes, height=5)
        pipeline = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(pipeline, text='4  Encryption & operations')
        ttk.Label(pipeline, text='Random samples → SHA-256 → AES-GCM → RSA key wrapping → HTTP(S) → receiver decrypts',
                  font=('Segoe UI', 11, 'bold')).pack(anchor='w', pady=5)
        self.trace = self.text_box(pipeline, height=13)
        ttk.Label(pipeline, text='Live DSA operations', font=('Segoe UI', 12, 'bold')).pack(anchor='w', pady=5)
        self.operations = self.text_box(pipeline, height=9)
        ttk.Label(self, textvariable=self.status, padding=10, wraplength=1100).pack(fill='x')
        if self.role == 'receiver':
            self.view.set('Received')
            self.tabs.select(1)

    def selector(self, parent):
        row = ttk.Frame(parent)
        row.pack(fill='x')
        ttk.Label(row, text='Inspect history: ').pack(side='left')
        for label in ('Sent', 'Received'):
            ttk.Radiobutton(row, text=label, variable=self.view, value=label, command=self.refresh).pack(side='left', padx=8)

    def text_box(self, parent, height):
        widget = scrolledtext.ScrolledText(parent, height=height, wrap='word', font=('Consolas', 11), state='disabled')
        widget.pack(fill='both', expand=True, pady=6)
        return widget

    def table(self, parent, columns):
        frame = ttk.Frame(parent)
        frame.pack(fill='both', expand=True)
        widget = ttk.Treeview(frame, columns=columns, show='headings', height=6)
        for column in columns:
            widget.heading(column, text=column.title())
            widget.column(column, width=390 if column == 'message' else 150, minwidth=80)
        scrollbar = ttk.Scrollbar(frame, orient='vertical', command=widget.yview)
        widget.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
        widget.pack(fill='both', expand=True)
        return widget

    def write(self, widget, text, append=False):
        widget.configure(state='normal')
        if not append:
            widget.delete('1.0', 'end')
        widget.insert('end', text + '\n')
        widget.see('end')
        widget.configure(state='disabled')

    def log(self, text):
        self.write(self.operations, time.strftime('%H:%M:%S ') + text, append=True)

    def start_receiver(self, local_demo=False):
        try:
            self.receiver = Receiver(self.data_dir / 'receiver', self.received, self.port)
            self.receiver.start()
            if local_demo:
                self.config = dict(self.receiver.config)
                self.url.set(self.config['url'])
                self.pair_status.set('Local demo connected automatically. No pairing required.')
            elif not self.url.get():
                self.url.set(self.receiver.config['url'])
            self.log(f'Receiver listening on localhost:{self.port}; received messages use their own linked list and hash index.')
        except Exception as exc:
            messagebox.showerror('Receiver could not start', str(exc))

    def save_connection(self, config):
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.config_path.with_suffix('.tmp')
        temp.write_text(json.dumps(config, indent=2), encoding='utf-8')
        temp.replace(self.config_path)
        self.config = config

    def connect(self):
        if self.busy or self.pairing or self.role == 'receiver':
            return
        try:
            url = validate_url(self.url.get().strip())
        except ValueError as exc:
            return messagebox.showerror('Receiver URL required', str(exc))
        self.pairing = True
        self.pair_cancel = threading.Event()
        cancel = self.pair_cancel
        self.pair_status.set('Connecting. Receiver must click Allow pairing first.')
        self.refresh()

        def worker():
            try:
                pair = begin_pairing(url)
                self.events.put(('pair_code', cancel, pair['code']))
                while not cancel.is_set() and time.time() < pair['expires']:
                    config = finish_pairing(pair)
                    if config:
                        self.events.put(('paired', cancel, config))
                        return
                    cancel.wait(1.0)
                if not cancel.is_set():
                    raise ValueError('Pairing expired. Allow pairing and connect again.')
            except Exception as exc:
                if not cancel.is_set():
                    self.events.put(('pair_failed', cancel, str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def allow_pairing(self):
        if self.receiver:
            self.receiver.allow_pairing()
            self.pending_session = None
            self.pair_status.set('Pairing open for 2 minutes. Click Connect on the sender.')

    def approve_pair(self):
        if self.receiver and self.pending_session:
            try:
                self.receiver.approve_pair(self.pending_session)
                self.pair_status.set('Approved. Sender will save the connection automatically.')
                self.pending_session = None
            except ValueError as exc:
                self.pair_status.set(str(exc))

    def cancel_pair(self):
        self.pair_cancel.set()
        self.pairing = False
        if self.receiver:
            self.receiver.reject_pair()
        self.pending_session = None
        self.pair_status.set('Pairing cancelled. Existing saved connections still work.')

    def enqueue(self):
        if self.role == 'receiver':
            return messagebox.showinfo('Receiver mode', 'Use Sender.bat or Demo.bat to compose messages.')
        text = self.message.get('1.0', 'end').strip()
        if not text:
            return
        if len(text.encode('utf-8')) > 16000:
            return messagebox.showerror('Message too long', 'Use at most 16000 UTF-8 bytes.')
        # Time-based integer is readable and remains distinct across sender restarts.
        msg_id = max(time.time_ns() // 1000000, max((x['id'] for x in self.sent.snapshot()), default=0) + 1)
        value = {'id': msg_id, 'text': text, 'status': 'Queued', 'time': time.strftime('%H:%M:%S')}
        self.sent.add(value)
        self.outgoing.enqueue(value)
        self.message.delete('1.0', 'end')
        self.log(f'ENQUEUE {msg_id}: rear linked to new node, size={self.outgoing.size}. O(1)\n'
                 f'History: append node at tail O(1). Hash index: insert reference in bucket {msg_id % 8}.')
        self.status.set('Queued. Prepare front to inspect encryption, then deliver it.')
        self.refresh()

    def work(self, action):
        if self.busy or self.pairing or not self.outgoing.peek():
            return
        if not self.config:
            return messagebox.showinfo('Connection required', 'Enter the receiver URL and pair once, or launch Demo.bat.')
        try:
            config = dict(self.config, url=validate_url(self.url.get().strip()))
            self.save_connection(config)
        except Exception as exc:
            return messagebox.showerror('Connection error', str(exc))
        self.busy = True
        self.refresh()
        batch = [dict(x) for x in self.outgoing] if action == 'all' else [dict(self.outgoing.peek())]
        self.status.set('Working… receiver acknowledgment is required before dequeue.')

        def worker():
            try:
                for record in batch:
                    cached = self.prepared.get(record['id'])
                    if cached and cached[1] == config:
                        packet = cached[0]
                    else:
                        binding = {'url': config['url'], 'fingerprint': config['fingerprint']}
                        if record.get('packet') and record.get('destination', {}).get('fingerprint') == binding['fingerprint']:
                            packet = record['packet']
                            trace = f"Reusing persisted encrypted packet for {record['id']} so retries are idempotent."
                        else:
                            packet, trace = prepare(record, config)
                        self.events.put(('prepared', record['id'], packet, config, trace))
                    if action == 'prepare':
                        break
                    acknowledgment = deliver(packet, config)
                    self.events.put(('delivered', record['id'], acknowledgment['status']))
                self.events.put(('done',))
            except Exception as exc:
                self.events.put(('failed', str(exc)))
        threading.Thread(target=worker, daemon=True).start()

    def poll(self):
        try:
            while True:
                event = self.events.get_nowait()
                if event[0].startswith('pair_') or event[0] == 'paired':
                    if event[1] is not self.pair_cancel or event[1].is_set():
                        continue
                    if event[0] == 'pair_code':
                        self.pair_status.set(f'Code: {event[2]}. Compare on receiver, then approve there.')
                    elif event[0] == 'paired':
                        try:
                            self.save_connection(event[2])
                            self.url.set(self.config['url'])
                            self.prepared.clear()
                            self.pair_status.set('Paired and saved. Future messages authenticate automatically.')
                            self.log('PAIR: receiver approved; credentials saved locally. No per-message approval needed.')
                        except OSError as exc:
                            self.pair_status.set('Could not save pairing: ' + str(exc))
                        self.pairing = False
                    elif event[0] == 'pair_failed':
                        self.pair_status.set('Pairing failed: ' + event[2])
                        self.pairing = False
                elif event[0] == 'prepared':
                    _, msg_id, packet, config, trace = event
                    self.prepared[msg_id] = (packet, config)
                    self.sent.update(msg_id, status='Prepared', packet=packet,
                                     destination={'url': config['url'], 'fingerprint': config['fingerprint']})
                    self.write(self.trace, trace)
                    self.log(f'PEEK {msg_id} O(1). Encrypted front; queue order unchanged.')
                elif event[0] == 'delivered':
                    _, msg_id, acknowledgment = event
                    if self.outgoing.peek()['id'] != msg_id:
                        raise RuntimeError('FIFO invariant violated')
                    self.sent.update(msg_id, status='Delivered')
                    self.outgoing.dequeue()
                    self.prepared.pop(msg_id, None)
                    self.log(f'ACK {msg_id}: {acknowledgment}. DEQUEUE front O(1); size={self.outgoing.size}.\n'
                             'Update the same history node via hash index; receiver has decrypted and stored the message.')
                elif event[0] == 'done':
                    self.busy = False
                    self.status.set('Operation complete. Inspect history, hash buckets, or the encryption trace.')
                elif event[0] == 'failed':
                    self.busy = False
                    self.status.set('Delivery stopped: ' + event[1] + '. Front retained for retry.')
                    self.log('ERROR: ' + event[1] + '. No dequeue; later messages stay queued.')
        except queue.Empty:
            pass
        if self.receiver:
            pending = self.receiver.pending_pair()
            if pending and pending['status'] == 'pending':
                self.pending_session = pending['session']
                seconds = max(0, int(pending['expires'] - time.time()))
                self.pair_status.set(f"Code: {pending['code']} ({seconds}s). Approve only if it matches the sender screen.")
            elif self.pending_session:
                self.pending_session = None
                self.pair_status.set('Pairing expired or cancelled. Click Allow pairing to try again.')
        self.refresh()
        self.poll_timer = self.after(300, self.poll)

    def refresh(self):
        pending = list(self.outgoing)
        self.write(self.queue_diagram, 'FRONT → ' + ' → '.join(f"[{x['id']} | {x['status']}]" for x in pending) +
                   (' ← REAR' if pending else 'empty (front = rear = None)') + f'\nsize = {len(pending)}')
        self.fill_table(self.queue_table, pending)
        store = self.sent if self.view.get() == 'Sent' else self.received
        with store.lock:
            values = store.snapshot()
            self.write(self.list_diagram, 'HEAD → ' + ' → '.join(f"[{x['id']} | {x['status']} | next]" for x in values) +
                       ' → None\nTAIL = ' + (str(values[-1]['id']) if values else 'None') + f' | nodes = {len(values)}')
            lines = []
            for index, bucket in enumerate(store.index.buckets):
                lines.append(f'Bucket {index}: ' + (' → '.join(f"node({n.value['id']})" for n in bucket) or 'empty'))
            self.write(self.hash_diagram, '\n'.join(lines))
        self.fill_table(self.history_table, values)
        for button in (self.prepare_button, self.deliver_button, self.all_button):
            button.configure(state='disabled' if self.busy or self.pairing or not pending or self.role == 'receiver' else 'normal')
        self.add_button.configure(state='disabled' if self.role == 'receiver' else 'normal')
        self.connect_button.configure(state='disabled' if self.busy or self.pairing or self.role == 'receiver' else 'normal')
        self.allow_button.configure(state='normal' if self.receiver else 'disabled')
        self.approve_button.configure(state='normal' if self.pending_session else 'disabled')
        self.reject_button.configure(state='normal' if self.receiver or self.pairing else 'disabled')

    def fill_table(self, widget, values):
        snapshot = [(v['id'], v['text'], v['status'], v['time']) for v in values]
        if self.table_snapshots.get(str(widget)) == snapshot:
            return
        self.table_snapshots[str(widget)] = snapshot
        existing = widget.get_children()
        if existing:
            widget.delete(*existing)
        for value in values:
            row = [value['id'], value['text'], value['status']]
            if len(widget['columns']) == 4:
                row.append(value['time'])
            widget.insert('', 'end', values=row)

    def lookup(self):
        try:
            msg_id = int(self.lookup_id.get())
        except ValueError:
            return self.write(self.lookup_result, 'Enter an integer message ID from history.')
        store = self.sent if self.view.get() == 'Sent' else self.received
        with store.lock:
            value, probes = store.index.lookup(msg_id)
            result = dict(value) if value else None
        self.write(self.lookup_result, f'{msg_id} % 8 = bucket {msg_id % 8}\nCompared IDs: {probes}\n' +
                   (f"Found: {result['text']}\nStatus: {result['status']}" if result else 'No matching message.') +
                   '\nAverage O(1 + load factor); worst O(n). Fixed 8 buckets make collisions visible.')
        self.log(f'LOOKUP {msg_id}: bucket {msg_id % 8}, {len(probes)} comparison(s).')

    def animate(self):
        self.phase += 0.07
        c = self.pendulum
        c.delete('all')
        x = 115 + 54 * math.sin(self.phase)
        y = 40 + 54 * math.cos(self.phase)
        x2 = x + 40 * math.sin(self.phase * 1.7)
        y2 = y + 40 * math.cos(self.phase * 1.7)
        c.create_line(115, 35, x, y, x2, y2, width=3, fill='#235c93')
        c.create_oval(x-6, y-6, x+6, y+6, fill='#509bdd', outline='')
        c.create_oval(x2-8, y2-8, x2+8, y2+8, fill='#dc8242', outline='')
        c.create_text(115, 148, text='SIMULATED • no Arduino', fill='#334455')
        self.animation_timer = self.after(40, self.animate)

    def close(self):
        if self.busy:
            messagebox.showinfo('Delivery in progress', 'Wait for the current operation before closing.')
            return
        if self.receiver:
            self.receiver.stop()
        self.pair_cancel.set()
        self.after_cancel(self.poll_timer)
        self.after_cancel(self.animation_timer)
        self.destroy()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--role', choices=['demo', 'sender', 'receiver'], default='demo')
    parser.add_argument('--port', type=int, default=5055)
    parser.add_argument('--data-dir', type=Path)
    args = parser.parse_args()
    directory = args.data_dir or ROOT / 'data' / args.role
    App(args.role, directory, args.port).mainloop()
