# CipherChaos

A Python desktop application that demonstrates queues, linked lists, and hash tables through encrypted message delivery. Built with Tkinter, it supports a local demonstration and messaging between two PCs through Cloudflare Tunnel.

Pendulum movement is animated for demonstration. Key input comes from OS-generated random samples, so no Arduino or physical connection is required.

## Features

- Encrypt messages with AES-256-GCM and wrap session keys with RSA-3072/OAEP-SHA256.
- Inspect outgoing messages in a FIFO queue before delivery.
- Traverse sent and received history as linked nodes.
- Find messages by ID through visible hash buckets and collision chains.
- Inspect sample generation, encryption, and delivery operations.
- Persist history and pending messages across restarts.
- Retain failed messages for retry and prevent duplicate delivery records.

## Data Structures

| Structure | Purpose | Complexity |
| --- | --- | --- |
| Linked FIFO queue | Buffer outgoing messages using front and rear pointers | Enqueue, peek, dequeue: O(1) |
| Singly linked list | Store history using head, tail, and next pointers | Append: O(1); traversal: O(n) |
| Hash table | Map message IDs to history nodes using separate chaining | Average lookup: O(1 + load factor); worst case: O(n) |

The hash table uses `message_id % 8` to make collisions visible. Its buckets reference the same nodes used by the history list. JSON provides disk persistence; the structures are rebuilt in memory at startup.

## Setup

Requires Python 3.10 or later with Tkinter. On Windows:

```powershell
git clone https://github.com/aaryanadiger/CipherChaos.git
cd CipherChaos
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Local Demonstration

Run `Demo.bat`, or:

```powershell
.\.venv\Scripts\python.exe app.py --role demo
```

1. Compose several messages and select **Enqueue message**.
2. Inspect the FIFO queue, linked-list history, and hash buckets.
3. Select **Prepare front (encrypt)** to inspect the encryption process.
4. Select **Deliver front** or **Send entire queue**.
5. Switch history to **Received** to view the decrypted messages.

The demo starts a real receiver on `127.0.0.1:5055`. Messages leave the queue only after receiver acknowledgment. Enqueue at least nine messages to guarantee a collision in the eight hash buckets.

## Two-PC Messaging

Install the application on both PCs. Install `cloudflared` on the receiver PC.

**Receiver**

1. Run `Receiver.bat`.
2. Start a tunnel:

   ```powershell
   cloudflared tunnel --url http://127.0.0.1:5055
   ```

3. Paste the generated HTTPS URL into the application's Receiver URL field.
4. Select **Export receiver config** and transfer the JSON privately to the sender.

**Sender**

1. Run `Sender.bat` and select **Import config**.
2. Enqueue, prepare, and deliver messages.
3. Inspect received history on the receiver PC.

Keep the receiver and tunnel running. Export and import the configuration again if the tunnel URL changes. Both PCs need synchronized clocks for timestamp validation.

## Project Structure

```text
app.py                Desktop interface and send workflow
structures.py         FIFO queue, linked list, hash table, persistence
network.py            Encryption, authentication, client, receiver
test_cipherchaos.py   Data structure and delivery tests
Demo.bat              Local demonstration launcher
Sender.bat            Sender launcher
Receiver.bat          Receiver launcher
requirements.txt      Python dependency
```

## Tests

```powershell
.\.venv\Scripts\python.exe -m unittest -v test_cipherchaos
```

Tests cover FIFO order, collision handling, shared node references, persistence, encryption and decryption, authentication failure, tampering rejection, and idempotent retries.

## Storage and Security

Runtime files are stored under `data/`, separated by application role. This includes plaintext history, pending packets, receiver credentials, and the private key. Configuration exports contain shared credentials and should be transferred privately.

Remote delivery requires HTTPS with certificate validation and a pinned public-key fingerprint. Requests use bearer authentication, HMAC-SHA256 signatures, timestamps, and replay protection. Acknowledgments do not return plaintext.

CipherChaos is an educational project using Python's standard-library HTTP server and unencrypted local storage. Messaging flows from sender to receiver with acknowledgments; bidirectional chat and file transfer are outside its scope.

Based on the [Chaos Pendulum Encryption System](https://github.com/aaryanadiger/Chaos-Pendulum-Encryption-System).

made with ❤️ by aarya
