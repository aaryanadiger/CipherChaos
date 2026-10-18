# CipherChaos

A Python desktop application that demonstrates queues, linked lists, and hash tables through encrypted message delivery. Built with Tkinter, it supports a local demonstration and messaging between two PCs through Cloudflare Tunnel.

Version `v1.1.0` provides separate messaging and DSA Lab windows. Version `v1.0.0` preserves the previous interface with pairing and DSA views in one window.

Pendulum movement is animated for demonstration. Key input comes from OS-generated random samples, so no Arduino or physical connection is required.

## Features

- Encrypt messages with AES-256-GCM and wrap session keys with RSA-3072/OAEP-SHA256.
- Inspect outgoing messages in a FIFO queue before delivery.
- Traverse sent and received history as linked nodes.
- Find messages by ID through visible hash buckets and collision chains.
- Inspect sample generation, encryption, and delivery operations.
- Persist history and pending messages across restarts.
- Retain failed messages for retry and prevent duplicate delivery records.
- Pair a sender once with a matching code and receiver approval, without transferring configuration files.
- Send and read messages in a clean interface, with pairing controls in the same window.
- Open the DSA Lab separately to inspect live data structures and encryption activity.

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

1. Type a message in the sender window and select **Send message**. Encryption and delivery run automatically.
2. Select **Open receiver inbox** to see the decrypted messages in a separate window.
3. Select **Open DSA Lab** when you want to inspect the processing behind those messages.

For a step-by-step DSA presentation, use the Lab's composer to enqueue several messages, inspect the queue and history, select **Prepare front (encrypt)**, then **Deliver front** or **Send entire queue**. The Lab and messaging window use the same queue and history. Closing the Lab hides it and leaves messaging running.

The demo starts a real receiver on `127.0.0.1:5055`. Messages leave the queue only after receiver acknowledgment. Enqueue at least nine messages to guarantee a collision in the eight hash buckets.

## Two-PC Messaging

Install the application on both PCs. Install `cloudflared` on the receiver PC.

**Receiver**

1. Run `Receiver.bat`.
2. Start a tunnel:

   ```powershell
   cloudflared tunnel --url http://127.0.0.1:5055
   ```

3. Share the generated HTTPS URL with the sender. The URL does not contain credentials.
4. Select **Allow pairing (2 min)** in the receiver app.

**Sender**

1. Run `Sender.bat`, enter the receiver's HTTPS URL, and select **Connect / pair**.
2. Compare the code shown on both PCs. On the receiver, select **Approve matching code** only if both codes match.
3. Wait for the sender to report that the connection is paired and saved.
4. Type a message and select **Send message**. The receiver sees the decrypted text and timestamp in its inbox.
5. Use **Retry pending** if delivery fails. Open **DSA Lab** on either PC only when you want to inspect its data structures.

Pairing is required once. Both apps retain the credentials across restarts, and each message authenticates automatically. Each paired sender receives separate credentials. Pairing requests expire after two minutes, require local receiver approval, and have attempt limits. **Reject / cancel** closes pairing without affecting existing saved connections.

Keep the receiver and tunnel running. If the tunnel URL changes, update the sender's Receiver URL field and send normally. The new address is saved when sending; the receiver's pinned key remains the same. Pair again if credentials are deleted, reset, or you connect to a different receiver. Both PCs need synchronized clocks for timestamp validation.

## Project Structure

```text
app.py                Messaging windows, separate DSA Lab, pairing
structures.py         FIFO queue, linked list, hash table, persistence
network.py            Encryption, authentication, client, receiver
test_cipherchaos.py   Data structure and delivery tests
test_gui.py           Messaging, shared state, and pairing GUI tests
Demo.bat              Local demonstration launcher
Sender.bat            Sender launcher
Receiver.bat          Receiver launcher
requirements.txt      Python dependency
```

## Tests

```powershell
.\.venv\Scripts\python.exe -m unittest -v test_cipherchaos
```

Tests cover FIFO order, collision handling, shared node references, persistence, encryption and decryption, authentication failure, tampering rejection, idempotent retries, pairing approval, expiry, rejection, attempt limits, and saved credentials after receiver restart.

Run the GUI integration checks on a desktop with Tkinter:

```powershell
.\.venv\Scripts\python.exe -m unittest -v test_gui
```

## Storage and Security

Runtime files are stored under `data/`, separated by application role. This includes plaintext history, pending packets, saved connections, paired sender credentials, and the receiver's private key. These files are excluded from Git. No configuration file needs to be transferred between PCs.

Remote delivery requires HTTPS with certificate validation and a pinned public-key fingerprint. Requests use bearer authentication, HMAC-SHA256 signatures, timestamps, and replay protection. Acknowledgments do not return plaintext.

CipherChaos is an educational project using Python's standard-library HTTP server and unencrypted local storage. Messaging flows from sender to receiver with acknowledgments; bidirectional chat and file transfer are outside its scope.

Based on the [Chaos Pendulum Encryption System](https://github.com/aaryanadiger/Chaos-Pendulum-Encryption-System).

made with ❤️ by aarya
