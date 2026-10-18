# CipherChaos

A desktop application with a C data structure engine and a Python interface. It demonstrates queues, linked lists, and hash tables through encrypted message delivery, with a local demo and two-PC messaging through Cloudflare Tunnel.

Version `v1.2.0` moves the data structures into C. Version `v1.1.0` introduced separate messaging and DSA Lab windows. Version `v1.0.0` preserves the original combined interface with pairing.

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

All three structures are implemented in `native/cc_dsa.c`, using C structs, pointers, dynamic allocation, and explicit cleanup. The hash table uses `message_id % 8` to make collisions visible. Its C collision chains reference the same nodes used by the history list.

C owns the message records, linked nodes, queue front and rear pointers, and bucket array. The queue and history share references to the same C-owned message record. Python calls this library through `ctypes` and handles the GUI, encryption, networking, and JSON persistence. Python bucket lists are display snapshots, not the authoritative hash table. There is no Python DSA fallback.

The complexity figures describe native operations. JSON conversion, disk saves, and rendering add separate overhead. Python rebuilds the C structures from saved JSON on startup. A per-store lock and a native-call lock serialize access; the C API itself is not thread-safe.

## Setup

Requires Python 3.10 or later with Tkinter. The repository includes a compiled Windows x64 C library, so a 64-bit Python installation can run it without a C compiler. On Windows:

```powershell
git clone https://github.com/aaryanadiger/CipherChaos.git
cd CipherChaos
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### Building the C Engine

To rebuild after editing C sources, install Visual Studio C++ Build Tools with the C++ desktop workload, then run:

```powershell
.\.venv\Scripts\python.exe build_native.py --force
```

On Linux or macOS, install a C compiler and run `python3 build_native.py`. On other architectures, a matching C compiler is required. The bridge builds the library if a matching binary is missing or its C source stamp has changed. Close running CipherChaos windows before replacing a loaded DLL.

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
structures.py         ctypes bridge, native record views, persistence
native/cc_dsa.c       C queue, linked list, hash table, memory ownership
native/cc_dsa.h       C structs' opaque handles and public API
native/test_dsa.c     Standalone C tests
native/bin/           Compiled Windows x64 library and source stamp
build_native.py       C library and standalone test build script
network.py            Encryption, authentication, client, receiver
test_cipherchaos.py   Data structure and delivery tests
test_native.py        C integration, shared records, memory cleanup
test_gui.py           Messaging, shared state, and pairing GUI tests
Demo.bat              Local demonstration launcher
Sender.bat            Sender launcher
Receiver.bat          Receiver launcher
requirements.txt      Python dependency
```

## Tests

```powershell
.\.venv\Scripts\python.exe -m unittest -v test_native test_cipherchaos
```

Tests cover FIFO order, collision handling, shared node references, persistence, encryption and decryption, authentication failure, tampering rejection, idempotent retries, pairing approval, expiry, rejection, attempt limits, and saved credentials after receiver restart.

To compile and run the standalone C assertions with a C compiler:

```powershell
.\.venv\Scripts\python.exe build_native.py --test
```

These exercise FIFO order, C linked traversal, hash collisions, shared record updates, and allocation cleanup without Python or the GUI running the data structure operations.

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
