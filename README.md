# ssc-2018

mkdir -p ~/.ssc && cd ~/.ssc

echo "🔹 Cloning GitHub solution repositories..."
git clone https://github.com/kamyu104/LeetCode-Solutions.git || true
git clone https://github.com/SuryaPratapK/GFG-Problems.git || true
git clone https://github.com/mostafa-saad/MyCompetitiveProgramming.git || true

echo "🔹 Fetching Codeforces problemset via API..."
curl -s https://codeforces.com/api/problemset.problems | jq '.' > codeforces_problems.json




==========================================================================================



Nice — that’s a lot to cover. I’ll walk through the types of questions described in that Media.net / Heizen interview report and give clear, practical answers, short explanations of how they work, plus runnable code examples you can study or adapt. I’ll keep each section focused so you can use it for interview prep or practice.

1) Quick theory checklist (round-1 topics)

Short bullets you should be able to explain clearly in interviews:

Computer Networks: OSI vs TCP/IP, IP addressing & CIDR, ARP, TCP handshake, UDP vs TCP tradeoffs, sockets, NAT, routing basics, basics of TLS handshake.

Linux & OS: process lifecycle, threading vs multiprocessing, scheduling, signals, file permissions, pipes, system calls, virtual memory, page faults, context switch.

DBMS: ACID, transactions/isolation levels, indexes & types (B-tree, hash), normalization, joins & explain plan, basics of replication & sharding.

Programming / DSA: arrays, strings, hashmaps, linked lists, trees, complexity analysis (big-O), common patterns (two pointers, sliding window, divide&conquer).

If interviewer asks a quick definition, give one-sentence crisp answers + one short real-world example.

2) Example coding problems (arrays & trees) — with code

Two typical problems with Python solutions.

Problem A — Arrays (medium): Given an array, find the length of the longest subarray with sum = K.
(Technique: prefix-sum + hashmap)

# longest_subarray_sum_k.py
def longest_subarray_with_sum_k(arr, K):
    prefix_index = {0: -1}
    s = 0
    best = 0
    for i, v in enumerate(arr):
        s += v
        if (s - K) in prefix_index:
            best = max(best, i - prefix_index[s - K])
        if s not in prefix_index:
            prefix_index[s] = i
    return best

# Example
print(longest_subarray_with_sum_k([1, -1, 5, -2, 3], 3))  # -> 4 (subarray [1,-1,5,-2])


Problem B — Trees (medium): Lowest Common Ancestor (LCA) in a binary tree (not BST).
(Technique: post-order recursion)

# lca_binary_tree.py
class Node:
    def __init__(self, val, left=None, right=None):
        self.val = val; self.left = left; self.right = right

def lca(root, p, q):
    if not root: return None
    if root is p or root is q:
        return root
    left = lca(root.left, p, q)
    right = lca(root.right, p, q)
    if left and right:
        return root
    return left or right

# Build small tree and test
a = Node('a'); b = Node('b'); c = Node('c'); d = Node('d')
a.left = b; a.right = c; b.left = d
print(lca(a, d, c).val)  # -> 'a'


Be ready to explain complexity: arrays O(n) time, O(n) space. LCA: O(n) time worst, O(h) recursion stack.

3) TCP/UDP / Socket question & sample code (Round 2 / machine coding context)

Concepts to explain:

TCP: reliable, ordered, connection-oriented, flow control (window), three-way handshake.

UDP: connectionless, unreliable, no ordering — used for low-latency or custom reliability.

Sockets: interface to the OS networking stack (AF_INET, SOCK_STREAM for TCP, SOCK_DGRAM for UDP).

Small practical example — client connecting to a server URL given in the prompt (simulate remote server returning a challenge; we connect and read response). I'll provide a TCP client and a minimal server you can run locally to test.

# tcp_server.py  (run this on one machine)
import socket
HOST='0.0.0.0'; PORT=5005
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((HOST, PORT)); srv.listen(1)
print("listening", PORT)
while True:
    conn, addr = srv.accept()
    print("conn from", addr)
    data = conn.recv(4096).decode().strip()
    if data == "HELLO":
        conn.sendall(b"WORLD\n")
    else:
        conn.sendall(b"UNKNOWN\n")
    conn.close()

# tcp_client.py  (what interview OA might expect)
import socket, sys
host = sys.argv[1] if len(sys.argv)>1 else '127.0.0.1'
port = int(sys.argv[2]) if len(sys.argv)>2 else 5005
with socket.create_connection((host, port), timeout=5) as s:
    s.sendall(b"HELLO\n")
    resp = s.recv(4096)
    print("Response:", resp.decode().strip())


Explain: the interview OA that gives a server URL expects you to connect, send required bytes, parse server response, and enter the output.

4) SQL remote DB tasks (Round 2)

Explain how it works: interviewer often gives a DB endpoint and expects you to run queries and return results. You must be comfortable with psql / mysql CLI or use Python's DB driver to run queries.

Example: Suppose they provide a remote PostgreSQL. Here’s how you'd connect and run a query:

# Using psql
psql "host=remote_host user=username password=secret dbname=challenge_db" -c "SELECT count(*) FROM users WHERE active=true;"


Or Python:

# query_remote_postgres.py
import psycopg2
conn = psycopg2.connect(host='host', dbname='db', user='u', password='p', port=5432)
cur = conn.cursor()
cur.execute("SELECT id, name FROM customers WHERE created_at > now() - interval '7 days';")
for row in cur.fetchall(): print(row)
cur.close(); conn.close()


Prepare: JOIN, GROUP BY, window functions, EXPLAIN ANALYZE.

5) Machine coding round (object-oriented design + socket) — approach + example

What they look for: modular code, classes with clear responsibilities, unit-testable modules, separation of IO and logic, good variable names, error handling.

Example problem (similar to description): You must build a client on a given server that connects to a remote server via TCP and handles a set of tasks (parse, transform, compute). I'll sketch an OO structure in Python and show how to wire a socket runner.

# machine_code_example.py
import socket, json, time

class RemoteConnector:
    def __init__(self, host, port, timeout=5):
        self.host = host; self.port = port; self.timeout = timeout

    def send_and_receive(self, payload):
        # payload is a bytes or str
        with socket.create_connection((self.host, self.port), timeout=self.timeout) as s:
            s.sendall(payload if isinstance(payload, bytes) else payload.encode())
            result = s.recv(8192)
            return result.decode()

class TaskProcessor:
    def __init__(self, connector):
        self.connector = connector

    def run_task(self, task_spec):
        # task_spec: dict describing task
        # Example: {"op":"reverse","data":"hello"}
        op = task_spec.get("op")
        if op == "reverse":
            return task_spec["data"][::-1]
        elif op == "remote_echo":
            # forward to remote server and return response
            return self.connector.send_and_receive(task_spec["data"])
        else:
            raise ValueError("unknown op")

# Main run: parse tasks and execute
if __name__ == "__main__":
    connector = RemoteConnector("remote.example.com", 6000)
    proc = TaskProcessor(connector)
    tasks = [{"op":"reverse","data":"abc"}, {"op":"remote_echo","data":"PING"}]
    for t in tasks:
        print(proc.run_task(t))


Explain unit testing by injecting a mock RemoteConnector during tests.

6) Creating a subnet / network question (Round 4)

What they likely expect:

How to design subnets for isolation (public/private), CIDR math, route tables, NAT for outbound, security groups vs NACLs.

Example: Given 10.0.0.0/16, split into four /18 (or eight /19) subnets for AZ redundancy — explain how to compute ranges.

CIDR example using ipcalc (or mental math):

10.0.0.0/16 → first /24: 10.0.0.0/24, 10.0.1.0/24, etc. Convert boundaries accordingly.

For AWS: create subnets per AZ and tag k8s:public / k8s:private.

AWS CLI sample to create a subnet:

aws ec2 create-subnet --vpc-id vpc-0abc1234 --cidr-block 10.0.1.0/24 --availability-zone us-east-1a


Explain route tables: public subnet routes 0.0.0.0/0 → internet gateway; private subnet routes 0.0.0.0/0 → NAT gateway in public subnet.

7) DSA small/medium examples (Round 4)

We provided arrays & trees above. Add a quick medium-level DSA problem often asked:

Find Kth largest element (heap approach):

import heapq
def kth_largest(arr, k):
    return heapq.nlargest(k, arr)[-1]

print(kth_largest([3,2,1,5,6,4], 2))  # -> 5


Explain: O(n log k) time and O(k) extra space.

8) SRE role motivation & behavioral pointers

Short, interview-ready answer you can adapt:

"I enjoy SRE because it blends software engineering and systems thinking: building reliable systems, automating toil, and measuring reliability (SLIs/SLOs). I like working on observability, CI/CD, and incident response because it delivers immediate impact on users. At my last project I reduced deployment time from X to Y by automating steps (briefly mention an example and outcome)."

Be ready to give a concrete example where you automated something, triaged incidents, or improved visibility/alerting.

9) System design round (load balancers, scaling, DBs) — short blueprint + diagrams (verbal) + reasons

Simple scalable web app design:

Client → CDN (static) → Load Balancer (ALB) → stateless app servers (auto-scaling group / k8s deployment) → caching layer (Redis) → primary DB (RDS) + read replicas for reads → object storage for blobs (S3) → background workers (queue: SQS / Kafka) → monitoring (Prometheus / Datadog), logging (ELK/CloudWatch).

Key points to discuss:

Why LB: distribute traffic, health checks.

Autoscaling triggers: CPU, request latency, queue depth.

Caching: reduces DB load; cache invalidation strategy.

DB scaling: vertical vs read replicas vs sharding.

Consistency: use strong consistency for certain operations, eventual where okay.

Fault tolerance: multi-AZ, circuit breaker patterns, retries with backoff.

Data stores: relational for transactional, NoSQL for high throughput.

Prepare to draw:

Show 3 availability zones, LB in front, app pods in each AZ, sticky sessions avoided by using stateless apps + shared session store (Redis).

10) DevOps / Docker / resume techs (Round 5)

Key topics & one-line explanations to rehearse:

Docker: container image layers, Dockerfile best practices (small base, multi-stage builds).

Kubernetes: deployments, services, ingress, ConfigMaps, Secrets, HPA, pod lifecycle.

CI/CD: pipelines, artifact registry, canary/blue-green deployments, rollbacks.

Infra as code: terraform/cloudformation — idempotent infra and state management.

Observability: metrics (Prometheus), traces (OpenTelemetry), logs aggregation.

Security: least privilege IAM, network policies, image scanning.

Short Dockerfile example:

# multi-stage
FROM node:18 as build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:stable
COPY --from=build /app/build /usr/share/nginx/html

11) Final round distributed-file processing (Large file across servers) — design + code

This is a classic divide and conquer / map-reduce style question. Interviewer expects:

How you partition the file (by lines or byte ranges) such that tasks are independent.

Worker orchestration: controller assigns chunk ranges; workers process and respond.

Fault tolerance: retry failed chunks, persist intermediate outputs, idempotency.

Reduce phase: combine results (e.g., summation, aggregation).

Minimize I/O: send offsets not entire file when possible (workers read from shared storage).

Design choices:

Put the big file in shared object storage (S3) accessible by all servers — workers fetch only needed byte ranges using ranged GETs. (Or distribute chunks ahead of time.)

Controller splits file into N chunks (byte offsets) and assigns to M workers.

Workers process chunk and write results to object storage or return to controller.

Controller aggregates results and marks chunk as done. On worker failure, reassign chunk.

Use a queue (SQS / Kafka / RabbitMQ) to hold tasks and let workers pull.

Simple runnable prototype — controller + worker using HTTP + range reads (assumes file accessible via HTTP range or local copy).
This is a simplified local demo where controller splits file by byte ranges and workers fetch ranges (we’ll use Flask for worker to simulate remote servers).

controller.py (assigns chunks and aggregates):

# controller.py
import requests, math, threading

FILE_URL = "http://localhost:8000/bigfile"  # simple static HTTP server for demo
NUM_CHUNKS = 8
WORKERS = ["http://localhost:5001/process", "http://localhost:5002/process"]

def get_file_length(url):
    r = requests.head(url)
    return int(r.headers['Content-Length'])

def make_chunks(size, n):
    chunk_size = math.ceil(size / n)
    for i in range(n):
        start = i*chunk_size
        end = min(start + chunk_size - 1, size - 1)
        yield start, end

def dispatch_task(worker_url, url, start, end):
    resp = requests.post(worker_url, json={'url': url, 'start': start, 'end': end}, timeout=60)
    return resp.json()

if __name__ == "__main__":
    total = get_file_length(FILE_URL)
    tasks = list(make_chunks(total, NUM_CHUNKS))
    results = []
    for i, (start,end) in enumerate(tasks):
        worker = WORKERS[i % len(WORKERS)]
        print("Dispatch", i, start, end, "->", worker)
        r = dispatch_task(worker, FILE_URL, start, end)
        results.append(r)
    # Example reduce: sum counts
    total_count = sum(r.get('count',0) for r in results)
    print("Aggregate result:", total_count)


worker.py (Flask app that reads http range and processes chunk):

# worker.py
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

@app.route('/process', methods=['POST'])
def process():
    data = request.json
    url = data['url']; s = data['start']; e = data['end']
    headers = {'Range': f'bytes={s}-{e}'}
    r = requests.get(url, headers=headers, stream=True, timeout=60)
    text = r.content.decode(errors='replace')
    # Example processing: count lines containing 'ERROR'
    count = sum(1 for line in text.splitlines() if 'ERROR' in line)
    return jsonify({'start': s, 'end': e, 'count': count})

if __name__ == "__main__":
    app.run(port=5001)  # run one worker on 5001 and another on 5002


How it works: controller asks HEAD to learn file size, splits into offsets, posts tasks to workers telling them which byte range to GET (HTTP Range). Worker fetches only that byte range and runs local processing, returns results.

Improvements for production:

Use S3 ranged GETs (no need to proxy through HTTP server).

Use a durable task queue and persistent task store.

Workers write partial outputs to durable storage and controller runs final reduce job (avoid large network payloads).

Idempotent tasks and checkpoints for restart.

12) Interview follow-up tips & how to present code during live rounds

When coding on remote server: structure files, create classes, keep functions short (<= 40 lines), add docstrings, and provide a README with how to run tests.

When monitored on Zoom: talk through your thinking — explain tradeoffs and complexity. Don’t freeze — if stuck, state assumptions and continue.

Testing & edge cases: always run sample inputs and show outputs; handle connection errors/timeouts for network tasks.

13) Bonus: Short checklist for the specific rounds you listed

OA (networks/Linux/DBMS/programming): revise basic commands (netstat, ss, iptables, top, htop, ps, strace), DB queries (joins, aggregates), and DSA templates.

Socket OA: know socket.create_connection, timeouts, message framing (newline vs length prefix).

Machine coding: use OO design, write modular code, include small test harness, and pass provided test cases.

Tech interviews: deep-dive your project — be ready to explain choices, tradeoffs, and what you would change.

System design & final coding: practice high-level design diagrams and distributed algorithms (map-reduce).










================================================================================








A. Chat-Server tasks — design, explanation and runnable Python server

We’ll provide one Python 3 server program that supports:

Objective 1 — echo behavior (you can telnet and see your message echoed).

Objective 2 — multi-group chat: clients give user_id and group_id; messages are relayed to other clients in same group.

Objective 3 — chat history: a new join receives previous messages for that group (bounded).

Bonus: persistence + retention: messages stored in SQLite (persistent across restarts) and a background task deletes messages older than 15 minutes; new joins receive only last 15 minutes (or less if DB has less).

Save as chat_server.py and run with python3 chat_server.py. Default port 6000. Use telnet localhost 6000 to simulate clients.

#!/usr/bin/env python3
"""
chat_server.py

Single-process threaded chat server that:
- Accepts telnet-like clients
- Asks for user_id and group_id on connect
- Echoes messages (objective 1)
- Relays messages to clients in same group (objective 2)
- Sends recent history (last 15 minutes) to new joiners (objective 3)
- Persists messages in SQLite and purges messages older than 15 minutes (bonus)
"""
import socket
import threading
import sqlite3
import time
from datetime import datetime, timedelta
import sys

HOST = '0.0.0.0'
PORT = 6000
DB_FILE = 'chat_messages.db'
HISTORY_RETENTION_SECONDS = 15 * 60  # 15 minutes
CLEANUP_INTERVAL = 60  # seconds

# Global in-memory structures
groups = {}  # group_id -> set of client sockets
clients_info = {}  # client_socket -> (user_id, group_id)

lock = threading.Lock()

# Database helpers
def init_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    cur = conn.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            ts INTEGER NOT NULL,
            text TEXT NOT NULL
        )
    ''')
    conn.commit()
    return conn

db_conn = init_db()
db_lock = threading.Lock()

def store_message(group_id, user_id, text, ts=None):
    if ts is None:
        ts = int(time.time())
    with db_lock:
        cur = db_conn.cursor()
        cur.execute('INSERT INTO messages (group_id, user_id, ts, text) VALUES (?,?,?,?)',
                    (group_id, user_id, ts, text))
        db_conn.commit()

def get_recent_messages(group_id, since_ts):
    with db_lock:
        cur = db_conn.cursor()
        cur.execute('SELECT user_id, ts, text FROM messages WHERE group_id = ? AND ts >= ? ORDER BY ts ASC',
                    (group_id, int(since_ts)))
        return cur.fetchall()

def cleanup_old_messages():
    cutoff = int(time.time()) - HISTORY_RETENTION_SECONDS
    with db_lock:
        cur = db_conn.cursor()
        cur.execute('DELETE FROM messages WHERE ts < ?', (cutoff,))
        db_conn.commit()

# Periodic cleanup thread for DB & in-memory housekeeping
def cleanup_worker():
    while True:
        try:
            cleanup_old_messages()
        except Exception as e:
            print("Cleanup error:", e)
        time.sleep(CLEANUP_INTERVAL)

def send_line(sock, line):
    try:
        sock.sendall((line + '\r\n').encode())
    except Exception:
        # socket likely closed
        pass

def broadcast_to_group(group_id, sender_sock, line):
    with lock:
        sockets = list(groups.get(group_id, set()))
    for s in sockets:
        if s is sender_sock:
            # Also echo back to sender per Objective 1
            send_line(s, f"[you] {line}")
        else:
            send_line(s, line)

def handle_client(conn, addr):
    conn.settimeout(None)
    send_line(conn, "Welcome to SimpleChat! Please provide a user id:")
    try:
        user_id = conn.recv(1024).decode().strip()
        if not user_id:
            send_line(conn, "Invalid user id. Bye.")
            conn.close()
            return
    except Exception:
        conn.close(); return

    send_line(conn, "Enter group id to join (clients with same group id share messages):")
    try:
        group_id = conn.recv(1024).decode().strip()
        if not group_id:
            send_line(conn, "Invalid group id. Bye.")
            conn.close()
            return
    except Exception:
        conn.close(); return

    # Register client
    with lock:
        groups.setdefault(group_id, set()).add(conn)
        clients_info[conn] = (user_id, group_id)

    # Send history from last 15 minutes
    since_ts = int(time.time()) - HISTORY_RETENTION_SECONDS
    try:
        recent = get_recent_messages(group_id, since_ts)
        if recent:
            send_line(conn, f"--- last {HISTORY_RETENTION_SECONDS//60} minutes chat history for group {group_id} ---")
            for uid, ts, text in recent:
                tstr = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                send_line(conn, f"[{tstr}] {uid}: {text}")
            send_line(conn, "---- end history ----")
        else:
            send_line(conn, "(No recent messages in this group.)")
    except Exception as e:
        send_line(conn, f"(Could not load history: {e})")

    send_line(conn, f"Joined group '{group_id}' as '{user_id}'. Type messages and press Enter. Type '/leave' to switch group. Type '/quit' to disconnect.")

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            line = data.decode(errors='replace').strip()
            if not line:
                continue

            # Commands
            if line.lower() == '/quit':
                send_line(conn, "Goodbye.")
                break
            if line.lower() == '/leave':
                # ask for new group
                send_line(conn, "Enter new group id to join:")
                ng = conn.recv(1024).decode().strip()
                if not ng:
                    send_line(conn, "Invalid group id. Staying in current group.")
                    continue
                # deregister from old group, register to new
                with lock:
                    old_group = clients_info.get(conn, (None, None))[1]
                    if old_group and conn in groups.get(old_group, set()):
                        groups[old_group].remove(conn)
                    groups.setdefault(ng, set()).add(conn)
                    clients_info[conn] = (user_id, ng)
                group_id = ng
                send_line(conn, f"Switched to group '{group_id}'. Sending recent history...")
                recent = get_recent_messages(group_id, int(time.time()) - HISTORY_RETENTION_SECONDS)
                for uid, ts, text in recent:
                    tstr = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                    send_line(conn, f"[{tstr}] {uid}: {text}")
                continue

            # Normal message: store and broadcast
            ts = int(time.time())
            store_message(group_id, user_id, line, ts)
            timestamp = datetime.fromtimestamp(ts).strftime('%H:%M:%S')
            formatted = f"[{timestamp}] {user_id}: {line}"
            broadcast_to_group(group_id, conn, formatted)

    except Exception as e:
        print("client handler error:", e)
    finally:
        # cleanup
        with lock:
            info = clients_info.pop(conn, None)
            if info:
                grp = info[1]
                if conn in groups.get(grp, set()):
                    groups[grp].remove(conn)
        try:
            conn.close()
        except:
            pass

def main():
    # Start cleanup thread
    t = threading.Thread(target=cleanup_worker, daemon=True)
    t.start()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(100)
    print(f"Chat server listening on {HOST}:{PORT}")
    try:
        while True:
            conn, addr = srv.accept()
            print("Conn from", addr)
            thr = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thr.start()
    except KeyboardInterrupt:
        print("Shutting down server.")
        srv.close()
        db_conn.close()
        sys.exit(0)

if __name__ == '__main__':
    main()

How to test quickly

Open several terminals:

Terminal A:

python3 chat_server.py


Terminal B:

telnet localhost 6000
# when prompted, enter user id like "alice" then group id "g1"
# type messages -> see echoed and relayed messages


Terminal C:

telnet localhost 6000
# user "bob" joins group "g1" -> receives last 15min history then live messages


Switch group: in client type /leave then new group id; /quit disconnects.

Notes / production considerations (interview talking points)

Current design: single-process, threads — simple for test / small usage.

To scale: separate components — a front-end load balancer -> multiple stateless server instances -> shared message store or message broker (Kafka/Redis pub/sub) for inter-instance broadcasting; use sticky sessions or better: sessions stored centrally (Redis).

For persistence and search: use database (time-series DB), or object storage + indices; consider eventual consistency for chat.

For retention: TTL on DB or background job (we implemented).

For high throughput and low latency: use TCP connections over websockets; use binary framing and backpressure; message batching; sharding groups across brokers.

Security: authentication, TLS for sockets, rate-limiting, validation to avoid injection.

B. Short, crisp answers to the technical interview questions (with conceptual depth)

Below are compact explanations you can use in interviews. Keep them crisp and give an example or two if asked.

1. What happens when you type google.com in a browser?

Sequence (brief):

URL parsing: browser breaks https://google.com/path into scheme, host, path.

DNS lookup: browser/OS resolver gets IP for google.com (cache → hosts file → DNS server). If not cached, recursive DNS resolves to authoritative name server.

TCP handshake: browser opens TCP connection to server IP: SYN, SYN-ACK, ACK.

TLS handshake (if HTTPS): client and server exchange keys, verify certificates, derive session keys.

HTTP request: client sends HTTP GET with headers (Host, User-Agent).

Server processes: server returns response (200 OK), content.

Rendering: browser parses HTML, fetches CSS/JS/images (parallel requests), executes JS, lays out and paints.

Persistent connections/keep-alive: reuse TCP for multiple requests.

Mention DNS caching, CDN involvement (CDN returning edge IP), and HTTP/2 multiplexing.

2. Explain whole DNS message exchange

Recursive resolver (ISP or OS) is asked to resolve google.com.

If not cached, resolver asks root server → gets TLD server for .com.

Resolver asks .com TLD server → gets authoritative name server for google.com.

Resolver asks authoritative name server → gets final A/AAAA record(s).

Resolver returns IP to client; client may then reverse lookup or use IP directly.

DNS message fields: header (transaction ID, flags), question (QNAME, QTYPE), answer/authority/additional sections.

Mention UDP for typical queries (port 53) and TCP for zone transfers or large responses, DNSSEC authenticity.

3. What is subnetting? What is Network Id? Why classless addressing?

Subnetting: dividing a large IP network into smaller subnets to organize hosts and route efficiently.

Network ID: the network portion of an IP address determined by masking (e.g., for 10.0.1.5/24, network ID is 10.0.1.0).

Classless addressing (CIDR): Replace classful A/B/C blocks with prefix lengths /n to flexibly allocate IP space (e.g., 10.0.0.0/16, 192.168.1.0/24). Allows efficient IP utilization and route aggregation.

4. Why Private IPs and Public IPs?

Private IPs (RFC1918) are non-routable on the public internet; used inside organizations for conserving public IPs and for security/isolation (e.g., 10.0.0.0/8).

Public IPs are globally routable.

NAT (Network Address Translation) maps many private IPs to one public IP for internet access.

5. Explain TCP vs UDP and why UDP is "unreliable"

TCP: connection-oriented, reliable (ACKs, retransmissions), ordered, flow-control & congestion control (good for HTTP, file transfer).

UDP: connectionless, no retransmission, no ordering, minimal overhead (good for DNS, VoIP, real-time streaming where latency matters).

UDP is called "unreliable" because delivery, ordering, and duplication handling are not guaranteed by the protocol (apps must implement if needed).

6. What is a system call?

A system call is a controlled transfer of control from user-space to kernel-space to request privileged services (e.g., read, write, open, fork, execve, socket). It triggers a trap/interrupt causing kernel entry.

7. What happens when a process encounters a function in its text?

The function call may:

Push return address and arguments on stack (ABI-dependent).

Jump to function code (in text segment).

Setup stack frame (prologue), allocate local variables on stack/heap.

On return, tear down frame and resume at return address.

If function is external (dynamic), dynamic linker may resolve symbol via PLT/GOT on first call.

8. Explain 4 components of a process (text, data, heap, stack)

Text: executable code segment (read/execute).

Data: initialized global/static variables.

BSS: uninitialized globals (conceptually part of data).

Heap: dynamic memory (malloc/new) grows upward; managed by brk/sbrk or mmap.

Stack: function frames, local variables, grows downward; each thread has stack.

9. Explain Loading and Linking

Loading: loader (OS) reads executable file into memory, sets up process address space, maps segments (text, data), sets up stack and environment, and begins execution.

Linking:

Compile-time (static linking): linker resolves symbols and produces single binary.

Dynamic linking: loader and dynamic linker (ld.so) at runtime resolve shared library symbols, load .so files, and possibly perform relocations. Uses PLT/GOT for lazy binding.

C. Short answers for common Linux / OS interview tasks mentioned

Useful Linux commands:

netstat / ss — socket stats

top / htop — CPU/memory

ps aux / pstree — processes

strace — system call tracing

lsof — open files / sockets

iptables / nft — firewall rules

df -h, du — disk usage

When debugging sockets: ss -tulpn to see listening ports; use tcpdump/wireshark to inspect packets.

D. Sample short answers / one-liners you can memorize

TCP three-way handshake: SYN → SYN+ACK → ACK.

TCP teardown: 4-way FIN/ACK sequence (half-close).

NAT types: SNAT (source), DNAT (destination), PAT (port address translation).

ACID in DB: Atomicity, Consistency, Isolation, Durability.

E. How to present in the interview (behavioral + tech)

For each project item: state the problem, your approach, and impact (numbers if possible).

When you’re uncertain: state assumptions and proceed; interviewer values clarity of thought and trade-off discussion.

For system design: draw components, explain traffic estimates & scaling plan, discuss failure modes and trade-offs.


======================================================================================================================


🔹 Question 1: Echo Server (UDP)

Problem:
Implement a server and client using UDP protocol where the client sends a message, and the server echoes it back.

✅ How it Works

UDP is connectionless (no handshake like TCP).

The server binds to an IP and port, waits for messages.

Client sends a datagram to server.

Server simply echoes it back.

✅ Server Code (UDP Echo)
import socket

def udp_echo_server(host="127.0.0.1", port=12345):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    print(f"UDP Echo Server running on {host}:{port}...")

    while True:
        data, addr = sock.recvfrom(1024)  # receive message
        print(f"Received from {addr}: {data.decode()}")
        sock.sendto(data, addr)  # echo back

if __name__ == "__main__":
    udp_echo_server()

✅ Client Code
import socket

def udp_client(server_host="127.0.0.1", server_port=12345):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        msg = input("Enter message: ")
        sock.sendto(msg.encode(), (server_host, server_port))
        data, _ = sock.recvfrom(1024)
        print("Echo from server:", data.decode())

if __name__ == "__main__":
    udp_client()


Key Points:

UDP is fast but unreliable.

If packet drops, client must handle retry logic.

🔹 Question 2: Client-Server Heartbeat

Problem:
Client should send periodic heartbeat messages to server. Server must keep track of active clients and mark them inactive if no heartbeat is received in time.

✅ How it Works

Client: sends "HEARTBEAT" every X seconds.

Server: keeps a dictionary {client_id: last_seen_time}.

If current_time - last_seen > threshold, mark client as inactive.

✅ Server Code (Heartbeat Tracker)
import socket
import threading
import time

clients = {}

def heartbeat_checker():
    while True:
        now = time.time()
        for client, last_seen in list(clients.items()):
            if now - last_seen > 10:  # 10s timeout
                print(f"Client {client} is INACTIVE")
                del clients[client]
        time.sleep(5)

def heartbeat_server(host="127.0.0.1", port=12346):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    print(f"Heartbeat Server running on {host}:{port}...")

    threading.Thread(target=heartbeat_checker, daemon=True).start()

    while True:
        data, addr = sock.recvfrom(1024)
        msg = data.decode()
        if msg.startswith("HEARTBEAT"):
            clients[addr] = time.time()
            print(f"Received heartbeat from {addr}")
        else:
            print(f"Command from {addr}: {msg}")

if __name__ == "__main__":
    heartbeat_server()

✅ Client Code
import socket, time

def heartbeat_client(server_host="127.0.0.1", server_port=12346):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        sock.sendto(b"HEARTBEAT", (server_host, server_port))
        print("Heartbeat sent")
        time.sleep(3)

if __name__ == "__main__":
    heartbeat_client()


Key Points:

Useful for monitoring liveness in distributed systems.

Can be extended to queue commands from server → client.

🔹 Question 3: Array Manipulation with Permutation

Problem:

Given two arrays, delete elements from one based on the permutation in the other.

Split the array.

Find maximum sum after splitting.

✅ Example
arr1 = [5, 2, 9, 1, 7]
arr2 = [2, 4]  # delete elements at indices 2 and 4
After deletion → [5, 2, 1]

Now split into 2 parts:
[5, 2] and [1]
Max sum = sum([5,2]) = 7

✅ Python Implementation
def array_manipulation(arr, perm):
    # delete elements at given indices
    new_arr = [arr[i] for i in range(len(arr)) if i not in perm]

    # try all splits and compute max sum
    max_sum = float('-inf')
    for i in range(1, len(new_arr)+1):
        left_sum = sum(new_arr[:i])
        right_sum = sum(new_arr[i:])
        max_sum = max(max_sum, left_sum, right_sum)
    
    return new_arr, max_sum

# Example
arr1 = [5, 2, 9, 1, 7]
arr2 = [2, 4]  # delete 2nd & 4th index
print(array_manipulation(arr1, arr2))


Output:

([5, 2, 1], 7)

🔹 Key Takeaways for Media.net Machine Coding

Socket Programming → TCP & UDP basics, client-server model.

Threading → Handle multiple clients concurrently.

System Design → Think about persistence, scaling, monitoring.

Data Structures & Algorithms → Efficient array operations, splitting, sums.

Clean Code → Use classes/modules, not just scripts.




============================================================================================================


Backend & Systems Problems
1. Echo Server with Heartbeat

Concept:

UDP client sends heartbeat packets.

Server maintains active clients, can queue commands.

Client executes commands (e.g., ls, exit).

LLD Classes:

HeartbeatServer: listens for heartbeats & commands.

Client: sends heartbeat + executes commands.

Server Code (skeleton):

import socket, threading, time

class HeartbeatServer:
    def __init__(self, host="127.0.0.1", port=5000):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.clients = {}
        self.commands = {}

    def monitor_clients(self):
        while True:
            now = time.time()
            for client, last_seen in list(self.clients.items()):
                if now - last_seen > 10:
                    print(f"Client {client} timed out")
                    del self.clients[client]
            time.sleep(5)

    def start(self):
        threading.Thread(target=self.monitor_clients, daemon=True).start()
        while True:
            data, addr = self.sock.recvfrom(1024)
            msg = data.decode()
            if msg == "HEARTBEAT":
                self.clients[addr] = time.time()
                if addr in self.commands:
                    cmd = self.commands.pop(addr)
                    self.sock.sendto(cmd.encode(), addr)
            else:
                print(f"Data from {addr}: {msg}")

if __name__ == "__main__":
    HeartbeatServer().start()

2. Ad-Click Aggregator

Concept: Collect ad-click events → aggregate counts → query by adID.

LLD Classes:

ClickEvent: represents a single click.

Aggregator: processes & aggregates.

Code Skeleton:

from collections import defaultdict

class AdClickAggregator:
    def __init__(self):
        self.clicks = defaultdict(int)

    def add_click(self, ad_id):
        self.clicks[ad_id] += 1

    def get_count(self, ad_id):
        return self.clicks[ad_id]

    def top_ads(self, k):
        return sorted(self.clicks.items(), key=lambda x: -x[1])[:k]

3. Meeting Scheduler

Concept: Given meetings with times, schedule without overlap.

LLD Classes:

Meeting: holds start, end.

Scheduler: validates & books meetings.

Code Skeleton:

class Meeting:
    def __init__(self, start, end):
        self.start, self.end = start, end

class Scheduler:
    def __init__(self):
        self.meetings = []

    def add_meeting(self, m: Meeting):
        for booked in self.meetings:
            if not (m.end <= booked.start or m.start >= booked.end):
                return False
        self.meetings.append(m)
        return True

4. Load Balancer

Concept: Distribute requests across servers.

LLD Classes:

Server: holds ID, handles requests.

LoadBalancer: distributes in round-robin.

Code Skeleton:

class Server:
    def __init__(self, id):
        self.id = id

    def handle(self, req):
        return f"Server {self.id} handled {req}"

class LoadBalancer:
    def __init__(self):
        self.servers = []
        self.index = 0

    def add_server(self, server):
        self.servers.append(server)

    def get_server(self):
        s = self.servers[self.index % len(self.servers)]
        self.index += 1
        return s

5. In-Memory Key-Value Store

Concept: Similar to Redis Lite.

LLD Classes:

KeyValueStore: supports set, get, delete, TTL.

Code Skeleton:

import time

class KeyValueStore:
    def __init__(self):
        self.store = {}

    def set(self, key, value, ttl=None):
        expire_at = time.time() + ttl if ttl else None
        self.store[key] = (value, expire_at)

    def get(self, key):
        val, exp = self.store.get(key, (None, None))
        if exp and exp < time.time():
            del self.store[key]
            return None
        return val

🔹 Game Design Problems
Snake & Ladder

Classes:

Game: runs loop.

Board: size, snakes/ladders.

Player: name, position.

Dice: roll.

Skeleton:

import random

class Dice:
    def roll(self): return random.randint(1, 6)

class Player:
    def __init__(self, name): self.name, self.pos = name, 0

class Game:
    def __init__(self, size=100):
        self.players, self.board, self.dice = [], size, Dice()

    def add_player(self, p): self.players.append(p)

    def play(self):
        while True:
            for p in self.players:
                move = self.dice.roll()
                p.pos += move
                if p.pos >= self.board:
                    print(f"{p.name} wins!")
                    return

Tic-Tac-Toe

Classes:

Board: 3x3 grid.

Player: symbol (X/O).

Game: manages turns.

🔹 Web Development Problems
Restaurant Search/Sort (React)

Features:

Input box for search.

Dropdown to sort by name/rating/ETA.

Skeleton (React):

import { useState } from "react";

function RestaurantList({ data }) {
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState("name");

  const filtered = data
    .filter(r => r.name.toLowerCase().includes(query.toLowerCase()))
    .sort((a, b) => (a[sort] > b[sort] ? 1 : -1));

  return (
    <div>
      <input onChange={e => setQuery(e.target.value)} placeholder="Search"/>
      <select onChange={e => setSort(e.target.value)}>
        <option value="name">Name</option>
        <option value="rating">Rating</option>
        <option value="eta">ETA</option>
      </select>
      {filtered.map(r => <div key={r.id}>{r.name} - {r.rating}</div>)}
    </div>
  );
}

Shopping Cart (React)

Features:

List of products.

Add/remove from cart.

Show total price.

🔹 DSA Problems
Kth Smallest Element
import heapq
def kth_smallest(arr, k):
    return heapq.nsmallest(k, arr)[-1]

Clone Linked List with Random Pointer
class Node:
    def __init__(self, val):
        self.val, self.next, self.random = val, None, None

def clone_list(head):
    if not head: return None
    mapping, cur = {}, head
    while cur:
        mapping[cur] = Node(cur.val)
        cur = cur.next
    cur = head
    while cur:
        mapping[cur].next = mapping.get(cur.next)
        mapping[cur].random = mapping.get(cur.random)
        cur = cur.next
    return mapping[head]



=====================================================================================================



✅ Objective 1: Echo Server

A simple server that accepts clients, and whatever message is received from a client is echoed back to the same client.
We’ll use Python sockets + threading so multiple clients can connect at once.

Code (Echo Server)
import socket
import threading

# Handle client connection
def handle_client(client_socket, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    try:
        while True:
            msg = client_socket.recv(1024).decode()
            if not msg:
                break
            print(f"[RECEIVED from {addr}] {msg}")
            client_socket.send(msg.encode())  # echo back
    except:
        print(f"[ERROR] Client {addr} disconnected unexpectedly.")
    finally:
        client_socket.close()

def start_server(host="0.0.0.0", port=12345):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen()
    print(f"[STARTED] Echo server running on {host}:{port}")

    while True:
        client_socket, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count()-1}")

if __name__ == "__main__":
    start_server()

How it works

Run the server: python3 echo_server.py

Connect using telnet localhost 12345

Anything you type is echoed back.

✅ Objective 2: Multi-Group Chat Server

Now extend it:

Each client provides a group id after connecting.

If group does not exist, create it.

Any message from a client is broadcast to all other clients in that group only.

Code (Multi-Group Chat)
import socket
import threading
from collections import defaultdict

groups = defaultdict(list)  # group_id -> list of (client_socket, addr)
lock = threading.Lock()

def handle_client(client_socket, addr):
    try:
        # Ask client for group id
        client_socket.send("Enter your group id: ".encode())
        group_id = client_socket.recv(1024).decode().strip()

        with lock:
            groups[group_id].append((client_socket, addr))
        client_socket.send(f"Joined group {group_id}\n".encode())
        print(f"[JOIN] {addr} joined group {group_id}")

        while True:
            msg = client_socket.recv(1024).decode()
            if not msg:
                break

            formatted_msg = f"[{addr}]: {msg}"
            print(formatted_msg)

            # Broadcast to other members in group
            with lock:
                for sock, other_addr in groups[group_id]:
                    if sock != client_socket:
                        try:
                            sock.send(formatted_msg.encode())
                        except:
                            pass
    except:
        print(f"[ERROR] Client {addr} disconnected unexpectedly.")
    finally:
        # Remove client from group
        with lock:
            for gid, clients in groups.items():
                groups[gid] = [(s, a) for s, a in clients if s != client_socket]
        client_socket.close()
        print(f"[DISCONNECTED] {addr}")

def start_server(host="0.0.0.0", port=12346):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen()
    print(f"[STARTED] Multi-Group Chat Server on {host}:{port}")

    while True:
        client_socket, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count()-1}")

if __name__ == "__main__":
    start_server()

How it works

Start server: python3 group_chat_server.py

Open multiple terminals: telnet localhost 12346

Enter group id (e.g., group1, group2).

Messages go only to members of the same group.

✅ Objective 3: Keep Chat History

Now extend further:

Store all previous messages of a group in memory.

When a new client joins, send them the chat history first.

Code (Multi-Group Chat with History)
import socket
import threading
from collections import defaultdict

groups = defaultdict(list)       # group_id -> list of (client_socket, addr)
chat_history = defaultdict(list) # group_id -> list of messages
lock = threading.Lock()

def handle_client(client_socket, addr):
    try:
        # Ask client for group id
        client_socket.send("Enter your group id: ".encode())
        group_id = client_socket.recv(1024).decode().strip()

        # Add client to group
        with lock:
            groups[group_id].append((client_socket, addr))

        # Send chat history
        if chat_history[group_id]:
            client_socket.send("Previous chats:\n".encode())
            for old_msg in chat_history[group_id]:
                client_socket.send((old_msg + "\n").encode())

        client_socket.send(f"Joined group {group_id}\n".encode())
        print(f"[JOIN] {addr} joined group {group_id}")

        while True:
            msg = client_socket.recv(1024).decode()
            if not msg:
                break

            formatted_msg = f"[{addr}]: {msg}"
            print(formatted_msg)

            with lock:
                chat_history[group_id].append(formatted_msg)  # save history

                for sock, other_addr in groups[group_id]:
                    if sock != client_socket:
                        try:
                            sock.send((formatted_msg + "\n").encode())
                        except:
                            pass
    except:
        print(f"[ERROR] Client {addr} disconnected unexpectedly.")
    finally:
        # Remove client from group
        with lock:
            for gid, clients in groups.items():
                groups[gid] = [(s, a) for s, a in clients if s != client_socket]
        client_socket.close()
        print(f"[DISCONNECTED] {addr}")

def start_server(host="0.0.0.0", port=12347):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen()
    print(f"[STARTED] Multi-Group Chat Server with History on {host}:{port}")

    while True:
        client_socket, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count()-1}")

if __name__ == "__main__":
    start_server()

🚀 Explanation

Objective 1: Basic echo server (proof of socket programming).

Objective 2: Multiple groups using dict[group_id] -> clients. Ensures isolation of chats.

Objective 3: Extend with chat_history[group_id] -> messages. Any new client gets previous chats.

👉 You can now simulate clients using:

telnet localhost 12347
