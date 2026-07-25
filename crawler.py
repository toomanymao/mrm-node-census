#!/usr/bin/env python3
"""
mrm-node-census — a minimal recursive Bitcoin P2P crawler.
Handshakes reachable clearnet nodes, records user agents, counts Knots share.
v1: IPv4/IPv6 clearnet only (no Tor yet) — results are labeled accordingly.
"""
import asyncio, socket, struct, hashlib, json, time, random, re, sys

MAGIC = bytes.fromhex("f9beb4d9")          # mainnet
PROTO = 70016
BUDGET_S = int(sys.argv[1]) if len(sys.argv) > 1 else 480   # crawl budget (seconds)
CONNS = 400                                 # concurrent dials
DIAL_TIMEOUT = 6
SEEDS = ["seed.bitcoin.sipa.be","dnsseed.bluematt.me","seed.bitcoinstats.com",
         "seed.btc.petertodd.org","seed.bitcoin.sprovoost.nl","dnsseed.emzy.de",
         "seed.bitcoin.wiz.biz"]

def dsha(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def msg(cmd, payload=b""):
    return MAGIC + cmd.ljust(12, b"\x00") + struct.pack("<I", len(payload)) + dsha(payload)[:4] + payload

def version_payload():
    ts = int(time.time())
    addr = struct.pack("<Q", 0) + b"\x00"*10 + b"\xff\xff" + b"\x00"*4 + struct.pack(">H", 0)
    nonce = random.getrandbits(64)
    ua = b"\x10/mrm-census:0.1/"           # varint(16) + string
    return (struct.pack("<iQq", PROTO, 0, ts) + addr + addr +
            struct.pack("<Q", nonce) + ua + struct.pack("<i", 0) + b"\x00")

async def read_msg(r):
    hdr = await r.readexactly(24)
    if hdr[:4] != MAGIC: raise ValueError("bad magic")
    cmd = hdr[4:16].rstrip(b"\x00").decode(errors="replace")
    ln = struct.unpack("<I", hdr[16:20])[0]
    if ln > 4_000_000: raise ValueError("oversized")
    payload = await r.readexactly(ln)
    return cmd, payload

def read_varint(b, i):
    v = b[i]
    if v < 0xfd: return v, i+1
    if v == 0xfd: return struct.unpack_from("<H", b, i+1)[0], i+3
    if v == 0xfe: return struct.unpack_from("<I", b, i+1)[0], i+5
    return struct.unpack_from("<Q", b, i+1)[0], i+9

def parse_version_ua(p):
    # skip version(4) services(8) ts(8) addr_recv(26) addr_from(26) nonce(8)
    i = 80
    n, i = read_varint(p, i)
    return p[i:i+n].decode(errors="replace")

def parse_addr(p):
    out=[]; n,i = read_varint(p,0)
    for _ in range(min(n,1000)):
        i += 12                              # time(4)+services(8)
        raw = p[i:i+16]; i += 16
        port = struct.unpack(">H", p[i:i+2])[0]; i += 2
        if raw[:12] == b"\x00"*10 + b"\xff\xff":
            out.append((socket.inet_ntoa(raw[12:]), port))
        else:
            try: out.append((socket.inet_ntop(socket.AF_INET6, raw), port))
            except OSError: pass
    return out

def parse_addrv2(p):
    out=[]; n,i = read_varint(p,0)
    for _ in range(min(n,1000)):
        i += 4                               # time
        _, i = read_varint(p, i)             # services (compact)
        net = p[i]; i += 1
        alen, i = read_varint(p, i)
        raw = p[i:i+alen]; i += alen
        port = struct.unpack(">H", p[i:i+2])[0]; i += 2
        if net == 1 and alen == 4: out.append((socket.inet_ntoa(raw), port))
        elif net == 2 and alen == 16:
            try: out.append((socket.inet_ntop(socket.AF_INET6, raw), port))
            except OSError: pass
        # net 4 = torv3 — collected in v2 of this crawler
    return out

seen=set(); frontier=asyncio.Queue(); agents={}; deadline=0

async def probe(host, port):
    r=w=None
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), DIAL_TIMEOUT)
        w.write(msg(b"version", version_payload())); await w.drain()
        got_ver=False
        end=time.time()+8
        while time.time()<end:
            cmd, p = await asyncio.wait_for(read_msg(r), 8)
            if cmd=="version":
                agents[f"{host}:{port}"]=parse_version_ua(p); got_ver=True
                w.write(msg(b"verack")); await w.drain()
            elif cmd=="verack" and got_ver:
                w.write(msg(b"getaddr")); await w.drain()
            elif cmd in ("addr","addrv2"):
                peers = parse_addr(p) if cmd=="addr" else parse_addrv2(p)
                for hp in peers:
                    if hp not in seen and len(seen)<60000:
                        seen.add(hp); frontier.put_nowait(hp)
                if len(peers)>5: break       # got a real addr batch — done here
            elif cmd=="ping":
                w.write(msg(b"pong", p)); await w.drain()
    except Exception:
        pass
    finally:
        if w:
            try: w.close()
            except Exception: pass

async def worker():
    while time.time()<deadline:
        try: host,port = await asyncio.wait_for(frontier.get(), 3)
        except asyncio.TimeoutError: return
        await probe(host,port)

async def main():
    global deadline
    deadline=time.time()+BUDGET_S
    for s in SEEDS:
        try:
            for fam,_,_,_,sa in socket.getaddrinfo(s,8333,proto=socket.IPPROTO_TCP):
                hp=(sa[0],8333)
                if hp not in seen: seen.add(hp); frontier.put_nowait(hp)
        except OSError: pass
    print(f"[census] seeded {frontier.qsize()} addresses; budget {BUDGET_S}s")
    await asyncio.gather(*[worker() for _ in range(CONNS)])
    total=len(agents)
    knots=sum(1 for ua in agents.values() if re.search(r"knots", ua, re.I))
    print(f"[census] handshaked {total} reachable nodes; {knots} Knots")
    top={}
    for ua in agents.values(): top[ua]=top.get(ua,0)+1
    for ua,c in sorted(top.items(), key=lambda x:-x[1])[:10]:
        print(f"[census]   {c:5d}  {ua}")
    out={"total":total,"knots":knots,
         "updated":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
         "method":"mrm-census v1 - clearnet reachable (getaddr crawl, no Tor)"}
    with open("nodes.json","w") as f: json.dump(out,f)
    print("[census] wrote nodes.json:", out)

asyncio.run(main())
