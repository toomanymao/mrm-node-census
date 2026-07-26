#!/usr/bin/env python3
"""
mrm-node-census — a minimal recursive Bitcoin P2P crawler.
Handshakes reachable nodes, records user agents, counts Knots share.

v2: clearnet IPv4/IPv6 + Tor v3 onion services.
    - negotiates sendaddrv2 (BIP 155) so peers relay onion addresses
    - parses torv3 entries from addrv2 and derives .onion hostnames
    - dials .onion peers through a local Tor daemon (SOCKS5 on 127.0.0.1:9050)
    - persists discovered onion addresses (onions.json) so each run starts warm
      instead of rediscovering the Tor side from scratch
    Results carry a per-network breakdown; total/knots stay combined for the site.
"""
import asyncio, socket, struct, hashlib, json, time, random, re, sys, base64

MAGIC = bytes.fromhex("f9beb4d9")          # mainnet
PROTO = 70016
BUDGET_S = int(sys.argv[1]) if len(sys.argv) > 1 else 1800  # crawl budget (seconds)
ONION_CACHE = "onions.json"                 # onion addresses carried between runs
CLEAR_CONNS = 300                           # concurrent clearnet dials
TOR_CONNS = 100                             # concurrent Tor circuits (be kind to the daemon)
DIAL_TIMEOUT = 6                            # clearnet
TOR_DIAL_TIMEOUT = 25                       # onion circuits are slow to build
READ_WINDOW = 8                             # clearnet post-handshake listen (s)
TOR_READ_WINDOW = 15
SOCKS_HOST, SOCKS_PORT = "127.0.0.1", 9050
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
    ua = b"\x10/mrm-census:0.2/"           # varint(16) + string
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

def onion_v3(pubkey):
    """torv3 spec: onion = base32(PUBKEY | CHECKSUM | VERSION), checksum =
    sha3_256(".onion checksum" | PUBKEY | VERSION)[:2], VERSION = 0x03."""
    ver = b"\x03"
    chk = hashlib.sha3_256(b".onion checksum" + pubkey + ver).digest()[:2]
    return base64.b32encode(pubkey + chk + ver).decode().lower() + ".onion"

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
        elif net == 4 and alen == 32:        # torv3 — the whole point of v2
            out.append((onion_v3(raw), port))
        # net 3 = torv2 (dead network), 5 = i2p, 6 = cjdns — skipped
    return out

async def open_via_tor(host, port):
    """Minimal SOCKS5 CONNECT through the local Tor daemon (hostname resolved
    inside Tor, so .onion works). No auth — standard tor package default."""
    r, w = await asyncio.open_connection(SOCKS_HOST, SOCKS_PORT)
    try:
        w.write(b"\x05\x01\x00"); await w.drain()
        if await r.readexactly(2) != b"\x05\x00": raise OSError("socks: auth refused")
        hb = host.encode()
        w.write(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + struct.pack(">H", port))
        await w.drain()
        rep = await r.readexactly(4)
        if rep[1] != 0: raise OSError(f"socks: connect failed ({rep[1]})")
        atyp = rep[3]                        # drain the bound-address field
        if atyp == 1: await r.readexactly(6)
        elif atyp == 3:
            ln = (await r.readexactly(1))[0]; await r.readexactly(ln + 2)
        elif atyp == 4: await r.readexactly(18)
        return r, w
    except BaseException:
        w.close()
        raise

clear_q=asyncio.Queue(); tor_q=asyncio.Queue()
seen=set(); agents={}; deadline=0

def enqueue(hp):
    if hp in seen or len(seen) >= 120000: return
    seen.add(hp)
    (tor_q if hp[0].endswith(".onion") else clear_q).put_nowait(hp)

async def probe(host, port):
    tor = host.endswith(".onion")
    w=None
    try:
        if tor:
            r, w = await asyncio.wait_for(open_via_tor(host, port), TOR_DIAL_TIMEOUT)
        else:
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port), DIAL_TIMEOUT)
        w.write(msg(b"version", version_payload())); await w.drain()
        got_ver=got_ack=sent_getaddr=False
        window = TOR_READ_WINDOW if tor else READ_WINDOW
        end=time.time()+window
        while time.time()<end:
            cmd, p = await asyncio.wait_for(read_msg(r), window)
            if cmd=="version":
                agents[f"{host}:{port}"]=parse_version_ua(p); got_ver=True
                # BIP 155: sendaddrv2 must go out after version, before verack —
                # without it peers will never relay onion addresses to us
                w.write(msg(b"sendaddrv2")); w.write(msg(b"verack")); await w.drain()
            elif cmd=="verack":
                got_ack=True
            elif cmd in ("addr","addrv2"):
                peers = parse_addr(p) if cmd=="addr" else parse_addrv2(p)
                for hp in peers: enqueue(hp)
                if len(peers)>5: break       # got a real addr batch — done here
            elif cmd=="ping":
                w.write(msg(b"pong", p)); await w.drain()
            if got_ver and got_ack and not sent_getaddr:
                w.write(msg(b"getaddr")); await w.drain(); sent_getaddr=True
    except Exception:
        pass
    finally:
        if w:
            try: w.close()
            except Exception: pass

async def worker(q):
    while time.time()<deadline:
        try: host,port = await asyncio.wait_for(q.get(), 3)
        except asyncio.TimeoutError: return
        await probe(host,port)

async def main():
    global deadline
    deadline=time.time()+BUDGET_S
    try:  # warm start: onion addresses discovered by previous runs
        for h,p in json.load(open(ONION_CACHE)):
            enqueue((h,int(p)))
        print(f"[census] warm cache: {tor_q.qsize()} onion addresses loaded")
    except Exception:
        print("[census] no onion cache yet — cold start on Tor")
    for s in SEEDS:
        try:
            for fam,_,_,_,sa in socket.getaddrinfo(s,8333,proto=socket.IPPROTO_TCP):
                enqueue((sa[0],8333))
        except OSError: pass
    tor_up=True
    try: (await asyncio.wait_for(asyncio.open_connection(SOCKS_HOST,SOCKS_PORT),3))[1].close()
    except Exception:
        tor_up=False
        print("[census] WARNING: no Tor SOCKS on 9050 — onion peers will be collected but not dialed")
    print(f"[census] seeded {clear_q.qsize()} addresses; budget {BUDGET_S}s; tor={'up' if tor_up else 'DOWN'}")
    workers=[worker(clear_q) for _ in range(CLEAR_CONNS)]
    if tor_up: workers+=[worker(tor_q) for _ in range(TOR_CONNS)]
    await asyncio.gather(*workers)
    is_tor=lambda k: ".onion:" in k
    ct=sum(1 for k in agents if not is_tor(k)); tt=len(agents)-ct
    kn=lambda keys: sum(1 for k in keys if re.search(r"knots", agents[k], re.I))
    ck=kn([k for k in agents if not is_tor(k)]); tk=kn([k for k in agents if is_tor(k)])
    total=len(agents); knots=ck+tk
    print(f"[census] handshaked {total} reachable ({ct} clearnet + {tt} tor); {knots} Knots ({ck}+{tk})")
    print(f"[census] onion addresses discovered: {sum(1 for hp in seen if hp[0].endswith('.onion'))}")
    top={}
    for ua in agents.values(): top[ua]=top.get(ua,0)+1
    for ua,c in sorted(top.items(), key=lambda x:-x[1])[:10]:
        print(f"[census]   {c:5d}  {ua}")
    out={"total":total,"knots":knots,
         "updated":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
         "method":"mrm-census v2.1 - clearnet + Tor reachable (addrv2 crawl, warm onion cache)",
         "clearnet":{"total":ct,"knots":ck},
         "tor":{"total":tt,"knots":tk}}
    with open("nodes.json","w") as f: json.dump(out,f)
    print("[census] wrote nodes.json:", out)
    onions=sorted(hp for hp in seen if hp[0].endswith(".onion"))[:30000]
    with open(ONION_CACHE,"w") as f: json.dump([[h,p] for h,p in onions],f)
    print(f"[census] cached {len(onions)} onion addresses for the next run")

asyncio.run(main())
