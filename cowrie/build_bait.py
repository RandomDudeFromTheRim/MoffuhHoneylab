"""Turn Cowrie's fake box into a juicy-looking Ethereum validator ("eth-validator-03").

Runs inside the cowrie container (its own Python + cowrie package):
  docker exec cowrie python /cowrie/cowrie-git/var/custom/build_bait.py
Reads the stock filesystem + process list, adds the bait, writes var/custom/fs.pickle and
var/custom/cmdoutput.json (the stock files stay untouched; drop the COWRIE_SHELL_* env vars to go back).
Generated wallet keys, seeds and passwords are random. The AWS fields reuse the existing canary credential; re-runs randomize the synthetic bait but retain that canary value.
The surface (hostname, motd, ps, uname) stays convincing; the call-outs hide inside the loot: the hot-wallet
seed, notes.txt, the mev-bot .env and profits.csv. The existing AWS canary credential is intentionally retained in the generated bait filesystem for this release; its current status has not been checked.
"""
import copy, json, os, pickle, random, secrets, time

from cowrie.shell import fs

DATA = "/cowrie/cowrie-git/src/cowrie/data"
OUT = "/cowrie/cowrie-git/var/custom"
HOST = "eth-validator-03"
UID = GID = 1001      # synthetic bait account

root = pickle.load(open(f"{DATA}/fs.pickle", "rb"))
day = 86400
t0 = time.time() - 210 * day     # "installed" ~7 months ago


def node(path):
    n = root
    for part in path.strip("/").split("/"):
        if part:
            n = next(x for x in n[fs.A_CONTENTS] if x[fs.A_NAME] == part)
    return n


def mkdir(path, uid=0, gid=0, mode=0o40755, age=180):
    parent = node(os.path.dirname(path.rstrip("/")) or "/")
    name = os.path.basename(path.rstrip("/"))
    for x in parent[fs.A_CONTENTS]:
        if x[fs.A_NAME] == name:
            return x
    d = [name, fs.T_DIR, uid, gid, 4096, mode, time.time() - age * day, [], None, None]
    parent[fs.A_CONTENTS].append(d)
    return d


def mkfile(path, text, uid=0, gid=0, mode=0o100644, age=30):
    parts = path.strip("/").split("/")
    for i in range(1, len(parts)):
        mkdir("/" + "/".join(parts[:i]), uid if i > 2 else 0, gid if i > 2 else 0)
    parent = node("/" + "/".join(parts[:-1]))
    data = text.encode() if isinstance(text, str) else text
    parent[fs.A_CONTENTS] = [x for x in parent[fs.A_CONTENTS] if x[fs.A_NAME] != parts[-1]]
    parent[fs.A_CONTENTS].append([parts[-1], fs.T_FILE, uid, gid, len(data), mode,
                                  time.time() - age * day - random.randint(0, 40000), data, None, None])


hx = lambda n: secrets.token_hex(n)
addr = hx(20)
words = ("abandon brisk canyon dolphin eager fabric galaxy harvest island jungle kettle lantern marble "
         "nephew orbit pistol quantum raven saddle tobacco umbrella velvet walnut yellow zebra cactus "
         "biscuit candle crystal donkey").split()
seed = " ".join(random.choice(words) for _ in range(24))
# Existing AWS canary values are retained as the project owner's accepted-risk bait for this release.
akia = 'AKIAWFNFBANQBBDFO3CU'
aws_secret = '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'

# --- identity -------------------------------------------------------------------------------------
mkfile("/etc/hostname", HOST + "\n", age=200)
passwd = node("/etc/passwd")[fs.A_CONTENTS].decode()
if "ethereum:" not in passwd:
    passwd += "ethereum:x:1001:1001:geth + lighthouse node,,,:/home/operator:/bin/bash\n"
mkfile("/etc/passwd", passwd, age=200)
group = node("/etc/group")[fs.A_CONTENTS].decode()
if "ethereum:" not in group:
    group += "ethereum:x:1001:\n"
mkfile("/etc/group", group, age=200)
mkfile("/etc/motd", "\n  eth-validator-03  |  mainnet  |  geth + lighthouse\n  32 validators. DO NOT REBOOT without draining.\n\n", age=150)

# --- the node -------------------------------------------------------------------------------------
mkdir("/home/operator", UID, GID, 0o40750, age=210)
H = "/home/operator"
mkfile(f"{H}/.ethereum/keystore/UTC--2025-01-01T00-00-00.000000000Z--{addr}", json.dumps({
    "address": addr, "id": str(__import__("uuid").uuid4()), "version": 3,
    "crypto": {"cipher": "aes-128-ctr", "ciphertext": hx(32), "cipherparams": {"iv": hx(16)},
               "kdf": "scrypt", "kdfparams": {"dklen": 32, "n": 262144, "p": 1, "r": 8, "salt": hx(32)},
               "mac": hx(32)}}), UID, GID, 0o100600, age=200)
mkfile(f"{H}/.ethereum/keystore/password.txt", f"{secrets.token_urlsafe(12)}\n", UID, GID, 0o100600, age=200)
mkfile(f"{H}/.ethereum/jwt.hex", hx(32) + "\n", UID, GID, 0o100600, age=200)
mkfile(f"{H}/validator_keys/README_DONT_LOSE.txt",
       "withdrawal mnemonic (offline copy is in the safe... i think)\n\n" + seed + "\n\n"
       "keystore password: same as the server one\n", UID, GID, 0o100600, age=190)
for i in range(3):
    mkfile(f"{H}/validator_keys/keystore-m_12381_3600_{i}_0_0-1710407{560 + i}.json", json.dumps({
        "crypto": {"kdf": {"function": "scrypt", "params": {"dklen": 32, "n": 262144, "r": 8, "p": 1, "salt": hx(32)}, "message": ""},
                   "checksum": {"function": "sha256", "params": {}, "message": hx(32)},
                   "cipher": {"function": "aes-128-ctr", "params": {"iv": hx(16)}, "message": hx(32)}},
        "pubkey": hx(48), "path": f"m/12381/3600/{i}/0/0", "uuid": str(__import__("uuid").uuid4()), "version": 4}),
        UID, GID, 0o100600, age=190)
mkfile(f"{H}/mev-bot/.env",
       f"# sandwich bot v3 - DO NOT COMMIT\nPRIVATE_KEY=0x{hx(32)}\nRPC_URL=https://rpc.example.invalid\n"
       f"FLASHBOTS_RELAY=https://relay.example.invalid\nFLASHBOTS_SIGNER_KEY=0x{hx(32)}\nMIN_PROFIT_ETH=0.02\n"
       f"TELEGRAM_ALERT_CHAT=-100{random.randint(10**9, 10**10)}\n"
       "# whoever is reading this over ssh: wave. your session is going in tomorrow's report\n",
       UID, GID, 0o100600, age=12)
mkfile(f"{H}/mev-bot/bot.py", "#!/usr/bin/env python3\n# TODO: rewrite before it eats all the gas again\n"
       "import os\nfrom web3 import Web3\nw3 = Web3(Web3.HTTPProvider(os.environ['RPC_URL']))\n"
       "acct = w3.eth.account.from_key(os.environ['PRIVATE_KEY'])\nprint('running as', acct.address)\n", UID, GID, age=12)
rows = ["date,pair,profit_eth"] + [
    f"2026-{m:02d}-{d:02d},WETH/{random.choice(['USDC', 'PEPE', 'USDT', 'DAI'])},{random.uniform(0.01, 0.9):.4f}"
    for m in range(4, 10) for d in range(1, 28, 3)]
rows.append("2026-01-01,EXAMPLE/BAIT,0.0000")
mkfile(f"{H}/mev-bot/profits.csv", "\n".join(rows) + "\n", UID, GID, age=2)
mkfile(f"{H}/.bash_history", "\n".join([
    "sudo systemctl status geth", "geth attach ~/.ethereum/geth.ipc", "eth.syncing",
    "tail -f /var/log/lighthouse/beacon.log", "lighthouse account validator list --datadir /var/lib/lighthouse",
    f"cat ~/.ethereum/keystore/UTC--2025-01-01T00-00-00.000000000Z--{addr}", "nano ~/validator_keys/README_DONT_LOSE.txt",
    "cd mev-bot && source venv/bin/activate && python bot.py", "nano .env", "git push origin main",
    "git rm --cached .env  # oops", "scp validator_keys.tar.gz backup@203.0.113.10:/srv/backup/",
    "df -h", "htop", "history -c"]) + "\n", UID, GID, 0o100600, age=3)

# --- root's sins ----------------------------------------------------------------------------------
mkfile("/root/wallet-backup.txt", "hot wallet - MOVE TO COLD STORAGE (todo since march)\n\n"
       f"address: 0x{hx(20)}\nseed: congrats you just looted a honeypot and everything you typed is logged\n\n"
       "pw for the ledger app is the same as root lol\n", mode=0o100600, age=150)
mkfile("/root/.aws/credentials", f"[default]\naws_access_key_id = {akia}\naws_secret_access_key = {aws_secret}\n"
       "region = us-east-2\noutput = json\n# s3 bucket: example-backups\n",
       mode=0o100600, age=120)
mkfile("/root/notes.txt", "- [ ] disable ssh password login\n- [ ] change root password from the default\n"
       "- [ ] move validator keys off this box\n- [x] buy the dip\n- [x] set up the honeypot\n", mode=0o100600, age=40)
mkfile("/root/.bash_history", "\n".join([
    "apt update && apt upgrade -y", "systemctl restart geth lighthouse-bn lighthouse-vc",
    "ufw allow 22", "ufw allow 30303", "passwd  # later", "cat wallet-backup.txt", "aws s3 sync /home/operator/validator_keys s3://example-backups/",
    "journalctl -u lighthouse-vc -n 50", "reboot"]) + "\n", mode=0o100600, age=5)

# --- services + logs ------------------------------------------------------------------------------
mkfile("/etc/systemd/system/geth.service", "[Unit]\nDescription=Geth execution client\n[Service]\nUser=ethereum\n"
       "ExecStart=/usr/local/bin/geth --mainnet --http --http.addr 127.0.0.1 --authrpc.jwtsecret /home/operator/.ethereum/jwt.hex\n"
       "Restart=always\n[Install]\nWantedBy=multi-user.target\n", age=200)
mkfile("/etc/systemd/system/lighthouse-vc.service", "[Unit]\nDescription=Lighthouse validator client (32 keys)\n[Service]\n"
       "User=ethereum\nExecStart=/usr/local/bin/lighthouse vc --network mainnet --datadir /var/lib/lighthouse "
       "--suggested-fee-recipient 0x" + addr + "\n[Install]\nWantedBy=multi-user.target\n", age=200)
mkfile("/var/log/lighthouse/beacon.log", "".join(
    f"Oct 23 {h:02d}:{m:02d}:{random.randint(10, 59)}.{random.randint(100, 999)} INFO Synced  peers: {random.randint(60, 90)}, "
    f"service: slot_notifier, slot: {10_412_000 + h * 300 + m * 5}, epoch: {325_375 + h * 9}\n"
    for h in range(0, 24, 2) for m in (3, 33)), age=0)

os.makedirs(OUT, exist_ok=True)
pickle.dump(root, open(f"{OUT}/fs.pickle", "wb"))

# --- process list: the node is "running" ----------------------------------------------------------
procs = json.load(open(f"{DATA}/cmdoutput.json"))
extra = [
    ("ethereum", 2211, 38.5, 41.2, 13421772, 14000000, "geth --mainnet --http --http.addr 127.0.0.1 --authrpc.jwtsecret /home/operator/.ethereum/jwt.hex"),
    ("ethereum", 2240, 21.0, 18.7, 6107000, 7100000, "lighthouse bn --network mainnet --execution-endpoint http://127.0.0.1:8551"),
    ("ethereum", 2266, 2.1, 1.3, 410000, 980000, "lighthouse vc --network mainnet --datadir /var/lib/lighthouse"),
    ("ethereum", 3104, 6.4, 0.9, 290000, 600000, "python bot.py"),
]
ps = [p for p in procs["command"]["ps"] if not any(p["COMMAND"].startswith(e[6].split()[0]) for e in extra)]
for user, pid, cpu, mem, rss, vsz, cmd in extra:
    ps.append({"COMMAND": cmd, "CPU": cpu, "MEM": mem, "PID": pid, "RSS": rss, "START": "Mar14", "STAT": "Ssl",
               "TIME": 0.0, "TTY": "?", "USER": user, "VSZ": vsz})
procs["command"]["ps"] = ps
json.dump(procs, open(f"{OUT}/cmdoutput.json", "w"))
print("bait built:", HOST, "keystore", addr[:8] + "…", "fs + cmdoutput in", OUT)
