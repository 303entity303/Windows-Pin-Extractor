#!/usr/bin/env python3
"""
winhello_bruteforce.py
-----------------------
Pure-Python brute-forcer for the hashcat "$WINHELLO$*SHA512*..." hash format
(Windows Hello PIN verification blobs extracted with tools such as
WINHELLO2hashcat).

Hash format:
    $WINHELLO$*SHA512*{pin_iterations}*{pin_salt}*{sign}*{masterkey}*{hmac}*{verif_blob}*{entropy}

Algorithm credit: Banaanhangwagen (hashcat/hashcat#3034). This script is a
direct, verbatim port of that reference implementation -- it does not
reverse-engineer or extend it.

Still pure Python ("hashcat speed" this is NOT), but parallelized across OS
processes (not threads -- CPython's GIL means threads give ~1.0x speedup on
this CPU-bound workload; measured). Each guess runs a PBKDF2-HMAC-SHA256
(pin_iterations rounds, typically 10000) plus a handful of SHA1/SHA512
calls, so expect roughly low-thousands of guesses/second per core. That's
fine for numeric PINs up to 6-8 digits; full alphanumeric brute force still
gets impractical fast even with many cores -- use a narrow length range or
switch to a dictionary/mask-based approach for anything longer.

Usage:
    python3 winhello_bruteforce.py --self-test
    python3 winhello_bruteforce.py '$WINHELLO$*SHA512*10000*...' --mode numeric --max-length 6
    python3 winhello_bruteforce.py --hash-file hash.txt --mode alpha --min-length 1 --max-length 4 --workers 8
"""

import argparse
import binascii
import hashlib
import string
import sys
import time
import multiprocessing as mp


# --------------------------------------------------------------------------
# Hash parsing
# --------------------------------------------------------------------------

def parse_winhello_hash(hash_line: str) -> dict:
    hash_line = hash_line.strip()
    parts = hash_line.split('*')

    if len(parts) < 8 or not parts[0].startswith('$WINHELLO$'):
        raise ValueError(
            "Hash does not look like a $WINHELLO$*SHA512*... line "
            f"(got {len(parts)} '*'-separated fields)."
        )

    algo = parts[1]
    if algo.upper() != 'SHA512':
        raise ValueError(f"Only the SHA512 variant is supported by this script (got '{algo}').")

    pin_iterations = int(parts[2])
    pin_salt = binascii.unhexlify(parts[3])
    sign = binascii.unhexlify(parts[4].strip())
    masterkey = binascii.unhexlify(parts[5])
    hmac_field = binascii.unhexlify(parts[6])
    # defensive: some tool/doc versions prefix verif_blob with a stray quote
    verif_blob_hex = parts[7].lstrip("'").strip()
    verif_blob = binascii.unhexlify(verif_blob_hex)
    entropy = binascii.unhexlify(parts[8].strip()) if len(parts) > 8 and parts[8].strip() else b''

    return {
        'pin_iterations': pin_iterations,
        'pin_salt': pin_salt,
        'sign': sign,
        'masterkey': masterkey,
        'hmac': hmac_field,
        'verif_blob': verif_blob,
        'entropy': entropy,
    }


# --------------------------------------------------------------------------
# Core algorithm (verbatim port of the hashcat/hashcat#3034 reference impl)
# --------------------------------------------------------------------------

def convert_userpin_to_secretpin(user_pin: str, pin_salt: bytes, pin_rounds: int) -> bytes:
    stage1_hexpin = user_pin.encode().hex().upper().encode('UTF-16LE')
    stage2_pbkdf2 = hashlib.pbkdf2_hmac('sha256', stage1_hexpin, pin_salt, pin_rounds)
    stage3_hexconvert = stage2_pbkdf2.hex().upper().encode('UTF-16LE')
    stage4_sha512 = hashlib.sha512(stage3_hexconvert).digest()
    return stage4_sha512


def is_signature_matching(sign: bytes, masterkey: bytes, hmac_val: bytes,
                           verif_blob: bytes, secret_pin: bytes) -> bool:
    sha512_blocksize = 128

    mk = hashlib.sha1(masterkey).digest()
    mk += b'\x00' * 108  # pad SHA1 digest (20 bytes) out to 128 bytes

    sub_digest_seed = bytes(b ^ 0x36 for b in mk)
    main_digest_seed = bytes(b ^ 0x5c for b in mk)

    sub_digest = hashlib.sha512()
    sub_digest.update(sub_digest_seed)
    sub_digest.update(hmac_val)
    sub_digest.update(b'\x78\x54\x35\x72\x5a\x57\x35\x71\x56\x56\x62\x72\x76\x70\x75\x41\x00' + secret_pin)
    sub_digest.update(verif_blob)

    main_digest = hashlib.sha512()
    main_digest.update(main_digest_seed)
    main_digest.update(sub_digest.digest())

    return main_digest.digest() == sign


def try_pin(pin: str, h: dict) -> bool:
    secret_pin = convert_userpin_to_secretpin(pin, h['pin_salt'], h['pin_iterations'])
    return is_signature_matching(h['sign'], h['masterkey'], h['hmac'], h['verif_blob'], secret_pin)


# --------------------------------------------------------------------------
# Brute-force driver (multiprocessing)
#
# Plain Python threads do NOT speed up this workload -- hashlib's
# pbkdf2_hmac/sha1/sha512 calls here are too CPU-bound and the GIL
# serializes them (measured ~1.0x "speedup" with 8 threads on this
# algorithm). Real parallelism needs separate OS processes, which is what
# this does: the search space for each length is split into N contiguous
# index ranges, one per worker process, and each worker independently
# derives its candidate strings from the index (no large data passed
# between processes). A shared Event stops all workers as soon as any one
# of them finds a match.
# --------------------------------------------------------------------------

NUMERIC_CHARSET = string.digits
ALPHANUMERIC_CHARSET = string.ascii_letters + string.digits


def index_to_candidate(index: int, charset: str, length: int) -> str:
    """Map an integer in [0, len(charset)**length) to a candidate string.
    (For numeric charset '0123456789' this happens to yield ascending
    numeric order, e.g. index 0 -> '0000', 1 -> '0001', ...)
    """
    base = len(charset)
    chars = [''] * length
    for i in range(length - 1, -1, -1):
        index, rem = divmod(index, base)
        chars[i] = charset[rem]
    return ''.join(chars)


def _worker_search(h: dict, charset: str, length: int, start_idx: int, end_idx: int,
                    worker_id: int, counters, found_event, result_queue,
                    check_interval: int = 500):
    """Runs in a separate process. Scans [start_idx, end_idx) for this length."""
    local = 0
    try:
        for idx in range(start_idx, end_idx):
            if local % check_interval == 0 and found_event.is_set():
                counters[worker_id] += local
                return

            candidate = index_to_candidate(idx, charset, length)
            local += 1

            if try_pin(candidate, h):
                counters[worker_id] += local
                found_event.set()
                result_queue.put(candidate)
                return

            if local >= check_interval:
                counters[worker_id] += local
                local = 0
    finally:
        counters[worker_id] += local


def brute_force(h: dict, mode: str, min_len: int, max_len: int,
                 custom_charset: str = None, workers: int = None):
    import multiprocessing as mp

    if custom_charset:
        charset = custom_charset
    elif mode == 'numeric':
        charset = NUMERIC_CHARSET
    elif mode == 'alpha':
        charset = ALPHANUMERIC_CHARSET
    else:
        raise ValueError(f"Unknown mode: {mode}")

    if workers is None or workers < 1:
        workers = mp.cpu_count()

    ctx = mp.get_context('spawn')  # consistent, safe behavior on Linux/macOS/Windows
    overall_start = time.time()
    overall_tried = 0

    for length in range(min_len, max_len + 1):
        total = len(charset) ** length

        # Length 0 ("empty PIN") is a single candidate; no need to spin up workers.
        if total <= 1:
            overall_tried += 1
            if try_pin('', h):
                elapsed = time.time() - overall_start
                print(f"\n[+] FOUND: ''  (tried {overall_tried:,} guesses in {elapsed:.1f}s)")
                return ''
            continue

        n_workers = min(workers, total)
        boundaries = [i * total // n_workers for i in range(n_workers + 1)]

        counters = ctx.Array('Q', n_workers)
        found_event = ctx.Event()
        result_queue = ctx.Queue()

        procs = []
        for wid in range(n_workers):
            p = ctx.Process(
                target=_worker_search,
                args=(h, charset, length, boundaries[wid], boundaries[wid + 1],
                      wid, counters, found_event, result_queue),
            )
            p.start()
            procs.append(p)

        length_start = time.time()
        last_report = length_start
        found_pin = None

        try:
            while any(p.is_alive() for p in procs):
                time.sleep(0.2)
                now = time.time()
                if now - last_report >= 1.0:
                    length_tried = sum(counters)
                    rate = length_tried / (now - length_start) if now > length_start else 0
                    print(f"\r[.] length={length} ({n_workers} workers) "
                          f"tried={overall_tried + length_tried:,} rate={rate:,.0f}/s    ",
                          end='', flush=True)
                    last_report = now
                if found_event.is_set():
                    break

            if found_event.is_set():
                found_pin = result_queue.get()
        except KeyboardInterrupt:
            found_event.set()
            raise
        finally:
            # Make sure no worker process is left running, whether we found
            # a match, exhausted this length, or were interrupted.
            for p in procs:
                if p.is_alive():
                    p.terminate()
            for p in procs:
                p.join()

        overall_tried += sum(counters)

        if found_pin is not None:
            elapsed = time.time() - overall_start
            print(f"\n[+] FOUND: '{found_pin}'  (tried {overall_tried:,} guesses in {elapsed:.1f}s)")
            return found_pin

    elapsed = time.time() - overall_start
    print(f"\n[-] Exhausted search space ({overall_tried:,} guesses in {elapsed:.1f}s). PIN not found.")
    return None


# --------------------------------------------------------------------------
# Known-answer self-test
#
# This is hashcat's OWN official self-test vector, taken verbatim from
# src/modules/module_28100.c (ST_HASH / ST_PASS) in the hashcat source tree
# -- i.e. the exact hash hashcat uses to verify its own WINHELLO/SHA512
# kernel is correct. PIN is "hashcat".
# --------------------------------------------------------------------------

ST_HASH = (
    "$WINHELLO$*SHA512*10000*00761655*"
    "3b3d3197efb2839a6072e922cc03be910be55d1e60389689c05b520d2d57c06258dc5a48798ba65"
    "424004cbe2e003d0509036f3394bcae108eb6b77c7eb306d7*"
    "c0772a3aca949db60f274f315b3a5f63fea552fc0d1f2032db5293ca9690735217d918d4cf697aa"
    "45b2fe598168804040e18fe00758be94aac971985ea7a5521*"
    "bff47e398df761733b5aeda7035cdf289547db3afb94b70cbad2aaea21a5cd58*"
    "8a4d5b88832e10bad57303324e6c9021733733df4acbf91366f51cebdc755e00fe1d01b3202469e"
    "e6ad5e667975b4f50e3110b00ef60414cd2cf96cc47df532e36b997727ffec2924d979d3fb6e677"
    "cb5827f4313131a46be8712926c42158339b55183e2fd7f2f0761980b1413897825c3759c566ff8"
    "a438189a6c8fb2d630dc33c6330de45c784d11957c686b40b6fe31fd8f2b1b664f542392326af5d"
    "334fdf92155343335e1b964955ac0b0e6f7254a599f0f0dc99becc2216515ba9e9472a54e60a145"
    "07fc353ebc47b9f0a8249a2a1bfa5d2cf526bd15ee68bd52e944ece9de6bbda913bc5083e262296"
    "73340fcc5285df0d38cbc7bb14584ced2fe9e9b3c283fa3c5ad4dd2034b7a67c8e7a1632fae8979"
    "a0abdd19be91c6bc371966121e04d433923e44df0b60c156bd90bc61c9fed01a7a76353f79dd4da"
    "3e07e12810ec3765128ec44b44b0789d6aa9e9702211a22ab8055ea32e9513fb1bd9d24ca04b332"
    "82632f63ab1b213e9644f97bc31dc4d2e7050c1fa23c0000facbf7c76fd7be4b112586f73f0c27a"
    "bcf7cbe8c9d9fb83af70f60c490936fef84ed5301f73917b4e4170674a5d5e4bfbebdfeda958422"
    "1a0f190545efea7245dd2517ade393bedc255c4e016d9919e6e3f3711bca677fc099bf4e1730a75"
    "2ea2a90a20ff3d09c909771849d3b009ba8d95d2b84fff889e38b079f1325aa42daa067a52abb5c"
    "064de3a5040e4a64e76b397b5c9ee6d045f3b5150cf428a92c141735908bb278077d52beefdc87e"
    "fa156b8ebda071cb425fad0372a8a7cb6eb29926e8f6411ff1b818750c5b6888302fee9b1591b1c"
    "23db131538db2aa3de61dcd76fb7067be7ab71ee372bac18be0f446c974e92e79e27e7e3b2aa5ff"
    "c3f5f923f2df8ac2edcbb9392d1ac35e4cd52037d9dceedec6391e713e78770307bfde6a31b4e11"
    "5904d285ac35db055ae8253b9968b7ed7b948da5f*"
    "785435725a573571565662727670754100"
)
ST_PASS = "hashcat"


def run_self_test():
    h = parse_winhello_hash(ST_HASH)
    ok = try_pin(ST_PASS, h)
    print(f"Self-test PIN '{ST_PASS}' -> {'PASS' if ok else 'FAIL'}")
    return ok


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Brute-force a Windows Hello PIN from a $WINHELLO$*SHA512*... hash."
    )
    parser.add_argument('hash', nargs='?',
                         help="The $WINHELLO$*SHA512*... hash line (or use --hash-file)")
    parser.add_argument('--hash-file', help="Path to a file containing the single hash line")
    parser.add_argument('--mode', choices=['numeric', 'alpha'], default='numeric',
                         help="Charset: 'numeric' (0-9, default) or 'alpha' (a-zA-Z0-9)")
    parser.add_argument('--charset', help="Override with a custom charset string, e.g. 'abc123'")
    parser.add_argument('--min-length', type=int, default=0, help="Minimum PIN length (default: 0)")
    parser.add_argument('--max-length', type=int, help="Maximum PIN length to try (required unless --self-test)")
    parser.add_argument('--workers', type=int, default=None,
                         help="Number of worker processes (default: all CPU cores). "
                              "Use 1 to run single-process.")
    parser.add_argument('--self-test', action='store_true',
                         help="Run the built-in known-answer test vector and exit")
    args = parser.parse_args()

    if args.self_test:
        ok = run_self_test()
        sys.exit(0 if ok else 1)

    if args.max_length is None:
        parser.error("--max-length is required (unless using --self-test)")

    if args.hash_file:
        with open(args.hash_file) as f:
            hash_line = f.read().strip()
    elif args.hash:
        hash_line = args.hash
    else:
        parser.error("Provide a hash as an argument, or use --hash-file")
        return

    try:
        parsed = parse_winhello_hash(hash_line)
    except (ValueError, binascii.Error) as e:
        print(f"Error parsing hash: {e}", file=sys.stderr)
        sys.exit(1)

    import multiprocessing as mp
    n_workers = args.workers if args.workers and args.workers > 0 else mp.cpu_count()

    effective_mode = 'custom' if args.charset else args.mode
    print(f"[*] Loaded hash: iterations={parsed['pin_iterations']} salt={parsed['pin_salt'].hex()}")
    print(f"[*] Mode={effective_mode}  length range=[{args.min_length}, {args.max_length}]  "
          f"workers={n_workers}")

    if args.max_length > 6 and (args.charset or args.mode == 'alpha'):
        print("[!] Warning: alphanumeric/custom-charset brute force beyond ~5-6 chars is "
              "extremely slow (a KDF with "
              f"{parsed['pin_iterations']:,} rounds runs per guess). Consider narrowing "
              "the range.")

    try:
        found = brute_force(parsed, args.mode, args.min_length, args.max_length,
                             args.charset, workers=n_workers)
    except KeyboardInterrupt:
        print("\n[-] Interrupted by user. Worker processes stopped cleanly. "
              "No match found yet -- current run has no resume support, so a "
              "re-run starts this length over from the beginning.")
        sys.exit(130)

    sys.exit(0 if found is not None else 2)


if __name__ == '__main__':
    mp.freeze_support()
    main()
