"""
Research-Grade Malware Dataset Builder v3.0
============================================
Implements all improvements from the design review:

  - Async downloads (aiohttp) with exponential backoff + semaphore rate limiting
  - Partitioned Parquet output (by family + architecture) with ZSTD compression
  - Hybrid function detection: prologue scan + ret-based splitting
  - Extended register normalization (zmm0-31, AVX-512, GPU, vendor extensions)
  - Richer per-function metadata (num_mem_ops, num_calls, avg_instr_len, entropy)
  - Structured logging with context (family, sha256, exception type)
  - Manifest file for reproducibility (versions, timestamps, API responses)
  - Graceful partial-download recovery + ZIP truncation validation
  - Modular design: each concern is a separate class/function
  - Config via families.txt (one family per line)
  - Type hints and docstrings throughout
  - Security: raw bytes only, no execution, magic-byte validation
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.metadata
import json
import logging
import math
import os
import re
import sqlite3
import sys
import time
import zlib
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Iterator

import pyzipper
import requests

# ── Optional heavy deps ───────────────────────────────────────
try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    from elftools.elf.elffile import ELFFile
    HAS_ELFTOOLS = True
except ImportError:
    HAS_ELFTOOLS = False

try:
    import pandas as pd
    import pyarrow as pa
    import pyarrow.parquet as pq
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False

from capstone import (
    CS_ARCH_ARM, CS_ARCH_ARM64, CS_ARCH_MIPS, CS_ARCH_X86,
    CS_MODE_32, CS_MODE_64, CS_MODE_ARM,
    CS_MODE_LITTLE_ENDIAN, CS_MODE_MIPS32,
    Cs,
)


# ══════════════════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════════════════

def setup_logging(log_path: str = "dataset_builder.log") -> logging.Logger:
    """Structured logging to stdout + rotating log file."""
    fmt = "%(asctime)s  %(levelname)-8s  [%(context)s]  %(message)s"

    class ContextFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            if not hasattr(record, "context"):
                record.context = "main"
            return True

    handler_file   = logging.FileHandler(log_path, encoding="utf-8")
    handler_stdout = logging.StreamHandler(sys.stdout)
    for h in (handler_file, handler_stdout):
        h.setFormatter(logging.Formatter(fmt))
        h.addFilter(ContextFilter())

    logger = logging.getLogger("dsbuilder")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    logger.addHandler(handler_file)
    logger.addHandler(handler_stdout)
    return logger

log = setup_logging()


def ctx_log(level: str, msg: str, context: str = "main", **kwargs) -> None:
    """Log with structured context field."""
    extra = {"context": context}
    getattr(log, level)(msg, extra=extra, **kwargs)


# ══════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════

@dataclass
class Config:
    """All runtime configuration in one place. Edit here or override via CLI."""

    data_root:       str  = r"C:\binary_pairs\training_data"
    output_dir:      str  = r"C:\binary_pairs\dataset"
    zip_password:    bytes = b"infected"

    # Dataset targets
    min_families:    int  = 250
    max_families:    int  = 500
    samples_per_fam: int  = 25

    # Function extraction
    min_instructions: int = 10
    max_instructions: int = 5000

    # Performance
    workers:         int  = max(1, (os.cpu_count() or 4) - 1)
    batch_size:      int  = 5000
    dl_concurrency:  int  = 8       # async download slots
    dl_delay:        float = 0.5    # seconds between individual downloads
    max_retries:     int  = 4

    # Parquet
    parquet_row_group_mb: int = 256  # target row group size in MB
    parquet_compression:  str = "zstd"

    # Families config file (one family per line); overrides embedded list if present
    families_file:   str  = "families.txt"

    # MalwareBazaar API key — required for get_file downloads
    # Register free at https://mb-api.abuse.ch/
    bazaar_api_key:  str  = ""


CFG = Config()

# COLAB: If running in Google Colab, mount Google Drive and adjust paths
if 'google.colab' in sys.modules or os.getenv('COLAB_GPU'):
    try:
        # Attempt to mount Google Drive
        from google.colab import drive  # type: ignore
        # Mount drive at /content/drive; force_remount ensures mount if previously mounted
        drive.mount('/content/drive', force_remount=True)
    except Exception:
        # If mounting fails (e.g., already mounted), proceed without raising
        pass
    # Set data_root and output_dir to locations within the user's Google Drive
    CFG.data_root  = '/content/drive/MyDrive/binary_pairs/training_data'
    CFG.output_dir = '/content/drive/MyDrive/binary_pairs/dataset'
    # Create directories if they do not exist
    os.makedirs(CFG.data_root, exist_ok=True)
    os.makedirs(CFG.output_dir, exist_ok=True)


# ══════════════════════════════════════════════════════════════
# MALWARE FAMILIES
# ══════════════════════════════════════════════════════════════

_DEFAULT_FAMILIES: list[str] = [
    # ransomware
    "WannaCry","Ryuk","Revil","Lockbit","Conti","Blackcat","Hive","Darkside",
    "Maze","Netwalker","Dharma","Gandcrab","Cerber","Teslacrypt","Locky",
    "Sodinokibi","Blackmatter","Egregor","Mountlocker","Phobos","Stop","Makop",
    "Babuk","Avoslocker","Cl0p","Cuba","Quantum","Vice","Play","Royal",
    # banking trojans
    "Emotet","Trickbot","Dridex","Zeus","Icedid","Qakbot","Gozi","Ursnif",
    "Panda","Zloader","Banker","Retefe","Tinba","Ramnit","Shylock","Citadel",
    "Neverquest","Corebot","Gootkit","Kronos","Ursnif","Valak","Bokbot","Icedid",
    # rats
    "asyncrat","njrat","quasarrat","remcosrat","darkcomet","gh0strat","netwire",
    "revengerat","warzone","blackshades","cybergate","xtreme","adwind",
    "luminosity","spygate","agenttesla","nanocore","imminent","lilith","xworm",
    "dcrat","bitrat","pandora",
    # stealers
    "redline","vidar","raccoon","azorult","formbook","predator","mars","erbium",
    "aurora","titan","loki","pony","hawkeye","lokibot","arkei","masad",
    "blackguard","snake",
    # loaders
    "bazarloader","gootloader","hancitor","smokeloader","guloader",
    "privateloader","amadey","systembc","cobaltstrike","matanbuchus","danabot",
    # botnets
    "mirai","bashlite","mozi","hajime","gafgyt","satori","reaper","xorddos",
    "botenago","fodcha","muhstik","tsunami","echobot","rapperbot","darknexus",
    # backdoors / rootkits
    "necurs","zeroaccess","azazel","gapz","sinowal","rovnix","alureon",
    "rustock","cutwail","kelihos",
    # miners
    "xmrig","coinminer","wannamine","powerghost","glupteba","crackonosh",
    "massminer","nrsminer",
    # apt / spyware
    "finfisher","regin","flame","duqu","carbanak","turla","lazarus","winnti",
    # recent
    "blackbasta","nokoyawa","akira","cactus","rhysida","hunters","ransomhub",
    "3am","trigona","bianlian","monti","agenda","luna","dragonforce","killsec",
    # classic
    "conficker","stuxnet","blaster","sasser","mydoom","netsky","slammer",
    "codered","nimda","bagle","sobig","klez","virut","virlock","expiro","neshta",
]


def load_families(cfg: Config) -> list[str]:
    """
    Load families from external file if present, else use built-in list.
    Deduplicates (case-insensitive) and caps at max_families.
    """
    if Path(cfg.families_file).exists():
        raw = Path(cfg.families_file).read_text(encoding="utf-8").splitlines()
        families = [l.strip() for l in raw if l.strip() and not l.startswith("#")]
        ctx_log("info", f"Loaded {len(families)} families from {cfg.families_file}")
    else:
        families = _DEFAULT_FAMILIES

    seen: set[str] = set()
    deduped: list[str] = []
    for f in families:
        k = f.lower()
        if k not in seen:
            seen.add(k)
            deduped.append(f)

    return deduped[:cfg.max_families]


# ══════════════════════════════════════════════════════════════
# INSTRUCTION NORMALIZER
# ══════════════════════════════════════════════════════════════

# Covers: general-purpose, r8-r15 variants, all SIMD (xmm/ymm/zmm 0-31),
# MMX, x87 stack, AVX-512 mask (k0-k7), control/debug/segment, TMM (AMX),
# vendor tile registers
_REG_PATTERN = re.compile(
    r"\b("  # word boundary and group start
    # General purpose 64/32/16/8
    r"r?[abcd]x|r?[abcd][hl]|r[abcd]x|"
    r"r\d{1,2}[dwb]?|"
    r"[er]?(si|di|bp|sp)|"
    # SIMD: xmm/ymm/zmm 0-31
    r"[xyz]mm(?:[12]?\d|3[01])|"
    # AMX tile registers
    r"tmm[0-7]|"
    # MMX
    r"mm[0-7]|"
    # x87
    r"st(?:\(\d\)|\d)?|"
    # AVX-512 opmask
    r"k[0-7]|"
    # Control / debug
    r"cr\d|dr\d|"
    # Segment
    r"[cdefgs]s|"
    # IP / FLAGS
    r"r?ip|r?flags|eflags"
    r")\b",
    re.IGNORECASE,
)

_RET_MNEMONICS: frozenset[str] = frozenset(
    {"ret", "retn", "retf", "iret", "iretd", "iretq"}
)

_PROLOGUE_MNEMONICS: frozenset[str] = frozenset(
    {"push", "endbr64", "endbr32", "sub"}
)
_PROLOGUE_OPS: frozenset[str] = frozenset({"rbp", "ebp"})


def normalize_operand(op: str) -> str:
    """Normalize a single instruction operand to a semantic token."""
    op = op.strip().lower()
    if not op:
        return ""
    if "[" in op:
        return "<MEM>"
    if _REG_PATTERN.search(op):
        return "<REG>"
    if op.startswith(("0x", "-0x")) or op.lstrip("-").isdigit():
        return "<IMM>"
    return "<ADDR>"


def normalize_instruction(mnemonic: str, op_str: str) -> str:
    """Normalize a full instruction to 'mnemonic <TOKEN>, <TOKEN>' form."""
    mnemonic = mnemonic.strip().lower()
    if not op_str.strip():
        return mnemonic
    ops = [normalize_operand(o) for o in op_str.split(",")]
    return mnemonic + " " + ", ".join(filter(None, ops))


# ══════════════════════════════════════════════════════════════
# ARCHITECTURE DETECTION
# ══════════════════════════════════════════════════════════════

@dataclass
class BinaryInfo:
    arch:     int
    mode:     int
    arch_str: str
    sections: list[bytes]


def _parse_pe(data: bytes) -> BinaryInfo | None:
    """Parse PE header for architecture and executable sections."""
    if not HAS_PEFILE:
        # Manual fallback: PE optional header magic
        try:
            e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
            machine  = int.from_bytes(data[e_lfanew + 4: e_lfanew + 6], "little")
            magic    = int.from_bytes(data[e_lfanew + 24:e_lfanew + 26], "little")
            arch, mode, arch_str = {
                0x8664: (CS_ARCH_X86, CS_MODE_64, "x64"),
                0x014c: (CS_ARCH_X86, CS_MODE_32, "x86"),
                0x01c4: (CS_ARCH_ARM, CS_MODE_ARM, "ARM"),
                0xAA64: (CS_ARCH_ARM64, CS_MODE_ARM, "ARM64"),
            }.get(machine, (CS_ARCH_X86, CS_MODE_64 if magic == 0x20B else CS_MODE_32, "x64"))
            return BinaryInfo(arch, mode, arch_str, [data])
        except Exception:
            return None

    try:
        pe = pefile.PE(data=data, fast_load=False)
        machine = pe.FILE_HEADER.Machine
        arch, mode, arch_str = {
            0x8664: (CS_ARCH_X86,  CS_MODE_64,  "x64"),
            0x014C: (CS_ARCH_X86,  CS_MODE_32,  "x86"),
            0x01C4: (CS_ARCH_ARM,  CS_MODE_ARM, "ARM"),
            0xAA64: (CS_ARCH_ARM64,CS_MODE_ARM, "ARM64"),
        }.get(machine, (CS_ARCH_X86, CS_MODE_64, "x64"))

        sections = [
            s.get_data()
            for s in pe.sections
            if s.Characteristics & 0x20000000  # IMAGE_SCN_MEM_EXECUTE
        ]
        return BinaryInfo(arch, mode, arch_str, sections or [data])
    except Exception as e:
        ctx_log("debug", f"pefile failed: {e}", "parse_pe")
        return None


def _parse_elf(data: bytes) -> BinaryInfo | None:
    """Parse ELF header for architecture and executable sections."""
    if not HAS_ELFTOOLS:
        try:
            e_machine = int.from_bytes(data[18:20], "little")
            arch, mode, arch_str = {
                0x3E: (CS_ARCH_X86,   CS_MODE_64,  "x64"),
                0x03: (CS_ARCH_X86,   CS_MODE_32,  "x86"),
                0x28: (CS_ARCH_ARM,   CS_MODE_ARM, "ARM"),
                0xB7: (CS_ARCH_ARM64, CS_MODE_ARM, "ARM64"),
            }.get(e_machine, (CS_ARCH_X86, CS_MODE_64, "x64"))
            return BinaryInfo(arch, mode, arch_str, [data])
        except Exception:
            return None

    try:
        elf       = ELFFile(BytesIO(data))
        m         = elf.header["e_machine"]
        endian    = (CS_MODE_LITTLE_ENDIAN
                     if elf.header["e_ident"]["EI_DATA"] == "ELFDATA2LSB"
                     else 0)
        arch, mode, arch_str = {
            "EM_X86_64":  (CS_ARCH_X86,   CS_MODE_64,               "x64"),
            "EM_386":     (CS_ARCH_X86,   CS_MODE_32,               "x86"),
            "EM_ARM":     (CS_ARCH_ARM,   CS_MODE_ARM,              "ARM"),
            "EM_AARCH64": (CS_ARCH_ARM64, CS_MODE_ARM,              "ARM64"),
            "EM_MIPS":    (CS_ARCH_MIPS,  CS_MODE_MIPS32 | endian,  "MIPS"),
        }.get(m, (CS_ARCH_X86, CS_MODE_64, "x64"))

        sections = [
            s.data()
            for s in elf.iter_sections()
            if s["sh_flags"] & 0x4 and s.data_size > 0  # SHF_EXECINSTR
        ]
        return BinaryInfo(arch, mode, arch_str, sections or [data])
    except Exception as e:
        ctx_log("debug", f"pyelftools failed: {e}", "parse_elf")
        return None


def parse_binary(data: bytes) -> BinaryInfo | None:
    """Detect format by magic bytes and parse accordingly."""
    if data[:2] == b"MZ":
        return _parse_pe(data)
    if data[:4] == b"\x7fELF":
        return _parse_elf(data)
    return None


# ══════════════════════════════════════════════════════════════
# FUNCTION EXTRACTOR
# ══════════════════════════════════════════════════════════════

@dataclass
class FunctionRecord:
    """One extracted function with all metadata."""
    architecture:    str
    function_length: int
    fn_hash:         str
    instructions:    bytes   # zlib-compressed newline-joined normalized asm
    num_mem_ops:     int
    num_calls:       int
    avg_instr_len:   float
    entropy:         float


def _byte_entropy(data: bytes) -> float:
    """Shannon entropy of raw bytes (0.0 – 8.0)."""
    if not data:
        return 0.0
    freq   = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum(
        (c / n) * math.log2(c / n)
        for c in freq if c > 0
    )


def _is_prologue(mnemonic: str, op_str: str) -> bool:
    """Heuristic: does this instruction look like a function start?"""
    m = mnemonic.lower()
    if m in ("endbr64", "endbr32"):
        return True
    if m == "push" and op_str.strip().lower() in _PROLOGUE_OPS:
        return True
    if m == "sub" and "rsp" in op_str.lower():
        return True
    return False


def extract_functions(data: bytes, cfg: Config) -> list[FunctionRecord]:
    """
    Hybrid function extractor:
      - Splits on prologue patterns (push rbp, endbr64, sub rsp) for start
      - Splits on ret-family instructions for end
      - Falls back to pure ret-based splitting if no prologues found
    Returns a list of FunctionRecord for functions within [min, max] instruction bounds.
    """
    info = parse_binary(data)
    if info is None:
        return []

    md = Cs(info.arch, info.mode)
    md.detail = False

    records: list[FunctionRecord] = []

    for sec_data in info.sections:
        all_insns = list(md.disasm(sec_data, 0x1000))
        if not all_insns:
            continue

        # Detect prologue split points
        split_pts = [
            i for i, ins in enumerate(all_insns)
            if _is_prologue(ins.mnemonic, ins.op_str)
        ]

        # If too few prologues detected (<5% of rets), fall back to pure ret split
        ret_count = sum(1 for ins in all_insns if ins.mnemonic.lower() in _RET_MNEMONICS)
        use_prologue = len(split_pts) > max(1, ret_count * 0.05)

        if use_prologue:
            split_pts.append(len(all_insns))
            ranges = [(split_pts[i], split_pts[i+1]) for i in range(len(split_pts)-1)]
        else:
            # ret-based: accumulate until ret
            ranges = []
            start  = 0
            for i, ins in enumerate(all_insns):
                if ins.mnemonic.lower() in _RET_MNEMONICS:
                    ranges.append((start, i + 1))
                    start = i + 1

        for start, end in ranges:
            chunk = all_insns[start:end]
            if not (cfg.min_instructions <= len(chunk) <= cfg.max_instructions):
                continue

            norm_list = [
                normalize_instruction(ins.mnemonic, ins.op_str)
                for ins in chunk
            ]
            joined    = " \n ".join(norm_list)
            fn_hash   = hashlib.sha256(joined.encode()).hexdigest()
            compressed = zlib.compress(joined.encode(), level=6)

            # Rich metadata
            num_mem_ops   = sum(1 for ins in chunk if "[" in ins.op_str)
            num_calls     = sum(1 for ins in chunk if ins.mnemonic.lower() in ("call", "bl", "blx"))
            avg_instr_len = sum(len(n) for n in norm_list) / max(len(norm_list), 1)
            entropy       = _byte_entropy(sec_data[
                chunk[0].address - 0x1000: chunk[-1].address + chunk[-1].size - 0x1000
            ] if chunk else b"")

            records.append(FunctionRecord(
                architecture    = info.arch_str,
                function_length = len(chunk),
                fn_hash         = fn_hash,
                instructions    = compressed,
                num_mem_ops     = num_mem_ops,
                num_calls       = num_calls,
                avg_instr_len   = round(avg_instr_len, 3),
                entropy         = round(entropy, 4),
            ))

    return records


# ══════════════════════════════════════════════════════════════
# WORKER  (subprocess)
# ══════════════════════════════════════════════════════════════

def worker_process_binary(
    args: tuple[str, str, bool, Config]
) -> tuple[str, str, list[FunctionRecord], str, str]:
    """
    Multiprocessing worker: reads binary (zip or direct), extracts functions.
    Returns (binary_name, family, records, status, path).
    """
    path, family, from_zip, cfg = args
    binary_name = Path(path).name

    try:
        raw: bytes | None = None

        if from_zip:
            # Validate zip is not truncated
            fsize = os.path.getsize(path)
            if fsize < 22:  # minimum valid ZIP
                return binary_name, family, [], "fail:truncated_zip", path

            try:
                with pyzipper.AESZipFile(path) as z:
                    z.pwd = cfg.zip_password
                    for name in z.namelist():
                        candidate = z.read(name)
                        # Magic-byte validation — skip readme/sig etc.
                        if candidate[:2] == b"MZ" or candidate[:4] == b"\x7fELF":
                            raw = candidate
                            break
            except Exception as e:
                return binary_name, family, [], f"fail:zip_error:{type(e).__name__}", path
        else:
            with open(path, "rb") as f:
                raw = f.read()

        if not raw:
            return binary_name, family, [], "ok:no_pe_elf_in_zip", path

        # Validate binary is not truncated (PE: check DOS/PE headers readable)
        if raw[:2] == b"MZ" and len(raw) < 0x40:
            return binary_name, family, [], "fail:truncated_pe", path

        records = extract_functions(raw, cfg)
        return binary_name, family, records, "ok", path

    except MemoryError:
        return binary_name, family, [], "fail:oom", path
    except Exception as e:
        return binary_name, family, [], f"fail:{type(e).__name__}", path


# ══════════════════════════════════════════════════════════════
# DATABASE
# ══════════════════════════════════════════════════════════════

def init_db(db_path: str) -> sqlite3.Connection:
    """Initialize SQLite database with WAL mode and full schema."""
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA cache_size=-131072")  # 128 MB cache
    conn.execute("PRAGMA mmap_size=1073741824") # 1 GB mmap

    conn.execute("""
        CREATE TABLE IF NOT EXISTS functions (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            family           TEXT    NOT NULL,
            binary_name      TEXT    NOT NULL,
            architecture     TEXT    NOT NULL,
            function_length  INTEGER NOT NULL,
            fn_hash          TEXT    NOT NULL UNIQUE,
            instructions     BLOB    NOT NULL,
            num_mem_ops      INTEGER NOT NULL DEFAULT 0,
            num_calls        INTEGER NOT NULL DEFAULT 0,
            avg_instr_len    REAL    NOT NULL DEFAULT 0.0,
            entropy          REAL    NOT NULL DEFAULT 0.0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS processed_files (
            path     TEXT PRIMARY KEY,
            family   TEXT NOT NULL,
            status   TEXT NOT NULL,
            added_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_family ON functions(family)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_arch   ON functions(architecture)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_len    ON functions(function_length)")
    conn.commit()
    return conn


def flush_batch(conn: sqlite3.Connection, batch: list[tuple]) -> int:
    """Batch-insert functions with executemany. Returns count inserted."""
    try:
        cur = conn.executemany("""
            INSERT OR IGNORE INTO functions
            (family, binary_name, architecture, function_length,
             fn_hash, instructions, num_mem_ops, num_calls, avg_instr_len, entropy)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, batch)
        conn.commit()
        return cur.rowcount
    except sqlite3.Error as e:
        ctx_log("error", f"Batch insert failed: {e}", "db")
        return 0


def print_stats(conn: sqlite3.Connection) -> None:
    total   = conn.execute("SELECT COUNT(*) FROM functions").fetchone()[0]
    fams    = conn.execute("SELECT COUNT(DISTINCT family) FROM functions").fetchone()[0]
    done    = conn.execute("SELECT COUNT(*) FROM processed_files WHERE status='ok'").fetchone()[0]
    failed  = conn.execute("SELECT COUNT(*) FROM processed_files WHERE status != 'ok'").fetchone()[0]

    print("\n" + "=" * 62)
    print("  DATASET STATS")
    print("=" * 62)
    print(f"  Total unique functions : {total:,}")
    print(f"  Families               : {fams}")
    print(f"  Binaries processed     : {done}")
    print(f"  Binaries failed        : {failed}")
    print("=" * 62)

    rows = conn.execute("""
        SELECT family,
               COUNT(*) as fns,
               AVG(function_length) as avg_len,
               AVG(entropy) as avg_ent
        FROM functions
        GROUP BY family
        ORDER BY fns DESC
    """).fetchall()
    print(f"\n  {'Family':<28} {'Functions':>10} {'Avg Len':>9} {'Avg Ent':>9}")
    print("  " + "-" * 58)
    for fam, fns, avg_len, avg_ent in rows:
        print(f"  {fam:<28} {fns:>10,} {avg_len:>9.1f} {avg_ent:>9.3f}")
    print()


# ══════════════════════════════════════════════════════════════
# PARTITIONED PARQUET EXPORT
# ══════════════════════════════════════════════════════════════

def export_parquet_partitioned(db_path: str, output_dir: str, cfg: Config) -> None:
    """
    Export to Parquet partitioned by family and architecture.
    Uses ZSTD compression, 256MB row groups, dictionary encoding for low-cardinality cols.
    Streams via pandas chunking — never loads full dataset into RAM.
    """
    if not HAS_PANDAS:
        ctx_log("warning", "pandas/pyarrow not installed — skipping parquet export", "export")
        return

    parquet_root = Path(output_dir) / "parquet"
    parquet_root.mkdir(exist_ok=True)
    ctx_log("info", f"Exporting partitioned Parquet → {parquet_root}", "export")

    conn  = sqlite3.connect(db_path)
    query = """
        SELECT family, binary_name, architecture, function_length,
               fn_hash, instructions, num_mem_ops, num_calls, avg_instr_len, entropy
        FROM functions
        ORDER BY family, architecture
    """

    # Group writers by (family, arch) partition
    writers: dict[tuple[str,str], pq.ParquetWriter] = {}
    rows_written = 0

    # Target ~256MB row groups: estimate ~500 bytes avg per row
    bytes_per_row  = 500
    chunk_rows     = max(10_000, (cfg.parquet_row_group_mb * 1024 * 1024) // bytes_per_row)

    for chunk in pd.read_sql_query(query, conn, chunksize=chunk_rows):
        # Decompress instructions
        chunk["instructions"] = chunk["instructions"].apply(
            lambda x: zlib.decompress(bytes(x)).decode()
            if isinstance(x, (bytes, bytearray, memoryview)) else x
        )

        # Write each (family, arch) partition separately
        for (family, arch), part in chunk.groupby(["family", "architecture"]):
            part_key  = (family, arch)
            part_dir  = parquet_root / f"family={family}" / f"arch={arch}"
            part_dir.mkdir(parents=True, exist_ok=True)
            part_path = str(part_dir / "data.parquet")

            table = pa.Table.from_pandas(
                part.reset_index(drop=True),
                preserve_index=False
            )

            if part_key not in writers:
                writers[part_key] = pq.ParquetWriter(
                    part_path,
                    table.schema,
                    compression=cfg.parquet_compression,
                    use_dictionary=["family", "architecture"],
                    write_statistics=True,
                )

            writers[part_key].write_table(table)
            rows_written += len(part)

        if rows_written % 500_000 == 0 and rows_written:
            ctx_log("info", f"Exported {rows_written:,} rows...", "export")

    for writer in writers.values():
        writer.close()

    conn.close()
    ctx_log("info", f"Parquet export complete: {rows_written:,} rows, "
            f"{len(writers)} partition(s)", "export")


# ══════════════════════════════════════════════════════════════
# MANIFEST  (reproducibility)
# ══════════════════════════════════════════════════════════════

def write_manifest(output_dir: str, cfg: Config, families: list[str]) -> None:
    """
    Write a manifest.json with environment, config, and family list.
    Append-safe: loads existing manifest and merges.
    """
    manifest_path = Path(output_dir) / "manifest.json"

    def pkg_version(name: str) -> str:
        try:
            return importlib.metadata.version(name)
        except Exception:
            return "unknown"

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "python_version": sys.version,
        "dependencies": {
            pkg: pkg_version(pkg)
            for pkg in ["pefile","pyelftools","capstone","pyzipper",
                        "pandas","pyarrow","requests","aiohttp"]
        },
        "config": {
            k: v for k, v in asdict(cfg).items()
            if k != "zip_password"  # never log password
        },
        "families": families,
        "family_count": len(families),
    }

    history: list[dict] = []
    if manifest_path.exists():
        try:
            history = json.loads(manifest_path.read_text())
            if not isinstance(history, list):
                history = [history]
        except Exception:
            pass

    history.append(entry)
    manifest_path.write_text(json.dumps(history, indent=2, default=str))
    ctx_log("info", f"Manifest written → {manifest_path}", "manifest")


# ══════════════════════════════════════════════════════════════
# ASYNC DOWNLOADER
# ══════════════════════════════════════════════════════════════

BAZAAR_API = "https://mb-api.abuse.ch/api/v1/"


def _is_pe_or_elf_sample(sample: dict) -> bool:
    """Best-effort PE/ELF filter tolerant to API field variations."""
    haystack = " ".join([
        str(sample.get("file_type", "")),
        str(sample.get("file_type_mime", "")),
        str(sample.get("file_information", "")),
        str(sample.get("file_name", "")),
    ]).lower()

    binary_markers = (
        "exe", "dll", "elf", "pe32", "pe32+", "win32 exe", "win64 exe",
        "x-dosexec", "x-executable", "x-sharedlib", "application/x-msdownload",
    )
    return any(marker in haystack for marker in binary_markers)


async def _query_bazaar_async(
    session: "aiohttp.ClientSession",
    tag: str,
    limit: int = 100
) -> list[dict]:
    """Query MalwareBazaar by tag, then by signature, with exponential backoff."""
    for query_type in ("get_taginfo", "get_siginfo"):
        key   = "tag" if query_type == "get_taginfo" else "signature"
        data  = {"query": query_type, key: tag, "limit": limit}
        if CFG.bazaar_api_key:
            data["apikey"] = CFG.bazaar_api_key
        delay = 1.0
        for attempt in range(CFG.max_retries):
            try:
                async with session.post(BAZAAR_API, data=data, timeout=aiohttp.ClientTimeout(total=30)) as r:
                    if r.status == 429:
                        await asyncio.sleep(delay)
                        delay *= 2
                        continue
                    j = await r.json(content_type=None)
                    if j.get("query_status") == "ok" and j.get("data"):
                        return j["data"]
                    break
            except Exception as e:
                ctx_log("debug", f"Query attempt {attempt+1} failed for '{tag}': {e}", "downloader")
                await asyncio.sleep(delay)
                delay *= 2
    return []


async def _download_sample_async(
    session: "aiohttp.ClientSession",
    sha256: str,
    dest: str,
    sem: asyncio.Semaphore,
) -> bool:
    """Download one sample zip with semaphore rate limiting and exponential backoff."""
    if Path(dest).exists():
        return True

    async with sem:
        delay = 1.0
        post_data: dict = {"query": "get_file", "sha256_hash": sha256}
        if CFG.bazaar_api_key:
            post_data["apikey"] = CFG.bazaar_api_key
        for attempt in range(CFG.max_retries):
            try:
                async with session.post(
                    BAZAAR_API,
                    data=post_data,
                    timeout=aiohttp.ClientTimeout(total=90),
                ) as r:
                    if r.status == 429:
                        await asyncio.sleep(delay)
                        delay *= 2
                        continue
                    ct = r.headers.get("content-type", "")
                    if r.status == 200 and ("zip" in ct or "octet" in ct):
                        # Write to temp file first, rename on success (atomic)
                        tmp = dest + ".tmp"
                        with open(tmp, "wb") as f:
                            async for chunk in r.content.iter_chunked(8192):
                                f.write(chunk)
                        # Validate: minimum valid ZIP = 22 bytes
                        if Path(tmp).stat().st_size >= 22:
                            os.replace(tmp, dest)
                            await asyncio.sleep(CFG.dl_delay)
                            return True
                        else:
                            os.remove(tmp)
                            return False
                    # Log unexpected response so silent 0/N failures are diagnosable
                    body_preview = (await r.text())[:200]
                    ctx_log("warning",
                        f"get_file rejected: status={r.status} ct='{ct}' body={body_preview!r}",
                        sha256[:12])
                    return False
            except Exception as e:
                ctx_log("debug", f"Download attempt {attempt+1} failed: {e}", sha256[:12])
                await asyncio.sleep(delay)
                delay *= 2
        return False


async def _download_family_async(
    session: "aiohttp.ClientSession",
    family: str,
    data_root: str,
    target: int,
    state: dict,
    output_dir: str,
    sem: asyncio.Semaphore,
) -> int:
    """Download up to `target` PE/ELF samples for one family."""
    fam_key   = re.sub(r"[^a-z0-9_]", "_", family.lower())
    fam_dir   = Path(data_root) / fam_key
    fam_state = state.get(fam_key, {"downloaded": 0, "done": False})

    if fam_state.get("done"):
        ctx_log("info", f"[{family}] already complete — skip", "downloader")
        return fam_state["downloaded"]

    ctx_log("info", f"[{family}] Querying MalwareBazaar...", "downloader")
    samples = await _query_bazaar_async(session, family)

    pe_elf = [s for s in samples if _is_pe_or_elf_sample(s)]

    if len(pe_elf) < 3:
        ctx_log("warning", f"[{family}] Only {len(pe_elf)} PE/ELF samples — skip", "downloader")
        state[fam_key] = {"downloaded": 0, "done": False, "skipped": True}
        return 0

    fam_dir.mkdir(exist_ok=True)
    downloaded = fam_state.get("downloaded", 0)
    tasks: list[asyncio.Task] = []

    for sample in pe_elf[:target + 5]:
        if downloaded >= target:
            break
        sha256    = sample.get("sha256_hash", "")
        file_name = re.sub(r'[\\/:*?"<>|]', "_", sample.get("file_name", sha256[:16]) or sha256[:16])
        dest      = str(fam_dir / f"{sha256[:12]}_{file_name}.zip")
        if Path(dest).exists():
            downloaded += 1
            continue
        tasks.append(asyncio.create_task(
            _download_sample_async(session, sha256, dest, sem)
        ))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if r is True:
            downloaded += 1

    done = downloaded >= target
    state[fam_key] = {"downloaded": downloaded, "done": done}
    ctx_log("info", f"[{family}] {downloaded}/{target} samples downloaded", "downloader")
    return downloaded


async def _download_all_async(data_root: str, output_dir: str, families: list[str], target: int) -> int:
    """Async entry point for downloading all families."""
    os.makedirs(data_root, exist_ok=True)
    state_path = Path(output_dir) / "download_state.json"
    state: dict = {}
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text())
        except Exception:
            pass

    sem = asyncio.Semaphore(CFG.dl_concurrency)
    connector = aiohttp.TCPConnector(limit=CFG.dl_concurrency)
    total_fams = 0

    async with aiohttp.ClientSession(connector=connector) as session:
        for family in families:
            if total_fams >= CFG.max_families:
                break
            n = await _download_family_async(
                session, family, data_root, target, state, output_dir, sem
            )
            if n > 0:
                total_fams += 1
            # Save state after every family
            state_path.write_text(json.dumps(state, indent=2))

    ctx_log("info", f"Download complete: {total_fams} families", "downloader")
    return total_fams


def download_all_families(data_root: str, output_dir: str, families: list[str], target: int) -> int:
    """Sync entry point — dispatches to async loop if aiohttp available."""
    if HAS_AIOHTTP:
        return asyncio.run(_download_all_async(data_root, output_dir, families, target))

    # Sync fallback
    ctx_log("warning", "aiohttp not installed — using sync downloads (slower)", "downloader")
    os.makedirs(data_root, exist_ok=True)
    state_path = Path(output_dir) / "download_state.json"
    state: dict = {}
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text())
        except Exception:
            pass

    total_fams = 0
    for family in families:
        if total_fams >= CFG.max_families:
            break
        fam_key = re.sub(r"[^a-z0-9_]", "_", family.lower())
        fam_dir = Path(data_root) / fam_key
        fam_state = state.get(fam_key, {"downloaded": 0, "done": False})
        if fam_state.get("done"):
            total_fams += 1
            continue

        ctx_log("info", f"[{family}] Querying...", "downloader")
        # Sync query
        downloaded = fam_state.get("downloaded", 0)
        for query_type, key in (("get_taginfo","tag"),("get_siginfo","signature")):
            try:
                q_data = {"query":query_type, key:family, "limit":100}
                if CFG.bazaar_api_key:
                    q_data["apikey"] = CFG.bazaar_api_key
                r = requests.post(BAZAAR_API, data=q_data, timeout=30)
                data = r.json()
                if data.get("query_status") == "ok" and data.get("data"):
                    pe_elf = [s for s in data["data"] if _is_pe_or_elf_sample(s)]
                    fam_dir.mkdir(exist_ok=True)
                    for sample in pe_elf[:target + 5]:
                        if downloaded >= target:
                            break
                        sha256 = sample.get("sha256_hash","")
                        fname  = re.sub(r'[\\/:*?"<>|]',"_",sample.get("file_name",sha256[:16]) or sha256[:16])
                        dest   = str(fam_dir / f"{sha256[:12]}_{fname}.zip")
                        if Path(dest).exists():
                            downloaded += 1
                            continue
                        delay = 1.0
                        dl_data: dict = {"query": "get_file", "sha256_hash": sha256}
                        if CFG.bazaar_api_key:
                            dl_data["apikey"] = CFG.bazaar_api_key
                        for attempt in range(CFG.max_retries):
                            try:
                                r2 = requests.post(
                                    BAZAAR_API, data=dl_data,
                                    timeout=60, stream=True
                                )
                                ct = r2.headers.get("content-type","")
                                if r2.status_code == 200 and ("zip" in ct or "octet" in ct):
                                    tmp = dest + ".tmp"
                                    with open(tmp,"wb") as f:
                                        for chunk in r2.iter_content(8192):
                                            f.write(chunk)
                                    if Path(tmp).stat().st_size >= 22:
                                        os.replace(tmp, dest)
                                        downloaded += 1
                                    else:
                                        os.remove(tmp)
                                    break
                                else:
                                    body_preview = r2.text[:200]
                                    ctx_log("warning",
                                        f"get_file rejected: status={r2.status_code} ct='{ct}' body={body_preview!r}",
                                        sha256[:12])
                                    break
                            except Exception as e:
                                ctx_log("debug", f"Sync download attempt {attempt+1}: {e}", sha256[:12])
                                time.sleep(delay)
                                delay *= 2
                        time.sleep(CFG.dl_delay)
                    break
            except Exception:
                pass

        done = downloaded >= target
        state[fam_key] = {"downloaded": downloaded, "done": done}
        state_path.write_text(json.dumps(state, indent=2))
        if downloaded > 0:
            total_fams += 1

    return total_fams


# ══════════════════════════════════════════════════════════════
# EXTRACTION PIPELINE
# ══════════════════════════════════════════════════════════════

def run_pipeline(data_root: str, output_dir: str, cfg: Config) -> None:
    """Main extraction pipeline: discover files → multiprocess extract → DB → Parquet."""
    os.makedirs(output_dir, exist_ok=True)
    db_path = os.path.join(output_dir, "functions.db")
    conn    = init_db(db_path)

    processed = {r[0] for r in conn.execute("SELECT path FROM processed_files")}

    tasks: list[tuple] = []
    for family_dir in sorted(d for d in Path(data_root).iterdir() if d.is_dir()):
        for f in family_dir.iterdir():
            p = str(f)
            if p in processed:
                continue
            is_zip = f.suffix.lower() == ".zip"
            if is_zip or f.suffix.lower() in (".exe", ".elf", ""):
                tasks.append((p, family_dir.name, is_zip, cfg))

    if not tasks:
        ctx_log("info", "No new files to process.", "pipeline")
        print_stats(conn)
        conn.close()
        return

    ctx_log("info", f"Processing {len(tasks)} files with {cfg.workers} workers", "pipeline")

    batch:          list[tuple] = []
    total_inserted: int         = 0
    total_done:     int         = 0
    error_counts:   dict[str, int] = {}

    with ProcessPoolExecutor(max_workers=cfg.workers) as executor:
        for result in executor.map(worker_process_binary, tasks, chunksize=10):
            binary_name, family, records, status, path = result

            conn.execute(
                "INSERT OR IGNORE INTO processed_files VALUES (?,?,?,?)",
                (path, family, status, datetime.now(timezone.utc).isoformat())
            )

            if status == "ok" and records:
                for rec in records:
                    batch.append((
                        family, binary_name,
                        rec.architecture, rec.function_length,
                        rec.fn_hash, rec.instructions,
                        rec.num_mem_ops, rec.num_calls,
                        rec.avg_instr_len, rec.entropy,
                    ))

            elif not status.startswith("ok"):
                error_counts[status] = error_counts.get(status, 0) + 1

            if len(batch) >= cfg.batch_size:
                n = flush_batch(conn, batch)
                total_inserted += n
                batch.clear()
                ctx_log("info", f"Running total: {total_inserted:,} functions", "pipeline")

            total_done += 1
            if total_done % 100 == 0:
                ctx_log("info", f"Files: {total_done}/{len(tasks)}", "pipeline")

    if batch:
        total_inserted += flush_batch(conn, batch)

    conn.commit()

    if error_counts:
        ctx_log("warning", f"Error breakdown: {error_counts}", "pipeline")

    ctx_log("info", f"Extraction complete. Unique functions: {total_inserted:,}", "pipeline")
    print_stats(conn)
    export_parquet_partitioned(db_path, output_dir, cfg)
    conn.close()


# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(
        description="Research-Grade Malware Dataset Builder v3.0",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--data",     default=CFG.data_root)
    parser.add_argument("--output",   default=CFG.output_dir)
    parser.add_argument("--mode",     choices=["download","build","all"], default="all",
        help="download=fetch only  build=extract only  all=both")
    parser.add_argument("--families", type=int, default=CFG.max_families,
        help=f"Max families (default {CFG.max_families})")
    parser.add_argument("--samples",  type=int, default=CFG.samples_per_fam,
        help=f"Samples per family (default {CFG.samples_per_fam})")
    parser.add_argument("--workers",  type=int, default=CFG.workers)
    parser.add_argument("--families-file", default=CFG.families_file,
        help="Path to plain-text families list (one per line)")
    parser.add_argument("--api-key", default=CFG.bazaar_api_key,
        help="MalwareBazaar API key (required for file downloads). "
             "Register free at https://mb-api.abuse.ch/")
    args = parser.parse_args()

    # Apply CLI overrides to config
    CFG.data_root      = args.data
    CFG.output_dir     = args.output
    CFG.max_families   = args.families
    CFG.samples_per_fam = args.samples
    CFG.workers        = args.workers
    CFG.families_file  = args.families_file
    CFG.bazaar_api_key = args.api_key

    if not CFG.bazaar_api_key and args.mode in ("download", "all"):
        ctx_log("warning",
            "No --api-key provided. MalwareBazaar file downloads require an API key "
            "(register free at https://mb-api.abuse.ch/). Downloads will likely return 0 samples.",
            "main")

    os.makedirs(CFG.output_dir, exist_ok=True)

    families = load_families(CFG)

    print("\n" + "=" * 62)
    print("  MALWARE DATASET BUILDER  v3.0")
    print(f"  Mode       : {args.mode}")
    print(f"  Families   : up to {CFG.max_families} ({len(families)} loaded)")
    print(f"  Samples    : {CFG.samples_per_fam} per family")
    print(f"  Workers    : {CFG.workers}")
    print(f"  Async DL   : {'yes (aiohttp)' if HAS_AIOHTTP else 'no (sync fallback)'}")
    print(f"  pefile     : {'yes' if HAS_PEFILE else 'no (fallback)'}")
    print(f"  pyelftools : {'yes' if HAS_ELFTOOLS else 'no (fallback)'}")
    print(f"  Parquet    : {'yes (partitioned ZSTD)' if HAS_PANDAS else 'no (pandas missing)'}")
    print(f"  Data dir   : {CFG.data_root}")
    print(f"  Output dir : {CFG.output_dir}")
    print("=" * 62 + "\n")

    write_manifest(CFG.output_dir, CFG, families)

    if args.mode in ("download", "all"):
        n = download_all_families(CFG.data_root, CFG.output_dir, families, CFG.samples_per_fam)
        ctx_log("info", f"Download phase done: {n} families collected.", "main")

    if args.mode in ("build", "all"):
        ctx_log("info", "Starting extraction pipeline...", "main")
        run_pipeline(CFG.data_root, CFG.output_dir, CFG)

    ctx_log("info", "All done!", "main")


if __name__ == "__main__":
    main()
