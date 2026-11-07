"""
Bulk URL Status Code Checker (WAF-aware)
=======================================

Checks HTTP status codes for a large list of URLs, follows redirects, and records
the full redirect chain (every hop URL + its status code) plus the final landing
status.

Designed for banking / WAF-protected sites:
  * Sends a full, realistic browser header set.
  * Uses GET (not HEAD - many WAFs block HEAD).
  * Configurable delay + jitter between requests and low concurrency, so the
    traffic pattern does not look like a scanner.
  * Retries transient failures with backoff.
  * Flags responses that look like a WAF block (403 / 406 / 429 / 503, or a
    known WAF vendor in the Server header).

On launch a dialog box asks how you want to supply the URLs:
  1. Type / paste URLs manually
  2. Give a Sitemap URL (sitemap.xml, sitemap index, or .xml.gz) - it is fetched
     and expanded to the list of <loc> URLs
  3. Select a local file that contains the URLs (.txt or .csv, one URL per line)

Output (written to the chosen output folder):
  * status_summary_<timestamp>.csv        - one row per input URL
  * status_redirect_chain_<timestamp>.csv - one row per hop in every redirect chain

Requires:  pip install -r requirements.txt      (only `requests` is third-party)
"""

from __future__ import annotations

import csv
import gzip
import io
import os
import queue
import random
import re
import sys
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
except Exception:  # pragma: no cover - very old urllib3
    from requests.packages.urllib3.util.retry import Retry  # type: ignore

import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext


# --------------------------------------------------------------------------- #
# Configuration defaults
# --------------------------------------------------------------------------- #

DEFAULT_TIMEOUT = 20          # seconds per request
DEFAULT_DELAY = 1.0           # base seconds to wait after each URL (per worker)
DEFAULT_JITTER = 0.6          # random extra 0..JITTER seconds added to the delay
DEFAULT_WORKERS = 2           # keep low for WAF-sensitive targets
DEFAULT_MAX_REDIRECTS = 20
DEFAULT_RETRIES = 2           # retry attempts for connection errors / 5xx

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
    "Connection": "keep-alive",
}

# Statuses that usually mean "the WAF/edge blocked or throttled this request"
WAF_BLOCK_STATUS = {401, 403, 406, 429, 503}

# vendor name -> substrings to look for in the Server header
WAF_SERVER_HINTS = {
    "Cloudflare": ("cloudflare",),
    "Akamai": ("akamai", "akamaighost"),
    "Imperva/Incapsula": ("imperva", "incapsula"),
    "Sucuri": ("sucuri",),
    "F5 BIG-IP": ("big-ip", "bigip", "bigipapm"),
    "AWS ELB/ALB": ("awselb",),
    "AWS CloudFront": ("cloudfront",),
    "Barracuda": ("barracuda",),
    "FortiWeb": ("fortiweb",),
    "ModSecurity": ("mod_security", "modsecurity"),
    "Citrix NetScaler": ("netscaler", "nscaler"),
    "Distil": ("distil",),
}

# vendor name -> response-header names that give the vendor away regardless of status
WAF_HEADER_HINTS = {
    "Cloudflare": ("cf-ray", "cf-cache-status", "cf-mitigated"),
    "Akamai": ("x-akamai-transformed", "akamai-grn", "x-akamai-request-id"),
    "Imperva/Incapsula": ("x-iinfo", "x-cdn"),
    "Sucuri": ("x-sucuri-id", "x-sucuri-cache"),
    "AWS CloudFront": ("x-amz-cf-id", "x-amz-cf-pop"),
    "F5 BIG-IP": ("x-waf-status",),
    "DataDome": ("x-datadome", "x-dd-b"),
    "PerimeterX/HUMAN": ("x-px",),
}

# body snippets that indicate an interstitial "challenge" page (HTTP 200 but not
# the real content) - common on banking WAFs
CHALLENGE_BODY_HINTS = (
    "just a moment", "attention required", "cf-browser-verification",
    "checking your browser before accessing", "cf_chl_opt", "_cf_chl",
    "captcha-delivery.com", "px-captcha", "please enable javascript and cookies",
    "incapsula incident id", "_incapsula_resource", "radware", "distil_r_captcha",
    "request unsuccessful. incapsula", "access denied", "bot detection",
)

SITEMAP_NS = "{http://www.sitemaps.org/schemas/sitemap/0.9}"

# Thread-local storage so every worker thread gets its own requests.Session
_thread_local = threading.local()


# --------------------------------------------------------------------------- #
# HTTP session / checking logic
# --------------------------------------------------------------------------- #

def build_session(retries: int, verify_ssl: bool) -> requests.Session:
    session = requests.Session()
    session.headers.update(BROWSER_HEADERS)
    session.verify = verify_ssl

    retry = Retry(
        total=retries,
        connect=retries,
        read=retries,
        status=retries,
        backoff_factor=1.5,
        status_forcelist=(500, 502, 503, 504),
        allowed_methods=frozenset(["GET"]),
        respect_retry_after_header=True,
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def get_session(retries: int, verify_ssl: bool) -> requests.Session:
    session = getattr(_thread_local, "session", None)
    if session is None:
        session = build_session(retries, verify_ssl)
        _thread_local.session = session
    return session


def detect_waf_vendor(headers) -> str:
    """Best-effort WAF/CDN vendor name from response headers (independent of the
    status code). Returns '' if nothing recognised."""
    server_l = (headers.get("Server", "") or "").lower()
    lower_keys = {k.lower() for k in headers.keys()}
    found: list[str] = []
    for vendor, hints in WAF_SERVER_HINTS.items():
        if any(h in server_l for h in hints):
            found.append(vendor)
    for vendor, hdrs in WAF_HEADER_HINTS.items():
        if vendor not in found and any(h in lower_keys for h in hdrs):
            found.append(vendor)
    return ", ".join(found)


def looks_like_challenge(status: int, headers, body_sample: str) -> bool:
    """Detect an interstitial 'are you human' page returned with HTTP 200."""
    if status != 200:
        return False
    ctype = headers.get("Content-Type", "").lower()
    if "html" not in ctype and ctype:
        return False
    b = (body_sample or "").lower()
    return any(hint in b for hint in CHALLENGE_BODY_HINTS)


def normalize_url(raw: str) -> str | None:
    raw = raw.strip().strip('"').strip("'")
    if not raw or raw.startswith("#"):
        return None
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        raw = "https://" + raw
    parsed = urlparse(raw)
    if not parsed.netloc:
        return None
    return raw


def check_url(
    url: str,
    timeout: int,
    max_redirects: int,
    retries: int,
    verify_ssl: bool,
) -> dict:
    """Return a dict describing the request result, including the full hop chain."""
    session = get_session(retries, verify_ssl)
    session.max_redirects = max_redirects

    result = {
        "input_url": url,
        "final_url": "",
        "final_status_code": "",
        "final_reason": "",
        "redirect_count": 0,
        "was_redirected": False,
        "redirect_chain": "",
        "waf_block_suspected": False,
        "challenge_suspected": False,
        "waf_vendor": "",
        "final_server": "",
        "elapsed_seconds": "",
        "error": "",
        "hops": [],  # list of per-hop dicts for the detailed CSV
    }

    started = time.perf_counter()
    try:
        resp = session.get(url, allow_redirects=True, timeout=timeout)
    except requests.exceptions.TooManyRedirects as exc:
        result["error"] = f"TooManyRedirects (> {max_redirects}): {exc}"
        return result
    except requests.exceptions.SSLError as exc:
        result["error"] = f"SSLError: {exc}"
        return result
    except requests.exceptions.ConnectTimeout as exc:
        result["error"] = f"ConnectTimeout: {exc}"
        return result
    except requests.exceptions.ReadTimeout as exc:
        result["error"] = f"ReadTimeout: {exc}"
        return result
    except requests.exceptions.ConnectionError as exc:
        result["error"] = f"ConnectionError: {exc}"
        return result
    except requests.exceptions.RequestException as exc:
        result["error"] = f"RequestException: {exc}"
        return result

    elapsed = time.perf_counter() - started

    # Body sample of the final response, for challenge-page detection.
    body_sample = ""
    try:
        body_sample = resp.text[:4000]
    except Exception:  # noqa: BLE001
        pass

    # Build the ordered hop chain: every redirect response, then the final one.
    responses = list(resp.history) + [resp]
    chain_parts = []
    block_suspected = False
    vendors: list[str] = []

    for idx, r in enumerate(responses):
        is_final = idx == len(responses) - 1
        server = r.headers.get("Server", "")
        location = r.headers.get("Location", "")
        hop_block = r.status_code in WAF_BLOCK_STATUS
        block_suspected = block_suspected or hop_block
        hop_vendor = detect_waf_vendor(r.headers)
        for v in hop_vendor.split(", "):
            if v and v not in vendors:
                vendors.append(v)

        hop = {
            "input_url": url,
            "hop_number": idx,
            "hop_type": "final" if is_final else ("initial" if idx == 0 else "redirect"),
            "url": r.url,
            "status_code": r.status_code,
            "reason": r.reason or "",
            "location_header": location,
            "server": server,
            "waf_vendor": hop_vendor,
            "waf_block_suspected": hop_block,
            "elapsed_seconds": round(r.elapsed.total_seconds(), 3),
        }
        result["hops"].append(hop)
        chain_parts.append(f"{r.status_code} {r.url}")

    challenge = looks_like_challenge(resp.status_code, resp.headers, body_sample)

    result["final_url"] = resp.url
    result["final_status_code"] = resp.status_code
    result["final_reason"] = resp.reason or ""
    result["redirect_count"] = len(resp.history)
    result["was_redirected"] = len(resp.history) > 0
    result["redirect_chain"] = "  ->  ".join(chain_parts)
    result["waf_block_suspected"] = block_suspected
    result["challenge_suspected"] = challenge
    result["waf_vendor"] = ", ".join(vendors)
    result["final_server"] = resp.headers.get("Server", "")
    result["elapsed_seconds"] = round(elapsed, 3)
    return result


# --------------------------------------------------------------------------- #
# URL source helpers
# --------------------------------------------------------------------------- #

def parse_urls_from_text(text: str) -> list[str]:
    """Parse URLs line by line. Whole-line `#` comments and blank lines are
    skipped; a line may still hold several URLs separated by comma/semicolon/space
    (e.g. when pasting from a spreadsheet cell)."""
    out, seen = [], set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        line = re.split(r"\s+#", line, maxsplit=1)[0]  # strip trailing " # comment"
        for token in re.split(r"[,;\s]+", line):
            u = normalize_url(token)
            if u and u not in seen:
                seen.add(u)
                out.append(u)
    return out


def parse_urls_from_file(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        content = fh.read()
    return parse_urls_from_text(content)


def fetch_sitemap_urls(sitemap_url: str, timeout: int, verify_ssl: bool,
                       _depth: int = 0, _seen_sitemaps: set | None = None) -> list[str]:
    """Fetch a sitemap (or sitemap index) and return all <loc> page URLs."""
    if _seen_sitemaps is None:
        _seen_sitemaps = set()
    if _depth > 5 or sitemap_url in _seen_sitemaps:
        return []
    _seen_sitemaps.add(sitemap_url)

    session = build_session(retries=2, verify_ssl=verify_ssl)
    resp = session.get(sitemap_url, timeout=timeout, allow_redirects=True)
    resp.raise_for_status()

    raw = resp.content
    if sitemap_url.lower().endswith(".gz") or raw[:2] == b"\x1f\x8b":
        try:
            raw = gzip.decompress(raw)
        except OSError:
            raw = gzip.GzipFile(fileobj=io.BytesIO(resp.content)).read()

    root = ET.fromstring(raw)
    tag = root.tag.lower()

    urls: list[str] = []
    if tag.endswith("sitemapindex"):
        for sm in root.findall(f"{SITEMAP_NS}sitemap"):
            loc = sm.findtext(f"{SITEMAP_NS}loc") or sm.findtext("loc")
            if loc:
                urls.extend(
                    fetch_sitemap_urls(loc.strip(), timeout, verify_ssl,
                                       _depth + 1, _seen_sitemaps)
                )
    else:  # urlset
        for u in root.findall(f"{SITEMAP_NS}url"):
            loc = u.findtext(f"{SITEMAP_NS}loc") or u.findtext("loc")
            if loc:
                n = normalize_url(loc.strip())
                if n:
                    urls.append(n)

    # de-dup while preserving order
    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

SUMMARY_FIELDS = [
    "input_url", "final_url", "final_status_code", "final_reason",
    "was_redirected", "redirect_count", "redirect_chain",
    "waf_block_suspected", "challenge_suspected", "waf_vendor",
    "final_server", "elapsed_seconds", "error",
]

CHAIN_FIELDS = [
    "input_url", "hop_number", "hop_type", "url", "status_code", "reason",
    "location_header", "server", "waf_vendor", "waf_block_suspected",
    "elapsed_seconds",
]


def write_outputs(results: list[dict], out_dir: str) -> tuple[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    summary_path = os.path.join(out_dir, f"status_summary_{stamp}.csv")
    chain_path = os.path.join(out_dir, f"status_redirect_chain_{stamp}.csv")

    with open(summary_path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=SUMMARY_FIELDS)
        w.writeheader()
        for r in results:
            w.writerow({k: r.get(k, "") for k in SUMMARY_FIELDS})

    with open(chain_path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=CHAIN_FIELDS)
        w.writeheader()
        for r in results:
            for hop in r.get("hops", []):
                w.writerow({k: hop.get(k, "") for k in CHAIN_FIELDS})

    return summary_path, chain_path


# --------------------------------------------------------------------------- #
# Runner (worker pool + delay/jitter) - reports progress via a callback
# --------------------------------------------------------------------------- #

def run_checks(
    urls: list[str],
    *,
    timeout: int,
    delay: float,
    jitter: float,
    workers: int,
    max_redirects: int,
    retries: int,
    verify_ssl: bool,
    progress_cb,
    stop_event: threading.Event,
) -> list[dict]:
    results: list[dict] = []
    total = len(urls)
    done = 0
    lock = threading.Lock()

    def task(u: str) -> dict:
        if stop_event.is_set():
            return {"input_url": u, "error": "cancelled", "hops": []}
        res = check_url(u, timeout, max_redirects, retries, verify_ssl)
        # polite pause so the pattern does not look like a scanner
        time.sleep(delay + random.uniform(0, jitter))
        return res

    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futures = {ex.submit(task, u): u for u in urls}
        for fut in as_completed(futures):
            res = fut.result()
            with lock:
                results.append(res)
                done += 1
            progress_cb(done, total, res)
            if stop_event.is_set():
                break

    # keep original input order
    order = {u: i for i, u in enumerate(urls)}
    results.sort(key=lambda r: order.get(r["input_url"], 1_000_000))
    return results


# --------------------------------------------------------------------------- #
# GUI
# --------------------------------------------------------------------------- #

class CheckerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Bulk URL Status Code Checker  (WAF-aware)")
        self.geometry("760x640")
        self.minsize(680, 560)

        self.mode = tk.StringVar(value="manual")
        self.sitemap_url = tk.StringVar()
        self.file_path = tk.StringVar()
        self.out_dir = tk.StringVar(
            value=os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
        )
        self.timeout = tk.IntVar(value=DEFAULT_TIMEOUT)
        self.delay = tk.DoubleVar(value=DEFAULT_DELAY)
        self.jitter = tk.DoubleVar(value=DEFAULT_JITTER)
        self.workers = tk.IntVar(value=DEFAULT_WORKERS)
        self.max_redirects = tk.IntVar(value=DEFAULT_MAX_REDIRECTS)
        self.retries = tk.IntVar(value=DEFAULT_RETRIES)
        self.verify_ssl = tk.BooleanVar(value=True)

        self.stop_event = threading.Event()
        self.msg_queue: queue.Queue = queue.Queue()
        self.worker_thread: threading.Thread | None = None

        self._build_ui()
        self.after(120, self._drain_queue)

    # ---- UI construction ------------------------------------------------- #
    def _build_ui(self) -> None:
        pad = {"padx": 8, "pady": 4}

        src = ttk.LabelFrame(self, text="1. Where do the URLs come from?")
        src.pack(fill="x", **pad)

        ttk.Radiobutton(src, text="Enter / paste URLs manually", value="manual",
                        variable=self.mode, command=self._sync_mode).grid(
            row=0, column=0, sticky="w", padx=6, pady=2)
        ttk.Radiobutton(src, text="Sitemap URL (sitemap.xml / index / .xml.gz)",
                        value="sitemap", variable=self.mode,
                        command=self._sync_mode).grid(
            row=1, column=0, sticky="w", padx=6, pady=2)
        ttk.Radiobutton(src, text="Select a file that contains the URLs (.txt / .csv)",
                        value="file", variable=self.mode,
                        command=self._sync_mode).grid(
            row=2, column=0, sticky="w", padx=6, pady=2)

        # manual text box
        self.text_box = scrolledtext.ScrolledText(self, height=8, wrap="word")
        self.text_box.pack(fill="both", expand=False, **pad)
        self.text_box.insert("1.0", "https://example-bank.com\n")

        # sitemap row
        self.sitemap_row = ttk.Frame(self)
        self.sitemap_row.pack(fill="x", **pad)
        ttk.Label(self.sitemap_row, text="Sitemap URL:").pack(side="left")
        ttk.Entry(self.sitemap_row, textvariable=self.sitemap_url).pack(
            side="left", fill="x", expand=True, padx=6)

        # file row
        self.file_row = ttk.Frame(self)
        self.file_row.pack(fill="x", **pad)
        ttk.Label(self.file_row, text="URL file:").pack(side="left")
        ttk.Entry(self.file_row, textvariable=self.file_path).pack(
            side="left", fill="x", expand=True, padx=6)
        ttk.Button(self.file_row, text="Browse...",
                   command=self._pick_file).pack(side="left")

        # settings
        opt = ttk.LabelFrame(self, text="2. Request settings (WAF-friendly defaults)")
        opt.pack(fill="x", **pad)
        self._spin(opt, "Timeout (s)", self.timeout, 0, 0, 1, 120)
        self._spin(opt, "Delay per URL (s)", self.delay, 0, 2, 0, 60, inc=0.5)
        self._spin(opt, "Delay jitter (s)", self.jitter, 0, 4, 0, 10, inc=0.1)
        self._spin(opt, "Concurrent workers", self.workers, 1, 0, 1, 20)
        self._spin(opt, "Max redirects", self.max_redirects, 1, 2, 1, 50)
        self._spin(opt, "Retries", self.retries, 1, 4, 0, 5)
        ttk.Checkbutton(opt, text="Verify SSL certificates",
                        variable=self.verify_ssl).grid(
            row=2, column=0, columnspan=2, sticky="w", padx=6, pady=2)

        # output dir
        out = ttk.Frame(self)
        out.pack(fill="x", **pad)
        ttk.Label(out, text="Output folder:").pack(side="left")
        ttk.Entry(out, textvariable=self.out_dir).pack(
            side="left", fill="x", expand=True, padx=6)
        ttk.Button(out, text="Browse...", command=self._pick_out).pack(side="left")

        # controls
        ctl = ttk.Frame(self)
        ctl.pack(fill="x", **pad)
        self.start_btn = ttk.Button(ctl, text="Start check", command=self._start)
        self.start_btn.pack(side="left")
        self.stop_btn = ttk.Button(ctl, text="Stop", command=self._stop,
                                   state="disabled")
        self.stop_btn.pack(side="left", padx=6)
        self.progress = ttk.Progressbar(ctl, mode="determinate")
        self.progress.pack(side="left", fill="x", expand=True, padx=6)

        self.log = scrolledtext.ScrolledText(self, height=10, wrap="none",
                                             state="disabled")
        self.log.pack(fill="both", expand=True, **pad)

        self._sync_mode()

    def _spin(self, parent, label, var, r, c, frm, to, inc=1):
        ttk.Label(parent, text=label).grid(row=r, column=c, sticky="e", padx=6, pady=2)
        ttk.Spinbox(parent, from_=frm, to=to, textvariable=var, width=8,
                    increment=inc).grid(row=r, column=c + 1, sticky="w", pady=2)

    # ---- UI behaviour -------------------------------------------------- #
    def _sync_mode(self) -> None:
        m = self.mode.get()
        state_text = "normal" if m == "manual" else "disabled"
        self.text_box.configure(state=state_text)
        for w in self.sitemap_row.winfo_children():
            if isinstance(w, ttk.Entry):
                w.configure(state="normal" if m == "sitemap" else "disabled")
        for w in self.file_row.winfo_children():
            if isinstance(w, (ttk.Entry, ttk.Button)):
                w.configure(state="normal" if m == "file" else "disabled")

    def _pick_file(self) -> None:
        p = filedialog.askopenfilename(
            title="Select a file containing URLs",
            filetypes=[("Text / CSV", "*.txt *.csv *.list"), ("All files", "*.*")],
        )
        if p:
            self.file_path.set(p)

    def _pick_out(self) -> None:
        p = filedialog.askdirectory(title="Select output folder")
        if p:
            self.out_dir.set(p)

    def _log(self, line: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", line + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    # ---- run --------------------------------------------------------- #
    def _collect_urls(self) -> list[str]:
        m = self.mode.get()
        if m == "manual":
            return parse_urls_from_text(self.text_box.get("1.0", "end"))
        if m == "file":
            p = self.file_path.get().strip()
            if not p or not os.path.isfile(p):
                raise ValueError("Please select a valid URL file.")
            return parse_urls_from_file(p)
        if m == "sitemap":
            sm = self.sitemap_url.get().strip()
            if not sm:
                raise ValueError("Please enter a sitemap URL.")
            self._log(f"Fetching sitemap: {sm}")
            return fetch_sitemap_urls(sm, self.timeout.get(), self.verify_ssl.get())
        return []

    def _start(self) -> None:
        if self.worker_thread and self.worker_thread.is_alive():
            return
        try:
            urls = self._collect_urls()
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Input error", str(exc))
            return
        if not urls:
            messagebox.showwarning("No URLs", "No valid URLs were found.")
            return

        self.stop_event.clear()
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.progress.configure(maximum=len(urls), value=0)
        self._log(f"\n=== Starting: {len(urls)} URL(s) | "
                  f"{self.workers.get()} worker(s) | "
                  f"delay {self.delay.get()}s (+{self.jitter.get()}s jitter) ===")

        cfg = dict(
            timeout=self.timeout.get(), delay=self.delay.get(),
            jitter=self.jitter.get(), workers=self.workers.get(),
            max_redirects=self.max_redirects.get(), retries=self.retries.get(),
            verify_ssl=self.verify_ssl.get(), out_dir=self.out_dir.get().strip(),
        )

        self.worker_thread = threading.Thread(
            target=self._worker, args=(urls, cfg), daemon=True)
        self.worker_thread.start()

    def _worker(self, urls: list[str], cfg: dict) -> None:
        def progress_cb(done: int, total: int, res: dict) -> None:
            self.msg_queue.put(("progress", (done, total, res)))

        try:
            results = run_checks(
                urls,
                timeout=cfg["timeout"], delay=cfg["delay"], jitter=cfg["jitter"],
                workers=cfg["workers"], max_redirects=cfg["max_redirects"],
                retries=cfg["retries"], verify_ssl=cfg["verify_ssl"],
                progress_cb=progress_cb, stop_event=self.stop_event,
            )
            summary_path, chain_path = write_outputs(results, cfg["out_dir"])
            self.msg_queue.put(("done", (results, summary_path, chain_path)))
        except Exception as exc:  # noqa: BLE001
            self.msg_queue.put(("error", str(exc)))

    def _stop(self) -> None:
        self.stop_event.set()
        self._log("Stop requested - finishing in-flight requests...")

    def _drain_queue(self) -> None:
        try:
            while True:
                kind, payload = self.msg_queue.get_nowait()
                if kind == "progress":
                    done, total, res = payload
                    self.progress.configure(value=done)
                    self._log(self._fmt_result(done, total, res))
                elif kind == "done":
                    results, summary_path, chain_path = payload
                    self._finish(results, summary_path, chain_path)
                elif kind == "error":
                    messagebox.showerror("Run failed", payload)
                    self._reset_buttons()
        except queue.Empty:
            pass
        self.after(120, self._drain_queue)

    @staticmethod
    def _fmt_result(done: int, total: int, res: dict) -> str:
        if res.get("error"):
            return f"[{done}/{total}] ERROR  {res['input_url']}  -> {res['error']}"
        flags = []
        if res.get("waf_block_suspected"):
            flags.append("WAF-BLOCK?")
        if res.get("challenge_suspected"):
            flags.append("CHALLENGE?")
        if res.get("waf_vendor"):
            flags.append(res["waf_vendor"])
        flag = f"  [{' | '.join(flags)}]" if flags else ""
        redir = ""
        if res.get("was_redirected"):
            redir = f"  ({res['redirect_count']} redirect(s) -> {res['final_url']})"
        return (f"[{done}/{total}] {res['final_status_code']}  "
                f"{res['input_url']}{redir}{flag}")

    def _finish(self, results: list[dict], summary_path: str, chain_path: str) -> None:
        ok = sum(1 for r in results if str(r.get("final_status_code")).startswith("2"))
        redirected = sum(1 for r in results if r.get("was_redirected"))
        waf = sum(1 for r in results
                  if r.get("waf_block_suspected") or r.get("challenge_suspected"))
        errors = sum(1 for r in results if r.get("error"))
        self._log("\n=== Done ===")
        self._log(f"  total={len(results)}  2xx={ok}  redirected={redirected}  "
                  f"waf_block/challenge={waf}  errors={errors}")
        self._log(f"  summary CSV : {summary_path}")
        self._log(f"  chain CSV   : {chain_path}")
        self._reset_buttons()
        try:
            os.startfile(os.path.dirname(summary_path))  # open folder (Windows)
        except Exception:  # noqa: BLE001
            pass
        messagebox.showinfo(
            "Finished",
            f"Checked {len(results)} URL(s).\n\n"
            f"2xx: {ok}   redirected: {redirected}   "
            f"WAF-suspected: {waf}   errors: {errors}\n\n"
            f"Saved:\n{summary_path}\n{chain_path}",
        )

    def _reset_buttons(self) -> None:
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")


def main() -> None:
    # Allow a quick non-GUI run:  python status_code_checker.py urls.txt
    if len(sys.argv) > 1 and sys.argv[1] not in ("--gui", "-g"):
        path = sys.argv[1]
        urls = parse_urls_from_file(path)
        print(f"Loaded {len(urls)} URL(s) from {path}")
        results = run_checks(
            urls, timeout=DEFAULT_TIMEOUT, delay=DEFAULT_DELAY,
            jitter=DEFAULT_JITTER, workers=DEFAULT_WORKERS,
            max_redirects=DEFAULT_MAX_REDIRECTS, retries=DEFAULT_RETRIES,
            verify_ssl=True,
            progress_cb=lambda d, t, r: print(CheckerApp._fmt_result(d, t, r)),
            stop_event=threading.Event(),
        )
        out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
        s, c = write_outputs(results, out_dir)
        print(f"\nSaved:\n  {s}\n  {c}")
        return

    CheckerApp().mainloop()


if __name__ == "__main__":
    main()
