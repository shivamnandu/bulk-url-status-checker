# Bulk URL Status Code Checker (WAF-aware)

Checks HTTP status codes for a large list of URLs, follows redirects, and records
the **full redirect chain** (every hop URL + its status code) plus the final
landing status. Tuned for banking / WAF-protected sites.

## What it does

- On launch, shows a **dialog box** asking how to supply the URLs:
  1. **Enter / paste URLs manually**
  2. **Sitemap URL** – give `sitemap.xml`, a sitemap index, or `.xml.gz`; it is
     fetched and expanded to all `<loc>` URLs (nested sitemap indexes supported)
  3. **Select a file** containing the URLs (`.txt` / `.csv`, one URL per line;
     `#` comment lines and bare domains are handled)
- For every URL it records:
  - final status code + reason
  - whether it was redirected and how many hops
  - the **entire redirect chain**: `301 https://a  ->  302 https://b  ->  200 https://c`
  - `waf_block_suspected` – a hop returned 401/403/406/429/503
  - `challenge_suspected` – HTTP 200 but the body is a "checking your browser" /
    CAPTCHA interstitial, not the real page
  - `waf_vendor` – WAF/CDN detected from headers (Cloudflare, Akamai,
    Imperva/Incapsula, F5 BIG-IP, AWS CloudFront, Sucuri, DataDome, …); this is
    informational, not a failure
- Writes two CSV files to the output folder:
  - `status_summary_<timestamp>.csv` – one row per input URL
  - `status_redirect_chain_<timestamp>.csv` – one row per hop of every chain

## WAF-sensitive design

- Full realistic browser header set (User-Agent, Accept, Sec-Fetch-*, etc.)
- Uses `GET` (not `HEAD` – many WAFs block `HEAD`)
- Configurable **delay + random jitter** between requests and **low concurrency**
  (defaults: 2 workers, 1.0 s delay + up to 0.6 s jitter) so traffic does not
  look like a scanner
- Transient errors / 5xx retried with backoff, honouring `Retry-After`
- One `requests.Session` per worker (keep-alive, cookie continuity)

> Note: JavaScript / meta-refresh redirects cannot be detected (no browser
> engine). Only HTTP 3xx `Location` redirects are followed.

## Setup

```powershell
# 1. Open the project folder in VS Code
#    File > Open Folder... > the cloned `bulk-url-status-checker` folder
#    (or from a terminal:)  code "bulk-url-status-checker"

# 2. Open the VS Code integrated terminal:  Ctrl + `  (backtick)
#    It already opens in the project folder. If not, switch to it:
cd "bulk-url-status-checker"

# 3. (Recommended) create a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1
#    If activation is blocked by execution policy, run once:
#    Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned

# 4. Install dependencies
pip install -r requirements.txt
```

If `Activate.ps1` is blocked and you don't want to change the policy, just use
the venv Python directly: `.\.venv\Scripts\python.exe status_code_checker.py`

## Run

### GUI (default)

```powershell
cd "bulk-url-status-checker"
python status_code_checker.py
```

Or in VS Code: open `status_code_checker.py` and press **F5** (Run) or the
**Run Python File** ▷ button (top-right). Make sure the selected interpreter is
your `.venv` – click the Python version in the bottom-right status bar to change
it, or run `Python: Select Interpreter` from the Command Palette (`Ctrl+Shift+P`).

### Quick CLI (no dialog)

```powershell
python status_code_checker.py sample_urls.txt
```

## Output columns

**status_summary_*.csv**

| column | meaning |
|---|---|
| `input_url` | URL as supplied (normalised to include scheme) |
| `final_url` | URL after all redirects |
| `final_status_code` / `final_reason` | landing response |
| `was_redirected` / `redirect_count` | redirect info |
| `redirect_chain` | full path: `status url  ->  status url  -> ...` |
| `waf_block_suspected` | `True` if a hop returned 401/403/406/429/503 |
| `challenge_suspected` | `True` if the 200 response is a browser-check / CAPTCHA page |
| `waf_vendor` | WAF/CDN detected from headers (informational) |
| `final_server` | `Server` header of the final response |
| `elapsed_seconds` | total time for the URL |
| `error` | populated when the request failed (timeout, SSL, DNS, …) |

**status_redirect_chain_*.csv** – one row per hop: `hop_number`, `hop_type`
(`initial` / `redirect` / `final`), `url`, `status_code`, `reason`,
`location_header`, `server`, `waf_vendor`, `waf_block_suspected`,
`elapsed_seconds`.
