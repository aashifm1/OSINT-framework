
# ─────────────────────────────────────────────────────────────────────────────
# IMPORTS
# ─────────────────────────────────────────────────────────────────────────────
import asyncio
import aiohttp
import csv
import hashlib
import ipaddress
import json
import logging
import platform as _platform
import random
import re
import socket
import sys
import time
import webbrowser
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import quote as url_quote

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.text import Text
    from rich import box
    RICH = True
except ImportError:
    RICH = False

try:
    import whois as pywhois
    WHOIS_OK = True
except ImportError:
    WHOIS_OK = False

try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    DNS_OK = False

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────

TOOL_NAME       = "OSINT Framework"
OUTPUT_DIR      = Path("osint_output")
CHECKPOINT_FILE = OUTPUT_DIR / ".checkpoint.json"

MAX_CONCURRENT  = 25
REQUEST_TIMEOUT = 10
MAX_RETRIES     = 1
RETRY_BACKOFF   = 2.0
JITTER_MAX      = 0.3

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

# ─────────────────────────────────────────────────────────────────────────────
# PLATFORM REGISTRY
# ─────────────────────────────────────────────────────────────────────────────

PLATFORMS: dict = {
    # ── Code / Tech ──────────────────────────────────────────────────────────
    "GitHub":         {"url": "https://github.com/{}",                              "not_found": "Not Found",                                 "category": "tech",         "risk": 5},
    "GitLab":         {"url": "https://gitlab.com/{}",                              "not_found": "404",                                       "category": "tech",         "risk": 5},
    "Bitbucket":      {"url": "https://bitbucket.org/{}",                           "not_found": "404",                                       "category": "tech",         "risk": 4},
    "HackerNews":     {"url": "https://news.ycombinator.com/user?id={}",            "not_found": "No such user",                              "category": "tech",         "risk": 3},
    "Replit":         {"url": "https://replit.com/@{}",                             "not_found": "404",                                       "category": "tech",         "risk": 3},
    "Codepen":        {"url": "https://codepen.io/{}",                              "not_found": "404",                                       "category": "tech",         "risk": 2},
    "Dev.to":         {"url": "https://dev.to/{}",                                  "not_found": "404",                                       "category": "tech",         "risk": 2},
    "npm":            {"url": "https://www.npmjs.com/~{}",                          "not_found": "404",                                       "category": "tech",         "risk": 3},
    "PyPI":           {"url": "https://pypi.org/user/{}/",                          "not_found": "404",                                       "category": "tech",         "risk": 3},
    "DockerHub":      {"url": "https://hub.docker.com/u/{}",                        "not_found": "404",                                       "category": "tech",         "risk": 3},

    # ── Security ─────────────────────────────────────────────────────────────
    "HackerOne":      {"url": "https://hackerone.com/{}",                           "not_found": "404",                                       "category": "security",     "risk": 5},
    "BugCrowd":       {"url": "https://bugcrowd.com/{}",                            "not_found": "404",                                       "category": "security",     "risk": 5},
    "Keybase":        {"url": "https://keybase.io/{}",                              "not_found": "404",                                       "category": "security",     "risk": 5},
    "Intigriti":      {"url": "https://app.intigriti.com/profile/{}",               "not_found": "404",                                       "category": "security",     "risk": 4},

    # ── Social Media ─────────────────────────────────────────────────────────
    "Instagram":      {"url": "https://www.instagram.com/{}/",                      "not_found": "Page Not Found",                            "category": "social",       "risk": 4},
    "Twitter/X":      {"url": "https://twitter.com/{}",                             "not_found": "This account doesn't exist",                "category": "social",       "risk": 4},
    "TikTok":         {"url": "https://www.tiktok.com/@{}",                         "not_found": "Couldn't find this account",                "category": "social",       "risk": 4},
    "Pinterest":      {"url": "https://www.pinterest.com/{}/",                      "not_found": "404",                                       "category": "social",       "risk": 2},
    "Tumblr":         {"url": "https://{}.tumblr.com/",                             "not_found": "There's nothing here",                      "category": "social",       "risk": 3},
    "Reddit":         {"url": "https://www.reddit.com/user/{}/",                    "not_found": "Sorry, nobody on Reddit goes by that name", "category": "social",       "risk": 3},
    "Snapchat":       {"url": "https://www.snapchat.com/add/{}",                    "not_found": "404",                                       "category": "social",       "risk": 3},
    "VK":             {"url": "https://vk.com/{}",                                  "not_found": "404",                                       "category": "social",       "risk": 3},
    "Twitch":         {"url": "https://www.twitch.tv/{}",                           "not_found": "Sorry. Unless you've got a time machine",   "category": "social",       "risk": 3},
    "Mastodon":       {"url": "https://mastodon.social/@{}",                        "not_found": "The page you're looking for",               "category": "social",       "risk": 2},
    "Threads":        {"url": "https://www.threads.net/@{}",                        "not_found": "Page Not Found",                            "category": "social",       "risk": 3},
    "BlueSky":        {"url": "https://bsky.app/profile/{}",                        "not_found": "Profile not found",                         "category": "social",       "risk": 2},
    "Minds":          {"url": "https://www.minds.com/{}",                           "not_found": "404",                                       "category": "social",       "risk": 2},

    # ── Professional ─────────────────────────────────────────────────────────
    "LinkedIn":       {"url": "https://www.linkedin.com/in/{}/",                    "not_found": "Page not found",                            "category": "professional", "risk": 5},
    "About.me":       {"url": "https://about.me/{}",                                "not_found": "404",                                       "category": "professional", "risk": 3},
    "Gravatar":       {"url": "https://en.gravatar.com/{}",                         "not_found": "404",                                       "category": "professional", "risk": 2},
    "AngelList":      {"url": "https://angel.co/u/{}",                              "not_found": "404",                                       "category": "professional", "risk": 4},
    "ProductHunt":    {"url": "https://www.producthunt.com/@{}",                    "not_found": "404",                                       "category": "professional", "risk": 3},
    "Xing":           {"url": "https://www.xing.com/profile/{}",                    "not_found": "404",                                       "category": "professional", "risk": 4},
    "Crunchbase":     {"url": "https://www.crunchbase.com/person/{}",               "not_found": "Page Not Found",                            "category": "professional", "risk": 4},

    # ── Gaming ───────────────────────────────────────────────────────────────
    "Steam":          {"url": "https://steamcommunity.com/id/{}",                   "not_found": "The specified profile could not be found",  "category": "gaming",       "risk": 3},
    "Roblox":         {"url": "https://www.roblox.com/user.aspx?username={}",       "not_found": "Page Not Found",                            "category": "gaming",       "risk": 2},
    "Chess.com":      {"url": "https://www.chess.com/member/{}",                    "not_found": "404",                                       "category": "gaming",       "risk": 2},
    "Lichess":        {"url": "https://lichess.org/@/{}",                           "not_found": "404",                                       "category": "gaming",       "risk": 2},
    "itch.io":        {"url": "https://{}.itch.io/",                                "not_found": "404",                                       "category": "gaming",       "risk": 3},

    # ── Creative / Content ───────────────────────────────────────────────────
    "Medium":         {"url": "https://medium.com/@{}",                             "not_found": "404",                                       "category": "creative",     "risk": 2},
    "Behance":        {"url": "https://www.behance.net/{}",                         "not_found": "404",                                       "category": "creative",     "risk": 2},
    "Dribbble":       {"url": "https://dribbble.com/{}",                            "not_found": "Whoops",                                    "category": "creative",     "risk": 2},
    "SoundCloud":     {"url": "https://soundcloud.com/{}",                          "not_found": "404",                                       "category": "creative",     "risk": 2},
    "Bandcamp":       {"url": "https://{}.bandcamp.com/",                           "not_found": "404",                                       "category": "creative",     "risk": 2},
    "Flickr":         {"url": "https://www.flickr.com/people/{}",                   "not_found": "404",                                       "category": "creative",     "risk": 2},
    "DeviantArt":     {"url": "https://www.deviantart.com/{}",                      "not_found": "404",                                       "category": "creative",     "risk": 2},
    "ArtStation":     {"url": "https://www.artstation.com/{}",                      "not_found": "404",                                       "category": "creative",     "risk": 2},
    "Substack":       {"url": "https://{}.substack.com",                            "not_found": "404",                                       "category": "creative",     "risk": 3},
    "Patreon":        {"url": "https://www.patreon.com/{}",                         "not_found": "404",                                       "category": "creative",     "risk": 3},

    # ── Forums / Communities ─────────────────────────────────────────────────
    "Pastebin":       {"url": "https://pastebin.com/u/{}",                          "not_found": "404",                                       "category": "forum",        "risk": 4},
    "Quora":          {"url": "https://www.quora.com/profile/{}",                   "not_found": "404",                                       "category": "forum",        "risk": 2},
    "Disqus":         {"url": "https://disqus.com/by/{}/",                          "not_found": "404",                                       "category": "forum",        "risk": 2},
    "Lemmy":          {"url": "https://lemmy.world/u/{}",                           "not_found": "404",                                       "category": "forum",        "risk": 2},

    # ── Messaging ────────────────────────────────────────────────────────────
    "Telegram":       {"url": "https://t.me/{}",                                    "not_found": "If you have Telegram",                      "category": "messaging",    "risk": 4},

    # ── Finance / Crypto ─────────────────────────────────────────────────────
    "Venmo":          {"url": "https://account.venmo.com/u/{}",                     "not_found": "404",                                       "category": "finance",      "risk": 4},
    "CashApp":        {"url": "https://cash.app/${}",                               "not_found": "404",                                       "category": "finance",      "risk": 4},

    # ── Misc ─────────────────────────────────────────────────────────────────
    "Linktree":       {"url": "https://linktr.ee/{}",                               "not_found": "Sorry, this page isn't available",          "category": "misc",         "risk": 3},
    "WordPress":      {"url": "https://{}.wordpress.com",                           "not_found": "doesn't exist",                             "category": "misc",         "risk": 3},
    "Blogger":        {"url": "https://{}.blogspot.com",                            "not_found": "Blog not found",                            "category": "misc",         "risk": 2},
    "Wikipedia":      {"url": "https://en.wikipedia.org/wiki/User:{}",              "not_found": "There is currently no text",                "category": "misc",         "risk": 2},
    "Fiverr":         {"url": "https://www.fiverr.com/{}",                          "not_found": "404",                                       "category": "misc",         "risk": 3},
    "Upwork":         {"url": "https://www.upwork.com/freelancers/~{}",             "not_found": "404",                                       "category": "misc",         "risk": 4},
    "Etsy":           {"url": "https://www.etsy.com/shop/{}",                       "not_found": "404",                                       "category": "misc",         "risk": 3},
    "Ebay":           {"url": "https://www.ebay.com/usr/{}",                        "not_found": "There are no registered sellers",           "category": "misc",         "risk": 3},
    "Goodreads":      {"url": "https://www.goodreads.com/{}",                       "not_found": "404",                                       "category": "misc",         "risk": 2},
    "Letterboxd":     {"url": "https://letterboxd.com/{}",                          "not_found": "404",                                       "category": "misc",         "risk": 2},
    "MyAnimeList":    {"url": "https://myanimelist.net/profile/{}",                 "not_found": "Invalid username",                          "category": "misc",         "risk": 2},
}

HIGH_RISK_PLATFORMS = {p for p, d in PLATFORMS.items() if d["risk"] >= 5}

# ─────────────────────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class PlatformResult:
    platform:   str
    username:   str
    status:     str          # found | not_found | rate_limited | timeout | error | http_XXX
    url:        str
    http_code:  Optional[int]   = None
    latency_ms: Optional[float] = None
    risk:       int  = 1
    category:   str  = "misc"

@dataclass
class TargetProfile:
    name:           str  = ""
    alias:          str  = ""
    email:          str  = ""
    mobile:         str  = ""
    country:        str  = ""
    city:           str  = ""
    employer:       str  = ""
    website:        str  = ""
    ip:             str  = ""
    notes:          str  = ""
    seed_usernames: list = field(default_factory=list)

@dataclass
class DNSRecord:
    domain: str
    a:   list = field(default_factory=list)
    mx:  list = field(default_factory=list)
    ns:  list = field(default_factory=list)
    txt: list = field(default_factory=list)

# ─────────────────────────────────────────────────────────────────────────────
# CONSOLE HELPERS
# ─────────────────────────────────────────────────────────────────────────────

console = Console(highlight=False) if RICH else None
_STRIP_MARKUP = re.compile(r"\[/?[^\[\]]*\]")

def cprint(text, style="", markup=True):
    if RICH:
        console.print(text, style=style, markup=markup)
    else:
        print(_STRIP_MARKUP.sub("", str(text)))

def sep(title=""):
    if RICH:
        console.rule(f"[bold yellow]{title}[/bold yellow]" if title else "", style="dim")
    else:
        pad = max(0, 60 - len(title))
        print(f"\n─── {title} {'─' * pad}" if title else "─" * 64)

def banner():
    width = 62  # total inner width between ║ ║

    def line(text=""):
        return f"║{text.center(width)}║"

    def line_left(text=""):
        return f"║{text.ljust(width)}║"

    cprint("\n" + "╔" + "═" * width + "╗", style="bold cyan")
    cprint(line("OSINT FRAMEWORK"), style="bold cyan")
    cprint(line("Advanced Open-Source Intelligence Reconnaissance"), style="bold cyan")

    platforms_text = f"Platforms: {len(PLATFORMS):>2}  │  Async Engine  │  Structured Reports"
    cprint(line_left(platforms_text), style="bold cyan")

    cprint("╚" + "═" * width + "╝", style="bold cyan")

    footer = (
        f"Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  │  "
        f"Python {sys.version.split()[0]}  │  {_platform.system()} {_platform.release()}"
    )

    cprint(footer + "\n", style="dim")

# ─────────────────────────────────────────────────────────────────────────────
# INPUT HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def ask(prompt: str, required=False, validator=None) -> str:
    while True:
        raw = input(prompt).strip()
        if not raw and required:
            cprint("  [!] Required.", style="yellow")
            continue
        if raw and validator and not validator(raw):
            continue
        return raw

def yes_no(prompt: str) -> bool:
    while True:
        c = input(f"{prompt} (y/n): ").strip().lower()
        if c in ("y", "yes"):
            return True
        if c in ("n", "no"):
            return False
        cprint("  [!] Enter y or n.", style="yellow")

def _valid_email(v: str) -> bool:
    ok = bool(re.match(r"^[\w.+\-]+@[\w\-]+\.[a-z]{2,}$", v, re.I))
    if not ok:
        cprint(f"  [!] Invalid email: {v}", style="yellow")
    return ok

def _valid_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        cprint(f"  [!] Invalid IP: {v}", style="yellow")
        return False

# ─────────────────────────────────────────────────────────────────────────────
# OPSEC CHECK
# ─────────────────────────────────────────────────────────────────────────────

def opsec_check():
    sep("OPSEC Pre-Flight")
    for w in [
        "All requests originate from YOUR public IP — use a VPN or Tor.",
        "Browser dorks leave your search history on Google servers.",
        "Repeated scans may trigger rate-limits or IP bans.",
        "LinkedIn and Instagram actively detect automated scraping.",
    ]:
        cprint(f"  [yellow]⚠[/yellow]  {w}")

    try:
        from urllib.request import urlopen
        ext_ip = urlopen("https://api.ipify.org", timeout=5).read().decode()
        cprint(f"\n  [bold red]Your external IP:[/bold red] {ext_ip}")
    except Exception:
        cprint("\n  [dim]Could not resolve external IP.[/dim]")

    if not yes_no("\n  Continue with this IP?"):
        cprint("  Aborted.", style="red")
        sys.exit(0)

# ─────────────────────────────────────────────────────────────────────────────
# TARGET COLLECTION
# ─────────────────────────────────────────────────────────────────────────────

def collect_target() -> TargetProfile:
    sep("Target Profile")
    cprint("  Leave blank if unknown.\n", style="dim")
    t = TargetProfile()

    t.name     = ask("  Full name           : ")
    t.alias    = ask("  Alias / handle      : ")

    raw_email  = ask("  Email               : ")
    if raw_email and not _valid_email(raw_email):
        raw_email = ask("  Email (retry)       : ")
    t.email    = raw_email

    t.mobile   = ask("  Mobile              : ")
    t.country  = ask("  Country             : ")
    t.city     = ask("  City                : ")
    t.employer = ask("  Employer / Org      : ")
    t.website  = ask("  Website             : ")

    raw_ip     = ask("  Known IP            : ")
    if raw_ip and not _valid_ip(raw_ip):
        raw_ip = ask("  IP (retry)          : ")
    t.ip       = raw_ip

    t.notes    = ask("  Notes               : ")

    cprint("\n  [bold]Seed usernames[/bold] — press ENTER to finish:", style="cyan")
    while True:
        u = input("    → ").strip()
        if not u:
            break
        t.seed_usernames.append(u)

    return t

# ─────────────────────────────────────────────────────────────────────────────
# USERNAME VARIANT GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

def generate_variants(seeds: list[str], name: str = "") -> list[str]:
    """
    Expand seeds with common handle transformations and name-derived patterns.
    Seeds always appear first; result is deduplicated and order-preserved.
    """
    year     = datetime.now().year
    seen:  set[str] = set(seeds)
    extra: list[str] = []

    def _add(v: str):
        if v and v not in seen:
            seen.add(v)
            extra.append(v)

    for u in seeds:
        lo = u.lower()
        for variant in (
            lo,
            lo + str(year),
            lo + str(year - 1),
            lo.replace("_", "."),
            lo.replace(".", "_"),
            lo.replace("-", "_"),
            lo + "1",
            lo + "123",
        ):
            _add(variant)
        # Only add leet variant when it actually differs
        leet = lo.translate(str.maketrans("aeios", "43105"))
        if leet != lo:
            _add(leet)

    if name:
        parts = name.lower().split()
        if len(parts) >= 2:
            f, l = parts[0], parts[-1]
            for v in (f+l, f+"."+l, f[0]+l, f+l[0], f+"_"+l, l+f):
                _add(v)

    return list(seeds) + extra

# ─────────────────────────────────────────────────────────────────────────────
# ASYNC HTTP ENGINE
# ─────────────────────────────────────────────────────────────────────────────

async def _check(
    session:  aiohttp.ClientSession,
    sem:      asyncio.Semaphore,
    username: str,
    pname:    str,
    pdata:    dict,
) -> PlatformResult:

    url      = pdata["url"].format(username)
    nf_text  = pdata.get("not_found", "")
    fi_text  = pdata.get("found_indicator")
    risk     = pdata.get("risk", 1)
    category = pdata.get("category", "misc")

    # Small per-request jitter to avoid burst fingerprinting
    await asyncio.sleep(random.uniform(0, JITTER_MAX))

    headers = {
        "User-Agent":      random.choice(USER_AGENTS),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept":          "text/html,application/xhtml+xml,*/*;q=0.8",
    }

    # Platforms whose not_found text is a bare "404" should rely on HTTP status,
    # not body matching — the string "404" appears on countless legitimate pages
    # (navigation links, error codes in footers, etc.).
    nf_is_generic = isinstance(nf_text, str) and nf_text.strip() == "404"

    for attempt in range(MAX_RETRIES + 1):
        try:
            t0 = time.monotonic()
            async with sem:
                async with session.get(
                    url, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
                    allow_redirects=True,
                    ssl=False,
                ) as resp:
                    lat  = round((time.monotonic() - t0) * 1000, 1)
                    code = resp.status
                    # Read body only when meaningful text-matching is needed
                    need_body = (fi_text or (nf_text and not nf_is_generic))
                    body = (await resp.text(errors="replace")) if need_body else ""

            if code == 404:
                return PlatformResult(pname, username, "not_found",    url, code, lat, risk, category)
            if code == 429:
                return PlatformResult(pname, username, "rate_limited", url, code, lat, risk, category)
            if code in (200, 301, 302, 303):
                # Only do body-text not-found check when the indicator is specific
                if nf_text and not nf_is_generic:
                    nf_list = nf_text if isinstance(nf_text, list) else [nf_text]
                    if any(s.lower() in body.lower() for s in nf_list):
                        return PlatformResult(pname, username, "not_found", url, code, lat, risk, category)
                if fi_text and fi_text.lower() not in body.lower():
                    return PlatformResult(pname, username, "not_found", url, code, lat, risk, category)
                # For generic-404 platforms on a 200 response, trust the status code
                return PlatformResult(pname, username, "found", url, code, lat, risk, category)

            return PlatformResult(pname, username, f"http_{code}", url, code, lat, risk, category)

        except asyncio.TimeoutError:
            if attempt < MAX_RETRIES:
                await asyncio.sleep(RETRY_BACKOFF ** (attempt + 1))
                continue
            return PlatformResult(pname, username, "timeout", url, risk=risk, category=category)
        except aiohttp.ClientConnectorError:
            return PlatformResult(pname, username, "error", url, risk=risk, category=category)
        except Exception as exc:
            logging.debug("%s/%s: %s", pname, username, exc)
            return PlatformResult(pname, username, "error", url, risk=risk, category=category)

    return PlatformResult(pname, username, "error", url, risk=risk, category=category)


async def _run_async(usernames: list[str]) -> list[PlatformResult]:
    sem       = asyncio.Semaphore(MAX_CONCURRENT)
    connector = aiohttp.TCPConnector(ssl=False, limit=MAX_CONCURRENT, ttl_dns_cache=300)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            _check(session, sem, u, pname, pdata)
            for u in usernames
            for pname, pdata in PLATFORMS.items()
        ]

        if RICH:
            results: list[PlatformResult] = []
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(bar_width=40),
                TextColumn("{task.completed}/{task.total}"),
                TimeElapsedColumn(),
                console=console,
                transient=True,   # bar disappears cleanly when done
            ) as prog:
                tid = prog.add_task(
                    f"[cyan]Scanning {len(usernames)} username(s) × {len(PLATFORMS)} platforms",
                    total=len(tasks),
                )
                for coro in asyncio.as_completed(tasks):
                    r = await coro
                    results.append(r)
                    prog.advance(tid)
            return results
        else:
            print(f"[*] Scanning {len(tasks)} checks ...")
            return list(await asyncio.gather(*tasks))


def run_scan(usernames: list[str]) -> list[PlatformResult]:
    return asyncio.run(_run_async(usernames))

# ─────────────────────────────────────────────────────────────────────────────
# RESULTS DISPLAY
# not_found results are intentionally silent — only found + anomalous shown
# ─────────────────────────────────────────────────────────────────────────────

def display_results(results: list[PlatformResult]):
    sep("Scan Results")
    usernames = list(dict.fromkeys(r.username for r in results))

    for username in usernames:
        u_res     = [r for r in results if r.username == username]
        found     = [r for r in u_res if r.status == "found"]
        anomalous = [r for r in u_res if r.status in ("rate_limited", "error", "timeout")]

        if RICH:
            t = Table(
                title=f"[bold]@{username}[/bold]  ·  {len(found)} match(es) / {len(u_res)} platforms",
                box=box.SIMPLE_HEAD,
                show_lines=False,
                header_style="bold cyan",
                title_justify="left",
            )
            t.add_column("Platform",  min_width=16, style="bold")
            t.add_column("Category",  min_width=12)
            t.add_column("Risk",      min_width=6,  justify="center")
            t.add_column("Latency",   min_width=8,  justify="right", style="dim")
            t.add_column("URL",       overflow="fold")

            for r in sorted(found, key=lambda x: (-x.risk, x.platform)):
                t.add_row(
                    r.platform,
                    r.category,
                    "★" * r.risk + "☆" * (5 - r.risk),
                    f"{r.latency_ms} ms" if r.latency_ms else "—",
                    f"[link={r.url}]{r.url}[/link]",
                )

            # Append anomalous rows only if any exist — keeps table clean
            if anomalous:
                t.add_section()
                for r in anomalous:
                    t.add_row(r.platform, r.category, "—", "—", f"[yellow]{r.status}[/yellow]")

            console.print(t)
        else:
            print(f"\n  @{username}  —  {len(found)}/{len(u_res)} found")
            for r in sorted(found, key=lambda x: (-x.risk, x.platform)):
                print(f"  ✔ {r.platform:<22} {r.url}")
            for r in anomalous:
                print(f"  ? {r.platform:<22} {r.status}")

# ─────────────────────────────────────────────────────────────────────────────
# CORRELATION
# ─────────────────────────────────────────────────────────────────────────────

def correlate(results: list[PlatformResult]) -> dict:
    sep("Correlation")

    platform_hits: dict[str, list[str]] = {}
    username_hits: dict[str, list[str]] = {}

    for r in results:
        if r.status == "found":
            platform_hits.setdefault(r.platform, []).append(r.username)
            username_hits.setdefault(r.username, []).append(r.platform)

    strong = {p: u for p, u in platform_hits.items() if len(u) > 1}

    if strong:
        cprint("  [bold red]Strong correlation — multiple usernames on same platform:[/bold red]")
        for p, u in strong.items():
            cprint(f"    {p}: {', '.join(u)}")
    else:
        cprint("  No strong cross-username correlation found.", style="dim")

    cprint(f"  Active on [bold]{len(platform_hits)}[/bold] platform(s).")
    return {"platform_hits": platform_hits, "username_hits": username_hits, "strong_matches": strong}

# ─────────────────────────────────────────────────────────────────────────────
# DNS / WHOIS
# ─────────────────────────────────────────────────────────────────────────────

def enumerate_dns(domain: str) -> DNSRecord:
    rec = DNSRecord(domain=domain)
    if not DNS_OK:
        return rec
    for qtype in ("A", "MX", "NS", "TXT"):
        try:
            ans = dns.resolver.resolve(domain, qtype, lifetime=6)
            if qtype == "A":
                rec.a   = [r.address for r in ans]
            elif qtype == "MX":
                rec.mx  = [str(r.exchange).rstrip(".") for r in ans]
            elif qtype == "NS":
                rec.ns  = [str(r.target).rstrip(".")  for r in ans]
            elif qtype == "TXT":
                rec.txt = [b.decode(errors="replace") for r in ans for b in r.strings]
        except Exception:
            pass
    return rec


def enumerate_whois(domain: str) -> dict:
    if not WHOIS_OK:
        return {}
    try:
        w = pywhois.whois(domain)
        return {k: getattr(w, k, None) for k in
                ("registrar", "creation_date", "expiration_date", "name_servers", "emails", "org", "country")}
    except Exception:
        return {}

# ─────────────────────────────────────────────────────────────────────────────
# INTELLIGENCE MODULES
# ─────────────────────────────────────────────────────────────────────────────

def analyze_email(email: str) -> dict:
    if not email:
        return {}
    out: dict = {}
    try:
        _, domain = email.rsplit("@", 1)
        out["domain"] = domain
        gh = hashlib.md5(email.lower().encode()).hexdigest()
        out["gravatar_hash"] = gh
        out["gravatar_url"]  = f"https://www.gravatar.com/avatar/{gh}?d=404"
        if DNS_OK:
            try:
                out["mx_records"] = [str(r.exchange).rstrip(".") for r in dns.resolver.resolve(domain, "MX", lifetime=5)]
            except Exception:
                out["mx_records"] = []
        import os
        hibp_key = os.environ.get("HIBP_API_KEY", "")
        if hibp_key:
            import requests as _req
            resp = _req.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={"hibp-api-key": hibp_key, "user-agent": f"{TOOL_NAME}"},
                timeout=8,
            )
            out["hibp_breaches"] = resp.json() if resp.status_code == 200 else []
    except Exception as exc:
        logging.debug("Email intel: %s", exc)
    return out


def analyze_phone(mobile: str) -> dict:
    if not mobile:
        return {}
    import os
    digits = re.sub(r"\D", "", mobile)
    out    = {"raw": mobile, "digits": digits, "length": len(digits)}
    key    = os.environ.get("NUMVERIFY_API_KEY", "")
    if key:
        try:
            import requests as _req
            out.update(_req.get(
                f"http://apilayer.net/api/validate?access_key={key}&number={digits}",
                timeout=8,
            ).json())
        except Exception as exc:
            logging.debug("Phone intel: %s", exc)
    return out


def analyze_ip(ip: str) -> dict:
    if not ip:
        return {}
    import os
    out: dict = {"ip": ip}
    try:
        out["hostname"] = socket.gethostbyaddr(ip)[0]
    except Exception:
        out["hostname"] = None
    key = os.environ.get("SHODAN_API_KEY", "")
    if key:
        try:
            import shodan as _shodan
            out["shodan"] = _shodan.Shodan(key).host(ip)
        except Exception as exc:
            logging.debug("Shodan: %s", exc)
    return out

# ─────────────────────────────────────────────────────────────────────────────
# DORK GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

_DORK_TEMPLATES: dict[str, list[str]] = {
    "identity": [
        '"{name}" site:linkedin.com',
        '"{name}" "resume" OR "cv" OR "portfolio"',
        '"{name}" filetype:pdf',
        '"{name}" "{city}" "{country}"',
        '"{alias}" site:reddit.com',
        '"{alias}" site:twitter.com OR site:x.com',
    ],
    "credentials": [
        '"{email}"',
        '"{email}" site:pastebin.com',
        '"{email}" filetype:txt OR filetype:log OR filetype:sql',
        '"{email}" "password" OR "breach" OR "dump"',
    ],
    "employer": [
        '"{name}" site:linkedin.com "{employer}"',
        '"{employer}" employees site:linkedin.com',
    ],
    "code_leaks": [
        '"{username}" site:github.com',
        '"{username}" site:gitlab.com',
        '"{username}" site:pastebin.com',
        '"{email}" site:github.com',
    ],
    "documents": [
        '"{name}" filetype:doc OR filetype:docx OR filetype:pdf',
        "site:{website}",
        "site:{website} filetype:pdf",
    ],
    "location": [
        '"{name}" "{city}" "{country}"',
        '"{mobile}"',
    ],
}

# A rendered dork is useless if any substituted field was empty, leaving
# bare quotes, a trailing site: with no domain, or a lone quoted space.
_EMPTY_DORK = re.compile(r'(?:^|[\s(])""\s*(?:OR\s*"")*|site:\s*(?:$|\s)|^\s*""\s*$')

def _dork_is_valid(q: str) -> bool:
    """Return False if the rendered dork contains empty-field artifacts."""
    return not _EMPTY_DORK.search(q)

def build_dorks(target: TargetProfile, results: list[PlatformResult]) -> dict[str, list[str]]:
    found_usernames = list(dict.fromkeys(r.username for r in results if r.status == "found"))
    domain = re.sub(r"^https?://", "", target.website).split("/")[0] if target.website else ""

    subs = dict(
        name=target.name, alias=target.alias, email=target.email,
        city=target.city, country=target.country, employer=target.employer,
        website=domain, mobile=target.mobile,
        username=found_usernames[0] if found_usernames else "",
    )

    dorks: dict[str, list[str]] = {cat: [] for cat in _DORK_TEMPLATES}

    for cat, templates in _DORK_TEMPLATES.items():
        for tmpl in templates:
            try:
                rendered = tmpl.format(**subs)
            except KeyError:
                continue
            if _dork_is_valid(rendered):
                dorks[cat].append(rendered)

        if cat == "code_leaks":
            for u in found_usernames[1:]:
                dorks["code_leaks"].extend([
                    f'"{u}" site:github.com',
                    f'"{u}" site:pastebin.com',
                ])

    total = sum(len(v) for v in dorks.values())
    # Only print the dork summary when there's something worth reporting
    if total:
        sep("Dork Generation")
        cprint(f"  [bold]{total}[/bold] queries across [bold]{sum(1 for v in dorks.values() if v)}[/bold] categories.")
    return dorks


def open_dorks(dorks: dict[str, list[str]]):
    for queries in dorks.values():
        for q in queries:
            webbrowser.open(f"https://www.google.com/search?q={url_quote(q)}")
            time.sleep(0.35)

# ─────────────────────────────────────────────────────────────────────────────
# EXPOSURE SCORE
# ─────────────────────────────────────────────────────────────────────────────

_SCORE_MAX = {"pii_density": 25, "platform_footprint": 30, "cross_correlation": 15,
              "high_risk_platforms": 15, "email_intel": 10, "dns_exposure": 5}

def score_exposure(
    target:      TargetProfile,
    results:     list[PlatformResult],
    correlation: dict,
    email_intel: dict,
    dns_rec:     DNSRecord,
) -> tuple[int, str, dict]:
    sep("Exposure Score")

    found = [r for r in results if r.status == "found"]
    bd: dict[str, int] = {}

    bd["pii_density"] = min(
        (5 if target.name else 0) + (8 if target.email else 0) +
        (7 if target.mobile else 0) + (3 if target.city else 0) +
        (2 if target.country else 0), 25,
    )
    bd["platform_footprint"]  = min(sum(r.risk for r in found), 30)
    bd["cross_correlation"]   = min(len(correlation.get("strong_matches", {})) * 5, 15)
    bd["high_risk_platforms"] = min(sum(1 for r in found if r.platform in HIGH_RISK_PLATFORMS) * 3, 15)
    bd["email_intel"]         = min(
        (3 if email_intel.get("domain") else 0) +
        (2 if email_intel.get("mx_records") else 0) +
        (5 if email_intel.get("hibp_breaches") else 0), 10,
    )
    bd["dns_exposure"] = min(
        (2 if dns_rec.a else 0) + (2 if dns_rec.mx else 0) + (1 if dns_rec.txt else 0), 5,
    )

    total = min(sum(bd.values()), 100)
    label = (
        "CRITICAL" if total >= 80 else
        "HIGH"     if total >= 60 else
        "MEDIUM"   if total >= 35 else
        "LOW"
    )
    color = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}[label]

    if RICH:
        t = Table(box=box.SIMPLE, header_style="bold cyan", show_edge=False)
        t.add_column("Category", min_width=24)
        t.add_column("Score",    justify="right", min_width=6)
        t.add_column("Max",      justify="right", min_width=5, style="dim")
        for k, v in bd.items():
            t.add_row(k.replace("_", " ").title(), str(v), f"/{_SCORE_MAX[k]}")
        t.add_section()
        t.add_row("[bold]Total[/bold]", f"[bold]{total}[/bold]", "/100")
        console.print(t)
        cprint(f"\n  Risk: [{color}]{label}[/{color}]  ({total}/100)")
    else:
        for k, v in bd.items():
            print(f"  {k:<26} {v:>3}/{_SCORE_MAX[k]}")
        print(f"  {'Total':<26} {total:>3}/100  [{label}]")

    return total, label, bd

# ─────────────────────────────────────────────────────────────────────────────
# REPORT OUTPUT
# ─────────────────────────────────────────────────────────────────────────────

def save_reports(
    target:      TargetProfile,
    results:     list[PlatformResult],
    correlation: dict,
    dorks:       dict,
    score:       int,
    label:       str,
    breakdown:   dict,
    email_intel: dict,
    phone_intel: dict,
    ip_intel:    dict,
    dns_rec:     DNSRecord,
    whois_data:  dict,
) -> tuple[Path, Path, Path, Path]:
    sep("Saving Reports")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
    base  = OUTPUT_DIR / ts
    found = [r for r in results if r.status == "found"]

    # JSON
    payload = {
        "meta":        {"tool": TOOL_NAME, "timestamp": str(datetime.now()), "score": score, "risk": label},
        "target":      asdict(target),
        "breakdown":   breakdown,
        "enumeration": [asdict(r) for r in results],
        "correlation": correlation,
        "dorks":       dorks,
        "email_intel": email_intel,
        "phone_intel": phone_intel,
        "ip_intel":    ip_intel,
        "dns":         asdict(dns_rec),
        "whois":       whois_data,
    }
    json_path = base.with_suffix(".json")
    json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    cprint(f"  ✔  JSON   → [bold]{json_path}[/bold]")

    # CSV
    csv_path = OUTPUT_DIR / f"{ts}_profiles.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["Username", "Platform", "Category", "Risk", "URL", "Latency_ms"])
        for r in found:
            w.writerow([r.username, r.platform, r.category, r.risk, r.url, r.latency_ms])
    cprint(f"  ✔  CSV    → [bold]{csv_path}[/bold]")

    # TXT
    txt_path = OUTPUT_DIR / f"{ts}_summary.txt"
    lines = [
        f"{TOOL_NAME}  —  {payload['meta']['timestamp']}",
        "=" * 68,
        f"Target    : {target.name or '—'}",
        f"Email     : {target.email or '—'}",
        f"Mobile    : {target.mobile or '—'}",
        f"Location  : {(target.city + ' ' + target.country).strip() or '—'}",
        f"Employer  : {target.employer or '—'}",
        f"Risk      : {label}  ({score}/100)", "",
        f"CONFIRMED PROFILES  ({len(found)} found)", "-" * 68,
    ]
    for r in sorted(found, key=lambda x: (-x.risk, x.platform)):
        lines.append(f"  [{'★'*r.risk:<5}] [{r.category:<12}] {r.platform:<22} {r.url}")
    lines += ["", "DORKS", "-" * 68]
    for cat, qs in dorks.items():
        if qs:
            lines.append(f"\n  [{cat.upper()}]")
            lines.extend(f"    {q}" for q in qs)
    txt_path.write_text("\n".join(lines), encoding="utf-8")
    cprint(f"  ✔  TXT    → [bold]{txt_path}[/bold]")

    # HTML
    html_path = OUTPUT_DIR / f"{ts}_report.html"
    _write_html(html_path, target, found, dorks, label, score, ts)
    cprint(f"  ✔  HTML   → [bold]{html_path}[/bold]")

    return json_path, csv_path, txt_path, html_path


def _write_html(path: Path, target: TargetProfile, found: list, dorks: dict, label: str, score: int, ts: str):
    rc = {"CRITICAL": "#c0392b", "HIGH": "#e74c3c", "MEDIUM": "#f39c12", "LOW": "#27ae60"}.get(label, "#95a5a6")

    profile_rows = "".join(
        f"<tr><td>{r.username}</td><td>{r.platform}</td><td>{r.category}</td>"
        f"<td>{'★'*r.risk}</td><td><a href='{r.url}' target='_blank'>{r.url}</a></td>"
        f"<td>{r.latency_ms} ms</td></tr>\n"
        for r in sorted(found, key=lambda x: (-x.risk, x.platform))
    )
    dork_rows = "".join(
        f"<tr><td>{cat}</td>"
        f"<td><a href='https://www.google.com/search?q={url_quote(q)}' target='_blank'>{q}</a></td></tr>\n"
        for cat, qs in dorks.items() for q in qs
    )
    loc = (target.city + " " + target.country).strip() or "—"

    # CSS is kept in a separate variable (not an f-string) to avoid
    # escaping every brace in the minified ruleset.
    css = (
        ":root{--bg:#0d1117;--bg2:#161b22;--bd:#30363d;--tx:#c9d1d9;--ac:#58a6ff;--rk:" + rc + ";}"
        "*{box-sizing:border-box;margin:0;padding:0;}"
        "body{background:var(--bg);color:var(--tx);font-family:'Segoe UI',monospace;padding:28px;font-size:14px;}"
        "h1{color:var(--ac);font-size:1.6rem;margin-bottom:4px;}"
        "h2{color:var(--ac);font-size:.95rem;margin:28px 0 8px;border-bottom:1px solid var(--bd);padding-bottom:4px;}"
        ".meta{display:flex;gap:14px;flex-wrap:wrap;margin:16px 0;}"
        ".card{background:var(--bg2);border:1px solid var(--bd);border-radius:8px;padding:14px 18px;flex:1;min-width:150px;}"
        ".card label{font-size:.7rem;color:#8b949e;text-transform:uppercase;letter-spacing:.07em;}"
        ".card p{font-size:.95rem;font-weight:600;margin-top:4px;}"
        ".badge{display:inline-block;padding:3px 10px;border-radius:20px;background:var(--rk);color:#fff;font-weight:700;}"
        "table{width:100%;border-collapse:collapse;font-size:.82rem;margin-top:6px;}"
        "th{background:var(--bg2);border:1px solid var(--bd);padding:7px 10px;text-align:left;color:var(--ac);}"
        "td{border:1px solid var(--bd);padding:6px 10px;}"
        "tr:hover td{background:var(--bg2);}"
        "a{color:var(--ac);text-decoration:none;}a:hover{text-decoration:underline;}"
        ".foot{margin-top:40px;font-size:.7rem;color:#8b949e;text-align:center;}"
    )

    html = (
        '<!DOCTYPE html><html lang="en"><head>'
        '<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        f'<title>OSINT Report — {target.name or "Target"}</title>'
        f'<style>{css}</style></head><body>'
        '<h1>🔍 OSINT Report</h1>'
        f'<p style="color:#8b949e;font-size:.78rem">Generated: {ts} &nbsp;|&nbsp; {TOOL_NAME}</p>'
        '<div class="meta">'
        f'<div class="card"><label>Target</label><p>{target.name or "—"}</p></div>'
        f'<div class="card"><label>Email</label><p>{target.email or "—"}</p></div>'
        f'<div class="card"><label>Location</label><p>{loc}</p></div>'
        f'<div class="card"><label>Employer</label><p>{target.employer or "—"}</p></div>'
        f'<div class="card"><label>Risk</label><p><span class="badge">{label}</span>&nbsp;{score}/100</p></div>'
        f'<div class="card"><label>Profiles Found</label><p>{len(found)}</p></div>'
        '</div>'
        '<h2>Confirmed Profiles</h2>'
        '<table><tr><th>Username</th><th>Platform</th><th>Category</th>'
        '<th>Risk</th><th>URL</th><th>Latency</th></tr>'
        f'{profile_rows}</table>'
        '<h2>Google Dorks</h2>'
        '<table><tr><th>Category</th><th>Query</th></tr>'
        f'{dork_rows}</table>'
        f'<div class="foot">Confidential — authorised use only &nbsp;|&nbsp; {TOOL_NAME}</div>'
        '</body></html>'
    )

    path.write_text(html, encoding="utf-8")

# ─────────────────────────────────────────────────────────────────────────────
# CHECKPOINT
# ─────────────────────────────────────────────────────────────────────────────

def _save_cp(results: list[PlatformResult]):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    CHECKPOINT_FILE.write_text(
        json.dumps({"timestamp": str(datetime.now()), "results": [asdict(r) for r in results]}, default=str),
        encoding="utf-8",
    )

def _load_cp() -> Optional[list[PlatformResult]]:
    if not CHECKPOINT_FILE.exists():
        return None
    try:
        data = json.loads(CHECKPOINT_FILE.read_text())
        if yes_no(f"\n  Resume checkpoint from {data.get('timestamp', '?')}?"):
            return [PlatformResult(**r) for r in data.get("results", [])]
    except Exception:
        pass
    return None

def _clear_cp():
    if CHECKPOINT_FILE.exists():
        CHECKPOINT_FILE.unlink()

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def run():
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")
    banner()

    # Consent gate
    notice = (
        "[bold yellow]LEGAL NOTICE[/bold yellow]\n\n"
        "Use only with [bold]explicit written authorisation[/bold].\n"
        "Unauthorised use may violate CFAA, GDPR, CCPA, and local laws."
    )
    cprint(Panel(notice, border_style="red", expand=False) if RICH else notice)
    if not yes_no("\n  I confirm authorisation"):
        cprint("  Aborted.", style="red")
        sys.exit(0)

    if yes_no("  Run OPSEC pre-flight check?"):
        opsec_check()

    # Resume checkpoint if available
    results: Optional[list[PlatformResult]] = _load_cp()

    # Collect target info
    target = collect_target()

    # Build username list
    seeds = list(dict.fromkeys(
        [u for u in target.seed_usernames if u] +
        ([target.alias] if target.alias else [])
    ))

    if not seeds:
        cprint("\n  [yellow]No usernames provided — enumeration skipped.[/yellow]")
        results = []
    elif results is None:
        sep("Enumeration")
        use_variants = yes_no("  Generate username variants?")
        usernames    = generate_variants(seeds, target.name) if use_variants else seeds

        # Show compact summary so user knows what was generated
        extras = [u for u in usernames if u not in seeds]
        cprint(f"  Seeds     : {', '.join(seeds)}")
        if extras:
            preview = extras[:6]
            more    = len(extras) - len(preview)
            cprint(f"  Variants  : {', '.join(preview)}" + (f"  … +{more} more" if more else ""), style="dim")
        cprint(f"  Total     : [bold]{len(usernames)}[/bold] username(s) × [bold]{len(PLATFORMS)}[/bold] platforms\n")

        results = run_scan(usernames)
        _save_cp(results)

    display_results(results)
    correlation = correlate(results)

    # Intelligence modules — print only meaningful findings
    sep("Intelligence")
    email_intel = analyze_email(target.email)
    phone_intel = analyze_phone(target.mobile)
    ip_intel    = analyze_ip(target.ip)
    dns_rec     = DNSRecord(domain="")
    whois_data: dict = {}

    if target.website:
        domain     = re.sub(r"^https?://", "", target.website).split("/")[0]
        dns_rec    = enumerate_dns(domain)
        whois_data = enumerate_whois(domain)

    # Surface only non-empty findings
    findings = [
        ("DNS A",       ", ".join(dns_rec.a)                              if dns_rec.a else None),
        ("DNS MX",      ", ".join(dns_rec.mx)                             if dns_rec.mx else None),
        ("Registrar",   str(whois_data.get("registrar"))                  if whois_data.get("registrar") else None),
        ("Registered",  str(whois_data.get("creation_date"))              if whois_data.get("creation_date") else None),
        ("Email MX",    ", ".join(email_intel.get("mx_records", []))      if email_intel.get("mx_records") else None),
        ("HIBP",        f"[red]{len(email_intel['hibp_breaches'])} breach(es)[/red]" if email_intel.get("hibp_breaches") else None),
        ("Gravatar",    email_intel.get("gravatar_url")                   if email_intel.get("gravatar_url") else None),
        ("IP hostname", ip_intel.get("hostname")                          if ip_intel.get("hostname") else None),
    ]
    printed = False
    for label_str, value in findings:
        if value:
            cprint(f"  {label_str:<14}: {value}")
            printed = True
    if not printed:
        cprint("  No supplementary data resolved.", style="dim")

    # Dorks
    dorks = build_dorks(target, results)
    if any(dorks.values()) and yes_no("\n  Open dorks in browser?"):
        open_dorks(dorks)

    # Score
    score, risk_label, breakdown = score_exposure(target, results, correlation, email_intel, dns_rec)

    # Save reports
    if yes_no("\n  Save reports? (JSON / CSV / TXT / HTML)"):
        paths = save_reports(
            target, results, correlation, dorks,
            score, risk_label, breakdown,
            email_intel, phone_intel, ip_intel, dns_rec, whois_data,
        )
        if yes_no("  Open HTML in browser?"):
            webbrowser.open(paths[3].resolve().as_uri())

    _clear_cp()
    sep()
    cprint(f"\n  [bold green]Complete.[/bold green]  Risk: [bold]{risk_label}[/bold]  ({score}/100)\n")


if __name__ == "__main__":
    run()
