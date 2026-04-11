"""
Authentica CLI — full ExifTool-parity command-line tool.

Commands:
  scan       — full AI authenticity scan (C2PA + watermark + forensics)
  meta       — read all EXIF/IPTC/XMP/GPS metadata (like exiftool FILE)
  c2pa       — read C2PA content credentials
  watermark  — detect invisible watermarks
  forensics  — ELA + noise + frequency forensics
  diff       — compare metadata between two files (like exiftool -diff)
  scan-dir   — batch scan a directory (like exiftool -r DIR)
  thumbnail  — extract embedded JPEG thumbnail

Cross-platform: works on Linux, macOS, Windows.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box as rich_box

from authentica.core import scan as _scan
from authentica.c2pa.reader import C2PAReader
from authentica.watermark.detector import WatermarkDetector
from authentica.forensics.analyzer import ForensicsAnalyzer
from authentica.metadata.reader import MetadataReader
from authentica.metadata.diff import diff_metadata
from authentica.metadata.thumbnail import extract_thumbnail
from authentica.scanner.batch import BatchScanner, results_to_csv, results_to_json
from authentica.utils.platform import platform_info

console = Console()


@click.group()
@click.version_option(package_name="authentica")
def cli() -> None:
    """Authentica — AI content authenticity + metadata toolkit.\n
    Cross-platform alternative to ExifTool with C2PA, watermark & forensics."""


# ── scan ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--json", "as_json", is_flag=True)
@click.option("--heatmap", type=click.Path(path_type=Path), default=None)
@click.option("--no-c2pa",      is_flag=True)
@click.option("--no-watermark", is_flag=True)
@click.option("--no-forensics", is_flag=True)
def scan(file, as_json, heatmap, no_c2pa, no_watermark, no_forensics):
    """Run full AI authenticity scan on FILE."""
    with console.status(f"[bold cyan]Scanning {file.name}…[/]"):
        result = _scan(file, run_c2pa=not no_c2pa,
                       run_watermark=not no_watermark,
                       run_forensics=not no_forensics)

    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
        return

    _print_banner(file, result.file_type, result.scan_time_s)
    _print_trust_score(result.trust_score)
    if result.c2pa:
        _print_c2pa(result.c2pa)
    if result.watermark:
        _print_watermark(result.watermark)
    if result.forensics:
        _print_forensics(result.forensics)
    if result.errors:
        console.print("\n[yellow]Errors:[/]")
        for m, msg in result.errors.items():
            console.print(f"  [red]{m}[/]: {msg}")
    if heatmap and result.watermark and result.watermark.heatmap is not None:
        result.watermark.save_heatmap(heatmap)
        console.print(f"\n[green]✓[/] Heatmap → [bold]{heatmap}[/]")


# ── meta ──────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--json",     "as_json",  is_flag=True, help="JSON output  (-j in exiftool)")
@click.option("--csv",      "as_csv",   is_flag=True, help="CSV output   (-csv in exiftool)")
@click.option("--short",    "short",    is_flag=True, help="Tag names only (-s in exiftool)")
@click.option("--no-group", "no_group", is_flag=True, help="Flat output   (-G off)")
@click.option("--no-hash",  "no_hash",  is_flag=True, help="Skip MD5/SHA256")
@click.option("--gps-dms",  "gps_dms",  is_flag=True, help="GPS as deg/min/sec (-c in exiftool)")
def meta(file, as_json, as_csv, short, no_group, no_hash, gps_dms):
    """Read all metadata from FILE (EXIF, IPTC, XMP, GPS, ICC…).

    Equivalent to:  exiftool -j -G FILE"""
    with console.status("[bold cyan]Reading metadata…[/]"):
        reader = MetadataReader(compute_hashes=not no_hash)
        result = reader.read(file)

    data = result.to_dict(group=not no_group)

    if as_json:
        click.echo(json.dumps(data, indent=2, default=str))
        return

    if as_csv:
        flat = result.to_dict(group=False)
        flat["SourceFile"] = str(file)
        click.echo(results_to_csv([flat]))
        return

    console.print(Panel(
        f"[bold]{file.name}[/]  ·  {result.mime_type}  ·  {result.file_size:,} bytes",
        title="[bold cyan]Metadata[/]", border_style="cyan",
    ))

    for group_name, tags in data.items():
        if not isinstance(tags, dict) or not tags:
            continue
        tbl = Table(box=rich_box.SIMPLE, show_header=True, pad_edge=False)
        tbl.add_column(group_name, style="bold cyan", no_wrap=True, width=26)
        tbl.add_column("Value")
        for k, v in tags.items():
            if v is None:
                continue
            if k == "ThumbnailJPEG":
                v = f"<{len(v)} bytes JPEG>"
            tbl.add_row(k, str(v)[:120])
        console.print(tbl)

    if result.gps and result.gps.latitude is not None:
        fmt = "dms" if gps_dms else "decimal"
        console.print(f"\n[bold]GPS position[/]: {result.gps.coord_format(fmt)}")

    if result.md5:
        console.print(f"\n[dim]MD5:    {result.md5}[/]")
        console.print(f"[dim]SHA256: {result.sha256}[/]")

    for w in result.warnings:
        console.print(f"[dim yellow]⚠ {w}[/]")


# ── diff ──────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("file_a", type=click.Path(exists=True, path_type=Path))
@click.argument("file_b", type=click.Path(exists=True, path_type=Path))
@click.option("--json", "as_json", is_flag=True)
def diff(file_a, file_b, as_json):
    """Compare metadata between two files.

    Equivalent to:  exiftool -diff FILE1 FILE2"""
    with console.status("[bold cyan]Comparing metadata…[/]"):
        result = diff_metadata(file_a, file_b)

    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2, default=str))
        return

    console.print(Panel(result.summary(),
                        title="[bold cyan]Metadata diff[/]", border_style="cyan"))

    if result.added:
        console.print("\n[green]Added tags:[/]")
        for e in result.added:
            console.print(f"  [green]+[/] [bold]{e.tag}[/] = {str(e.value_b)[:80]}")

    if result.removed:
        console.print("\n[red]Removed tags:[/]")
        for e in result.removed:
            console.print(f"  [red]-[/] [bold]{e.tag}[/] = {str(e.value_a)[:80]}")

    if result.changed:
        console.print("\n[yellow]Changed tags:[/]")
        for e in result.changed:
            console.print(f"  [yellow]~[/] [bold]{e.tag}[/]")
            console.print(f"      was: {str(e.value_a)[:80]}")
            console.print(f"      now: {str(e.value_b)[:80]}")

    if not result.entries:
        console.print("[dim]No differences found.[/]")


# ── scan-dir ──────────────────────────────────────────────────────────────────

@cli.command("scan-dir")
@click.argument("directory", type=click.Path(exists=True, path_type=Path))
@click.option("--ext",        multiple=True,  help="Extensions to include (e.g. --ext jpg)")
@click.option("--no-recurse", is_flag=True,   help="Don't recurse into subdirectories")
@click.option("--json",       "as_json", is_flag=True)
@click.option("--csv",        "as_csv",  is_flag=True)
@click.option("--out",        "outfile", type=click.Path(path_type=Path), default=None)
@click.option("--progress",   is_flag=True)
@click.option("--authentica", "run_auth", is_flag=True, help="Also run authenticity scan")
def scan_dir(directory, ext, no_recurse, as_json, as_csv, outfile, progress, run_auth):
    """Batch scan a directory for metadata.

    Equivalent to:  exiftool -r -json DIR"""
    extensions = {f".{e.lstrip('.')}" for e in ext} if ext else None
    scanner = BatchScanner(
        extensions=extensions,
        recurse=not no_recurse,
        progress=progress,
    )

    def processor(path: Path) -> dict:
        reader = MetadataReader(compute_hashes=False)
        r = reader.read(path)
        d = r.to_dict(group=False)
        if run_auth:
            auth = _scan(path, run_c2pa=True, run_watermark=False, run_forensics=False)
            d["C2PA_Found"] = auth.has_c2pa
            d["TrustScore"] = round(auth.trust_score, 1)
        return d

    with console.status("[bold cyan]Scanning directory…[/]"):
        results, stats = scanner.scan_all(directory, processor)

    console.print(f"\n[bold cyan]Complete[/]: {stats.summary()}")

    if as_json or (outfile and str(outfile).endswith(".json")):
        out = results_to_json(results, outfile)
        if not outfile:
            click.echo(out)
    elif as_csv or outfile:
        out = results_to_csv(results, outfile)
        if not outfile:
            click.echo(out)
    else:
        console.print(f"[dim]{len(results)} files scanned. Use --json or --csv to export.[/]")

    if outfile:
        console.print(f"[green]✓[/] Saved → [bold]{outfile}[/]")


# ── thumbnail ─────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--out",  "outfile", type=click.Path(path_type=Path), default=None,
              help="Save thumbnail to file  (exiftool: -ThumbnailImage -b)")
@click.option("--json", "as_json", is_flag=True)
def thumbnail(file, outfile, as_json):
    """Extract embedded JPEG thumbnail from FILE.

    Equivalent to:  exiftool -ThumbnailImage -b FILE > thumb.jpg"""
    result = extract_thumbnail(file)

    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
        return

    if result.found:
        console.print(
            f"[green]✓[/] Thumbnail found  "
            f"source={result.source}  "
            f"{result.width}×{result.height}  "
            f"{len(result.data):,} bytes"
        )
        if outfile:
            result.save(outfile)
            console.print(f"[green]✓[/] Saved → [bold]{outfile}[/]")
        else:
            console.print("[dim]Use --out PATH to save the thumbnail.[/]")
    else:
        console.print("[dim]✗ No embedded thumbnail found.[/]")


# ── c2pa ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--json", "as_json", is_flag=True)
def c2pa(file, as_json):
    """Read C2PA content credentials from FILE."""
    with console.status("[bold cyan]Reading C2PA manifest…[/]"):
        result = C2PAReader().read(file)
    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
        return
    _print_c2pa(result)


# ── watermark ────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--save-heatmap", "heatmap_path", type=click.Path(path_type=Path), default=None)
@click.option("--json", "as_json", is_flag=True)
def watermark(file, heatmap_path, as_json):
    """Detect passive invisible watermarks in FILE."""
    with console.status("[bold cyan]Analysing watermark signals…[/]"):
        result = WatermarkDetector().detect(file)
    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
        return
    _print_watermark(result)
    if heatmap_path:
        result.save_heatmap(heatmap_path)
        console.print(f"[green]✓[/] Heatmap → [bold]{heatmap_path}[/]")


# ── forensics ────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("file", type=click.Path(exists=True, path_type=Path))
@click.option("--save-ela",   "ela_path",   type=click.Path(path_type=Path), default=None)
@click.option("--save-noise", "noise_path", type=click.Path(path_type=Path), default=None)
@click.option("--json", "as_json", is_flag=True)
def forensics(file, ela_path, noise_path, as_json):
    """Run image forensics on FILE (ELA, noise, frequency)."""
    with console.status("[bold cyan]Running forensics…[/]"):
        result = ForensicsAnalyzer().analyze(file)
    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
        return
    _print_forensics(result)
    if ela_path:
        result.save_ela_heatmap(ela_path)
        console.print(f"[green]✓[/] ELA heatmap → [bold]{ela_path}[/]")
    if noise_path:
        result.save_noise_heatmap(noise_path)
        console.print(f"[green]✓[/] Noise heatmap → [bold]{noise_path}[/]")


# ── version ───────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--verbose", is_flag=True, help="Show platform info  (exiftool: -ver -v)")
def version(verbose):
    """Show version and platform info."""
    from authentica import __version__
    console.print(f"[bold]Authentica[/] {__version__}")
    if verbose:
        for k, v in platform_info().items():
            console.print(f"  {k}: {v}")


# ── Rich display helpers ──────────────────────────────────────────────────────

def _print_banner(file: Path, file_type: str, elapsed: float) -> None:
    console.print(Panel(
        f"[bold]{file.name}[/]  ·  {file_type}  ·  {elapsed:.2f}s",
        title="[bold cyan]Authentica[/]", border_style="cyan",
    ))


def _print_trust_score(score: float) -> None:
    bar_len = 30
    filled = int(score / 100 * bar_len)
    colour = "green" if score >= 65 else "yellow" if score >= 35 else "red"
    bar = f"[{colour}]{'█' * filled}[/][dim]{'░' * (bar_len - filled)}[/]"
    label = "HIGH" if score >= 65 else "MEDIUM" if score >= 35 else "LOW"
    console.print(f"\nTrust  {bar}  [{colour}]{score:.0f}/100 ({label})[/]\n")


def _print_c2pa(result) -> None:
    found, sig = result.manifest_found, result.signature_valid
    status = (
        "[green]✓ Manifest found, signature intact[/]" if found and sig else
        "[yellow]⚠ Manifest found, signature INVALID[/]" if found else
        "[dim]✗ No C2PA manifest[/]"
    )
    console.print(f"[bold]C2PA[/]  {status}")
    if found and result.claims:
        c = result.claims[0]
        console.print(f"  Generator : {c.claim_generator}")
        console.print(f"  Recorder  : {c.recorder}")
        for a in c.assertions:
            console.print(f"  [cyan]{a.label}[/]  {a.description}")
    for w in result.parse_warnings:
        console.print(f"  [dim yellow]⚠ {w}[/]")
    console.print()


def _print_watermark(result) -> None:
    icon = "[green]✓[/]" if result.detected else "[dim]✗[/]"
    conf = result.confidence
    colour = "green" if conf > 0.6 else "yellow" if conf > 0.35 else "dim"
    console.print(f"[bold]Watermark[/]  {icon}  [{colour}]{conf:.0%} confidence[/]")
    if result.method_scores:
        console.print("  " + "  ".join(
            f"{k}={v:.2f}" for k, v in result.method_scores.items()))
    console.print()


def _print_forensics(result) -> None:
    score = result.anomaly_score
    colour = "red" if score > 0.6 else "yellow" if score > 0.3 else "green"
    console.print(f"[bold]Forensics[/]  anomaly [{colour}]{score:.0%}[/]")
    console.print(
        f"  ELA {result.ela_score:.0%}  "
        f"Noise {result.noise_score:.0%}  "
        f"Freq {result.frequency_score:.0%}"
    )
    console.print()
