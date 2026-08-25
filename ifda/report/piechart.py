"""Rootfs directory-composition pie chart (FR-INV dashboard visual): renders
report.dir_breakdown (top-level directory -> on-disk byte share) to a PNG.

Tries a CUDA per-pixel rasterizer first -- each GPU thread computes one
pixel's wedge membership and color directly from polar coordinates, which is
genuinely parallel work rather than a GPU-flavored wrapper around CPU
drawing -- and falls back to CPU vector rendering via Pillow (a core
dependency) whenever no usable CUDA device is present, since most machines
running this tool won't have one. Never raises: any failure on the GPU path
(cupy not installed, no NVIDIA driver, no device, a runtime error probing
it) just means the CPU path runs instead.

Text labels (in-wedge names, outside leader-line callouts with pct/size) are
always composited on the CPU afterward via Pillow regardless of which path
drew the wedges -- font rasterization isn't a workload that benefits from a
custom CUDA kernel, and doing it host-side keeps the kernel itself simple
(pure per-pixel wedge coloring).
"""

from __future__ import annotations

import math

# Distinct, colorblind-tolerant hues; reused cyclically for >12 top-level dirs.
_PALETTE = [
    (66, 133, 244), (219, 68, 55), (244, 160, 0), (15, 157, 88),
    (171, 71, 188), (0, 172, 193), (255, 112, 67), (158, 157, 36),
    (92, 107, 192), (0, 121, 107), (194, 24, 91), (121, 85, 72),
]

_CUDA_SOURCE = r"""
extern "C" __global__
void render_pie(unsigned char* out, int size, const float* boundaries, int n_slices,
                 const unsigned char* colors, float radius_frac) {
    int x = blockIdx.x * blockDim.x + threadIdx.x;
    int y = blockIdx.y * blockDim.y + threadIdx.y;
    if (x >= size || y >= size) return;

    float cx = size * 0.5f, cy = size * 0.5f;
    float radius = size * radius_frac;
    float inner = radius * 0.42f; // donut hole

    float dx = x - cx, dy = y - cy;
    float dist = sqrtf(dx * dx + dy * dy);
    int idx = (y * size + x) * 4;

    if (dist > radius || dist < inner) {
        out[idx] = 0; out[idx + 1] = 0; out[idx + 2] = 0; out[idx + 3] = 0;
        return; // transparent outside the ring, so the page's own theme shows through
    }

    float angle = atan2f(dy, dx) / (2.0f * 3.14159265358979f); // (-0.5, 0.5]
    if (angle < 0.0f) angle += 1.0f;
    angle = fmodf(angle + 0.25f, 1.0f); // start at 12 o'clock, sweep clockwise

    int chosen = n_slices - 1;
    for (int i = 0; i < n_slices; i++) {
        if (angle >= boundaries[i] && angle < boundaries[i + 1]) { chosen = i; break; }
    }
    out[idx] = colors[chosen * 3];
    out[idx + 1] = colors[chosen * 3 + 1];
    out[idx + 2] = colors[chosen * 3 + 2];
    out[idx + 3] = 255;
}
"""


def render_dir_pie_chart(breakdown: list[dict], out_path: str, size: int = 820) -> str:
    """Writes a labeled donut/pie chart PNG for `breakdown` (list of
    {"name", "bytes", "pct"}, as produced by inventory.top_level_dir_breakdown)
    to `out_path`: each directory's name inside its wedge, and a leader line
    out to its percentage + formatted on-disk size outside the ring. Returns
    which renderer actually drew the wedges: "cuda" or "cpu"."""
    for d in breakdown:
        d.setdefault("label", _format_bytes(d.get("bytes", 0)))
    return render_pie_chart(breakdown, out_path, size, value_key="bytes", annotate=True)


def render_pie_chart(slices: list[dict], out_path: str, size: int = 640,
                      value_key: str = "value", annotate: bool = False) -> str:
    """Generic version of render_dir_pie_chart: writes a donut/pie chart PNG
    for `slices` (list of {"name", <value_key>}, any non-negative numeric
    values -- byte counts, function counts, whatever the caller is
    breaking down) to `out_path`. Returns which renderer was actually used:
    "cuda" or "cpu". Reused by the compare-scan function-diff visualization
    (added/removed/modified/unchanged counts) as well as the rootfs
    directory-composition chart above.

    `annotate`, when set, draws in-wedge name labels and outside leader-line
    callouts (see render_dir_pie_chart) -- off by default because the
    smaller charts this function also serves (the live per-scan progress
    donut, the compare-diff donut) already have their own adjacent HTML
    legend and render at a size where callout text wouldn't have room.
    """
    # A smaller wedge radius when annotating leaves the outer margin the
    # leader lines and callout text need; unannotated charts use the full
    # radius since they have no need for that margin.
    radius_frac = 0.26 if annotate else 0.42
    prepared = _prepare_slices(slices, value_key)

    image = _try_cuda_render(prepared, size, radius_frac)
    renderer = "cuda"
    if image is None:
        image = _cpu_render(prepared, size, radius_frac)
        renderer = "cpu"

    if annotate:
        _draw_labels(image, slices, value_key, size, radius_frac)

    image.save(out_path, "PNG")
    return renderer


def _format_bytes(n: float) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    n = float(max(n, 0))
    i = 0
    while n >= 1024 and i < len(units) - 1:
        n /= 1024
        i += 1
    return f"{n:.0f} {units[i]}" if i == 0 else f"{n:.1f} {units[i]}"


def _luminance(rgb: tuple) -> float:
    r, g, b = rgb
    return 0.299 * r + 0.587 * g + 0.114 * b


def _prepare_slices(slices: list[dict], value_key: str = "value") -> list[tuple]:
    total = sum(max(d.get(value_key, 0), 0) for d in slices) or 1
    out = []
    for i, d in enumerate(slices):
        frac = max(d.get(value_key, 0), 0) / total
        out.append((d.get("name", "?"), frac, _PALETTE[i % len(_PALETTE)]))
    return out


def _try_cuda_render(slices, size: int, radius_frac: float = 0.42):
    if not slices:
        return None
    try:
        import cupy as cp
    except ImportError:
        return None
    try:
        if cp.cuda.runtime.getDeviceCount() < 1:
            return None
    except Exception:
        return None

    try:
        import numpy as np
        from PIL import Image

        n = len(slices)
        fracs = np.array([s[1] for s in slices], dtype=np.float32)
        boundaries = np.concatenate(([0.0], np.cumsum(fracs))).astype(np.float32)
        boundaries[-1] = 1.0  # absorb float drift so the last wedge closes exactly
        colors = np.array([s[2] for s in slices], dtype=np.uint8)

        d_boundaries = cp.asarray(boundaries)
        d_colors = cp.asarray(colors)
        d_out = cp.zeros((size, size, 4), dtype=cp.uint8)

        kernel = cp.RawKernel(_CUDA_SOURCE, "render_pie")
        threads = 16
        blocks = (size + threads - 1) // threads
        kernel((blocks, blocks), (threads, threads),
               (d_out, cp.int32(size), d_boundaries, cp.int32(n), d_colors,
                cp.float32(radius_frac)))
        cp.cuda.Stream.null.synchronize()

        return Image.fromarray(cp.asnumpy(d_out), "RGBA")
    except Exception:
        return None


def _cpu_render(slices, size: int, radius_frac: float = 0.42):
    """CPU fallback: vector polygon fill via Pillow -- the CPU-appropriate
    technique (a per-pixel Python loop over a large canvas would be far
    slower than filling a dozen wedge polygons directly)."""
    from PIL import Image, ImageDraw

    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    cx, cy = size / 2, size / 2
    radius = size * radius_frac
    inner = radius * 0.42
    box = [cx - radius, cy - radius, cx + radius, cy + radius]

    start_deg = -90.0  # 12 o'clock
    for _name, frac, color in slices:
        sweep = frac * 360.0
        if sweep <= 0:
            continue
        draw.pieslice(box, start_deg, start_deg + sweep, fill=color + (255,))
        start_deg += sweep

    if inner > 0:
        hole_box = [cx - inner, cy - inner, cx + inner, cy + inner]
        draw.ellipse(hole_box, fill=(0, 0, 0, 0))

    return image


def _load_fonts(size: int):
    from PIL import ImageFont

    try:
        return (ImageFont.load_default(size=max(11, int(size * 0.024))),
                ImageFont.load_default(size=max(10, int(size * 0.020))))
    except TypeError:
        # Pillow < 10.1: load_default() takes no size argument, and the
        # bitmap font it returns doesn't support the `anchor` kwarg either
        # -- callers must not pass anchor= when using this fallback font.
        f = ImageFont.load_default()
        return f, f


def _draw_labels(image, slices: list[dict], value_key: str, size: int, radius_frac: float) -> None:
    """Composites in-wedge name labels and outside pct/size leader-line
    callouts onto an already-rendered wedge image, in place. Uses the exact
    same start-at-12-o'clock, clockwise-sweep angle convention as the CUDA
    kernel and _cpu_render above, so labels line up with the wedges under
    them regardless of which one drew this image."""
    from PIL import ImageDraw

    total = sum(max(d.get(value_key, 0), 0) for d in slices) or 1
    draw = ImageDraw.Draw(image)
    cx, cy = size / 2, size / 2
    radius = size * radius_frac
    inner = radius * 0.42
    mid_r = (radius + inner) / 2
    label_r = radius + size * 0.05

    font_in, font_out = _load_fonts(size)
    try:
        draw.text((0, 0), "", font=font_in, anchor="mm")
        anchor_supported = True
    except TypeError:
        anchor_supported = False

    start_deg = -90.0
    for i, d in enumerate(slices):
        value = max(d.get(value_key, 0), 0)
        frac = value / total
        sweep = frac * 360.0
        if sweep <= 0:
            continue
        mid_deg = start_deg + sweep / 2
        mid_rad = math.radians(mid_deg)
        color = _PALETTE[i % len(_PALETTE)]
        name = str(d.get("name", "?"))

        # In-wedge name -- only where there's visually enough angular room;
        # a sub-14-degree sliver can't legibly hold text regardless of font
        # size and would just spill into its neighbors.
        if sweep >= 14:
            mx = cx + mid_r * math.cos(mid_rad)
            my = cy + mid_r * math.sin(mid_rad)
            text_color = (255, 255, 255, 255) if _luminance(color) < 140 else (25, 25, 25, 255)
            label_text = name if len(name) <= 12 else name[:11] + "…"
            if anchor_supported:
                draw.text((mx, my), label_text, font=font_in, fill=text_color, anchor="mm")
            else:
                w = draw.textlength(label_text, font=font_in)
                draw.text((mx - w / 2, my - 6), label_text, font=font_in, fill=text_color)

        # Outside leader line + pct/size callout. Skipped below ~2% (7deg):
        # real firmware rootfs trees commonly have a dozen-plus top-level
        # dirs, most of them tiny, and cramming a callout onto every one of
        # them produces an unreadable pile of overlapping text rather than
        # more information -- the HTML legend beside this image already
        # lists every single directory with its exact pct/size in plain
        # text, so nothing is actually lost by not also repeating the small
        # ones as PNG callouts.
        if sweep >= 7:
            ex, ey = cx + radius * math.cos(mid_rad), cy + radius * math.sin(mid_rad)
            lx, ly = cx + label_r * math.cos(mid_rad), cy + label_r * math.sin(mid_rad)
            draw.line([(ex, ey), (lx, ly)], fill=(150, 150, 150, 220), width=1)

            label = str(d.get("label", value))
            text = f"{name}  {frac * 100:.1f}% · {label}"
            on_right = math.cos(mid_rad) >= 0
            text_w = draw.textlength(text, font=font_out)
            # Clamp so the callout can't run off the canvas edge -- a
            # leader-line label's whole point is to sit outside the ring,
            # not necessarily at a fixed radius, so nudging it inward
            # horizontally when needed doesn't break the layout.
            if on_right and lx + text_w > size - 6:
                lx = size - 6 - text_w
            elif not on_right and lx - text_w < 6:
                lx = 6 + text_w
            ly = min(max(ly, 10), size - 10)
            if anchor_supported:
                draw.text((lx, ly), text, font=font_out, fill=(190, 190, 190, 255),
                          anchor=("lm" if on_right else "rm"))
            else:
                tx = lx if on_right else lx - text_w
                draw.text((tx, ly - 6), text, font=font_out, fill=(190, 190, 190, 255))

        start_deg += sweep
