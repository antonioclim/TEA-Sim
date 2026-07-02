from __future__ import annotations

from pathlib import Path
import struct
import zlib
from typing import Dict, Tuple, Iterable, List

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Rectangle
from matplotlib.lines import Line2D
from matplotlib.ticker import LogLocator, ScalarFormatter

LJI_LOWER_THRESHOLD = -0.05
LJI_UPPER_THRESHOLD = 0.10

plt.rcParams.update({
    "font.family": "Liberation Sans",
    "font.size": 8.5,
    "axes.titlesize": 10,
    "axes.labelsize": 8.5,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
    "legend.fontsize": 8,
    "figure.titlesize": 10.5,
    "axes.spines.top": False,
    "axes.spines.right": False,
})

COL = {
    "ink": "#222222",
    "muted": "#6f6f6f",
    "light_line": "#d0d0d0",
    "lane": "#f7f7f7",
    "semantic": "#ffffff",
    "interface": "#f0f4f7",
    "backend": "#f5f5f5",
    "payload": "#fbfbfb",
    "source": "#ffffff",
    "actor": "#ffffff",
    "a1": "#1b1b1b",
    "a2": "#666666",
    "a3": "#aaaaaa",
    "lji": "#333333",
}

ARCH_STYLE = {
    "A1 Central audit": {"marker": "o", "color": COL["a1"], "label": "A1 central audit"},
    "A2 Hash log": {"marker": "s", "color": COL["a2"], "label": "A2 hash log"},
    "A3 Ledger-like": {"marker": "^", "color": COL["a3"], "label": "A3 ledger-like"},
}


def strip_png_text_chunks(path: Path) -> None:
    data = path.read_bytes()
    signature = b"\x89PNG\r\n\x1a\n"
    if not data.startswith(signature):
        return
    offset = len(signature)
    kept = [signature]
    removable = {b"tEXt", b"zTXt", b"iTXt", b"tIME"}
    while offset < len(data):
        length = struct.unpack(">I", data[offset:offset + 4])[0]
        chunk_type = data[offset + 4:offset + 8]
        chunk_data = data[offset + 8:offset + 8 + length]
        if chunk_type not in removable:
            new_crc = struct.pack(">I", zlib.crc32(chunk_type + chunk_data) & 0xffffffff)
            kept.append(struct.pack(">I", length) + chunk_type + chunk_data + new_crc)
        offset += 12 + length
        if chunk_type == b"IEND":
            break
    path.write_bytes(b"".join(kept))


def save_public_figure(fig, base: Path, png_dpi: int = 300, tiff_dpi: int = 300, vector: bool = True) -> None:
    base.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(base.with_suffix(".png"), dpi=png_dpi, bbox_inches="tight", pad_inches=0.04)
    strip_png_text_chunks(base.with_suffix(".png"))
    fig.savefig(base.with_suffix(".tiff"), dpi=tiff_dpi, bbox_inches="tight", pad_inches=0.04,
                pil_kwargs={"compression": "tiff_lzw"})
    if vector:
        fig.savefig(base.with_suffix(".pdf"), bbox_inches="tight", pad_inches=0.04,
                    metadata={"Creator": "TEA-Sim plotting scripts"})
        fig.savefig(base.with_suffix(".svg"), bbox_inches="tight", pad_inches=0.04,
                    metadata={"Creator": "TEA-Sim plotting scripts"})
    plt.close(fig)


def read_specs(root: Path):
    spec_dir = root / "data" / "figure_specs"
    nodes = pd.read_csv(spec_dir / "figure_1_nodes.csv")
    edges = pd.read_csv(spec_dir / "figure_1_edges.csv").fillna("")
    groups = pd.read_csv(spec_dir / "figure_1_groups.csv")
    legend = pd.read_csv(spec_dir / "figure_1_legend.csv")
    return nodes, edges, groups, legend


def node_record(nodes: pd.DataFrame) -> Dict[str, dict]:
    return {r["node_id"]: r.to_dict() for _, r in nodes.iterrows()}


def anchor(node: dict, anchor_name: str) -> Tuple[float, float]:
    x, y, w, h = float(node["x"]), float(node["y"]), float(node["w"]), float(node["h"])
    if anchor_name == "left":
        return x, y + h / 2
    if anchor_name == "right":
        return x + w, y + h / 2
    if anchor_name == "top":
        return x + w / 2, y + h
    if anchor_name == "bottom":
        return x + w / 2, y
    return x + w / 2, y + h / 2


def parse_via(via: str) -> List[Tuple[float, float]]:
    if not isinstance(via, str) or not via.strip():
        return []
    pts = []
    for item in via.split(";"):
        x, y = item.split(":")
        pts.append((float(x), float(y)))
    return pts


def edge_properties(edge_type: str):
    if edge_type == "payload":
        return {"linestyle": (0, (4, 2)), "lw": 1.0, "color": "#555555"}
    if edge_type == "verification":
        return {"linestyle": (0, (1, 2)), "lw": 1.0, "color": "#555555"}
    return {"linestyle": "-", "lw": 1.05, "color": "#222222"}


def draw_poly_arrow(ax, points: Iterable[Tuple[float, float]], edge_type: str) -> None:
    pts = list(points)
    props = edge_properties(edge_type)
    if len(pts) < 2:
        return
    if len(pts) > 2:
        xs, ys = zip(*pts[:-1])
        ax.plot(xs, ys, linestyle=props["linestyle"], lw=props["lw"], color=props["color"], solid_capstyle="round")
    ax.annotate(
        "",
        xy=pts[-1],
        xytext=pts[-2],
        arrowprops=dict(
            arrowstyle="-|>",
            lw=props["lw"],
            color=props["color"],
            linestyle=props["linestyle"],
            mutation_scale=8.5,
            shrinkA=0,
            shrinkB=4,
            zorder=4,
        ),
    )


def draw_node(ax, row: dict) -> None:
    x, y, w, h = map(float, (row["x"], row["y"], row["w"], row["h"]))
    node_type = str(row.get("node_type", ""))
    fill = COL.get(node_type, "#ffffff")
    if node_type == "backend":
        fill = COL["backend"]
    lw = 1.35 if node_type == "interface" else 0.9
    box = FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.014,rounding_size=0.016",
        linewidth=lw,
        edgecolor=COL["ink"],
        facecolor=fill,
        zorder=3,
    )
    ax.add_patch(box)
    ax.text(x + w / 2, y + h / 2, str(row["label"]), ha="center", va="center",
            fontsize=8.2, color=COL["ink"], linespacing=1.12, zorder=4)


def validate_figure1_specs(nodes: pd.DataFrame, edges: pd.DataFrame) -> pd.DataFrame:
    errors = []
    ids = set(nodes["node_id"])
    for _, r in nodes.iterrows():
        x, y, w, h = map(float, (r["x"], r["y"], r["w"], r["h"]))
        if x < 0 or y < 0 or x + w > 1 or y + h > 1:
            errors.append(("node_outside_canvas", r["node_id"]))
    for i, a in nodes.iterrows():
        ax0, ay0, aw, ah = map(float, (a["x"], a["y"], a["w"], a["h"]))
        for j, b in nodes.iterrows():
            if j <= i:
                continue
            bx, by, bw, bh = map(float, (b["x"], b["y"], b["w"], b["h"]))
            overlap = ax0 < bx + bw and ax0 + aw > bx and ay0 < by + bh and ay0 + ah > by
            if overlap:
                errors.append(("node_overlap", f"{a['node_id']}:{b['node_id']}"))
    for _, e in edges.iterrows():
        if e["source"] not in ids or e["target"] not in ids:
            errors.append(("undefined_edge_endpoint", e["edge_id"]))
    return pd.DataFrame(errors, columns=["check", "detail"])


def make_architecture_figure(root: Path, out_figs: Path) -> None:
    nodes, edges, groups, _legend = read_specs(root)
    validation = validate_figure1_specs(nodes, edges)
    if not validation.empty:
        validation.to_csv(out_figs / "figure_1_validation_errors.csv", index=False)
        raise ValueError("Figure 1 specification failed validation")
    fig, ax = plt.subplots(figsize=(10.0, 5.8))
    ax.set_xlim(0, 1)
    ax.set_ylim(0.05, 0.92)
    ax.axis("off")

    for _, g in groups.iterrows():
        rect = Rectangle((float(g["x"]), float(g["y"])), float(g["w"]), float(g["h"]),
                         facecolor=COL["lane"], edgecolor="#e0e0e0", linewidth=0.8, zorder=0)
        ax.add_patch(rect)
        ax.text(float(g["x"]) + 0.010, float(g["y"]) + float(g["h"]) - 0.030,
                str(g["label"]), ha="left", va="top", fontsize=7.4, color=COL["muted"], zorder=1)

    recs = node_record(nodes)
    for _, n in nodes.iterrows():
        draw_node(ax, n.to_dict())

    for _, e in edges.iterrows():
        pts = [anchor(recs[e["source"]], e["start_anchor"])] + parse_via(e["via"]) + [anchor(recs[e["target"]], e["end_anchor"])]
        draw_poly_arrow(ax, pts, e["edge_type"])

    # Compact legend drawn from actual edge styles.
    handles = [
        Line2D([0], [0], color="#222222", lw=1.1, linestyle="-", label="evidence emission/write"),
        Line2D([0], [0], color="#555555", lw=1.0, linestyle=(0, (4, 2)), label="payload custody"),
        Line2D([0], [0], color="#555555", lw=1.0, linestyle=(0, (1, 2)), label="audit/query access"),
    ]
    ax.legend(handles=handles, loc="lower left", bbox_to_anchor=(0.035, 0.045), frameon=False,
              ncol=3, columnspacing=1.6, handlelength=2.2)
    ax.text(0.965, 0.055, "Conceptual interface model; not a production FHIR server or blockchain deployment.",
            ha="right", va="bottom", fontsize=7.2, color=COL["muted"])
    save_public_figure(fig, out_figs / "figure_teasim_architecture", png_dpi=300, tiff_dpi=300, vector=True)


def make_metric_dotplot(summary_df: pd.DataFrame, metric: str, out_figs: Path, fname: str, xlabel: str, logx: bool = False) -> None:
    scenarios = list(pd.unique(summary_df["scenario_id"]))
    y = np.arange(len(scenarios))
    fig, ax = plt.subplots(figsize=(7.4, 4.6))
    for i, scenario in enumerate(scenarios):
        vals = summary_df.loc[summary_df["scenario_id"] == scenario, ["architecture", metric]].set_index("architecture")[metric]
        ax.plot([vals.min(), vals.max()], [i, i], color="#dadada", lw=1.0, zorder=1)
        for arch, st in ARCH_STYLE.items():
            val = float(vals.loc[arch])
            ax.scatter(val, i, marker=st["marker"], s=36, color=st["color"], edgecolors="#222222", linewidths=0.35, zorder=3)
    ax.set_yticks(y)
    ax.set_yticklabels(scenarios)
    ax.invert_yaxis()
    ax.set_xlabel(xlabel)
    if logx:
        ax.set_xscale("log")
        ax.xaxis.set_major_locator(LogLocator(base=10, numticks=5))
        ax.xaxis.set_major_formatter(ScalarFormatter())
    ax.grid(axis="x", color="#eeeeee", linewidth=0.8)
    handles = [Line2D([0], [0], marker=st["marker"], color="none", markerfacecolor=st["color"],
                      markeredgecolor="#222222", markersize=6, label=st["label"]) for st in ARCH_STYLE.values()]
    ax.legend(handles=handles, frameon=False, ncol=3, loc="upper center", bbox_to_anchor=(0.5, 1.12))
    save_public_figure(fig, out_figs / fname, png_dpi=300, tiff_dpi=600, vector=True)


def make_lji_figure(lji_df: pd.DataFrame, out_figs: Path) -> None:
    scenarios = list(lji_df["scenario_id"])
    y = np.arange(len(scenarios))
    fig, ax = plt.subplots(figsize=(7.0, 4.4))
    for i, row in lji_df.iterrows():
        value = float(row["LJI"])
        ax.plot([0, value], [i, i], color="#cfcfcf", lw=1.1)
        ax.scatter(value, i, marker="D", s=36, color=COL["lji"], edgecolor="#222222", linewidth=0.35)
    ax.axvline(0, color="#8a8a8a", lw=0.9)
    ax.axvline(LJI_LOWER_THRESHOLD, color="#a6a6a6", lw=0.8, linestyle=(0, (3, 2)))
    ax.axvline(LJI_UPPER_THRESHOLD, color="#a6a6a6", lw=0.8, linestyle=(0, (3, 2)))
    ax.set_yticks(y)
    ax.set_yticklabels(scenarios)
    ax.invert_yaxis()
    ax.set_xlabel("Ledger Justification Index")
    ax.grid(axis="x", color="#eeeeee", linewidth=0.8)
    save_public_figure(fig, out_figs / "figure_lji", png_dpi=300, tiff_dpi=600, vector=True)


def make_graphical_abstract(out_figs: Path) -> None:
    fig, ax = plt.subplots(figsize=(10, 4.0))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")
    blocks = [
        (0.035, 0.55, 0.21, 0.22, "Off-chain clinical\npayload custody"),
        (0.285, 0.55, 0.21, 0.22, "Compact TrustEvidence\nartefacts"),
        (0.535, 0.55, 0.21, 0.22, "Evidence-storage\nalternatives"),
        (0.785, 0.55, 0.18, 0.22, "Conditional ledger\njustification"),
    ]
    for x, y, w, h, label in blocks:
        ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.014,rounding_size=0.018",
                                    linewidth=1.0, edgecolor=COL["ink"], facecolor="#f7f7f7"))
        ax.text(x + w/2, y + h/2, label, ha="center", va="center", fontsize=10, color=COL["ink"], linespacing=1.15)
    for i in range(3):
        x0 = blocks[i][0] + blocks[i][2]
        x1 = blocks[i+1][0]
        y = 0.66
        ax.annotate("", xy=(x1 - 0.012, y), xytext=(x0 + 0.012, y),
                    arrowprops=dict(arrowstyle="-|>", lw=1.1, color=COL["ink"], mutation_scale=9))
    ax.text(0.5, 0.28,
            "Payload repositories remain authoritative; audit evidence is stored centrally, hash-linked or ledger-like according to governance need.",
            ha="center", va="center", fontsize=9.2, color=COL["ink"])
    save_public_figure(fig, out_figs / "graphical_abstract", png_dpi=300, tiff_dpi=300, vector=True)


def make_all_figures(summary_df: pd.DataFrame, lji_df: pd.DataFrame, out_figs: Path, root: Path) -> None:
    make_architecture_figure(root, out_figs)
    make_lji_figure(lji_df, out_figs)
    make_metric_dotplot(summary_df, "storage_mb", out_figs, "figure_storage_mb", "Storage burden (MB, log scale)", logx=True)
    make_metric_dotplot(summary_df, "verification_units", out_figs, "figure_verification_units", "Normalised verification units", logx=False)
    make_metric_dotplot(summary_df, "write_cost_units", out_figs, "figure_write_cost_units", "Normalised write-cost units", logx=False)
    make_metric_dotplot(summary_df, "privacy_score", out_figs, "figure_privacy_score", "Metadata-exposure proxy", logx=False)
    make_graphical_abstract(out_figs)
