"""Yaragon visual system - "Ink & Signal" design language (BRAND.md).

Direction (a precision instrument, not a cyber dashboard):
  * Neutrals do the work: an ink ground with layered surfaces and hairline
    borders instead of shadows, cards, gradients or glow.
  * ONE accent - Signal Amber - marks the single primary action per screen and
    the brand mark. It never appears decoratively.
  * `live` (mint) means "running / healthy"; `danger` (red) means "stop / gone".
    Amber and warn share the hue by design: both mean "your attention here".
  * Colour otherwise appears only where it is information: protocol coding in the
    packet table, severity in alerts.
  * Data is monospaced with tabular figures - column alignment and numeric
    readouts are meaning in a packet analyzer.
This module is the single source of truth for tokens; the QSS and every widget
consume it, so the whole app reads as one system.
"""
from __future__ import annotations

# ---- typography ------------------------------------------------------------
FONT_UI = "'Inter', 'IBM Plex Sans', 'Noto Sans', 'DejaVu Sans', sans-serif"
FONT_MONO = "'IBM Plex Mono', 'JetBrains Mono', 'DejaVu Sans Mono', monospace"

# ---- spacing & corner radius scale (px) ------------------------------------
SPACE = {"xs": 4, "sm": 8, "md": 12, "lg": 16, "xl": 24}
RADIUS = {"sm": 4, "md": 6, "lg": 8, "pill": 999}

# ---- palette - DARK (primary theme) ----------------------------------------
_DARK = {
    # surfaces - ink base, layered
    "bg":         "#0E1215",   # ink - app ground
    "bg_alt":     "#10161B",   # rail + top strip (one step up from ink)
    "panel":      "#151B21",   # surface - panels / table
    "panel_2":    "#1B232B",   # surface-2 - headers, selected, inputs
    "border":     "#26313B",   # hairline 1px
    "border_sub": "#1C242C",   # softer divider
    # text
    "text":       "#E6EDF3",
    "text_dim":   "#8B98A5",   # labels / secondary
    "muted":      "#5B6772",   # disabled / idle
    # signal + state (sparingly; never decoration)
    "primary":    "#E0A34E",   # accent amber - the ONE filled primary action
    "primary_d":  "#C98B36",   # amber pressed / darker
    "accent":     "#ECB566",   # brighter amber - primary :hover + attention fg
    "ok":         "#46D39A",   # live mint - capture running / healthy ONLY
    "warning":    "#E0A34E",   # warn = accent hue by design (attention)
    "anomaly":    "#FF5C6B",   # alias of danger (some code reads 'anomaly')
    "danger":     "#FF5C6B",   # stop / destructive / error
    "selection":  "#202B34",   # cool neutral row selection (NOT amber)
}

# ---- palette - LIGHT (mirrors the roles) -----------------------------------
_LIGHT = {
    "bg":         "#F7F9FB",
    "bg_alt":     "#EEF2F6",
    "panel":      "#FFFFFF",
    "panel_2":    "#EDF1F5",
    "border":     "#CDD6E0",
    "border_sub": "#DEE5EC",
    "text":       "#0E1215",
    "text_dim":   "#56636F",
    "muted":      "#8A97A3",
    "primary":    "#E0A34E",   # filled amber unchanged (ink text on it)
    "primary_d":  "#B4741E",
    "accent":     "#B4741E",   # darker amber for :hover + fg on light
    "ok":         "#12855F",   # mint darkened for fg contrast on light
    "warning":    "#B4741E",
    "anomaly":    "#D3303F",
    "danger":     "#D3303F",   # red darkened for fg contrast on light
    "selection":  "#E4ECF3",
}

PALETTE = _DARK   # default theme (dark is the primary theme)

# Per-protocol colours (packet table only - meaning, not decoration). Tuned for
# equal perceived weight on `panel`; no protocol hue equals the Signal-Amber
# accent, or a protocol row would read as "the primary action".
PROTOCOL_COLORS = {
    "TCP":    "#6E9BE8",   # calm blue baseline
    "UDP":    "#A98BFF",   # violet
    "DNS":    "#57C98A",   # green (kept distinct from live mint)
    "HTTP":   "#E67E5B",   # coral - deliberately NOT amber nor pink
    "TLS":    "#6EC7FF",   # cyan
    "ARP":    "#FF9EB6",   # pink
    "ICMP":   "#E6C15A",   # muted gold (nudged off the accent)
    "ICMPv6": "#D4A85A",   # gold, sibling of ICMP
    "DHCP":   "#7CE3A0",   # light green
    "IPv6":   "#B79BFF",   # lavender
    "OTHER":  "#7A8794",   # muted neutral
}


def set_theme(name: str) -> None:
    """Rebind the module PALETTE to the dark or light token set. Callers must
    re-apply build_stylesheet() afterwards. Dark is the default."""
    global PALETTE
    PALETTE = _LIGHT if name == "light" else _DARK


def build_stylesheet() -> str:
    p = PALETTE
    return f"""
    * {{
        font-family: {FONT_UI};
        font-size: 13px;
        color: {p['text']};
        outline: none;
    }}
    QMainWindow, QWidget#Root {{ background: {p['bg']}; }}
    QWidget#Content {{ background: {p['bg']}; }}

    /* ---- Stage rail (guided workflow) ---- */
    QFrame#StageRail {{ background: {p['bg_alt']};
                        border-bottom: 1px solid {p['border_sub']}; }}
    QLabel#Wordmark {{ font-size: 15px; font-weight: 600; color: {p['text']};
                       letter-spacing: 1px; }}
    QPushButton#Stage {{
        text-align: left; padding: 6px 12px; border: none;
        border-radius: {RADIUS['sm']}px; background: transparent;
        color: {p['text_dim']}; font-weight: 600; border-bottom: 2px solid transparent;
    }}
    QPushButton#Stage[state="locked"] {{ color: {p['muted']}; }}
    QPushButton#Stage[state="available"] {{ color: {p['text_dim']}; }}
    QPushButton#Stage[state="current"] {{ color: {p['text']};
        border-bottom: 2px solid {p['primary']}; }}
    QPushButton#Stage[state="done"] {{ color: {p['text_dim']}; }}
    QPushButton#Stage:hover {{ color: {p['text']}; }}
    QLabel#StageIndex {{ color: {p['muted']}; font-family: {FONT_MONO};
                         font-size: 11px; }}
    QLabel#StageSep {{ color: {p['border']}; }}
    QFrame#StageLink {{ border: none; border-top: 1px solid {p['border']};
                        background: transparent; }}
    QFrame#StageLinkSkip {{ border: none; border-top: 1px dashed {p['muted']};
                            background: transparent; }}

    /* ---- Top instrument strip ---- */
    QLabel#StripKey {{ color: {p['text_dim']}; font-size: 11px; font-weight: 600;
                       letter-spacing: 0.06em; }}
    QLabel#StripVal {{ color: {p['text']}; font-family: {FONT_MONO};
                       font-size: 12px; }}

    /* ---- Cards & panels ---- */
    QFrame#Card {{ background: {p['panel']}; border: 1px solid {p['border_sub']};
                   border-radius: {RADIUS['md']}px; }}
    QLabel#CardTitle {{ font-size: 11px; font-weight: 600; color: {p['text_dim']};
                        letter-spacing: 0.06em; }}
    QLabel#H1 {{ font-size: 20px; font-weight: 600; color: {p['text']}; }}
    QLabel#H2 {{ font-size: 14px; font-weight: 600; color: {p['text']}; }}
    QLabel#Dim {{ color: {p['text_dim']}; }}
    QLabel#Mono {{ font-family: {FONT_MONO}; color: {p['text']}; }}
    QLabel#EmptyTitle {{ font-size: 15px; font-weight: 600; color: {p['text_dim']}; }}
    QLabel#EmptyBody {{ color: {p['muted']}; }}

    QLabel#Pill {{ border-radius: 9px; padding: 3px 11px; font-weight: 700;
                   font-size: 10px; letter-spacing: 0.5px; }}

    /* ---- Buttons ---- */
    QPushButton {{ background: {p['panel_2']}; border: 1px solid {p['border']};
                   border-radius: {RADIUS['sm']}px; padding: 8px 15px;
                   color: {p['text']}; font-weight: 600; }}
    QPushButton:hover {{ border-color: {p['accent']}; color: {p['text']}; }}
    QPushButton:disabled {{ color: {p['muted']}; background: {p['panel']};
                            border-color: {p['border_sub']}; }}
    QPushButton#Primary {{ background: {p['primary']}; border: none;
                           color: {p['bg']}; font-weight: 700; }}
    QPushButton#Primary:hover {{ background: {p['accent']}; }}
    QPushButton#Primary:pressed {{ background: {p['primary_d']}; }}
    QPushButton#Danger {{ background: transparent; border: 1px solid {p['danger']};
                          color: {p['danger']}; font-weight: 700; }}
    QPushButton#Danger:hover {{ background: rgba(255,92,107,0.12); }}
    QPushButton#Ghost {{ background: transparent; border: 1px solid {p['border']};
                         color: {p['text_dim']}; }}
    QPushButton#Ghost:hover {{ border-color: {p['accent']}; color: {p['text']}; }}

    /* ---- Inputs ---- */
    QLineEdit, QComboBox {{
        background: {p['bg']}; border: 1px solid {p['border']};
        border-radius: {RADIUS['sm']}px; padding: 7px 10px; color: {p['text']};
        selection-background-color: {p['selection']};
    }}
    QLineEdit:focus, QComboBox:focus {{ border-color: {p['accent']}; }}
    QComboBox::drop-down {{ border: none; width: 20px; }}
    QComboBox QAbstractItemView {{ background: {p['panel_2']};
        border: 1px solid {p['border']}; selection-background-color: {p['selection']};
        padding: 4px; }}

    /* ---- Tables (monospaced data) ---- */
    QTableView, QTreeView, QTableWidget, QTreeWidget {{
        background: {p['panel']}; border: 1px solid {p['border_sub']};
        border-radius: {RADIUS['md']}px; gridline-color: {p['border_sub']};
        selection-background-color: {p['selection']}; selection-color: {p['text']};
        alternate-background-color: {p['bg_alt']};
        font-family: {FONT_MONO}; font-size: 12px;
    }}
    QHeaderView::section {{ background: {p['panel_2']}; color: {p['text_dim']};
        padding: 8px 8px; border: none; border-bottom: 1px solid {p['border']};
        font-family: {FONT_UI}; font-weight: 600; font-size: 11px;
        letter-spacing: 0.06em; }}
    QTableView::item, QTreeView::item {{ padding: 4px 4px; }}
    QTableView::item:hover {{ background: {p['panel_2']}; }}
    QListWidget {{ background: {p['panel']}; border: 1px solid {p['border_sub']};
        border-radius: {RADIUS['md']}px; font-family: {FONT_MONO}; font-size: 12px; }}
    QListWidget::item {{ padding: 5px 8px; border-radius: 4px; }}
    QListWidget::item:selected {{ background: {p['selection']}; color: {p['text']}; }}

    /* ---- Tabs ---- */
    QTabWidget::pane {{ border: 1px solid {p['border_sub']};
                        border-radius: {RADIUS['md']}px; top: -1px; }}
    QTabBar::tab {{ background: transparent; color: {p['text_dim']};
        padding: 8px 16px; border-bottom: 2px solid transparent; font-weight: 600; }}
    QTabBar::tab:selected {{ color: {p['text']}; border-bottom: 2px solid {p['text']}; }}

    /* ---- Scrollbars ---- */
    QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
    QScrollBar::handle:vertical {{ background: {p['panel_2']}; border-radius: 5px;
                                   min-height: 30px; }}
    QScrollBar::handle:vertical:hover {{ background: {p['muted']}; }}
    QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
    QScrollBar::handle:horizontal {{ background: {p['panel_2']}; border-radius: 5px;
                                     min-width: 30px; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}

    QToolTip {{ background: {p['panel_2']}; color: {p['text']};
        border: 1px solid {p['border']}; padding: 6px 8px; border-radius: 6px; }}
    QStatusBar {{ background: {p['bg_alt']}; color: {p['muted']};
        border-top: 1px solid {p['border_sub']}; }}
    QSplitter::handle {{ background: {p['border_sub']}; }}
    QTextEdit {{ background: {p['bg']}; border: 1px solid {p['border_sub']};
        border-radius: {RADIUS['sm']}px; }}
    QProgressBar {{ background: {p['bg']}; border: 1px solid {p['border']};
        border-radius: 6px; text-align: center; color: {p['text_dim']}; }}
    QProgressBar::chunk {{ background: {p['primary']}; border-radius: 5px; }}
    QCheckBox {{ spacing: 8px; }}
    QCheckBox::indicator {{ width: 16px; height: 16px; border-radius: 4px;
        border: 1px solid {p['border']}; background: {p['bg']}; }}
    QCheckBox::indicator:checked {{ background: {p['primary']};
        border-color: {p['primary']}; }}
    """
