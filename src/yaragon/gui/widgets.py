"""Reusable Yaragon UI building blocks: cards, a live indicator, status pills,
key/value rows, empty states and the guided stage rail."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QPainter, QPixmap
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QPushButton,
                               QVBoxLayout, QWidget)

from .styles import PALETTE
from .workflow import STAGE_ORDER, Stage, StageState


def _assets_dir() -> Optional[Path]:
    """Locate the repo `assets/` directory (best effort; None if absent)."""
    here = Path(__file__).resolve()
    for base in here.parents:
        cand = base / "assets"
        if (cand / "yaragon-mark.svg").exists():
            return cand
    return None


def brand_mark_path() -> Optional[str]:
    d = _assets_dir()
    p = d / "yaragon-mark.svg" if d else None
    return str(p) if p and p.exists() else None


class Card(QFrame):
    """A titled surface panel."""

    def __init__(self, title: str = "", parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("Card")
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(16, 14, 16, 16)
        self._layout.setSpacing(10)
        if title:
            lbl = QLabel(title.upper())
            lbl.setObjectName("CardTitle")
            self._layout.addWidget(lbl)

    def add(self, widget: QWidget) -> None:
        self._layout.addWidget(widget)


class LiveDot(QWidget):
    """A small static status dot: mint when live, muted when idle.

    Deliberately not animated - the app is a calm instrument, and the status
    pill already carries the live/idle state in words.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(14, 14)
        self._live = False

    def set_live(self, live: bool) -> None:
        self._live = live
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        c = QColor(PALETTE["ok"] if self._live else PALETTE["muted"])
        p.setBrush(c); p.setPen(Qt.NoPen)
        p.drawEllipse(self.rect().center(), 4, 4)


class StatusPill(QLabel):
    """A compact coloured status indicator (ACTIVE / INACTIVE / …)."""

    def __init__(self, text: str = "INACTIVE", state: str = "off", parent=None):
        super().__init__(parent)
        self.setObjectName("Pill")
        self.setAlignment(Qt.AlignCenter)
        self.set_state(text, state)

    def set_state(self, text: str, state: str) -> None:
        colors = {
            "on":     (PALETTE["ok"], "rgba(70,211,154,0.14)"),
            "off":    (PALETTE["muted"], "rgba(91,103,114,0.14)"),
            "warn":   (PALETTE["warning"], "rgba(224,163,78,0.14)"),
            "danger": (PALETTE["danger"], "rgba(255,92,107,0.14)"),
            "info":   (PALETTE["accent"], "rgba(236,181,102,0.14)"),
        }
        fg, bg = colors.get(state, colors["off"])
        self.setText(text)
        self.setStyleSheet(
            f"background: {bg}; color: {fg}; border: 1px solid {fg};"
            f"border-radius: 9px; padding: 3px 11px; font-weight: 700; font-size: 10px;")


class KeyValueRow(QWidget):
    """A key (dim) with a right-aligned, selectable value."""

    def __init__(self, key: str, value: str = "-", mono: bool = True, parent=None):
        super().__init__(parent)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 3, 0, 3)
        k = QLabel(key); k.setObjectName("Dim")
        self.value_lbl = QLabel(value)
        self.value_lbl.setObjectName("Mono" if mono else "")
        self.value_lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self.value_lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lay.addWidget(k)
        lay.addStretch(1)
        lay.addWidget(self.value_lbl)

    def set_value(self, value: str) -> None:
        self.value_lbl.setText(value or "-")


class EmptyState(QWidget):
    """A centered, friendly placeholder for views with no data yet.

    `error=True` renders the danger variant (danger-tinted icon + title). An
    optional action button (`action_text` + `on_action`) covers the "Open a
    saved .pcap" call-to-action and error retries with one primitive.
    """

    def __init__(self, title: str, body: str = "", icon: str = "◫",
                 error: bool = False, action_text: str = "", on_action=None,
                 parent=None):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setAlignment(Qt.AlignCenter)
        lay.setSpacing(6)
        icon_color = PALETTE["danger"] if error else PALETTE["muted"]
        ic = QLabel(icon)
        ic.setAlignment(Qt.AlignCenter)
        ic.setStyleSheet(f"font-size: 34px; color: {icon_color};")
        t = QLabel(title); t.setObjectName("EmptyTitle"); t.setAlignment(Qt.AlignCenter)
        if error:
            t.setStyleSheet(f"color: {PALETTE['danger']};")
        b = QLabel(body); b.setObjectName("EmptyBody"); b.setAlignment(Qt.AlignCenter)
        b.setWordWrap(True)
        lay.addWidget(ic); lay.addWidget(t)
        if body:
            lay.addWidget(b)
        if action_text and on_action is not None:
            row = QHBoxLayout(); row.setAlignment(Qt.AlignCenter)
            self.action_btn = QPushButton(action_text)
            self.action_btn.setObjectName("Ghost")
            self.action_btn.clicked.connect(on_action)
            row.addWidget(self.action_btn)
            lay.addLayout(row)


class StageChip(QPushButton):
    """One stage in the rail. A `state` Qt property drives its QSS appearance
    (locked / available / current / done). `done` prepends a mint tick; the
    `current` state is the only one that shows the amber underline."""

    def __init__(self, stage: Stage, index: int, parent=None):
        super().__init__(parent)
        self.setObjectName("Stage")
        self.stage = stage
        self._index = index
        self._label = stage.value
        self.setFlat(True)
        self._apply("available")

    def _apply(self, state: str) -> None:
        self._state = state
        tick = "✓ " if state == "done" else ""
        self.setText(f"{self._index}  {tick}{self._label}")
        self.setProperty("state", state)
        self.setCursor(Qt.ForbiddenCursor if state == "locked"
                       else Qt.PointingHandCursor)
        # Re-polish so the [state="..."] selector takes effect.
        self.style().unpolish(self)
        self.style().polish(self)

    def set_state(self, state) -> None:
        self._apply(state.value if isinstance(state, StageState) else str(state))

    def state(self) -> str:
        return self._state


class StageRail(QFrame):
    """Horizontal guided-workflow rail: brand lockup, then the three stage chips
    DISCOVER · MITM · INVESTIGATE connected by hairlines. Pure widget - it holds
    no session state; it is fed via `set_states(dict)` from `compute_stages`.

    Clicking any chip (including a locked one) emits `stage_clicked`; the window
    decides whether to navigate or show a hint, so the rail stays presentational.
    """

    stage_clicked = Signal(object)   # emits a Stage

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("StageRail")
        self.setFixedHeight(52)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(16, 6, 16, 6)
        lay.setSpacing(10)

        lay.addWidget(self._build_lockup())
        sep0 = QLabel("│"); sep0.setObjectName("StageSep")
        lay.addSpacing(6); lay.addWidget(sep0); lay.addSpacing(6)

        self._chips: Dict[Stage, StageChip] = {}
        last = STAGE_ORDER[-1]
        for i, stage in enumerate(STAGE_ORDER, start=1):
            chip = StageChip(stage, i)
            chip.clicked.connect(lambda _=False, s=stage: self.stage_clicked.emit(s))
            self._chips[stage] = chip
            lay.addWidget(chip)
            if stage is not last:
                # A thin hairline connector between chips (not a text dash). The
                # MITM->INVESTIGATE link is dashed to read as skippable, since
                # MITM is optional - passive / offline journeys pass it by.
                skippable = stage is Stage.MITM
                link = QFrame()
                link.setObjectName("StageLinkSkip" if skippable else "StageLink")
                link.setFixedSize(24, 2)
                lay.addWidget(link, 0, Qt.AlignVCenter)
        lay.addStretch(1)
        self._states: Dict[Stage, StageState] = {}

    def _build_lockup(self) -> QWidget:
        box = QWidget()
        row = QHBoxLayout(box)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)
        mark = brand_mark_path()
        if mark:
            from PySide6.QtSvg import QSvgRenderer
            renderer = QSvgRenderer(mark)
            pix = QPixmap(22, 22)
            pix.fill(Qt.transparent)
            painter = QPainter(pix)
            renderer.render(painter)
            painter.end()
            ic = QLabel(); ic.setPixmap(pix)
            row.addWidget(ic)
        word = QLabel("YARAGON"); word.setObjectName("Wordmark")
        row.addWidget(word)
        return box

    def add_trailing(self, widget: QWidget) -> None:
        """Add a right-aligned widget (readouts / status pill) into the rail."""
        self.layout().addWidget(widget)

    def set_states(self, states: Dict[Stage, StageState]) -> None:
        self._states = dict(states)
        for stage, chip in self._chips.items():
            st = states.get(stage)
            if st is not None:
                chip.set_state(st)

    def state_of(self, stage: Stage) -> Optional[StageState]:
        return self._states.get(stage)

    def chip(self, stage: Stage) -> StageChip:
        return self._chips[stage]
