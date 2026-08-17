"""Qt-free session model + stage derivation for the guided workflow.

This module holds the pure decision logic behind the stage rail
(DISCOVER -> MITM -> INVESTIGATE). It imports no Qt, so every stage transition
is unit-testable headlessly - the highest-leverage testability seam in the GUI.

`MainWindow` keeps one `SessionState` and updates it from its existing handlers;
`compute_stages(state)` reads only that state and returns each stage's visual
state for the rail to render.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


class Stage(str, Enum):
    DISCOVER = "DISCOVER"
    MITM = "MITM"
    INVESTIGATE = "INVESTIGATE"


class StageState(str, Enum):
    LOCKED = "locked"        # prerequisite not met - not clickable
    AVAILABLE = "available"  # reachable but not visited
    CURRENT = "current"      # the screen you are on
    DONE = "done"            # completed; click to return


# Rail order (SELECT is not a stage - it is the Discover->MITM gate).
STAGE_ORDER: Tuple[Stage, ...] = (Stage.DISCOVER, Stage.MITM, Stage.INVESTIGATE)


@dataclass
class SessionState:
    """A single honest description of where the session is. Mirrors the loose
    attributes MainWindow already holds, consolidated so stage derivation reads
    from one place."""

    interface: str = ""
    targets: List[tuple] = field(default_factory=list)  # list[(ip, mac)]
    gateway: str = ""
    mitm_active: bool = False
    capture_running: bool = False
    capture_paused: bool = False
    mode: str = "live"                     # "live" | "offline"
    current_stage: Stage = Stage.DISCOVER  # the screen currently shown

    # ---- derived helpers -------------------------------------------------
    @property
    def has_interface(self) -> bool:
        return bool(self.interface)

    @property
    def has_targets(self) -> bool:
        return len(self.targets) >= 1

    @property
    def capture_ran(self) -> bool:
        return self.capture_running or self.capture_paused


def compute_stages(state: SessionState) -> Dict[Stage, StageState]:
    """Derive each stage's visual state from the session (DESIGN §2.3).

    Rules:
      offline (Open .pcap): DISCOVER/MITM stay AVAILABLE (non-blocking - you may
        start a live session); INVESTIGATE is where you are.
      live:
        DISCOVER    DONE once targets chosen OR capture ran; else AVAILABLE.
        MITM        LOCKED until >=1 interface AND >=1 target; DONE once a
                    session started; otherwise AVAILABLE. Always skippable.
        INVESTIGATE LOCKED until reachable (mitm active OR capture ran);
                    otherwise AVAILABLE.
      The screen currently shown is always CURRENT (you cannot be on a locked
      screen - navigation gating enforces that upstream).
    """
    if state.mode == "offline":
        stages = {
            Stage.DISCOVER: StageState.AVAILABLE,
            Stage.MITM: StageState.AVAILABLE,
            Stage.INVESTIGATE: StageState.AVAILABLE,
        }
    else:
        # DISCOVER
        discover = (StageState.DONE if (state.has_targets or state.capture_ran)
                    else StageState.AVAILABLE)
        # MITM
        if not (state.has_interface and state.has_targets):
            mitm = StageState.LOCKED
        elif state.mitm_active:
            mitm = StageState.DONE
        else:
            mitm = StageState.AVAILABLE
        # INVESTIGATE
        investigate = (StageState.AVAILABLE
                       if (state.mitm_active or state.capture_ran)
                       else StageState.LOCKED)
        stages = {
            Stage.DISCOVER: discover,
            Stage.MITM: mitm,
            Stage.INVESTIGATE: investigate,
        }

    # The screen you are on wins - exactly one CURRENT at a time.
    cur: Optional[Stage] = state.current_stage
    if cur in stages:
        stages[cur] = StageState.CURRENT
    return stages
