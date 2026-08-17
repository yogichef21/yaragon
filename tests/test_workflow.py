"""Stage-derivation tests for the guided workflow (Qt-free, headless).

Covers every transition idle -> interface -> targets -> mitm-active -> offline,
per DECISIONS A2 and DESIGN §2.3.
"""
from yaragon.gui.workflow import (STAGE_ORDER, SessionState, Stage, StageState,
                                  compute_stages)


def test_module_is_qt_free():
    import yaragon.gui.workflow as wf
    import sys
    # The module must not have imported any Qt binding.
    assert "PySide6" not in " ".join(k for k in sys.modules
                                     if k.startswith("yaragon.gui.workflow"))
    # And the source imports no Qt.
    src = open(wf.__file__).read()
    assert "PySide6" not in src and "import Qt" not in src


def test_idle_no_interface():
    s = SessionState(current_stage=Stage.DISCOVER)
    st = compute_stages(s)
    assert st[Stage.DISCOVER] == StageState.CURRENT
    assert st[Stage.MITM] == StageState.LOCKED
    assert st[Stage.INVESTIGATE] == StageState.LOCKED


def test_interface_selected_no_targets():
    s = SessionState(interface="eth0", current_stage=Stage.DISCOVER)
    st = compute_stages(s)
    assert st[Stage.DISCOVER] == StageState.CURRENT
    # MITM stays locked until at least one target is chosen.
    assert st[Stage.MITM] == StageState.LOCKED
    assert st[Stage.INVESTIGATE] == StageState.LOCKED


def test_targets_selected_unlocks_mitm():
    s = SessionState(interface="eth0", targets=[("10.0.0.5", "aa")],
                     current_stage=Stage.MITM)
    st = compute_stages(s)
    # DISCOVER is done (a target set was chosen); MITM is where we are.
    assert st[Stage.DISCOVER] == StageState.DONE
    assert st[Stage.MITM] == StageState.CURRENT
    # Investigate not reachable yet (no capture, no active session).
    assert st[Stage.INVESTIGATE] == StageState.LOCKED


def test_targets_selected_mitm_available_when_elsewhere():
    s = SessionState(interface="eth0", targets=[("10.0.0.5", "aa")],
                     current_stage=Stage.DISCOVER)
    st = compute_stages(s)
    assert st[Stage.MITM] == StageState.AVAILABLE


def test_mitm_active_marks_done_and_unlocks_investigate():
    s = SessionState(interface="eth0", targets=[("10.0.0.5", "aa")],
                     mitm_active=True, capture_running=True,
                     current_stage=Stage.INVESTIGATE)
    st = compute_stages(s)
    assert st[Stage.DISCOVER] == StageState.DONE
    assert st[Stage.MITM] == StageState.DONE
    assert st[Stage.INVESTIGATE] == StageState.CURRENT


def test_capture_only_unlocks_investigate_without_mitm():
    # Passive journey: capture running, no targets, on Investigate.
    s = SessionState(interface="eth0", capture_running=True,
                     current_stage=Stage.INVESTIGATE)
    st = compute_stages(s)
    assert st[Stage.DISCOVER] == StageState.DONE       # capture ran
    assert st[Stage.MITM] == StageState.LOCKED         # no targets
    assert st[Stage.INVESTIGATE] == StageState.CURRENT


def test_offline_mode_investigate_current_others_nonblocking():
    s = SessionState(mode="offline", current_stage=Stage.INVESTIGATE)
    st = compute_stages(s)
    assert st[Stage.INVESTIGATE] == StageState.CURRENT
    # DISCOVER / MITM are available (non-blocking), never locked, in offline.
    assert st[Stage.DISCOVER] == StageState.AVAILABLE
    assert st[Stage.MITM] == StageState.AVAILABLE


def test_exactly_one_current_stage():
    for cur in STAGE_ORDER:
        s = SessionState(interface="eth0", targets=[("10.0.0.5", "aa")],
                         mitm_active=True, capture_running=True,
                         current_stage=cur)
        st = compute_stages(s)
        currents = [k for k, v in st.items() if v == StageState.CURRENT]
        assert currents == [cur]
