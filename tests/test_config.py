"""Configuration load/save round-trip tests."""
import importlib


def _fresh_config_module(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    import yaragon.utils.config as cfgmod
    importlib.reload(cfgmod)
    return cfgmod


def test_defaults_are_lab_safe(tmp_path, monkeypatch):
    cfgmod = _fresh_config_module(tmp_path, monkeypatch)
    c = cfgmod.Config()
    assert c.packet_history_limit > 0
    assert c.max_capture_pps == 0                 # unlimited unless throttled


def test_save_and_load_roundtrip(tmp_path, monkeypatch):
    cfgmod = _fresh_config_module(tmp_path, monkeypatch)
    c = cfgmod.Config()
    c.interface = "wlp3s0"
    c.packet_history_limit = 4242
    c.gui_flush_interval_ms = 250
    c.save()
    loaded = cfgmod.Config.load()
    assert loaded.interface == "wlp3s0"
    assert loaded.packet_history_limit == 4242
    assert loaded.gui_flush_interval_ms == 250


def test_dropped_fields_are_gone(tmp_path, monkeypatch):
    """A14: vestigial config fields were removed."""
    cfgmod = _fresh_config_module(tmp_path, monkeypatch)
    c = cfgmod.Config()
    for gone in ("target_ip", "gateway_ip", "theme", "extra"):
        assert not hasattr(c, gone)


def test_save_sets_owner_only_mode(tmp_path, monkeypatch):
    """A14/S9: config.json is written owner-only (0600)."""
    import stat
    cfgmod = _fresh_config_module(tmp_path, monkeypatch)
    c = cfgmod.Config()
    c.save()
    path = cfgmod.config_dir() / "config.json"
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600


def test_corrupt_config_does_not_crash(tmp_path, monkeypatch):
    cfgmod = _fresh_config_module(tmp_path, monkeypatch)
    path = cfgmod.config_dir() / "config.json"
    path.write_text("{ this is not valid json ")
    c = cfgmod.Config.load()               # must fall back to defaults, not raise
    assert isinstance(c, cfgmod.Config)


def test_unknown_keys_ignored(tmp_path, monkeypatch):
    cfgmod = _fresh_config_module(tmp_path, monkeypatch)
    path = cfgmod.config_dir() / "config.json"
    path.write_text('{"interface": "eth9", "totally_unknown_key": 1}')
    c = cfgmod.Config.load()
    assert c.interface == "eth9"
    assert not hasattr(c, "totally_unknown_key")
