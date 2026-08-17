#!/usr/bin/env python3
"""Yaragon - MITM Lab & Network Traffic Analyzer.

Entry point. Ensures the ``src`` package directory is importable whether the
app is launched natively, from a venv, or inside the Docker image, then starts
the PySide6 GUI.

Authorized isolated-lab use only.
"""
from __future__ import annotations

import os
import sys

# Make `import yaragon...` work from a source checkout (src/ layout).
_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(_HERE, "src")
if os.path.isdir(_SRC) and _SRC not in sys.path:
    sys.path.insert(0, _SRC)


def main() -> int:
    from yaragon import __product_name__, __version__
    from yaragon.utils.logging import setup_logging
    from yaragon.utils.config import Config

    log = setup_logging()
    log.info("Starting %s v%s", __product_name__, __version__)

    # Import Qt lazily so --version / --check work without a display.
    if "--version" in sys.argv:
        print(f"{__product_name__} v{__version__}")
        return 0

    if "--check" in sys.argv:
        # Headless self-check: verify imports + interface discovery.
        from yaragon.network.interfaces import list_interfaces, default_gateway
        from yaragon.utils.permissions import check_privileges
        ifaces = list_interfaces()
        print(f"{__product_name__} v{__version__} self-check")
        print(f"  interfaces: {', '.join(i.name for i in ifaces)}")
        print(f"  default gateway: {default_gateway()}")
        print(f"  privileges: {check_privileges().detail}")
        return 0

    from PySide6.QtGui import QIcon
    from PySide6.QtWidgets import QApplication
    from yaragon.gui.main_window import MainWindow
    from yaragon.gui.widgets import brand_mark_path

    config = Config.load()
    app = QApplication(sys.argv)
    app.setApplicationName("Yaragon")
    app.setApplicationVersion(__version__)
    # Deliberately NOT setting applicationDisplayName: some desktops append it to
    # the window title, which duplicated the full product name in the title bar.
    # The window sets one clean, complete title itself.
    app.setOrganizationName("Yaragon Lab")
    mark = brand_mark_path()
    if mark:
        app.setWindowIcon(QIcon(mark))

    window = MainWindow(config)
    window.showMaximized()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
