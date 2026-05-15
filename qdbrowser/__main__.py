"""Entry point for qdbrowser."""

import argparse
import logging
import os
import sys

from PyQt6.QtCore import Qt


log = logging.getLogger("qdbrowser")

# QtWebEngineWidgets must be imported before QApplication is constructed —
# otherwise Qt raises "QtWebEngineWidgets must be imported or
# Qt.AA_ShareOpenGLContexts must be set before a QCoreApplication
# instance is created."
import PyQt6.QtWebEngineWidgets  # noqa: F401

from PyQt6.QtWidgets import QApplication

from qdbrowser import __version__


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="qdbrowser",
        description="qdbrowser — Qt-based web browser.",
    )
    p.add_argument("url", nargs="?", help="URL to open (optional)")
    p.add_argument("--profile", default="default",
                   help="Web profile to use (default: default; 'private' = OTR)")
    p.add_argument("--geometry", help="WxH or WxH+X+Y")
    p.add_argument("-f", "--fullscreen", action="store_true",
                   help="Open fullscreen")
    p.add_argument("-m", "--maximize", action="store_true",
                   help="Open maximized")
    p.add_argument("--no-restore", action="store_true",
                   help="Don't restore the previous session")
    p.add_argument("--agent-control", action="store_true",
                   help="Enable the agent_control plugin (same as setting "
                        "QDBROWSER_AGENT_CONTROL=1)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def _apply_geometry(window, geom):
    try:
        size_part = geom
        x = y = None
        for sep in ("+", "-"):
            if sep in geom[1:]:
                idx = geom.index(sep, 1)
                size_part = geom[:idx]
                pos_part = geom[idx:]
                import re
                m = re.match(r"([+-]\d+)([+-]\d+)", pos_part)
                if m:
                    x = int(m.group(1))
                    y = int(m.group(2))
                break
        w, h = size_part.split("x")
        window.resize(int(w), int(h))
        if x is not None and y is not None:
            window.move(x, y)
    except (ValueError, IndexError):
        pass


def main(argv=None):
    args = parse_args(argv)

    # Send qdbrowser-namespaced logs to the user journal where the
    # rest of the qdistro stack reports too. We use a single root
    # config; individual modules use ``logging.getLogger("qdbrowser.<x>")``.
    logging.basicConfig(
        level=os.environ.get("QDBROWSER_LOG_LEVEL", "WARNING").upper(),
        format="qdbrowser %(name)s %(levelname)s: %(message)s",
    )

    if args.agent_control:
        os.environ["QDBROWSER_AGENT_CONTROL"] = "1"

    # QtWebEngine needs a sandboxing env-friendly default. Don't override
    # if user already set something.
    os.environ.setdefault("QT_QPA_PLATFORM", os.environ.get("QT_QPA_PLATFORM", ""))

    app = QApplication(sys.argv)
    app.setApplicationName("qdbrowser")
    app.setApplicationVersion(__version__)
    app.setOrganizationName("qdistro")

    # Local imports after QApplication so QtWebEngine initialises with
    # the right platform integration.
    from qdbrowser.config import Config
    from qdbrowser.theme import apply_theme
    from qdbrowser.window import MainWindow

    config = Config()
    theme_mode = config.get("general", "theme_mode", default="system")
    resolved = apply_theme(app, theme_mode)

    window = MainWindow(resolved_theme=resolved)

    restored = False
    if (not args.no_restore
            and not args.url
            and config.get("general", "restore_session_on_start", default=True)):
        try:
            restored = window.restore_session()
        except Exception as exc:
            log.warning("session restore failed: %s", exc)

    if not restored:
        window.new_tab(url=args.url, profile_name=args.profile)

    if args.geometry:
        _apply_geometry(window, args.geometry)

    if args.fullscreen:
        window.showFullScreen()
    elif args.maximize:
        window.showMaximized()
    else:
        window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
