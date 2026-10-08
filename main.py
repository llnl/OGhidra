"""Workspace entry point: python main.py --config config.yaml."""

if __name__ == "__main__":
    # Retain a visible traceback even if dependencies fail before logging setup.
    import logging
    import faulthandler
    import sys

    try:
        faulthandler.enable(file=sys.stderr, all_threads=True)
    except (OSError, ValueError, RuntimeError):
        pass  # Some IDE stderr streams have no file descriptor.

    try:
        from src.oghidra_workflows.server import main

        main()
    except Exception:
        logging.basicConfig(stream=sys.stderr, level=logging.ERROR)
        logging.getLogger("oghidra_workflows").exception(
            "bootstrap.import_or_startup_failed"
        )
        raise SystemExit(1)
