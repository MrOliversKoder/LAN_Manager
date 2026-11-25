"""Entry point. davidlor/python-git-app runs `python .` which executes this file."""
import signal
import sys
import logging

from waitress import serve

from app import create_app, config

log = logging.getLogger("lan")


def main():
    app = create_app()
    # `docker stop` sends SIGTERM: exit cleanly so the scheduler shuts down.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    log.info("LAN Manager listening on http://%s:%s (data: %s)", config.HOST, config.PORT, config.DATA_DIR)
    serve(app, host=config.HOST, port=config.PORT, threads=8, ident="lan-manager")


if __name__ == "__main__":
    main()
