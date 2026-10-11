"""Start the OS-Ken app on loopback port 6653 in the Ubuntu lab."""

import logging
import sys
from pathlib import Path

from os_ken import cfg
from os_ken.base import app_manager
from os_ken.controller import controller as _ofp_controller  # Registers listener options.


ROOT = Path(__file__).resolve().parents[1]


def main():
    sys.path.insert(0, str(ROOT))
    cfg.CONF(args=[], project="os_ken")
    cfg.CONF.set_override("ofp_listen_host", "127.0.0.1")
    cfg.CONF.set_override("ofp_tcp_listen_port", 6653)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger(__name__).info("Starting OS-Ken OpenFlow 1.3 controller on 127.0.0.1:6653")
    app_manager.AppManager.run_apps(["controller.forwarding"])


if __name__ == "__main__":
    main()
