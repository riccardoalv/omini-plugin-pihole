"""Omini plugin for Pi-hole v6 (entrypoint run by the Omini core)."""

from omini_sdk import plugin

from omini_pihole.collect import apply, backup, collect, test

plugin.collect(collect)
plugin.test(test)
plugin.apply(apply)
plugin.backup(backup)

if __name__ == "__main__":
    plugin.run()
