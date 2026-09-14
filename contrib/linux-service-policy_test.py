#!/usr/bin/env python3
"""Exact policy assertions and optional unprivileged native D-Bus routing tests.

Run with /usr/bin/python3 contrib/linux-service-policy_test.py -v. Native tests
need dbus-python, GLib and dbus-broker-launch; no host bus or root access is used.
The echo peer tests transport policy, not the wallet's independent core auth.
"""

import importlib.util
import os
from pathlib import Path
import pwd
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET


POLICIES = Path(__file__).with_name("linux-service")
PREFIX = "org.ekubo.Wallet2."
PATH = "/org/ekubo/Wallet2/"
OWNER_CALLS = (("Owner1", "Owner", "Call"),
               ("Owner1", "Owner", "LegacyMove"),
               ("Owner1", "Owner", "HoldDesktopSession"),
               ("Custody1", "Custody", "Unlock"))
ROOT_CALLS = (("Provision1", "Provision", "Enroll"),
              ("InstallerRelay1", "InstallerRelay", "Persist"))


def policy(kind):
    return ET.parse(POLICIES / f"{PREFIX}{kind}.conf").getroot()


def route(interface, path, member, message_type="method_call"):
    return {"send_type": message_type, "send_interface": PREFIX + interface,
            "send_path": PATH + path, "send_member": member}


class PolicyTest(unittest.TestCase):
    def test_only_exact_typed_routes_are_allowed(self):
        expected = {
            "Owner": {"default": [route(*call) for call in OWNER_CALLS],
                      "ekubo-wallet-v2": [route("Owner1", "Owner", "DesktopSessionReady",
                                                "signal")]},
            "Provision": {"root": [route(*call) for call in ROOT_CALLS]},
        }
        for kind, grants in expected.items():
            actual = {}
            for section in policy(kind):
                sends = [rule.attrib for rule in section.findall("allow")
                         if any(key.startswith("send_") for key in rule.attrib)]
                if sends:
                    actual[section.get("user", section.get("context"))] = sends
            self.assertEqual(actual, grants)

    def test_name_ownership_and_privileged_interface_denials(self):
        for kind in ("Owner", "Provision"):
            root = policy(kind)
            default = root.find("policy[@context='default']")
            self.assertIn({"own_prefix": PREFIX + kind},
                          [rule.attrib for rule in default.findall("deny")])
            owners = [(section.attrib, rule.attrib) for section in root
                      for rule in section.findall("allow") if "own_prefix" in rule.attrib]
            self.assertEqual(owners, [({"user": "ekubo-wallet-v2"},
                                       {"own_prefix": PREFIX + kind})])
            for rule in root.iter():
                self.assertNotIn("send_destination_prefix", rule.attrib)
        denials = [rule.attrib for rule in
                   policy("Provision").find("policy[@context='default']").findall("deny")]
        for interface, _, _ in ROOT_CALLS:
            self.assertIn({"send_interface": PREFIX + interface}, denials)


# Exec rather than preexec_fn: pass_fds preserves the listener until the child
# assigns the systemd socket-activation fd and its own LISTEN_PID.
LAUNCH = """
import os, sys
fd = int(sys.argv[1])
os.dup2(fd, 3, inheritable=True)
os.set_inheritable(3, True)
os.environ.update(LISTEN_FDS='1', LISTEN_PID=str(os.getpid()))
os.execvp('dbus-broker-launch', ['dbus-broker-launch', '--scope', 'user',
                              '--config-file', sys.argv[2]])
"""
ECHO = """
import dbus, dbus.lowlevel, sys
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib
DBusGMainLoop(set_as_default=True)
bus = dbus.bus.BusConnection(sys.argv[1])
def reply(connection, message):
    if message.get_type() == dbus.lowlevel.MESSAGE_TYPE_METHOD_CALL:
        response = dbus.lowlevel.MethodReturnMessage(message)
        response.append('routed', signature='s')
        connection.send_message(response)
bus.add_message_filter(reply)
print(bus.get_unique_name(), flush=True)
GLib.MainLoop().run()
"""


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    if process.stdout:
        process.stdout.close()


@unittest.skipUnless(os.geteuid() != 0 and shutil.which("dbus-broker-launch")
                     and importlib.util.find_spec("dbus") and importlib.util.find_spec("gi"),
                     "non-root user, dbus-broker-launch, dbus-python and GLib required")
class NativeBrokerTest(unittest.TestCase):
    def start_bus(self, privileged=False):
        import dbus

        temporary = tempfile.TemporaryDirectory(prefix="wallet-bus-policy-")
        self.addCleanup(temporary.cleanup)
        work = Path(temporary.name)
        config = ET.Element("busconfig")
        ET.SubElement(config, "type").text = "system"
        baseline = ET.SubElement(config, "policy", context="default")
        for tag, attrs in (("allow", {"user": "*"}),
                           ("deny", {"own": "*"}),
                           ("deny", {"send_type": "method_call"}),
                           ("allow", {"send_destination": "org.freedesktop.DBus"}),
                           ("allow", {"send_type": "method_return", "send_requested_reply": "true"}),
                           ("allow", {"send_type": "error", "send_requested_reply": "true"}),
                           ("allow", {"receive_sender": "*"})):
            ET.SubElement(baseline, tag, attrs)
        for kind in ("Owner", "Provision"):
            for section in policy(kind):
                # Exercise the root policy on an isolated bus without root.
                # Never map the service ownership/signal grants to the caller.
                if privileged and section.get("user") == "root":
                    section.set("user", pwd.getpwuid(os.geteuid()).pw_name)
                config.append(section)
        filename = work / "bus.conf"
        ET.ElementTree(config).write(filename, encoding="unicode")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(str(work / "bus"))
        listener.listen()
        log = (work / "broker.log").open("w+")
        self.addCleanup(log.close)
        broker = subprocess.Popen([sys.executable, "-c", LAUNCH, str(listener.fileno()),
                                   str(filename)], pass_fds=(listener.fileno(),),
                                  stdout=log, stderr=log)
        self.addCleanup(stop, broker)
        address = f"unix:path={work / 'bus'}"
        peer = subprocess.Popen([sys.executable, "-c", ECHO, address],
                                stdout=subprocess.PIPE, stderr=log, text=True)
        self.addCleanup(stop, peer)
        ready = select.select([peer.stdout], [], [], 10)[0]
        if not ready:
            log.flush()
            log.seek(0)
            self.fail(f"echo peer startup timeout; broker={broker.poll()}: {log.read()}")
        name = peer.stdout.readline().strip()
        log.flush()
        log.seek(0)
        diagnostics = log.read()
        self.assertTrue(name.startswith(":"), diagnostics)
        self.assertNotIn("Unknown attribute", diagnostics)
        bus = dbus.bus.BusConnection(address)
        self.addCleanup(bus.close)
        return bus, name

    def call(self, bus, name, interface, path, member):
        import dbus.lowlevel

        message = dbus.lowlevel.MethodCallMessage(name, PATH + path,
                                                   PREFIX + interface, member)
        return bus.send_message_with_reply_and_block(message, 3).get_args_list()

    def denied(self, bus, name, interface, path, member):
        import dbus

        with self.assertRaises(dbus.DBusException) as caught:
            self.call(bus, name, interface, path, member)
        self.assertEqual(caught.exception.get_dbus_name(), "org.freedesktop.DBus.Error.AccessDenied")

    def test_ordinary_user_routes_and_denials(self):
        import dbus.lowlevel

        bus, name = self.start_bus()
        for call in OWNER_CALLS:
            with self.subTest(call=call):
                self.assertEqual(self.call(bus, name, *call), ["routed"])
        for call in ROOT_CALLS + (("Owner1", "Custody", "Call"),
                                  ("Custody1", "Owner", "Unlock"),
                                  ("Owner1", "Owner", "Unexpected"),
                                  ("Unrelated1", "Owner", "Call")):
            with self.subTest(denied=call):
                self.denied(bus, name, *call)
        # Standard introspection is not part of our typed route grants.
        message = dbus.lowlevel.MethodCallMessage(name, PATH + "Owner",
                                                   "org.freedesktop.DBus.Introspectable",
                                                   "Introspect")
        with self.assertRaises(dbus.DBusException) as caught:
            bus.send_message_with_reply_and_block(message, 3)
        self.assertEqual(caught.exception.get_dbus_name(), "org.freedesktop.DBus.Error.AccessDenied")
        for kind in ("Owner", "Provision"):
            with self.assertRaises(dbus.DBusException):
                bus.request_name(PREFIX + kind + ".u1000")

    def test_root_routes_with_test_only_uid_mapping(self):
        bus, name = self.start_bus(privileged=True)
        for call in ROOT_CALLS:
            with self.subTest(call=call):
                self.assertEqual(self.call(bus, name, *call), ["routed"])
                interface, path, member = call
                self.denied(bus, name, interface, path + "/Other", member)
                self.denied(bus, name, interface, path, "Unexpected")


if __name__ == "__main__":
    unittest.main()
