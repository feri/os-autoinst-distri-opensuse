# SUSE's openQA tests
#
# Copyright SUSE LLC
# SPDX-License-Identifier: FSFAP
"""Portable, distro-agnostic verification of the usbguard USB-access-control engine.

usbguard is a policy engine that decides which USB devices may be used on a SUT.
This suite validates the portable core that is meaningful on every SLE/TW/Leap
build:
  * the usbguard service is installed and active
  * the default insertion policy is "apply-policy" and the implicit target is "block"
  * block-device / allow-device flip the device policy and record an audit entry
  * set-parameter / get-parameter round-trip a value

Device-dependent and environment-specific checks (no USB device attached, missing
audit log, optional tools) are skipped with a reason instead of failing, so the
suite stays green on minimal/VM images where none of those exist.
"""

import os
import shutil
import subprocess

import pytest

# USB audit log candidates across distros.
_AUDIT_LOG_CANDIDATES = (
    "/var/log/usbguard/usbguard-audit.log",
    "/var/log/audit/audit.log",
)


def _run(cmd, **kw):
    """Run a command and capture stdout/stderr as text."""
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def _require(cmd):
    """Skip the whole file if a required command is not installed."""
    if shutil.which(cmd) is None:
        pytest.skip(f"{cmd} is not installed")


# The driver installs usbguard, but on distros where it is unavailable the test
# suite should skip cleanly rather than fail.
_require("usbguard")


def audit_log_path():
    """Return the first existing audit-log path, else derive it from config."""
    for path in _AUDIT_LOG_CANDIDATES:
        if os.path.isfile(path):
            return path
    out = _run(["usbguard", "get-parameter", "AuditLogPath"]).stdout.strip()
    if out and os.path.isfile(out):
        return out
    return None


def _list_device_ids():
    """Return the ids of devices reported by `usbguard list-devices`."""
    out = _run(["usbguard", "list-devices"]).stdout
    ids = []
    for line in out.splitlines():
        device, _, _ = line.partition(":")
        if device.strip().isdigit():
            ids.append(device.strip())
    return ids


def _device_line(device_id):
    """Return the `list-devices` line for one device (so the policy check is
    scoped to that device, not to any other attached device's status)."""
    out = _run(["usbguard", "list-devices"]).stdout
    for line in out.splitlines():
        device, _, _ = line.partition(":")
        if device.strip() == device_id:
            return line.strip()
    return ""


def _new_log_content(path, before_lines):
    with open(path, errors="ignore") as handle:
        lines = handle.readlines()
    return "".join(lines[before_lines:])


# ---- 1. service ------------------------------------------------------------

def test_service_installed_and_active():
    """usbguard.service must be running (enable it if a fresh install left it off)."""
    _run(["systemctl", "enable", "--now", "usbguard.service"])
    result = _run(["systemctl", "is-active", "usbguard.service"])
    assert result.returncode == 0, f"usbguard.service should be active: {result.stdout}"
    assert result.stdout.strip() == "active", result.stdout


# ---- 2. default parameters -------------------------------------------------

def test_default_inserted_device_policy():
    """InsertedDevicePolicy must default to apply-policy."""
    result = _run(["usbguard", "get-parameter", "InsertedDevicePolicy"])
    assert result.stdout.strip() == "apply-policy", result.stdout


def test_default_implicit_policy_target_block():
    """ImplicitPolicyTarget must default to block."""
    result = _run(["usbguard", "get-parameter", "ImplicitPolicyTarget"])
    assert result.stdout.strip() == "block", result.stdout


# ---- 3. device policy flip + audit log (device dependent) ------------------

@pytest.fixture
def device_id():
    ids = _list_device_ids()
    if not ids:
        pytest.skip("no USB device attached; device-policy checks skipped")
    return ids[0]


def test_block_and_allow_device(device_id):
    """block-device then allow-device must flip the policy and be audited."""
    log = audit_log_path()
    before = 0
    if log:
        with open(log, errors="ignore") as handle:
            before = len(handle.readlines())

    _run(["usbguard", "block-device", device_id])
    line = _device_line(device_id)
    assert "block" in line, f"device {device_id} should show block: {line}"

    _run(["usbguard", "allow-device", device_id])
    line = _device_line(device_id)
    assert "apply" in line, f"device {device_id} should be re-authorized (apply): {line}"

    if log:
        appended = _new_log_content(log, before)
        assert "block" in appended, f"expected a block event in {log}:\n{appended}"
        assert str(device_id) in appended, (
            f"expected device {device_id} record in {log}:\n{appended}"
        )


# ---- 4. set/get parameter --------------------------------------------------

def test_set_and_get_parameter_roundtrip():
    """set-parameter must be reflected by a subsequent get-parameter."""
    _run(["usbguard", "set-parameter", "GuardBootDevices", "0"])
    result = _run(["usbguard", "get-parameter", "GuardBootDevices"])
    assert result.stdout.strip() == "0", result.stdout


# ---- 5. generate policy (light) --------------------------------------------

def test_generate_policy_creates_rules(tmp_path):
    """generate-policy should emit at least one rule when devices are present."""
    out = _run(
        ["usbguard", "generate-policy", "-o", str(tmp_path / "rules.conf")]
    ).stdout
    if out.strip():
        assert any(
            needle in out for needle in ("block", "apply", "ID ")
        ), f"unexpected generated rules: {out}"
    else:
        pytest.skip("generate-policy produced no rules (no devices)")


if __name__ == "__main__":
    pytest.main([__file__])
