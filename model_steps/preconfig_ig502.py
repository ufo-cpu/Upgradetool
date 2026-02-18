import os
import subprocess
import sys
from typing import Dict, Optional, Tuple

from .base import ModelPreConfigStep


def _pick_edge_config_path(job_def: Dict) -> str:
    return job_def.get("incremental_config_path") or job_def.get("config_path") or ""


def _run_ig502_step(ctx: Dict, job_def: Dict) -> Tuple[bool, str, Optional[str]]:
    log = ctx["log"]
    check_ping = ctx["check_ping"]
    check_tcp = ctx["check_tcp"]
    expected_ip = "192.168.1.1"

    current_ip = job_def.get("ip") or job_def.get("initial_ip") or ""
    user = job_def.get("username") or ""
    pwd = job_def.get("password") or ""
    protocol = job_def.get("protocol") or "http"

    script_path = os.path.join(ctx["project_root"], "scripts", "ig502", "ig502_step.py")
    if not os.path.exists(script_path):
        return False, current_ip, f"IG502 script not found: {script_path}"

    cmd = [
        sys.executable,
        script_path,
        "--ip", current_ip,
        "--username", user,
        "--password", pwd,
        "--protocol", protocol,
        "--firmware", (job_def.get("firmware_path") or ""),
        "--edge-config", _pick_edge_config_path(job_def),
        "--import-config", (job_def.get("config_path") or ""),
        "--expected-ip", expected_ip,
    ]

    log(f"Start model pre-config step [IG502], target: {current_ip}", "INFO")
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        if process.stdout:
            for line in process.stdout:
                line = line.strip()
                if line:
                    log(f"[MODEL-STEP][IG502] {line}", "INFO")

        code = process.wait(timeout=900)
    except subprocess.TimeoutExpired:
        process.kill()
        return False, current_ip, "IG502 pre-config step timed out."
    except Exception as exc:  # noqa: BLE001
        return False, current_ip, f"IG502 pre-config step execution exception: {exc}"

    if code != 0:
        return False, current_ip, f"IG502 pre-config step failed with return code: {code}"

    try:
        port_val = int(job_def.get("port", 80))
    except (TypeError, ValueError):
        port_val = 80

    ping_ok = check_ping(expected_ip, count=1, timeout=2, max_retries=10, retry_delay=2)
    port_ok = check_tcp(expected_ip, port_val, timeout=30)
    if ping_ok and port_ok:
        log(f"IG502 pre-config step success, switched to {expected_ip}", "SUCCESS")
        return True, expected_ip, None

    return False, current_ip, f"IG502 pre-config step failed, target IP {expected_ip} unreachable."


IG502_PRECONFIG_STEP = ModelPreConfigStep(
    key="ig502_preconfig",
    display_name="IG502 Step (Optional / Model-Specific)",
    model_matcher=lambda model: "IG502" in model.upper(),
    executor=_run_ig502_step,
)
