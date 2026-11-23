import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECCOMP_PROFILE_PATH = ROOT / "infra" / "seccomp" / "api-seccomp.json"
APPARMOR_PROFILE_PATH = ROOT / "infra" / "apparmor" / "zt-hospital-api"
DOCKER_COMPOSE_PATH = ROOT / "docker-compose.yml"
DOCKER_COMPOSE_APPARMOR_PATH = ROOT / "docker-compose.apparmor.yml"


def test_seccomp_profile_enforces_default_deny_and_blocks_dangerous_syscalls():
    profile = json.loads(SECCOMP_PROFILE_PATH.read_text(encoding="utf-8"))

    assert profile["defaultAction"] == "SCMP_ACT_ERRNO"
    assert profile["defaultErrnoRet"] == 1

    arches = {entry["architecture"] for entry in profile["archMap"]}
    assert {"SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"}.issubset(arches)

    unrestricted_allowed: set[str] = set()
    clone_rules = []
    clone3_rules = []
    socket_rules = []

    for rule in profile["syscalls"]:
        names = set(rule["names"])
        action = rule["action"]
        has_args = bool(rule.get("args"))

        if action == "SCMP_ACT_ALLOW" and not has_args:
            unrestricted_allowed.update(names)
        if "clone" in names:
            clone_rules.append(rule)
        if "clone3" in names:
            clone3_rules.append(rule)
        if "socket" in names:
            socket_rules.append(rule)

    # Syscalls de alto riesgo jamás deben estar en la lista blanca sin restricción
    forbidden_syscalls = {
        "bpf",
        "chmod",
        "chown",
        "chroot",
        "clone",
        "clone3",
        "delete_module",
        "execveat",
        "fchmod",
        "fchown",
        "finit_module",
        "fork",
        "init_module",
        "kexec_file_load",
        "kexec_load",
        "keyctl",
        "memfd_create",
        "mount",
        "perf_event_open",
        "pivot_root",
        "process_vm_readv",
        "process_vm_writev",
        "ptrace",
        "reboot",
        "setgid",
        "setns",
        "setuid",
        "socket",
        "swapon",
        "swapoff",
        "umount2",
        "unshare",
        "userfaultfd",
        "vfork",
    }
    assert unrestricted_allowed.isdisjoint(forbidden_syscalls), (
        f"Syscalls peligrosos permitidos sin restricción: {unrestricted_allowed & forbidden_syscalls}"
    )

    # clone3 debe devolver ENOSYS (38) para forzar fallback a clone inspeccionado
    assert len(clone3_rules) == 1
    assert clone3_rules[0]["action"] == "SCMP_ACT_ERRNO"
    assert clone3_rules[0]["errnoRet"] == 38

    # clone solo permitido con bandera CLONE_THREAD (0x10000 = 65536)
    assert len(clone_rules) == 1
    assert clone_rules[0]["action"] == "SCMP_ACT_ALLOW"
    assert clone_rules[0]["args"] == [
        {"index": 0, "value": 65536, "valueTwo": 65536, "op": "SCMP_CMP_MASKED_EQ"}
    ]

    # socket restringido solo a AF_UNIX(1), AF_INET(2), AF_INET6(10) — bloquea AF_PACKET(17)
    allowed_socket_domains = {
        arg["value"]
        for rule in socket_rules
        if rule["action"] == "SCMP_ACT_ALLOW"
        for arg in rule.get("args", [])
        if arg["index"] == 0 and arg["op"] == "SCMP_CMP_EQ"
    }
    assert allowed_socket_domains == {1, 2, 10}


def test_apparmor_profile_contains_mandatory_confinement_rules():
    content = APPARMOR_PROFILE_PATH.read_text(encoding="utf-8")

    required_directives = [
        "profile zt-hospital-api",
        "/app/** r,",
        "/tmp/** rw,",
        "deny capability,",
        "deny mount,",
        "deny ptrace,",
        "deny /bin/** x,",
        "deny /usr/bin/sh x,",
        "deny /usr/bin/bash x,",
        "deny /tmp/** x,",
        "deny /app/** w,",
        "deny /etc/shadow rwx,",
    ]
    for directive in required_directives:
        assert directive in content, f"Directiva AppArmor faltante: {directive}"


def test_docker_compose_enables_seccomp_and_apparmor_override():
    import yaml

    compose_data = yaml.safe_load(DOCKER_COMPOSE_PATH.read_text(encoding="utf-8"))
    api_service = compose_data["services"]["api"]
    assert api_service["read_only"] is True
    assert "ALL" in api_service["cap_drop"]
    assert "no-new-privileges:true" in api_service["security_opt"]
    assert "seccomp=./infra/seccomp/api-seccomp.json" in api_service["security_opt"]

    override_data = yaml.safe_load(DOCKER_COMPOSE_APPARMOR_PATH.read_text(encoding="utf-8"))
    assert override_data["services"]["api"]["security_opt"] == ["apparmor=zt-hospital-api"]
