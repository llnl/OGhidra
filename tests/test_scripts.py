import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def make_script_repository(tmp_path: Path) -> Path:
    repository = tmp_path / "checkout with spaces"
    scripts = repository / "scripts"
    scripts.mkdir(parents=True)
    for name in ("setup.sh", "run-ghidra.sh"):
        shutil.copy2(REPOSITORY_ROOT / "scripts" / name, scripts / name)
    (repository / "config.example.yaml").write_text("lm: example\n")
    (repository / "pyproject.toml").write_text("[project]\nname = 'fixture'\n")
    return repository


def write_executable(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(0o755)


def fake_setup_tools(tmp_path: Path, python_version: str = "3.12") -> tuple[Path, Path]:
    tools = tmp_path / "fake tools"
    tools.mkdir()
    calls = tmp_path / "calls.log"
    write_executable(
        tools / "python3.12",
        f"""#!/usr/bin/env bash
set -eu
if [[ "${{1-}}" == "-c" ]]; then
    printf '%s\\n' '{python_version}'
    exit 0
fi
if [[ "${{1-}}" == "-m" && "${{2-}}" == "venv" ]]; then
    target="$3"
    mkdir -p "$target/bin"
    cp "$0" "$target/bin/python"
    exit 0
fi
if [[ "${{1-}}" == "-m" && "${{2-}}" == "pip" ]]; then
    printf 'pip' >> "{calls}"
    printf ' <%s>' "$@" >> "{calls}"
    printf '\\n' >> "{calls}"
    exit 0
fi
exit 91
""",
    )
    return tools, calls


def run_setup(
    repository: Path, tools: Path, *arguments: str
) -> subprocess.CompletedProcess[str]:
    outside = repository.parent / "outside"
    outside.mkdir(exist_ok=True)
    environment = os.environ.copy()
    environment["PATH"] = f"{tools}:/usr/bin:/bin"
    return subprocess.run(
        ["bash", str(repository / "scripts" / "setup.sh"), *arguments],
        cwd=outside,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_setup_runs_from_outside_checkout_and_preserves_existing_config(tmp_path):
    repository = make_script_repository(tmp_path)
    tools, calls = fake_setup_tools(tmp_path)

    first = run_setup(repository, tools)
    assert first.returncode == 0, first.stderr
    assert (repository / "config.yaml").read_text() == "lm: example\n"
    assert (repository / ".venv-ghidra" / "bin" / "python").exists()
    assert (repository / ".venv" / "bin" / "python").exists()
    install_calls = calls.read_text()
    assert "pyghidra-mcp==0.2.7" in install_calls
    assert "-e" in install_calls

    (repository / "config.yaml").write_text("keep: this\n")
    second = run_setup(repository, tools)
    assert second.returncode == 0, second.stderr
    assert (repository / "config.yaml").read_text() == "keep: this\n"


def test_setup_rejects_python_older_than_3_12(tmp_path):
    repository = make_script_repository(tmp_path)
    tools, _ = fake_setup_tools(tmp_path, python_version="3.11")

    result = run_setup(repository, tools)

    assert result.returncode != 0
    assert "Python 3.12" in result.stderr
    assert not (repository / ".venv").exists()


def test_setup_requires_codex_only_when_registration_is_requested(tmp_path):
    repository = make_script_repository(tmp_path)
    tools, _ = fake_setup_tools(tmp_path)

    without_registration = run_setup(repository, tools)
    with_registration = run_setup(repository, tools, "--register-codex")

    assert without_registration.returncode == 0, without_registration.stderr
    assert with_registration.returncode != 0
    assert "codex" in with_registration.stderr.lower()


def test_setup_registration_uses_absolute_checkout_paths(tmp_path):
    repository = make_script_repository(tmp_path)
    tools, calls = fake_setup_tools(tmp_path)
    write_executable(
        tools / "codex",
        f"""#!/usr/bin/env bash
set -eu
if [[ "${{1-}}" == "mcp" && "${{2-}}" == "get" ]]; then
    exit 1
fi
printf 'codex' >> "{calls}"
printf ' <%s>' "$@" >> "{calls}"
printf '\\n' >> "{calls}"
""",
    )

    result = run_setup(repository, tools, "--register-codex")

    assert result.returncode == 0, result.stderr
    log = calls.read_text()
    assert "<mcp> <add> <pyghidra> <--url> <http://127.0.0.1:8001/mcp>" in log
    assert f"<{repository / '.venv' / 'bin' / 'oghidra-workflows'}>" in log
    assert f"<{repository / 'config.yaml'}>" in log


def test_setup_registration_leaves_existing_server_unchanged(tmp_path):
    repository = make_script_repository(tmp_path)
    tools, calls = fake_setup_tools(tmp_path)
    write_executable(
        tools / "codex",
        f"""#!/usr/bin/env bash
set -eu
printf 'codex' >> "{calls}"
printf ' <%s>' "$@" >> "{calls}"
printf '\\n' >> "{calls}"
if [[ "${{1-}}" == "mcp" && "${{2-}}" == "get" ]]; then
    [[ "${{3-}}" == "pyghidra" ]]
fi
""",
    )

    result = run_setup(repository, tools, "--register-codex")

    assert result.returncode == 0, result.stderr
    log = calls.read_text()
    assert "<mcp> <add> <pyghidra>" not in log
    assert "<mcp> <add> <oghidra>" in log


def run_ghidra(
    repository: Path,
    *arguments: str,
    ghidra_install_dir: str | None = "/opt/ghidra",
    java_tool_options: str | None = None,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.pop("JAVA_TOOL_OPTIONS", None)
    if java_tool_options is not None:
        environment["JAVA_TOOL_OPTIONS"] = java_tool_options
    if ghidra_install_dir is None:
        environment.pop("GHIDRA_INSTALL_DIR", None)
    else:
        environment["GHIDRA_INSTALL_DIR"] = ghidra_install_dir
    return subprocess.run(
        ["bash", str(repository / "scripts" / "run-ghidra.sh"), *arguments],
        cwd=repository.parent,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize("prior_options", [None, "-Dexample.setting=keep"])
def test_runner_registers_ghidra_url_handler_before_jvm_start(tmp_path, prior_options):
    repository = make_script_repository(tmp_path)
    executable = repository / ".venv-ghidra" / "bin" / "pyghidra-mcp"
    executable.parent.mkdir(parents=True)
    write_executable(
        executable,
        "#!/usr/bin/env bash\nprintf '%s\\n' \"$JAVA_TOOL_OPTIONS\"\n",
    )

    result = run_ghidra(repository, java_tool_options=prior_options)

    assert result.returncode == 0, result.stderr
    assert "-Djava.protocol.handler.pkgs=ghidra.framework.protocol" in result.stdout
    if prior_options is not None:
        assert prior_options in result.stdout


def test_runner_requires_ghidra_install_dir(tmp_path):
    repository = make_script_repository(tmp_path)

    result = run_ghidra(repository, ghidra_install_dir=None)

    assert result.returncode != 0
    assert "GHIDRA_INSTALL_DIR" in result.stderr


@pytest.mark.parametrize(
    "session_arguments",
    [
        (
            "--project-path",
            "/tmp/projects",
            "--project-name",
            "research",
            "/tmp/a program",
        ),
        ("--project-path", "/tmp/existing project.gpr"),
    ],
)
def test_runner_adds_required_options_and_forwards_native_arguments(
    tmp_path, session_arguments
):
    repository = make_script_repository(tmp_path)
    executable = repository / ".venv-ghidra" / "bin" / "pyghidra-mcp"
    executable.parent.mkdir(parents=True)
    write_executable(
        executable,
        """#!/usr/bin/env bash
set -eu
printf 'ghidra=<%s>\\n' "$GHIDRA_INSTALL_DIR"
printf 'arg=<%s>\\n' "$@"
""",
    )

    result = run_ghidra(repository, *session_arguments)

    assert result.returncode == 0, result.stderr
    assert "ghidra=</opt/ghidra>" in result.stdout
    lines = result.stdout.splitlines()
    assert lines[1:] == [
        "arg=<--gui>",
        "arg=<--transport>",
        "arg=<streamable-http>",
        "arg=<--host>",
        "arg=<127.0.0.1>",
        "arg=<--port>",
        "arg=<8001>",
        *[f"arg=<{argument}>" for argument in session_arguments],
    ]
