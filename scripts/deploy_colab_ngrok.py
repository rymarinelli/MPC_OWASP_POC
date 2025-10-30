"""Utility script to launch the MCP server on Google Colab and expose it via ngrok."""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path
from typing import Iterable, Optional, Sequence, Tuple

DEFAULT_PIP_PACKAGES: Tuple[str, ...] = (
    "mcp>=1.2.0",
    "fastmcp>=0.4.1",
    "transformers>=4.40.0",
    "accelerate>=0.29.0",
    "pyngrok>=7.1.0",
)


def _install_packages(packages: Sequence[str]) -> None:
    if not packages:
        return
    print("📦 Installing Python packages:", ", ".join(packages))
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade"]
    cmd.extend(packages)
    subprocess.check_call(cmd)


def _load_pyngrok() -> "tuple":
    try:
        from pyngrok import conf, ngrok  # type: ignore
    except ImportError as exc:  # pragma: no cover - guarded by CLI flag
        raise RuntimeError(
            "pyngrok is required to create the tunnel. Install it first or run "
            "without --skip-install."
        ) from exc
    return ngrok, conf


def _start_mcp_server(repo_root: Path, env: Optional[dict] = None) -> subprocess.Popen:
    server_path = repo_root / "mcp_server.py"
    if not server_path.exists():
        raise FileNotFoundError(
            f"Could not find mcp_server.py at {server_path}. Run this from the repo root."
        )

    print("🚀 Starting MCP server...")
    return subprocess.Popen([sys.executable, str(server_path)], env=env)


def _configure_ngrok(authtoken: Optional[str]) -> None:
    _, conf = _load_pyngrok()
    if authtoken:
        conf.get_default().auth_token = authtoken
        print("🔐 Applied ngrok auth token.")
    elif os.getenv("NGROK_AUTHTOKEN"):
        conf.get_default().auth_token = os.environ["NGROK_AUTHTOKEN"]
        print("🔐 Loaded ngrok auth token from NGROK_AUTHTOKEN.")
    else:
        print(
            "⚠️  No ngrok auth token provided. Free tunnels may disconnect after a short time."
        )


def _open_tunnel(port: int):
    ngrok, _ = _load_pyngrok()
    print(f"🌐 Opening ngrok tunnel on port {port}...")
    return ngrok.connect(port, "http", bind_tls=True)


def _print_banner(public_url: str, port: int) -> None:
    local_endpoint = f"http://127.0.0.1:{port}"
    banner = textwrap.dedent(
        f"""
        ✅ MCP server is online!

        Local endpoint:   {local_endpoint}
        Public endpoint:  {public_url}

        Example curl request:
          curl -X POST {public_url}/call_tool \
            -H 'Content-Type: application/json' \
            -d '{{"tool_name":"scan_repo","params":{{"repo_path":".","semgrep_config":"p/ci","llm_proposal":false}}}}'
        """
    ).strip()
    print(banner)



def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Launch the MCP server in Colab and expose it via ngrok.",
    )
    parser.add_argument(
        "--port", type=int, default=8000, help="Local port used by the MCP server.")
    parser.add_argument(
        "--authtoken",
        type=str,
        default=None,
        help="ngrok auth token. Overrides the NGROK_AUTHTOKEN environment variable.",
    )
    parser.add_argument(
        "--skip-install",
        action="store_true",
        help="Do not install the default Python dependencies.",
    )
    parser.add_argument(
        "--extra-package",
        action="append",
        default=None,
        help="Additional pip packages to install before launching the server.",
    )
    parser.add_argument(
        "--skip-server",
        action="store_true",
        help="Do not spawn mcp_server.py (useful if you want to run it manually).",
    )

    args = parser.parse_args(argv)
    repo_root = Path.cwd()

    packages: Iterable[str] = ()
    if not args.skip_install:
        packages = list(DEFAULT_PIP_PACKAGES)
        if args.extra_package:
            packages = list(packages) + args.extra_package
        _install_packages(packages)
    elif args.extra_package:
        _install_packages(args.extra_package)

    server_proc: Optional[subprocess.Popen] = None
    try:
        _configure_ngrok(args.authtoken)
        tunnel = _open_tunnel(args.port)

        if not args.skip_server:
            server_proc = _start_mcp_server(repo_root)

        _print_banner(tunnel.public_url, args.port)
        print("Press Ctrl+C to stop the tunnel and server.")

        while True:
            time.sleep(2)
            if server_proc and server_proc.poll() is not None:
                raise RuntimeError("mcp_server.py terminated unexpectedly. Check the logs above.")
    except KeyboardInterrupt:
        print("\n🛑 Caught keyboard interrupt. Shutting down...")
    except Exception as exc:
        print(f"❌ Deployment failed: {exc}")
        return 1
    finally:
        try:
            ngrok, _ = _load_pyngrok()
            ngrok.kill()
        except Exception:
            pass

        if server_proc and server_proc.poll() is None:
            server_proc.send_signal(signal.SIGINT)
            try:
                server_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server_proc.kill()

    return 0


if __name__ == "__main__":
    sys.exit(main())
