# Copyright 2025-2026 AInvirion LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""CLI entry point for AIProxyGuard."""

from __future__ import annotations

import argparse
import asyncio
import sys

from aiproxyguard import __version__
from aiproxyguard.config import load_config
from aiproxyguard.logging import setup_logging, get_logger
from aiproxyguard.server import run_server


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="AIProxyGuard - LLM Security Proxy",
    )

    # Add subparsers for commands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Serve command (default behavior)
    serve_parser = subparsers.add_parser("serve", help="Start the proxy server")
    serve_parser.add_argument(
        "-c", "--config",
        default="/etc/aiproxyguard/config.yaml",
        help="Path to configuration file",
    )
    serve_parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate configuration and exit",
    )

    # Generate CA command
    ca_parser = subparsers.add_parser("generate-ca", help="Generate a CA certificate for TLS interception")
    ca_parser.add_argument(
        "--cert",
        default="/etc/aiproxyguard/ca.crt",
        help="Output path for CA certificate (default: /etc/aiproxyguard/ca.crt)",
    )
    ca_parser.add_argument(
        "--key",
        default="/etc/aiproxyguard/ca.key",
        help="Output path for CA private key (default: /etc/aiproxyguard/ca.key)",
    )
    ca_parser.add_argument(
        "--cn",
        default="AIProxyGuard CA",
        help="Common name for the CA certificate",
    )
    ca_parser.add_argument(
        "--org",
        default="AIProxyGuard",
        help="Organization name for the CA certificate",
    )
    ca_parser.add_argument(
        "--validity-days",
        type=int,
        default=3650,
        help="Number of days the CA certificate is valid (default: 3650)",
    )
    ca_parser.add_argument(
        "--key-size",
        type=int,
        default=4096,
        choices=[2048, 4096],
        help="RSA key size in bits (default: 4096)",
    )

    # Global arguments
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"aiproxyguard {__version__}",
    )

    # For backwards compatibility, also support the old arguments on the root parser
    parser.add_argument(
        "-c", "--config",
        default="/etc/aiproxyguard/config.yaml",
        help="Path to configuration file (for 'serve' command)",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate configuration and exit (for 'serve' command)",
    )

    return parser.parse_args()


def cmd_generate_ca(args: argparse.Namespace) -> int:
    """Handle generate-ca command."""
    from aiproxyguard.tls import generate_ca

    try:
        generate_ca(
            output_cert=args.cert,
            output_key=args.key,
            common_name=args.cn,
            organization=args.org,
            validity_days=args.validity_days,
            key_size=args.key_size,
        )
        print(f"CA certificate generated:")
        print(f"  Certificate: {args.cert}")
        print(f"  Private key: {args.key}")
        print()
        print("To use TLS interception, clients must trust the CA certificate.")
        print("Install instructions:")
        print("  - macOS: security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain " + args.cert)
        print("  - Linux: cp " + args.cert + " /usr/local/share/ca-certificates/ && update-ca-certificates")
        print("  - Windows: certutil -addstore -f \"ROOT\" " + args.cert)
        return 0
    except Exception as e:
        print(f"Error generating CA: {e}", file=sys.stderr)
        return 1


def cmd_serve(args: argparse.Namespace) -> int:
    """Handle serve command (default)."""
    # Load configuration
    try:
        config = load_config(args.config)
    except FileNotFoundError:
        print(f"Error: Configuration file not found: {args.config}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"Error: Invalid configuration: {e}", file=sys.stderr)
        return 1

    # Setup logging
    setup_logging(
        level=config.logging.level,
        format=config.logging.format,
        redact_keys=config.logging.redact_keys,
    )
    logger = get_logger("main")

    # Validate only mode
    if args.validate:
        print("Configuration valid.")
        return 0

    # Run server
    logger.info(f"Starting AIProxyGuard v{__version__}")
    try:
        asyncio.run(run_server(config))
    except KeyboardInterrupt:
        logger.info("Shutting down...")

    return 0


def main() -> int:
    """Main entry point."""
    args = parse_args()

    # Route to appropriate command handler
    if args.command == "generate-ca":
        return cmd_generate_ca(args)
    elif args.command == "serve":
        return cmd_serve(args)
    else:
        # Default to serve for backwards compatibility
        return cmd_serve(args)


if __name__ == "__main__":
    sys.exit(main())
