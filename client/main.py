import argparse
import asyncio

from .runtime import run_client


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Cliente CLI para chat E2EE")
    parser.add_argument("--url", default="ws://127.0.0.1:8765")
    parser.add_argument("--user", required=True)
    parser.add_argument("--room", default="general")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    asyncio.run(run_client(args.url, args.user, args.room))


if __name__ == "__main__":
    main()
