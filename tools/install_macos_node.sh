#!/bin/zsh
set -euo pipefail

WITNESS_INDEX="${1:-1}"
case "$WITNESS_INDEX" in
  1) EXPECTED_SHA256="fd74a5b00b4218aa0001c3fad5b0c84488afb2b0ef74b6e7a9a9f170156fc973" ;;
  2) EXPECTED_SHA256="3ad6a15115ed2f9477176944712409a73bbd517be0450acdf6fcd1ace84bc265" ;;
  3) EXPECTED_SHA256="95bf77d411e1a481c9fa02d061f1d82697904eb892dd3a8340402b6b59026008" ;;
  *) print -u2 "Witness index must be 1, 2, or 3."; exit 2 ;;
esac
BUNDLE_URL="https://github.com/tman747/noosphere/releases/download/mindchain-lan-devnet-v3/MindChain-macOS-ARM64-Witness-${WITNESS_INDEX}.zip"

if [[ "$(uname -s)" != "Darwin" ]]; then
  print -u2 "This installer must be run on a Mac."
  exit 1
fi
if [[ "$(uname -m)" != "arm64" ]]; then
  print -u2 "This invitation currently supports Apple Silicon Macs only (M1, M2, M3, M4, or newer)."
  exit 1
fi
for command in curl shasum unzip xattr; do
  command -v "$command" >/dev/null || { print -u2 "Missing required macOS command: $command"; exit 1; }
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/mindchain-install.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
ARCHIVE="$WORK/MindChain-node.zip"
APP="$WORK/MindChain-node"
mkdir -p "$APP"

print "Downloading the verified MindChain node…"
curl --fail --location --proto '=https' --tlsv1.2 "$BUNDLE_URL" --output "$ARCHIVE"
ACTUAL_SHA256="$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')"
if [[ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]]; then
  print -u2 "MindChain download verification failed. Expected $EXPECTED_SHA256 but received $ACTUAL_SHA256."
  exit 1
fi

unzip -q "$ARCHIVE" -d "$APP"
xattr -dr com.apple.quarantine "$APP"
chmod 700 "$APP/noosd" "$APP/JOIN MINDCHAIN.command"
print "The download is verified. Adding this Mac to MindChain…"
exec "$APP/JOIN MINDCHAIN.command"
