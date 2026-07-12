#!/bin/zsh
set -euo pipefail

WITNESS_INDEX="${1:-1}"
case "$WITNESS_INDEX" in
  1) EXPECTED_SHA256="36264b508ac98c1f7f7c36a897bf2ed70475163bdc1a44487e9afbb014d7f3ec" ;;
  2) EXPECTED_SHA256="1382acc816b276536e783d1b43cb3ca0fe523d04945e40c754fcdd06401cf3a8" ;;
  3) EXPECTED_SHA256="82b7cdbee475cad0b2b108ceb4243aed48d70659952361092c528a5490c230ec" ;;
  *) print -u2 "Witness index must be 1, 2, or 3."; exit 2 ;;
esac
BUNDLE_URL="https://github.com/tman747/noosphere/releases/download/mindchain-lan-devnet-v2/MindChain-macOS-ARM64-Witness-${WITNESS_INDEX}.zip"

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
