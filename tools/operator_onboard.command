#!/bin/zsh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
INVITE="$ROOT/invite.json"
NODE="$ROOT/noosd"
PARAMS="$ROOT/devnet-parameters.toml"
if [[ ! -f "$INVITE" || ! -x "$NODE" || ! -f "$PARAMS" ]]; then
  osascript -e 'display dialog "This MindChain invitation is incomplete. Download the bundle again." buttons {"OK"} default button "OK" with icon stop'
  exit 1
fi
read_json() { /usr/bin/python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); x=v'"$2"'; print(x)' "$INVITE"; }
SCHEMA="$(read_json '' '["schema"]')"
[[ "$SCHEMA" == "noos/one-click-invite/v1" ]] || { osascript -e 'display dialog "Unsupported MindChain invitation." buttons {"OK"} with icon stop'; exit 1; }
EXPECTED="$(read_json '' '["params_sha256"]')"
ACTUAL="$(shasum -a 256 "$PARAMS" | awk '{print $1}')"
[[ "$EXPECTED" == "$ACTUAL" ]] || { osascript -e 'display dialog "The network parameters failed their checksum." buttons {"OK"} with icon stop'; exit 1; }

INSTALL="$HOME/Library/Application Support/MindChain/Operator"
DATA="$HOME/Library/Application Support/MindChain/NodeData"
AGENT="$HOME/Library/LaunchAgents/network.mindchain.node.plist"
mkdir -p "$INSTALL" "$DATA" "$(dirname "$AGENT")"
cp "$NODE" "$INSTALL/noosd"
cp "$PARAMS" "$INSTALL/devnet-parameters.toml"
cp "$INVITE" "$INSTALL/invite.json"
chmod 700 "$INSTALL/noosd"

GENESIS="$(read_json '' '["genesis_time_ms"]')"
HOST="$(read_json '' '["validator_host"]')"
VALIDATOR_PORT="$(read_json '' '["validator_p2p_port"]')"
LOCAL_PORT="$(read_json '' '["local_p2p_port"]')"
WITNESS="$(read_json '' '["witness_index"]')"
ARGS=("--params" "$INSTALL/devnet-parameters.toml" "--data-dir" "$DATA" "--genesis-time" "$GENESIS" \
  "--p2p-listen" "/ip4/0.0.0.0/udp/$LOCAL_PORT/quic-v1" "--peer" "/ip4/$HOST/udp/$VALIDATOR_PORT/quic-v1" \
  "--observer" "--devnet-contract-fixture" "--devnet-witness" "$WITNESS")
while IFS= read -r account; do ARGS+=("--devnet-account" "$account"); done < <(/usr/bin/python3 -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["wallet_accounts"]))' "$INVITE")
/usr/bin/python3 - "$AGENT" "$INSTALL/noosd" "${ARGS[@]}" <<'PY'
import plistlib,sys
path,program,*args=sys.argv[1:]
value={"Label":"network.mindchain.node","ProgramArguments":[program,*args],"RunAtLoad":True,
       "KeepAlive":{"SuccessfulExit":False},"ThrottleInterval":30,
       "StandardOutPath":str(__import__('pathlib').Path.home()/"Library/Logs/MindChain-node.log"),
       "StandardErrorPath":str(__import__('pathlib').Path.home()/"Library/Logs/MindChain-node-error.log")}
with open(path,"wb") as out: plistlib.dump(value,out)
PY
launchctl bootout "gui/$(id -u)/network.mindchain.node" >/dev/null 2>&1 || true
launchctl bootstrap "gui/$(id -u)" "$AGENT"
MARKET="$(read_json '' '.get("compute_market_url","")')"
[[ -z "$MARKET" ]] || open "$MARKET"
osascript -e 'display dialog "This Mac is now helping MindChain and will reconnect automatically when you sign in." buttons {"OK"} default button "OK" with icon note'
