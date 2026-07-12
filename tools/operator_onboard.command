#!/bin/zsh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
INVITE="$ROOT/invite.json"
NODE="$ROOT/noosd"
PARAMS="$ROOT/devnet-parameters.toml"
DASHBOARD="$ROOT/node_status_dashboard.py"
if [[ ! -f "$INVITE" || ! -x "$NODE" || ! -f "$PARAMS" || ! -f "$DASHBOARD" ]]; then
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
STATUS_AGENT="$HOME/Library/LaunchAgents/network.mindchain.status.plist"
STATUS_CONFIG="$INSTALL/status-config.json"
mkdir -p "$INSTALL" "$DATA" "$(dirname "$AGENT")"
cp "$NODE" "$INSTALL/noosd"
cp "$DASHBOARD" "$INSTALL/node_status_dashboard.py"
cp "$PARAMS" "$INSTALL/devnet-parameters.toml"
cp "$INVITE" "$INSTALL/invite.json"
chmod 700 "$INSTALL/noosd" "$INSTALL/node_status_dashboard.py"

GENESIS="$(read_json '' '["genesis_time_ms"]')"
HOST="$(read_json '' '["validator_host"]')"
VALIDATOR_PORT="$(read_json '' '["validator_p2p_port"]')"
LOCAL_PORT="$(read_json '' '["local_p2p_port"]')"
WITNESS="$(read_json '' '["witness_index"]')"
RPC_TOKEN="$(/usr/bin/python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
ARGS=("--params" "$INSTALL/devnet-parameters.toml" "--data-dir" "$DATA" "--genesis-time" "$GENESIS" \
  "--p2p-listen" "/ip4/0.0.0.0/udp/$LOCAL_PORT/quic-v1" "--peer" "/ip4/$HOST/udp/$VALIDATOR_PORT/quic-v1" \
  "--rpc" "127.0.0.1:19632" "--rpc-token" "$RPC_TOKEN" \
  "--observer" "--devnet-contract-fixture" "--devnet-witness" "$WITNESS")
while IFS= read -r account; do ARGS+=("--devnet-account" "$account"); done < <(/usr/bin/python3 -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["wallet_accounts"]))' "$INVITE")
/usr/bin/python3 - "$AGENT" "$STATUS_AGENT" "$STATUS_CONFIG" "$INSTALL/noosd" "$INSTALL/node_status_dashboard.py" "$INSTALL/invite.json" "$RPC_TOKEN" "${ARGS[@]}" <<'PY'
import json,os,plistlib,sys
node_agent,status_agent,status_config,node_program,status_program,invite,rpc_token,*args=sys.argv[1:]
home=__import__('pathlib').Path.home()
node={"Label":"network.mindchain.node","ProgramArguments":[node_program,*args],"RunAtLoad":True,
      "KeepAlive":{"SuccessfulExit":False},"ThrottleInterval":30,
      "StandardOutPath":str(home/"Library/Logs/MindChain-node.log"),
      "StandardErrorPath":str(home/"Library/Logs/MindChain-node-error.log")}
status={"Label":"network.mindchain.status",
        "ProgramArguments":["/usr/bin/python3",status_program,"--config",status_config,"--listen","127.0.0.1:19440"],
        "RunAtLoad":True,"KeepAlive":{"SuccessfulExit":False},"ThrottleInterval":30,
        "StandardOutPath":str(home/"Library/Logs/MindChain-status.log"),
        "StandardErrorPath":str(home/"Library/Logs/MindChain-status-error.log")}
config={"schema":"noos/node-status-dashboard-config/v1","rpc_status_url":"http://127.0.0.1:19632/status",
        "rpc_token":rpc_token,"invite_path":invite}
with open(node_agent,"wb") as out: plistlib.dump(node,out)
with open(status_agent,"wb") as out: plistlib.dump(status,out)
with open(status_config,"w",encoding="utf-8") as out: json.dump(config,out,indent=2); out.write("\n")
os.chmod(status_config,0o600)
PY
launchctl bootout "gui/$(id -u)/network.mindchain.status" >/dev/null 2>&1 || true
launchctl bootout "gui/$(id -u)/network.mindchain.node" >/dev/null 2>&1 || true
launchctl bootstrap "gui/$(id -u)" "$AGENT"
launchctl bootstrap "gui/$(id -u)" "$STATUS_AGENT"
open "http://127.0.0.1:19440"
osascript -e 'display dialog "This Mac is now helping MindChain. The Node Status window shows live health, capacity, and capabilities, and the node will reconnect automatically when you sign in." buttons {"OK"} default button "OK" with icon note'
