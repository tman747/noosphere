"""Generate Prometheus rule and Grafana dashboard payloads from telemetry-v1."""
import json
from pathlib import Path

def generate(schema_path: Path, output: Path) -> None:
    schema=json.loads(schema_path.read_text("utf-8")); output.mkdir(parents=True,exist_ok=True)
    groups=[]
    for metric in schema["metrics"]:
        rules=[{"record":metric["recording_rule"],"expr":metric["recording_expression"]}]
        rules.append({"alert":metric["alert"],"expr":metric["alert_expression"],"for":metric["for"],"labels":{"severity":metric["severity"]},"annotations":{"summary":metric["help"],"unknown":"UNKNOWN blocks every release gate dependency"}})
        groups.append({"name":metric["name"],"interval":f'{metric["scrape_interval_seconds"]}s',"rules":rules})
    (output/"prometheus-rules.json").write_text(json.dumps({"groups":groups},sort_keys=True,indent=2),"utf-8")
    dashboards=[]
    for title in schema["dashboards"]:
        metrics=[m for m in schema["metrics"] if m["dashboard"]==title]
        dashboards.append({"title":title,"uid":"noos-"+title.lower().replace(" ","-"),"panels":[{"title":m["help"],"expr":m["recording_rule"],"unknown":"UNKNOWN"} for m in metrics]})
    (output/"grafana-dashboards.json").write_text(json.dumps(dashboards,sort_keys=True,indent=2),"utf-8")

if __name__=="__main__": generate(Path("../protocol/telemetry/telemetry-v1.yaml"),Path("monitoring/generated"))
