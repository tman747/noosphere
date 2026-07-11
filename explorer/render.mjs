export const CLAIM_DIMENSIONS = Object.freeze([
  ["Evidence label", "evidence_label"], ["Implementation", "implementation_status"],
  ["Evidence status", "evidence_status"], ["Lifecycle", "lifecycle"],
  ["Result", "result"], ["Enabled", "enabled"],
]);
export function statusView(status) {
  const coordinate = (point) => point ? `${point.height} · ${point.hash.slice(0,10)}…` : "UNKNOWN";
  return Object.freeze({ unsafe:coordinate(status.unsafe_head), justified:coordinate(status.justified), finalized:coordinate(status.finalized) });
}
export function evidenceView(value) {
  return CLAIM_DIMENSIONS.map(([label,key]) => ({ label, key, value:key === "enabled" ? (value[key] === true ? "ENABLED" : "DISABLED") : value[key] }));
}
