/**
 * Region exhibits are content-addressed: the region's own SHA-256 is its
 * identity, so re-analysing a PID (which overwrites that process's artifacts in
 * place) can never silently rebind a pin to a different region.
 *
 * Scored objects deliberately have no helper here. Their ref folds in a digest
 * of the label, and duplicating that hashing in the browser would create two
 * definitions that can drift apart — a pin that binds to nothing, or worse, to
 * the wrong finding. The backend computes it once and the store looks it up
 * from the assembled document.
 */
export function regionRef(pid: number, sha256: string): string {
  return `${pid}|${sha256}`;
}
