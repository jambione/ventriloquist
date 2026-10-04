// Peer-provided strings (phone names, error messages, device names) may
// contain bidirectional controls (e.g. U+202E) that reorder the UI text
// around them. Two defences, both applied wherever a peer string is put
// into a sentence: strip the raw controls, then wrap the string in an
// isolate (FSI … PDI) so that nothing inside can affect what is outside.

const BIDI_CONTROLS = /[‪-‮⁦-⁩‎‏؜]/g;
const FSI = "⁨";
const PDI = "⁩";

/** Remove embedding/override/isolate controls and the directional marks. */
export function stripBidi(s: string): string {
  return s.replace(BIDI_CONTROLS, "");
}

/** Stripped, and wrapped in FSI…PDI for embedding in a sentence. */
export function isolate(s: string): string {
  return `${FSI}${stripBidi(s)}${PDI}`;
}

/** At most `max` code points (a surrogate pair is never split), with "…". */
export function clip(s: string, max: number): string {
  const chars = Array.from(s);
  return chars.length <= max ? s : chars.slice(0, max).join("") + "…";
}
