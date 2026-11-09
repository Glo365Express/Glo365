// GLO 365 - Thailand 2D Game Rules
// Pure game-specific validation only. The shared API remains in thailand/index.js.

function normalize2DSelection(value) {
  const selection = String(value ?? "").trim();
  if (!/^\d{1,2}$/.test(selection)) {
    return { valid: false, selection: null, error: "2D selection must contain one or two digits (00-99)." };
  }
  return { valid: true, selection: selection.padStart(2, "0"), error: null };
}

function is2DGameName(value) {
  const name = String(value ?? "").trim().toLowerCase().replace(/[\s_-]/g, "");
  return name === "2d" || name === "thailand2d";
}

function twoDMatchesResult(selection, result) {
  const normalized = normalize2DSelection(selection);
  if (!normalized.valid || !result) return false;
  const lastTwo = String(result.last_two ?? result.lastTwo ?? "").padStart(2, "0");
  return normalized.selection === lastTwo;
}

module.exports = {
  normalize2DSelection,
  is2DGameName,
  twoDMatchesResult
};
