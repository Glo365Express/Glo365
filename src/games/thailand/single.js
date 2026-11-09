// GLO 365 - Thailand Single Game Rules
// Pure game-specific validation only. The shared API remains in thailand/index.js.

const SINGLE_GAME_NAMES = new Set(["single", "thailand single"]);

function normalizeSingleSelection(value) {
  const selection = String(value ?? "").trim();
  if (!/^\d$/.test(selection)) {
    return { valid: false, selection: null, error: "Single selection must be exactly one digit (0-9)." };
  }
  return { valid: true, selection, error: null };
}

function isSingleGameName(value) {
  const name = String(value ?? "").trim().toLowerCase();
  return SINGLE_GAME_NAMES.has(name);
}

function singleMatchesResult(selection, result) {
  const normalized = normalizeSingleSelection(selection);
  if (!normalized.valid || !result) return false;
  const firstPrize = String(result.first_prize ?? result.firstPrize ?? "").padStart(6, "0");
  return normalized.selection === firstPrize.slice(-1);
}

module.exports = {
  SINGLE_GAME_NAMES,
  normalizeSingleSelection,
  isSingleGameName,
  singleMatchesResult
};
