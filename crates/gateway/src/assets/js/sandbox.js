// ── Sandbox toggle ──────────────────────────────────────────
import * as S from "./state.js";
import { sendRpc } from "./helpers.js";

export function updateSandboxUI(enabled) {
  S.setSessionSandboxEnabled(!!enabled);
  if (!S.sandboxLabel || !S.sandboxToggleBtn) return;
  if (S.sessionSandboxEnabled) {
    S.sandboxLabel.textContent = "sandboxed";
    S.sandboxToggleBtn.style.borderColor = "var(--accent, #f59e0b)";
    S.sandboxToggleBtn.style.color = "var(--accent, #f59e0b)";
  } else {
    S.sandboxLabel.textContent = "direct";
    S.sandboxToggleBtn.style.borderColor = "";
    S.sandboxToggleBtn.style.color = "var(--muted)";
  }
}

export function bindSandboxToggleEvents() {
  if (!S.sandboxToggleBtn) return;
  S.sandboxToggleBtn.addEventListener("click", function () {
    var newVal = !S.sessionSandboxEnabled;
    sendRpc("sessions.patch", { key: S.activeSessionKey, sandbox_enabled: newVal }).then(function (res) {
      if (res && res.result) {
        updateSandboxUI(res.result.sandbox_enabled);
      } else {
        updateSandboxUI(newVal);
      }
    });
  });
}
