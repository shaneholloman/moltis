// ── Logs alert dot ──────────────────────────────────────────
import * as S from "./state.js";
import { sendRpc } from "./helpers.js";

var logsAlertDot = S.$("logsAlertDot");

export function updateLogsAlert() {
  if (S.unseenErrors > 0) {
    logsAlertDot.style.display = "";
    logsAlertDot.style.background = "var(--error)";
  } else if (S.unseenWarns > 0) {
    logsAlertDot.style.display = "";
    logsAlertDot.style.background = "var(--warn)";
  } else {
    logsAlertDot.style.display = "none";
  }
}

export function clearLogsAlert() {
  S.setUnseenErrors(0);
  S.setUnseenWarns(0);
  updateLogsAlert();
  if (S.connected) sendRpc("logs.ack", {});
}
