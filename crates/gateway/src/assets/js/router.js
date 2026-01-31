// ── Router ──────────────────────────────────────────────────
import * as S from "./state.js";
import { clearLogsAlert } from "./logs-alert.js";

var pages = {};
export var currentPage = null;
var pageContent = S.$("pageContent");
var sessionsPanel = S.$("sessionsPanel");

export function registerPage(path, init, teardown) {
  pages[path] = { init: init, teardown: teardown || function () {} };
}

export function navigate(path) {
  if (path === currentPage) return;
  history.pushState(null, "", path);
  mount(path);
}

export function mount(path) {
  if (currentPage && pages[currentPage]) {
    pages[currentPage].teardown();
  }
  pageContent.textContent = "";

  var page = pages[path] || pages["/"];
  currentPage = pages[path] ? path : "/";

  var links = document.querySelectorAll(".nav-link");
  links.forEach(function (a) {
    a.classList.toggle("active", a.getAttribute("href") === currentPage);
  });

  // Show sessions panel only on the chat page
  if (currentPage === "/") {
    sessionsPanel.classList.remove("hidden");
  } else {
    sessionsPanel.classList.add("hidden");
  }

  // Clear unseen logs alert when viewing the logs page
  if (currentPage === "/logs") clearLogsAlert();

  if (page) page.init(pageContent);
}

window.addEventListener("popstate", function () {
  mount(location.pathname);
});

// ── Nav panel (burger toggle) ────────────────────────────────
var burgerBtn = S.$("burgerBtn");
var navPanel = S.$("navPanel");

burgerBtn.addEventListener("click", function () {
  navPanel.classList.toggle("hidden");
});

navPanel.addEventListener("click", function (e) {
  var link = e.target.closest("[data-nav]");
  if (!link) return;
  e.preventDefault();
  navigate(link.getAttribute("href"));
});
