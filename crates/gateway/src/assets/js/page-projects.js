// ── Projects page ────────────────────────────────────────
import * as S from "./state.js";
import { sendRpc, createEl } from "./helpers.js";
import { registerPage } from "./router.js";
import { fetchProjects } from "./projects.js";

registerPage("/projects", function initProjects(container) {
  var wrapper = createEl("div", { className: "flex-1 flex flex-col min-w-0 p-4 gap-4 overflow-y-auto" });

  var header = createEl("div", { className: "flex items-center gap-3" }, [
    createEl("h2", { className: "text-lg font-medium text-[var(--text-strong)]", textContent: "Projects" })
  ]);

  var detectBtn = createEl("button", {
    className: "text-xs text-[var(--muted)] border border-[var(--border)] px-2.5 py-1 rounded-md hover:text-[var(--text)] hover:border-[var(--border-strong)] transition-colors cursor-pointer bg-transparent",
    textContent: "Auto-detect"
  });
  header.appendChild(detectBtn);
  wrapper.appendChild(header);

  var formRow = createEl("div", { className: "flex items-end gap-3 max-w-card" });
  var dirGroup = createEl("div", { className: "flex-1 pos-relative" });
  var dirLabel = createEl("div", { className: "text-xs text-[var(--muted)] mb-xs", textContent: "Directory" });
  dirGroup.appendChild(dirLabel);
  var dirInput = createEl("input", {
    type: "text",
    className: "provider-key-input mono full-width",
    placeholder: "/path/to/project"
  });
  dirGroup.appendChild(dirInput);

  var completionList = createEl("div", { className: "completion-dropdown" });
  dirGroup.appendChild(completionList);
  formRow.appendChild(dirGroup);

  var addBtn = createEl("button", {
    className: "bg-[var(--accent-dim)] text-white border-none px-3 py-1.5 rounded text-xs cursor-pointer hover:bg-[var(--accent)] transition-colors",
    textContent: "Add",
    className: "bg-[var(--accent-dim)] text-white border-none px-3 py-1.5 rounded text-xs cursor-pointer hover:bg-[var(--accent)] transition-colors btn-h-fixed"
  });
  formRow.appendChild(addBtn);
  wrapper.appendChild(formRow);

  var listEl = createEl("div", { className: "max-w-card mt-md" });
  wrapper.appendChild(listEl);
  container.appendChild(wrapper);

  var completeTimer = null;
  dirInput.addEventListener("input", function () {
    clearTimeout(completeTimer);
    completeTimer = setTimeout(function () {
      var val = dirInput.value;
      if (val.length < 2) { completionList.classList.remove("visible"); return; }
      sendRpc("projects.complete_path", { partial: val }).then(function (res) {
        if (!res || !res.ok) { completionList.classList.remove("visible"); return; }
        var paths = res.payload || [];
        while (completionList.firstChild) completionList.removeChild(completionList.firstChild);
        if (paths.length === 0) { completionList.classList.remove("visible"); return; }
        paths.forEach(function (p) {
          var item = createEl("div", {
            textContent: p,
            className: "completion-item"
          });
          item.addEventListener("click", function () {
            dirInput.value = p + "/";
            completionList.classList.remove("visible");
            dirInput.focus();
            dirInput.dispatchEvent(new Event("input"));
          });
          completionList.appendChild(item);
        });
        completionList.classList.add("visible");
      });
    }, 200);
  });

  function renderList() {
    while (listEl.firstChild) listEl.removeChild(listEl.firstChild);
    if (S.projects.length === 0) {
      listEl.appendChild(createEl("div", {
        className: "text-xs text-[var(--muted)]",
        textContent: "No projects configured. Add a directory above or use auto-detect.",
        className: "text-xs text-[var(--muted)] py-sm"
      }));
      return;
    }
    S.projects.forEach(function (p) {
      var card = createEl("div", {
        className: "provider-item mb-sm"
      });

      var info = createEl("div", { className: "project-info" });
      var nameRow = createEl("div", { className: "flex items-center gap-2" });
      nameRow.appendChild(createEl("div", { className: "provider-item-name", textContent: p.label || p.id }));
      if (p.detected) {
        nameRow.appendChild(createEl("span", { className: "provider-item-badge api-key", textContent: "auto" }));
      }
      if (p.auto_worktree) {
        nameRow.appendChild(createEl("span", { className: "provider-item-badge oauth", textContent: "worktree" }));
      }
      info.appendChild(nameRow);

      info.appendChild(createEl("div", {
        textContent: p.directory,
        className: "project-dir-sm"
      }));

      if (p.system_prompt) {
        info.appendChild(createEl("div", {
          textContent: "System prompt: " + p.system_prompt.substring(0, 80) + (p.system_prompt.length > 80 ? "..." : ""),
          className: "project-prompt-preview"
        }));
      }

      card.appendChild(info);

      var actions = createEl("div", { className: "actions-row" });

      var editBtn = createEl("button", {
        className: "session-action-btn",
        textContent: "edit",
        title: "Edit project"
      });
      editBtn.addEventListener("click", function (e) {
        e.stopPropagation();
        showEditForm(p, card);
      });
      actions.appendChild(editBtn);

      var delBtn = createEl("button", {
        className: "session-action-btn session-delete",
        textContent: "x",
        title: "Remove project"
      });
      delBtn.addEventListener("click", function (e) {
        e.stopPropagation();
        sendRpc("projects.delete", { id: p.id }).then(function () {
          fetchProjects();
          setTimeout(renderList, 200);
        });
      });
      actions.appendChild(delBtn);

      card.appendChild(actions);
      listEl.appendChild(card);
    });
  }

  function showEditForm(p, cardEl) {
    var form = createEl("div", { className: "edit-form" });

    function labeledInput(labelText, value, placeholder, mono) {
      var group = createEl("div", { className: "edit-form-group" });
      group.appendChild(createEl("div", {
        className: "text-xs text-[var(--muted)] edit-form-label",
        textContent: labelText
      }));
      var input = createEl("input", {
        type: "text",
        className: "provider-key-input full-width" + (mono ? " mono" : ""),
        value: value || "",
        placeholder: placeholder || ""
      });
      group.appendChild(input);
      return { group: group, input: input };
    }

    var labelField = labeledInput("Label", p.label, "Project name");
    form.appendChild(labelField.group);

    var dirField = labeledInput("Directory", p.directory, "/path/to/project", true);
    form.appendChild(dirField.group);

    var promptGroup = createEl("div", { className: "edit-form-group" });
    promptGroup.appendChild(createEl("div", {
      className: "text-xs text-[var(--muted)] edit-form-label",
      textContent: "System prompt (optional)"
    }));
    var promptInput = createEl("textarea", {
      className: "provider-key-input full-width textarea-prompt",
      placeholder: "Extra instructions for the LLM when working on this project..."
    });
    promptInput.value = p.system_prompt || "";
    promptGroup.appendChild(promptInput);
    form.appendChild(promptGroup);

    var setupField = labeledInput("Setup command", p.setup_command, "e.g. pnpm install", true);
    form.appendChild(setupField.group);

    var wtGroup = createEl("div", { className: "edit-form-group-lg flex items-center gap-2" });
    var wtCheckbox = createEl("input", { type: "checkbox" });
    wtCheckbox.checked = p.auto_worktree;
    wtGroup.appendChild(wtCheckbox);
    wtGroup.appendChild(createEl("span", {
      className: "text-xs text-[var(--text)]",
      textContent: "Auto-create git worktree per session"
    }));
    form.appendChild(wtGroup);

    var btnRow = createEl("div", { className: "btn-row" });
    var saveBtn = createEl("button", { className: "provider-btn", textContent: "Save" });
    var cancelBtn = createEl("button", { className: "provider-btn provider-btn-secondary", textContent: "Cancel" });

    saveBtn.addEventListener("click", function () {
      var updated = JSON.parse(JSON.stringify(p));
      updated.label = labelField.input.value.trim() || p.label;
      updated.directory = dirField.input.value.trim() || p.directory;
      updated.system_prompt = promptInput.value.trim() || null;
      updated.setup_command = setupField.input.value.trim() || null;
      updated.auto_worktree = wtCheckbox.checked;
      updated.updated_at = Date.now();

      sendRpc("projects.upsert", updated).then(function () {
        fetchProjects();
        setTimeout(renderList, 200);
      });
    });

    cancelBtn.addEventListener("click", function () {
      listEl.replaceChild(cardEl, form);
    });

    btnRow.appendChild(saveBtn);
    btnRow.appendChild(cancelBtn);
    form.appendChild(btnRow);

    listEl.replaceChild(form, cardEl);
  }

  addBtn.addEventListener("click", function () {
    var dir = dirInput.value.trim();
    if (!dir) return;
    addBtn.disabled = true;
    sendRpc("projects.detect", { directories: [dir] }).then(function (res) {
      addBtn.disabled = false;
      if (res && res.ok) {
        var detected = res.payload || [];
        if (detected.length === 0) {
          var slug = dir.split("/").filter(Boolean).pop() || "project";
          var now = Date.now();
          sendRpc("projects.upsert", {
            id: slug.toLowerCase().replace(/[^a-z0-9-]/g, "-"),
            label: slug,
            directory: dir,
            auto_worktree: false,
            detected: false,
            created_at: now,
            updated_at: now
          }).then(function () {
            dirInput.value = "";
            fetchProjects();
            setTimeout(renderList, 200);
          });
        } else {
          dirInput.value = "";
          fetchProjects();
          setTimeout(renderList, 200);
        }
      }
    });
  });

  detectBtn.addEventListener("click", function () {
    detectBtn.disabled = true;
    detectBtn.textContent = "Detecting...";
    sendRpc("projects.detect", { directories: [] }).then(function () {
      detectBtn.disabled = false;
      detectBtn.textContent = "Auto-detect";
      fetchProjects();
      setTimeout(renderList, 200);
    });
  });

  renderList();
});
