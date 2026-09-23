const taskGroups = document.querySelector("#task-groups");
const status = document.querySelector(".status");
let activeFilter = "all";
const search = document.querySelector("#task-search");

function refreshDashboard() {
  const cards = [...taskGroups.querySelectorAll(".task-card")];
  const query = search.value.trim().toLocaleLowerCase();
  let visible = 0;
  document.querySelectorAll("[data-count]").forEach((counter) => {
    counter.textContent = cards.filter((card) => counter.dataset.count === "all" || card.dataset.status === counter.dataset.count).length;
  });
  for (const card of cards) {
    const area = card.closest(".group-section").dataset.groupName;
    card.hidden = !(activeFilter === "all" || card.dataset.status === activeFilter)
      || !`${card.dataset.name} ${area}`.toLocaleLowerCase().includes(query);
    if (!card.hidden) visible++;
  }
  taskGroups.querySelectorAll(".group-section").forEach((section) => {
    const count = section.querySelectorAll(".task-card:not([hidden])").length;
    section.hidden = count === 0;
    section.querySelector(".group-count").textContent = `${count} task${count === 1 ? "" : "s"}`;
  });
  document.querySelector("#result-count").textContent = `${visible} of ${cards.length} tasks`;
  document.querySelector("#no-results").hidden = visible > 0 || cards.length === 0;
  document.querySelectorAll("[data-filter]").forEach((button) => {
    button.setAttribute("aria-pressed", String(button.dataset.filter === activeFilter));
    if (button.dataset.filter === activeFilter) document.querySelector("#view-title").textContent = button.querySelector("span").textContent;
  });
}

function sortTasks(section) {
  const rank = { overdue: 0, due_soon: 1, scheduled: 2, learning: 3, paused: 4 };
  const list = section.querySelector(".task-list");
  [...list.children].sort((a, b) => rank[a.dataset.status] - rank[b.dataset.status]
    || (a.dataset.dueAt || "").localeCompare(b.dataset.dueAt || "")
    || a.dataset.name.localeCompare(b.dataset.name)).forEach((card) => list.append(card));
}

function csrfToken() {
  return document.querySelector('input[name="_csrf_token"]').value;
}

function announce(message, isError = false) {
  status.textContent = message;
  status.classList.toggle("error", isError);
}

function groupOptions(select, selectedId) {
  for (const source of document.querySelector("#new-task-group").options) {
    const option = source.cloneNode(true);
    option.selected = Number(option.value) === Number(selectedId);
    select.append(option);
  }
}

function hiddenToken() {
  const input = document.createElement("input");
  input.type = "hidden";
  input.name = "_csrf_token";
  input.value = csrfToken();
  return input;
}

function numberField(labelText, name, value, min, max, step = "1") {
  const label = document.createElement("label");
  label.textContent = labelText;
  const input = document.createElement("input");
  input.type = "number";
  input.name = name;
  input.min = min;
  input.max = max;
  input.step = step;
  input.value = value ?? "";
  input.placeholder = "Automatic";
  label.append(input);
  return label;
}

function checkboxField(labelText, name, checked) {
  const label = document.createElement("label");
  label.className = "checkbox";
  const input = document.createElement("input");
  input.type = "checkbox";
  input.name = name;
  input.value = "1";
  input.checked = checked;
  label.append(input, labelText);
  return label;
}

function taskSettings(task) {
  const details = document.createElement("details");
  details.className = "task-settings";
  const summary = document.createElement("summary");
  summary.textContent = "Schedule & reminders";
  const form = document.createElement("form");
  form.className = "settings-form";
  form.method = "post";
  form.action = `/tasks/${task.id}/settings`;
  form.dataset.asyncAction = "settings";
  const submit = document.createElement("button");
  submit.type = "submit";
  submit.textContent = "Save settings";
  const help = document.createElement("p");
  help.className = "field-help";
  help.textContent = "Leave the repeat interval empty to use your completion history. A manual interval starts after a completion.";
  form.append(
    hiddenToken(),
    help,
    numberField("Repeat every, in days", "manual_interval_days", task.manual_interval_days, "0.1", "3650", "0.1"),
    numberField("Show as due soon, days before", "due_soon_lead_days", task.due_soon_lead_days, "1", "365"),
    checkboxField("Pause task", "is_paused", task.is_paused),
    checkboxField("Enable reminder emails", "reminders_enabled", task.reminders_enabled),
    submit,
  );
  details.append(summary, form);
  return details;
}

function taskCard(task) {
  const card = document.createElement("li");
  card.className = "task-card";
  card.dataset.taskId = task.id;
  card.dataset.status = task.dashboard_status;
  card.dataset.name = task.name;
  card.dataset.dueAt = task.cadence.due_at || "";
  card.tabIndex = -1;
  const top = document.createElement("div");
  top.className = "task-top";
  const heading = document.createElement("div");
  const name = document.createElement("h3");
  name.textContent = task.name;
  const completed = document.createElement("div");
  completed.className = "task-subtitle";
  completed.textContent = task.completed_ago;
  heading.append(name, completed);
  top.append(heading);
  card.append(top);
  const timing = document.createElement("div");
  timing.className = "task-timing";
  const cadence = document.createElement("p");
  cadence.className = `cadence ${task.dashboard_status}`;
  cadence.textContent = task.due_summary;
  const schedule = document.createElement("span");
  schedule.className = "schedule-summary";
  schedule.textContent = task.schedule_summary;
  timing.append(cadence, schedule);
  card.append(timing);
  const details = document.createElement("details");
  details.className = "task-details";
  const detailsSummary = document.createElement("summary");
  detailsSummary.textContent = "Details";
  const content = document.createElement("div");
  content.className = "detail-content";
  for (const text of [`Last completed: ${task.last_completed_display}`, task.cadence.message || "Complete this task three times to learn its repeat interval."]) {
    const paragraph = document.createElement("p");
    paragraph.className = "meta";
    paragraph.textContent = text;
    content.append(paragraph);
  }

  const actions = document.createElement("div");
  actions.className = "task-actions";
  const completeForm = document.createElement("form");
  completeForm.method = "post";
  completeForm.action = `/tasks/${task.id}/complete`;
  completeForm.dataset.asyncAction = "complete";
  const complete = document.createElement("button");
  complete.type = "submit";
  complete.textContent = "Complete with note";
  const note = document.createElement("input");
  note.type = "text";
  note.name = "note";
  note.maxLength = 500;
  note.placeholder = "What did you do?";
  note.setAttribute("aria-label", `Completion note for ${task.name}`);
  const noteLabel = document.createElement("label");
  noteLabel.textContent = "Completion note";
  noteLabel.append(note);
  completeForm.append(hiddenToken(), noteLabel, complete);
  const quickForm = document.createElement("form");
  quickForm.className = "quick-complete";
  quickForm.method = "post";
  quickForm.action = completeForm.action;
  quickForm.dataset.asyncAction = "complete";
  const quickButton = document.createElement("button");
  quickButton.type = "submit";
  quickButton.textContent = "✓ Complete";
  quickButton.setAttribute("aria-label", `Complete ${task.name}`);
  quickForm.append(hiddenToken(), quickButton);
  card.append(quickForm);
  const moveForm = document.createElement("form");
  moveForm.method = "post";
  moveForm.action = `/tasks/${task.id}/move`;
  moveForm.dataset.asyncAction = "move";
  const move = document.createElement("select");
  move.name = "group_id";
  move.setAttribute("aria-label", `Move ${task.name}`);
  groupOptions(move, task.group_id);
  const moveLabel = document.createElement("label");
  moveLabel.textContent = "Area";
  moveLabel.append(move);
  const moveButton = document.createElement("button");
  moveButton.type = "submit";
  moveButton.textContent = "Move";
  moveForm.append(hiddenToken(), moveLabel, moveButton);
  actions.append(completeForm, moveForm);
  content.append(actions);

  const history = document.createElement("details");
  history.className = "task-history";
  const summary = document.createElement("summary");
  summary.textContent = `History (${task.completion_count})`;
  history.append(summary);
  if (task.completion_history.length) {
    const list = document.createElement("ul");
    list.className = "history-list";
    for (const entry of task.completion_history) {
      const item = document.createElement("li");
      item.textContent = entry.display + (entry.days_since_previous === null ? "" : ` (${entry.days_since_previous} days since previous)`);
      if (entry.note) {
        const note = document.createElement("div");
        note.className = "completion-note";
        note.textContent = entry.note;
        item.append(note);
      }
      list.append(item);
    }
    history.append(list);
  } else {
    const empty = document.createElement("p");
    empty.className = "meta";
    empty.textContent = "No completion history yet.";
    history.append(empty);
  }
  content.append(taskSettings(task), history);
  details.append(detailsSummary, content);
  card.append(details);
  return card;
}

function ensureGroup(group) {
  let section = taskGroups.querySelector(`[data-group-id="${group.id}"]`);
  if (section) return section;
  section = document.createElement("section");
  section.className = "group-section";
  section.dataset.groupId = group.id;
  section.dataset.groupName = group.name;
  const heading = document.createElement("div");
  heading.className = "group-heading";
  const title = document.createElement("h2");
  title.textContent = group.name;
  const count = document.createElement("span");
  count.className = "group-count";
  count.textContent = "0 tasks";
  heading.append(title, count);
  const list = document.createElement("ul");
  list.className = "task-list";
  section.append(heading, list);
  taskGroups.append(section);
  return section;
}

function updateGroupCount(section) {
  const count = section.querySelector(".group-count");
  const total = section.querySelectorAll("[data-task-id]").length;
  count.textContent = `${total} task${total === 1 ? "" : "s"}`;
}

function upsertTask(task) {
  const existing = taskGroups.querySelector(`[data-task-id="${task.id}"]`);
  const previousSection = existing?.closest(".group-section");
  const section = taskGroups.querySelector(`[data-group-id="${task.group_id}"]`) || ensureGroup({ id: task.group_id, name: task.group_name });
  const card = taskCard(task);
  const hadFocus = existing?.contains(document.activeElement);
  for (const selector of [".task-details", ".task-settings", ".task-history"]) {
    if (existing?.querySelector(selector)?.open) card.querySelector(selector).open = true;
  }
  if (existing) existing.replaceWith(card);
  section.querySelector(".task-list").append(card);
  if (previousSection && previousSection !== section) updateGroupCount(previousSection);
  updateGroupCount(section);
  sortTasks(section);
  document.querySelector("#empty-tasks")?.remove();
  refreshDashboard();
  if (hadFocus) {
    if (card.hidden) document.querySelector(`[data-filter="${activeFilter}"]`).focus();
    else card.focus({ preventScroll: true });
  }
}

async function submitAsync(form) {
  const formData = new FormData(form);
  const controls = form.querySelectorAll("button, input, select");
  controls.forEach((control) => (control.disabled = true));
  try {
    const response = await fetch(form.action, { method: "POST", body: formData, headers: { Accept: "application/json" } });
    const contentType = response.headers.get("content-type") || "";
    const result = contentType.includes("application/json") ? await response.json() : {};
    if (!response.ok) throw new Error(result.error || "Could not save your change. Please try again.");
    return result;
  } finally {
    controls.forEach((control) => (control.disabled = false));
  }
}

document.addEventListener("submit", async (event) => {
  const form = event.target.closest("form[data-async-action]");
  if (!form) return;
  event.preventDefault();
  try {
    const result = await submitAsync(form);
    if (form.dataset.asyncAction === "create-group") {
      if (!result.created) return announce("That area already exists.", true);
      ensureGroup(result.group);
      document.querySelectorAll('select[name="group_id"]').forEach((select) => {
        const option = document.createElement("option");
        option.value = result.group.id;
        option.textContent = result.group.name;
        select.append(option);
      });
      form.reset();
      refreshDashboard();
      return announce(`${result.group.name} is ready.`);
    }
    if (form.dataset.asyncAction === "create-task" && !result.created) return announce("That task already exists.", true);
    upsertTask(result.task);
    if (form.dataset.asyncAction === "create-task") form.reset();
    const messages = {
      complete: `${result.task.name} completed.`,
      move: `${result.task.name} moved to ${result.task.group_name}.`,
      settings: `${result.task.name} settings saved.`,
    };
    announce(messages[form.dataset.asyncAction] || `${result.task.name} added.`);
  } catch (error) {
    announce(error.message, true);
  }
});

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-filter]");
  if (button) {
    activeFilter = button.dataset.filter;
    refreshDashboard();
  }
});
search.addEventListener("input", refreshDashboard);
document.querySelector("#clear-filters").addEventListener("click", () => {
  activeFilter = "all";
  search.value = "";
  refreshDashboard();
  search.focus();
});
taskGroups.querySelectorAll(".group-section").forEach(sortTasks);
document.querySelector(".summary-grid").hidden = false;
document.querySelector(".toolbar").hidden = false;
refreshDashboard();
