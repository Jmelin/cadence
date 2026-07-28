const taskGroups = document.querySelector("#task-groups");
const insights = document.querySelector("#insights");
const status = document.querySelector(".status");

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
  summary.textContent = "Cadence settings";
  const form = document.createElement("form");
  form.className = "settings-form";
  form.method = "post";
  form.action = `/tasks/${task.id}/settings`;
  form.dataset.asyncAction = "settings";
  const submit = document.createElement("button");
  submit.type = "submit";
  submit.textContent = "Save settings";
  form.append(
    hiddenToken(),
    numberField("Manual cadence, days", "manual_interval_days", task.manual_interval_days, "0.1", "3650", "0.1"),
    numberField("Due-soon lead, days", "due_soon_lead_days", task.due_soon_lead_days, "1", "365"),
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
  card.tabIndex = -1;
  const top = document.createElement("div");
  top.className = "task-top";
  const heading = document.createElement("div");
  const name = document.createElement("h3");
  name.textContent = task.name;
  const completed = document.createElement("div");
  completed.className = "task-subtitle";
  completed.textContent = `Last completed: ${task.last_completed_display}`;
  heading.append(name, completed);
  top.append(heading);
  card.append(top);
  if (task.cadence.message) {
    const cadence = document.createElement("p");
    cadence.className = `cadence${task.cadence.status ? ` ${task.cadence.status}` : ""}`;
    cadence.textContent = task.cadence.message;
    card.append(cadence);
  }

  const actions = document.createElement("div");
  actions.className = "task-actions";
  const completeForm = document.createElement("form");
  completeForm.method = "post";
  completeForm.action = `/tasks/${task.id}/complete`;
  completeForm.dataset.asyncAction = "complete";
  const complete = document.createElement("button");
  complete.className = "primary";
  complete.type = "submit";
  complete.textContent = "Complete";
  completeForm.append(hiddenToken(), complete);
  const moveForm = document.createElement("form");
  moveForm.method = "post";
  moveForm.action = `/tasks/${task.id}/move`;
  moveForm.dataset.asyncAction = "move";
  const move = document.createElement("select");
  move.name = "group_id";
  move.setAttribute("aria-label", `Move ${task.name}`);
  groupOptions(move, task.group_id);
  moveForm.append(hiddenToken(), move);
  actions.append(completeForm, moveForm);
  card.append(actions);

  const history = document.createElement("details");
  const summary = document.createElement("summary");
  summary.textContent = `History (${task.completion_count})`;
  history.append(summary);
  if (task.completion_history.length) {
    const list = document.createElement("ul");
    list.className = "history-list";
    for (const entry of task.completion_history) {
      const item = document.createElement("li");
      item.textContent = entry.display + (entry.days_since_previous === null ? "" : ` (${entry.days_since_previous} days since previous)`);
      list.append(item);
    }
    history.append(list);
  } else {
    const empty = document.createElement("p");
    empty.className = "meta";
    empty.textContent = "No completion history yet.";
    history.append(empty);
  }
  card.append(history, taskSettings(task));
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

function insightList(kind) {
  let section = insights.querySelector(`[data-insight-status="${kind}"]`);
  if (section) return section.querySelector(".insight-list");
  section = document.createElement("section");
  section.className = `insight-section ${kind}`;
  section.dataset.insightStatus = kind;
  const title = document.createElement("h2");
  title.textContent = kind === "overdue" ? "Overdue" : "Due soon";
  const list = document.createElement("ul");
  list.className = "insight-list";
  section.append(title, list);
  insights.append(section);
  return list;
}

function updateAlert(task) {
  insights.querySelectorAll(`[data-alert-task-id="${task.id}"]`).forEach((item) => item.remove());
  insights.querySelectorAll(".insight-section").forEach((section) => {
    if (!section.querySelector(".insight-list").children.length) section.remove();
  });
  if (!task.cadence.status) return;
  const item = document.createElement("li");
  item.dataset.alertTaskId = task.id;
  const button = document.createElement("button");
  button.className = "insight-task";
  button.type = "button";
  button.dataset.focusTaskId = task.id;
  button.textContent = task.name;
  const detail = document.createElement("div");
  detail.className = "meta";
  detail.textContent = task.cadence.message;
  item.append(button, detail);
  insightList(task.cadence.status).append(item);
}

function upsertTask(task) {
  const existing = taskGroups.querySelector(`[data-task-id="${task.id}"]`);
  const previousSection = existing?.closest(".group-section");
  const section = taskGroups.querySelector(`[data-group-id="${task.group_id}"]`) || ensureGroup({ id: task.group_id, name: task.group_name });
  const card = taskCard(task);
  if (existing) existing.replaceWith(card);
  section.querySelector(".task-list").append(card);
  if (previousSection && previousSection !== section) updateGroupCount(previousSection);
  updateGroupCount(section);
  updateAlert(task);
  document.querySelector("#empty-tasks")?.remove();
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

document.addEventListener("change", (event) => {
  if (event.target.matches('form[data-async-action="move"] select')) event.target.form.requestSubmit();
});

document.addEventListener("click", (event) => {
  const button = event.target.closest("[data-focus-task-id]");
  if (!button) return;
  const card = taskGroups.querySelector(`[data-task-id="${button.dataset.focusTaskId}"]`);
  card?.scrollIntoView({ behavior: "smooth", block: "center" });
  card?.focus({ preventScroll: true });
});
