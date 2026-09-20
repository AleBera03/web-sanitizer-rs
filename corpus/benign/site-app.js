const collapsed = new WeakSet();

export function toggle(section) {
  if (collapsed.has(section)) {
    collapsed.delete(section);
    section.removeAttribute("hidden");
    return true;
  }
  collapsed.add(section);
  section.setAttribute("hidden", "");
  return false;
}

export function summarise(items) {
  return items.reduce((total, item) => total + Number(item.weight || 0), 0);
}

export const version = "1.4.0";
