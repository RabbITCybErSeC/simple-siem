import { defaultCaseQueueState } from "../urlState";
import { parseOffset, resolveRange, toSecondIso } from "../timeRange";

const ANCHORED_EXPRESSIONS = new Set(["now", "now/d", "now/w"]);

export function absoluteLink(
  location: { origin: string; pathname: string; search: string },
  now: Date,
): string {
  const parameters = new URLSearchParams(location.search);
  const from = parameters.get("from") ?? defaultCaseQueueState.range.from;
  const to = parameters.get("to") ?? defaultCaseQueueState.range.to;
  // An invalid range shows the default in the queue, so freeze that instead.
  const resolved =
    resolveRange({ from, to }, now) ??
    resolveRange(defaultCaseQueueState.range, now);
  if (resolved === undefined) {
    return `${location.origin}${location.pathname}${location.search}`;
  }

  freezeExpression(parameters, "from", from, resolved.from);
  freezeExpression(parameters, "to", to, resolved.to);

  const query = parameters.toString().replaceAll("%3A", ":");
  return `${location.origin}${location.pathname}${query === "" ? "" : `?${query}`}`;
}

export async function copyText(text: string): Promise<boolean> {
  const clipboard: Clipboard | undefined = navigator.clipboard;
  if (clipboard === undefined) {
    return false;
  }

  try {
    await clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

function freezeExpression(
  parameters: URLSearchParams,
  name: string,
  value: string,
  resolved: Date,
) {
  if (ANCHORED_EXPRESSIONS.has(value) || parseOffset(value) !== undefined) {
    parameters.set(name, toSecondIso(resolved));
  }
}
