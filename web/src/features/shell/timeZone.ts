import { useSyncExternalStore } from "react";
import type { TimeZoneSetting } from "../cases/timeRange";

const STORAGE_KEY = "simple-siem.time-zone";
const subscribers = new Set<() => void>();
let current: TimeZoneSetting | undefined;

export function readTimeZone(): TimeZoneSetting {
  try {
    return window.localStorage.getItem(STORAGE_KEY) === "utc"
      ? "utc"
      : "local";
  } catch {
    return "local";
  }
}

export function writeTimeZone(setting: TimeZoneSetting): void {
  current = setting;
  try {
    window.localStorage.setItem(STORAGE_KEY, setting);
  } catch {
    // Storage can be unavailable; the setting still applies for this page.
  }
  for (const notify of subscribers) {
    notify();
  }
}

export function useTimeZone(): TimeZoneSetting {
  return useSyncExternalStore(subscribe, getSnapshot);
}

function subscribe(notify: () => void): () => void {
  subscribers.add(notify);
  return () => {
    subscribers.delete(notify);
  };
}

function getSnapshot(): TimeZoneSetting {
  if (current === undefined) {
    current = readTimeZone();
  }
  return current;
}
