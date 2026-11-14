import { useSyncExternalStore } from "react";
import type { TimeZoneSetting } from "./types";

const STORAGE_KEY = "simple-siem.time-zone";
const subscribers = new Set<() => void>();
let current: TimeZoneSetting | undefined;
let listening = false;

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
  notifySubscribers();
}

export function useTimeZone(): TimeZoneSetting {
  return useSyncExternalStore(subscribe, getSnapshot);
}

function subscribe(notify: () => void): () => void {
  if (!listening) {
    window.addEventListener("storage", handleStorage);
    listening = true;
  }
  subscribers.add(notify);
  return () => {
    subscribers.delete(notify);
  };
}

function handleStorage(event: StorageEvent): void {
  if (event.key !== STORAGE_KEY && event.key !== null) {
    return;
  }
  current = readTimeZone();
  notifySubscribers();
}

function notifySubscribers(): void {
  for (const notify of subscribers) {
    notify();
  }
}

function getSnapshot(): TimeZoneSetting {
  if (current === undefined) {
    current = readTimeZone();
  }
  return current;
}
