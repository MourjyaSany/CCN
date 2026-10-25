import { create } from "zustand";
import type { LiveSnapshot } from "./types";

const read = (k: string) => {
  try {
    return localStorage.getItem(k);
  } catch {
    return null;
  }
};
const write = (k: string, v: string | null) => {
  try {
    if (v === null) localStorage.removeItem(k);
    else localStorage.setItem(k, v);
  } catch {
    /* storage blocked: keep in memory only */
  }
};

interface AuthState {
  token: string | null;
  user: string | null;
  role: string | null;
  required: boolean;
  setSession: (token: string, user: string, role: string) => void;
  setRequired: (r: boolean) => void;
  expire: () => void;
}

export const useAuth = create<AuthState>((set) => ({
  token: read("ns-token"),
  user: read("ns-user"),
  role: read("ns-role"),
  required: false,
  setSession: (token, user, role) => {
    write("ns-token", token);
    write("ns-user", user);
    write("ns-role", role);
    set({ token, user, role });
  },
  setRequired: (required) => set({ required }),
  expire: () => {
    write("ns-token", null);
    set({ token: null });
  },
}));

export const can = (role: string | null, need: "viewer" | "operator" | "admin") => {
  const order = ["viewer", "operator", "admin"];
  return order.indexOf(role ?? "admin") >= order.indexOf(need);
};

interface UIState {
  dark: boolean;
  toggleTheme: () => void;
  paletteOpen: boolean;
  setPalette: (o: boolean) => void;
  selectedNode: string | null;
  selectNode: (n: string | null) => void;
  live: LiveSnapshot | null;
  setLive: (s: LiveSnapshot) => void;
  liveTransport: "websocket" | "polling" | "offline";
  setTransport: (t: UIState["liveTransport"]) => void;
}

export const useUI = create<UIState>((set, get) => ({
  dark: document.documentElement.classList.contains("dark"),
  toggleTheme: () => {
    const dark = !get().dark;
    document.documentElement.classList.toggle("dark", dark);
    write("ns-theme", dark ? "dark" : "light");
    set({ dark });
  },
  paletteOpen: false,
  setPalette: (paletteOpen) => set({ paletteOpen }),
  selectedNode: null,
  selectNode: (selectedNode) => set({ selectedNode }),
  live: null,
  setLive: (live) => set({ live }),
  liveTransport: "offline",
  setTransport: (liveTransport) => set({ liveTransport }),
}));
