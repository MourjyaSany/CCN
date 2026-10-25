import { useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "./api";
import { useAuth, useUI } from "./store";
import type { LiveSnapshot } from "./types";

/**
 * Keep the live snapshot in the store: WebSocket push first, HTTP polling as a
 * fallback (proxies that block upgrades, or the server restarting).
 */
export function useLiveFeed() {
  const token = useAuth((s) => s.token);
  const setLive = useUI((s) => s.setLive);
  const setTransport = useUI((s) => s.setTransport);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let poll: number | undefined;
    let retry: number | undefined;
    let closed = false;

    const startPolling = () => {
      if (poll) return;
      setTransport("polling");
      const tick = async () => {
        try {
          const s = (await api.status()) as unknown as LiveSnapshot;
          setLive({ ...useUI.getState().live, ...s } as LiveSnapshot);
        } catch {
          setTransport("offline");
        }
      };
      tick();
      poll = window.setInterval(tick, 1500);
    };

    const connect = () => {
      const proto = location.protocol === "https:" ? "wss" : "ws";
      const qs = new URLSearchParams({ interval_s: "1" });
      if (token) qs.set("token", token);
      try {
        ws = new WebSocket(`${proto}://${location.host}/ws/live?${qs}`);
      } catch {
        startPolling();
        return;
      }
      ws.onopen = () => {
        if (poll) {
          clearInterval(poll);
          poll = undefined;
        }
        setTransport("websocket");
      };
      ws.onmessage = (e) => setLive(JSON.parse(e.data));
      ws.onclose = () => {
        if (closed) return;
        startPolling();
        retry = window.setTimeout(connect, 5000);
      };
    };
    connect();
    return () => {
      closed = true;
      ws?.close();
      if (poll) clearInterval(poll);
      if (retry) clearTimeout(retry);
    };
  }, [token, setLive, setTransport]);
}

/** Poll an endpoint quickly while a simulation runs, slowly otherwise. */
export function useLiveQuery<T>(key: string, fn: () => Promise<T>, fastMs = 2000) {
  const running = useUI((s) => s.live?.state === "running");
  return useQuery({ queryKey: [key], queryFn: fn, refetchInterval: running ? fastMs : 15000 });
}
