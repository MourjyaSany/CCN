import { useEffect } from "react";
import { Route, Routes } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import { useLiveFeed } from "@/lib/live";
import { useAuth } from "@/lib/store";
import { Shell } from "@/components/layout/Shell";
import { ErrorBoundary } from "@/components/layout/ErrorBoundary";
import { Card, EmptyState, TooltipProvider } from "@/components/ui";
import { Overview } from "@/pages/Overview";
import { LiveNetwork } from "@/pages/LiveNetwork";
import { Incidents } from "@/pages/Incidents";
import { Alerts } from "@/pages/Alerts";
import { Mitigations } from "@/pages/Mitigations";
import { Research } from "@/pages/Research";
import { Replay } from "@/pages/Replay";
import { AttackBuilder, Experiments, Policy, Topologies } from "@/pages/Configure";
import { Ns3 } from "@/pages/Ns3";
import { About, Login } from "@/pages/About";

function Routed() {
  useLiveFeed();
  return (
    <Shell>
      <ErrorBoundary>
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/network" element={<LiveNetwork />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/mitigations" element={<Mitigations />} />
          <Route path="/experiments" element={<Experiments />} />
          <Route path="/research" element={<Research />} />
          <Route path="/replay" element={<Replay />} />
          <Route path="/ns3" element={<Ns3 />} />
          <Route path="/attack-builder" element={<AttackBuilder />} />
          <Route path="/topologies" element={<Topologies />} />
          <Route path="/policy" element={<Policy />} />
          <Route path="/about" element={<About />} />
          <Route path="*" element={<Card><EmptyState title="Page not found" hint="Use Ctrl K to jump anywhere." /></Card>} />
        </Routes>
      </ErrorBoundary>
    </Shell>
  );
}

export default function App() {
  const { token, required, setRequired } = useAuth();
  // Probe a protected endpoint: 401 means the server enforces authentication.
  const probe = useQuery({ queryKey: ["probe", token], queryFn: api.me, retry: false });
  useEffect(() => {
    if (probe.error instanceof ApiError && probe.error.status === 401) setRequired(true);
    if (probe.data) setRequired(probe.data.auth_enabled && !token ? true : false);
  }, [probe.error, probe.data, token, setRequired]);
  if (required && !token) return <Login />;
  return (
    <TooltipProvider>
      <Routed />
    </TooltipProvider>
  );
}
