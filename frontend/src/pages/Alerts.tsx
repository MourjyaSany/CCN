import { useMemo, useState } from "react";
import {
  createColumnHelper, flexRender, getCoreRowModel, getFilteredRowModel, getPaginationRowModel,
  getSortedRowModel, useReactTable, type SortingState,
} from "@tanstack/react-table";
import { ArrowUpDown, Check, Download, ShieldAlert } from "lucide-react";
import { api } from "@/lib/api";
import { useLiveQuery } from "@/lib/live";
import type { Alert } from "@/lib/types";
import { fmt, label } from "@/lib/utils";
import { Badge, Button, Card, DataTable, EmptyState, Input, PageHeader, Select, SeverityBadge } from "@/components/ui";

const col = createColumnHelper<Alert & { key: string }>();

function download(name: string, body: string, type: string) {
  const url = URL.createObjectURL(new Blob([body], { type }));
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  a.click();
  URL.revokeObjectURL(url);
}

export function Alerts() {
  const q = useLiveQuery("alerts", () => api.alerts(1000));
  const [sorting, setSorting] = useState<SortingState>([{ id: "timestamp", desc: true }]);
  const [filter, setFilter] = useState("");
  const [sev, setSev] = useState("all");
  const [acked, setAcked] = useState<Set<string>>(new Set());
  const data = useMemo(() => (q.data ?? []).map((a) => ({ ...a, key: `${a.window}-${a.node_id}` }))
    .filter((a) => sev === "all" || (sev === "high" ? a.confidence >= 0.85 : a.confidence >= 0.6 && a.confidence < 0.85)), [q.data, sev]);
  const columns = useMemo(() => [
    col.accessor("timestamp", { header: "Time", cell: (c) => <span className="num font-mono text-xs">{fmt.s(c.getValue())}</span> }),
    col.accessor("node_id", { header: "Node", cell: (c) => <span className="font-mono text-xs">{c.getValue()}</span> }),
    col.accessor("ip", { header: "Address", cell: (c) => <span className="text-xs text-muted">{c.getValue()}</span> }),
    col.accessor("confidence", { header: "P(hostile)", cell: (c) => <div className="flex items-center gap-2"><span className="num font-mono text-xs">{c.getValue().toFixed(3)}</span><SeverityBadge p={c.getValue()} /></div> }),
    col.accessor("packet_rate", { header: "pps", cell: (c) => <span className="num text-xs">{fmt.num(c.getValue(), 1)}</span> }),
    col.accessor("detector", { header: "Detector", cell: (c) => <Badge tone="accent">{label(c.getValue())}</Badge> }),
    col.accessor("message", { header: "Detail", enableSorting: false, cell: (c) => <span className="text-xs text-muted">{c.getValue()}</span> }),
    col.display({ id: "ack", header: "", cell: ({ row }) => acked.has(row.original.key)
      ? <Badge tone="good"><Check className="size-3" /> ack</Badge>
      : <Button size="xs" variant="ghost" onClick={() => setAcked(new Set(acked).add(row.original.key))}>Acknowledge</Button> }),
  ], [acked]);
  const table = useReactTable({
    data, columns, state: { sorting, globalFilter: filter }, onSortingChange: setSorting, onGlobalFilterChange: setFilter,
    getCoreRowModel: getCoreRowModel(), getSortedRowModel: getSortedRowModel(), getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(), initialState: { pagination: { pageSize: 25 } },
  });
  const exportAs = async (fmtName: "stix" | "cef") => {
    const body = await api.exportAlerts(fmtName);
    download(`netshield-alerts.${fmtName === "stix" ? "json" : "cef"}`, typeof body === "string" ? body : JSON.stringify(body, null, 2),
      fmtName === "stix" ? "application/json" : "text/plain");
  };
  return (
    <>
      <PageHeader title="Alerts" subtitle="Every node-window above the trigger, mapped to MITRE ATT&CK on export."
        actions={<>
          <Button size="sm" onClick={() => exportAs("stix")}><Download /> STIX 2.1</Button>
          <Button size="sm" onClick={() => exportAs("cef")}><Download /> CEF</Button>
        </>} />
      <Card>
        <div className="flex flex-wrap items-center gap-3 border-b border-border p-3">
          <Input placeholder="Search node, address, detail…" value={filter} onChange={(e) => setFilter(e.target.value)} className="max-w-xs" />
          <Select value={sev} onChange={(e) => setSev(e.target.value)}>
            <option value="all">All severities</option><option value="high">High and critical</option><option value="medium">Medium</option>
          </Select>
          <span className="ml-auto text-xs text-muted">{table.getFilteredRowModel().rows.length} alerts · {acked.size} acknowledged</span>
        </div>
        {data.length ? (
          <>
            <DataTable>
              <thead>{table.getHeaderGroups().map((hg) => (
                <tr key={hg.id}>{hg.headers.map((h) => (
                  <th key={h.id} onClick={h.column.getToggleSortingHandler()} className={h.column.getCanSort() ? "cursor-pointer select-none" : ""}>
                    <span className="inline-flex items-center gap-1">{flexRender(h.column.columnDef.header, h.getContext())}{h.column.getCanSort() && <ArrowUpDown className="size-3" />}</span>
                  </th>))}</tr>))}
              </thead>
              <tbody>{table.getRowModel().rows.map((r) => (
                <tr key={r.id}>{r.getVisibleCells().map((c) => <td key={c.id}>{flexRender(c.column.columnDef.cell, c.getContext())}</td>)}</tr>))}
              </tbody>
            </DataTable>
            <div className="flex items-center justify-end gap-2 p-3 text-xs text-muted">
              Page {table.getState().pagination.pageIndex + 1} of {Math.max(1, table.getPageCount())}
              <Button size="xs" onClick={() => table.previousPage()} disabled={!table.getCanPreviousPage()}>Prev</Button>
              <Button size="xs" onClick={() => table.nextPage()} disabled={!table.getCanNextPage()}>Next</Button>
            </div>
          </>
        ) : <EmptyState icon={<ShieldAlert />} title="No alerts in this run" hint="Alerts are raised when a node's hostile probability crosses the trigger." />}
      </Card>
    </>
  );
}
