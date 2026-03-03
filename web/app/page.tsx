"use client";

import { useEffect, useState } from "react";
import StatCard from "../components/StatCard";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

export default function HomePage() {
  const [stats, setStats] = useState({ total_assets: 0, total_services: 0, open_findings: 0, new_exposures_last_scan: 0 });
  const [query, setQuery] = useState("port:443");
  const [results, setResults] = useState<any>({ assets: [], services: [], findings: [] });
  const [target, setTarget] = useState("");

  useEffect(() => {
    fetch(`${API_BASE}/dashboard`).then((r) => r.json()).then(setStats).catch(() => null);
  }, []);

  const search = async () => {
    const r = await fetch(`${API_BASE}/search?query=${encodeURIComponent(query)}`);
    setResults(await r.json());
  };

  const createJob = async () => {
    await fetch(`${API_BASE}/scan-jobs`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
    });
    alert("Scan enqueued");
  };

  return (
    <main className="max-w-6xl mx-auto p-6 space-y-6">
      <h1 className="text-3xl font-bold">ScopeSearch Dashboard</h1>
      <div className="grid md:grid-cols-4 gap-4">
        <StatCard label="Total assets" value={stats.total_assets} />
        <StatCard label="Total services" value={stats.total_services} />
        <StatCard label="Open findings" value={stats.open_findings} />
        <StatCard label="New exposures (last scan)" value={stats.new_exposures_last_scan} />
      </div>

      <section className="rounded-lg border border-slate-800 bg-slate-900 p-4 space-y-3">
        <h2 className="font-semibold">Start Scan</h2>
        <div className="flex gap-2">
          <input className="flex-1 bg-slate-950 border border-slate-700 rounded px-3 py-2" placeholder="example.com" value={target} onChange={(e) => setTarget(e.target.value)} />
          <button className="bg-indigo-600 px-4 py-2 rounded" onClick={createJob}>Queue scan</button>
        </div>
      </section>

      <section className="rounded-lg border border-slate-800 bg-slate-900 p-4 space-y-3">
        <h2 className="font-semibold">Search</h2>
        <div className="flex gap-2">
          <input className="flex-1 bg-slate-950 border border-slate-700 rounded px-3 py-2" value={query} onChange={(e) => setQuery(e.target.value)} />
          <button className="bg-emerald-600 px-4 py-2 rounded" onClick={search}>Search</button>
        </div>
        <pre className="bg-slate-950 border border-slate-800 rounded p-3 text-xs overflow-auto">{JSON.stringify(results, null, 2)}</pre>
      </section>
    </main>
  );
}
