export default function StatCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg bg-slate-900 p-4 shadow border border-slate-800">
      <p className="text-slate-400 text-sm">{label}</p>
      <p className="text-2xl font-bold">{value}</p>
    </div>
  );
}
