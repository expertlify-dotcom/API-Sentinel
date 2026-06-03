import { ShieldAlert, Server, Activity } from 'lucide-react';

export default function Header() {
  return (
    <header className="border-b border-slate-200 bg-white shadow-xs">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-4 sm:px-6 lg:px-8">
        {/* Core Branding */}
        <div className="flex items-center space-x-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-slate-900 text-white shadow-sm transition-transform hover:scale-105">
            <ShieldAlert className="h-5 w-5 text-indigo-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-slate-900 sm:text-2xl">
              API Sentinel
            </h1>
            <p className="text-xs font-medium text-slate-500">
              DevSecOps Compliance & Credential Leak Auditor
            </p>
          </div>
        </div>

        {/* Status Indicators (Defensive UI Alignment - Minimal & Real, avoiding Larping logs) */}
        <div className="hidden items-center space-x-6 md:flex">
          <div className="flex items-center space-x-2 text-xs font-semibold text-slate-600 bg-slate-50 border border-slate-100 rounded-lg px-2.5 py-1.5">
            <Server className="h-3.5 w-3.5 text-indigo-500" />
            <span>Static SAST Engine</span>
          </div>
          <div className="flex items-center space-x-2 text-xs font-semibold text-slate-600 bg-emerald-50/80 border border-emerald-100 rounded-lg px-2.5 py-1.5">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500"></span>
            </span>
            <span className="text-emerald-700">Audit Node Active</span>
          </div>
        </div>
      </div>
    </header>
  );
}
