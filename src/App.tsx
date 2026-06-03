import { useState } from 'react';
import Header from './components/Header';
import ScannerForm from './components/ScannerForm';
import ScanResults from './components/ScanResults';
import VaultView from './components/VaultView';
import SupportPortal from './components/SupportPortal';
import { ScanResult } from './types';
import { 
  ShieldCheck, ShieldAlert, RefreshCw, Layers, Lock, Route, 
  CheckSquare, Code, HelpCircle, KeyRound, Radio 
} from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<'scanner' | 'vault' | 'support'>('scanner');
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  
  // Custom reassuring status lines for security scanning
  const [loadingStatus, setLoadingStatus] = useState('Initializing Security Auditor...');

  const performScanUrl = async (url: string) => {
    setIsLoading(true);
    setError(null);
    setScanResult(null);
    setLoadingStatus('Handshaking target endpoint...');

    try {
      setTimeout(() => setLoadingStatus('Scraping HTML markup & locating programmatic client scripts...'), 1500);
      setTimeout(() => setLoadingStatus('Parsing static regular expressions for standard API key leakage...'), 3000);
      setTimeout(() => setLoadingStatus('Streaming metadata to Gemini compliance auditor...'), 4500);

      const response = await fetch('/api/scan/url', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      });

      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || 'Failed to complete URL compliance scan.');
      }

      setScanResult(data);
    } catch (err: any) {
      console.error('URL Scan Exception:', err);
      setError(err.message || 'An error occurred during target audit sniffing.');
    } finally {
      setIsLoading(false);
    }
  };

  const performScanCode = async (files: { name: string; content: string }[]) => {
    setIsLoading(true);
    setError(null);
    setScanResult(null);
    setLoadingStatus('Structuring files tree mapped by schema parameters...');

    try {
      setTimeout(() => setLoadingStatus('Executing regex heuristic scanners for Stripe, AWS and GCP secrets...'), 1500);
      setTimeout(() => setLoadingStatus('Deploying cognitive static analysis checks via Gemini 3.5 Flash...'), 3200);
      setTimeout(() => setLoadingStatus('Assessing contract requirements & generating final scorecards...'), 4900);

      const response = await fetch('/api/scan/code', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ files }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to complete codebase SAST scan.');
      }

      setScanResult(data);
    } catch (err: any) {
      console.error('Code Scan Exception:', err);
      setError(err.message || 'An error occurred during static code audit review.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleReset = () => {
    setScanResult(null);
    setError(null);
  };

  return (
    <div className="min-h-screen bg-slate-50 font-sans text-slate-800">
      <Header />

      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        
        {/* Navigation Selector Tabs */}
        <div className="mb-8 flex space-x-1.5 rounded-xl bg-slate-200/60 p-1 max-w-md">
          <button
            onClick={() => setActiveTab('scanner')}
            className={`flex flex-1 items-center justify-center space-x-1.5 rounded-lg py-2.5 text-xs font-bold transition-all ${
              activeTab === 'scanner'
                ? 'bg-slate-900 text-white shadow-xs'
                : 'text-slate-650 hover:bg-slate-100 hover:text-slate-900'
            } cursor-pointer`}
          >
            <Radio className="h-4 w-4" />
            <span>Compliance Auditor</span>
          </button>
          
          <button
            onClick={() => setActiveTab('vault')}
            className={`flex flex-1 items-center justify-center space-x-1.5 rounded-lg py-2.5 text-xs font-bold transition-all ${
              activeTab === 'vault'
                ? 'bg-slate-900 text-white shadow-xs'
                : 'text-slate-650 hover:bg-slate-100 hover:text-slate-900'
            } cursor-pointer`}
          >
            <KeyRound className="h-4 w-4" />
            <span>Admin Key Vault</span>
          </button>

          <button
            onClick={() => setActiveTab('support')}
            className={`flex flex-1 items-center justify-center space-x-1.5 rounded-lg py-2.5 text-xs font-bold transition-all ${
              activeTab === 'support'
                ? 'bg-slate-900 text-white shadow-xs'
                : 'text-slate-650 hover:bg-slate-100 hover:text-slate-900'
            } cursor-pointer`}
          >
            <HelpCircle className="h-4 w-4" />
            <span>Secure Support</span>
          </button>
        </div>

        {/* Alerts / Error display */}
        {error && (
          <div className="mb-6 rounded-xl border border-red-200 bg-red-50 p-4 shadow-xs">
            <div className="flex space-x-3">
              <ShieldAlert className="h-5 w-5 text-red-600 shrink-0 mt-0.5" />
              <div>
                <h3 className="text-sm font-bold text-red-900 border-none pb-0">Scan Failure</h3>
                <p className="mt-1 text-xs text-red-700 leading-relaxed font-semibold">
                  {error}
                </p>
                <button
                  onClick={() => setError(null)}
                  className="mt-3 inline-flex items-center space-x-1 hover:underline text-xs text-red-800 font-bold cursor-pointer"
                >
                  Dismiss
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Loading audit status block */}
        {isLoading && (
          <div className="flex flex-col items-center justify-center rounded-xl border border-slate-205 bg-white p-12 text-center shadow-lg min-h-[420px] animate-fadeIn">
            <div className="relative flex h-14 w-14 items-center justify-center">
              <RefreshCw className="h-10 w-10 text-indigo-600 animate-spin" />
            </div>
            
            <h3 className="mt-6 text-base font-bold tracking-tight text-slate-900">
              Audit in Progress
            </h3>
            
            <div className="mt-2 text-xs font-semibold text-slate-500 max-w-md h-8">
              {loadingStatus}
            </div>

            {/* Simulated progress checklist */}
            <div className="mt-8 space-y-2.5 max-w-xs text-left">
              <div className="flex items-center space-x-3 text-xs text-slate-600 font-medium">
                <Layers className="h-4 w-4 text-slate-400 shrink-0" />
                <span>Payload Analysis Setup</span>
              </div>
              <div className="flex items-center space-x-3 text-xs text-slate-600 font-medium">
                <Lock className="h-4 w-4 text-slate-400 shrink-0" />
                <span>Credential Leaks Scanner</span>
              </div>
              <div className="flex items-center space-x-3 text-xs text-slate-600 font-medium">
                <Route className="h-4 w-4 text-slate-400 shrink-0" />
                <span>Endpoints Query Router</span>
              </div>
              <div className="flex items-center space-x-3 text-xs text-slate-600 font-medium">
                <CheckSquare className="h-4 w-4 text-indigo-500 shrink-0 animate-pulse" />
                <span className="font-semibold text-indigo-600">Cognitive Policy Evaluation</span>
              </div>
            </div>
          </div>
        )}

        {/* Main Interface Router */}
        {!isLoading && (
          <div className="space-y-8 animate-fadeIn">
            {activeTab === 'scanner' && (
              <>
                {!scanResult ? (
                  <div className="grid grid-cols-1 gap-8 lg:grid-cols-3">
                    {/* Scanner Configuration controls (pasting or uploading) */}
                    <div className="lg:col-span-2 space-y-6">
                      <ScannerForm 
                        onScanUrl={performScanUrl} 
                        onScanCode={performScanCode}
                        isLoading={isLoading} 
                      />
                    </div>

                    {/* Cognitive Auditor informational guidance panel */}
                    <div className="lg:col-span-1 space-y-6">
                      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-4">
                        <h3 className="text-sm font-bold text-slate-950 flex items-center space-x-2 border-b border-slate-100 pb-3">
                          <ShieldCheck className="h-4.5 w-4.5 text-indigo-600" />
                          <span>Security Audit Information</span>
                        </h3>
                        
                        <div className="space-y-4 text-xs font-medium text-slate-600 leading-relaxed font-medium">
                          <p>
                            Providing custom code inputs lets you statically inspect files for <strong>embedded credentials</strong> (like Stripe secrets, database connection URIs, AWS accounts, Slack integrations, and certificate private keys).
                          </p>
                          <p>
                            Scanning corporate web environments lets you audit the <strong>public-facing frontends</strong>, exposing visible credentials, active query gateways, and transport safety profiles.
                          </p>
                          <p className="bg-slate-50 border border-slate-100 rounded-lg p-3 text-[11px] text-slate-700">
                            This auditing system runs as a secure, in-house developer diagnostic utility under compliance tracking.
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-6">
                    <div className="flex items-center justify-between">
                      <button
                        onClick={handleReset}
                        className="flex items-center space-x-1 text-xs font-bold text-indigo-600 hover:text-indigo-700 border border-indigo-200 bg-indigo-50 hover:bg-indigo-100/60 px-3.5 py-2 rounded-xl transition-all cursor-pointer"
                      >
                        <span>&larr; Configure New Compliance Scan</span>
                      </button>
                    </div>

                    <ScanResults result={scanResult} />
                  </div>
                )}
              </>
            )}

            {activeTab === 'vault' && (
              <VaultView />
            )}

            {activeTab === 'support' && (
              <SupportPortal />
            )}
          </div>
        )}
      </main>
    </div>
  );
}
