import { useState, useRef, DragEvent, ChangeEvent, FormEvent } from 'react';
import { Globe, Code, UploadCloud, FileCode, Play, AlertCircle, Sparkles } from 'lucide-react';

interface ScannerFormProps {
  onScanUrl: (url: string | string[]) => void;
  onScanCode: (files: { name: string; content: string }[]) => void;
  isLoading: boolean;
}

// Excellent preloaded templates to let the user immediately perform test audits
const TEMPLATES = [
  {
    name: 'Exposed Stripe Setup',
    filename: 'paymentService.js',
    content: `// Corporate Payments Handler - Contractor Code version 1.2
const stripe = require('stripe')('sk_live_51Nv2KLK90saK_stripe_private_secret_key_prod_abcxyz');
const express = require('express');
const app = express();

// Public webhook integration
app.post('/api/charge', async (req, res) => {
  const { amount, source } = req.body;
  try {
    const charge = await stripe.charges.create({
      amount: amount * 100, // in cents
      currency: 'usd',
      source: source,
      description: 'Corporate client checkout'
    });
    res.json({ success: true, chargeId: charge.id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});`
  },
  {
    name: 'Google Map & Firebase Secrets',
    filename: 'index.html',
    content: `<!DOCTYPE html>
<html>
<head>
  <title>Corporate Store Locator Maps</title>
  <!-- Exposed maps credential -->
  <script src="https://maps.googleapis.com/maps/api/js?key=AIzaSyA4_exampleMapTokenXh9G_2891d_s8&callback=initMap" async defer></script>
</head>
<body>
  <div id="map"></div>
  <script>
    // Initialise secondary backend database
    const firebaseConfig = {
      apiKey: "AIzaSyCxOy_FirebaseSecretToken99120",
      authDomain: "corp-internal-vault.firebaseapp.com",
      databaseURL: "https://corp-internal-vault.firebaseio.com",
      projectId: "corp-internal-vault",
      storageBucket: "corp-internal-vault.appspot.com"
    };

    function initMap() {
      const map = new google.maps.Map(document.getElementById('map'), {
        center: {lat: -34.397, lng: 150.644},
        zoom: 8
      });
    }
  </script>
</body>
</html>`
  },
  {
    name: 'AWS S3 & PostgreSQL Integration',
    filename: 'config.py',
    content: `# Cloud connection parameters config
AWS_ACCESS_KEY_ID = "AKIAQ3STB4M97EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY"
S3_BUCKET_NAME = "corporate-restricted-financial-docs"

# Database sync endpoint
DATABASE_URL = "postgres://root_contractor_dev:CorpPassSecure991@postgresql-corporate-db.rds.amazonaws.com:5432/main_ledger"

def get_s3_connection():
    import boto3
    return boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY
    )
`
  }
];

export default function ScannerForm({ onScanUrl, onScanCode, isLoading }: ScannerFormProps) {
  const [activeTab, setActiveTab] = useState<'url' | 'code' | 'upload'>('url');
  
  // URL Scan state
  const [urlMode, setUrlMode] = useState<'single' | 'batch'>('single');
  const [urlInput, setUrlInput] = useState('');
  const [batchUrlsInput, setBatchUrlsInput] = useState('');
  
  // Code Snippet state
  const [pastedCode, setPastedCode] = useState(TEMPLATES[0].content);
  const [customFilename, setCustomFilename] = useState(TEMPLATES[0].filename);

  // File Upload State
  const [uploadedFiles, setUploadedFiles] = useState<{ name: string; content: string }[]>([]);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Trigger scans
  const handleUrlSubmit = (e: FormEvent) => {
    e.preventDefault();
    if (urlMode === 'single') {
      if (!urlInput.trim()) return;
      onScanUrl(urlInput.trim());
    } else {
      const parsedUrls = batchUrlsInput
        .split(/[\n,]+/)
        .map(u => u.trim())
        .filter(Boolean);
      if (parsedUrls.length === 0) return;
      onScanUrl(parsedUrls);
    }
  };

  const handleCodeSubmit = () => {
    if (!pastedCode.trim()) return;
    onScanCode([{ name: customFilename || 'codeSnippet.js', content: pastedCode }]);
  };

  const handleUploadSubmit = () => {
    if (uploadedFiles.length === 0) return;
    onScanCode(uploadedFiles);
  };

  // Preloaded template select
  const selectTemplate = (index: number) => {
    setPastedCode(TEMPLATES[index].content);
    setCustomFilename(TEMPLATES[index].filename);
  };

  // File Upload Handlers (Client-Side reader)
  const processUploadedFiles = (filesList: FileList | null) => {
    if (!filesList) return;
    const fileLoadPromises: Promise<{ name: string; content: string }>[] = [];

    for (let i = 0; i < filesList.length; i++) {
      const file = filesList[i];
      // Limit file size to 3MB for static text analysis
      if (file.size > 3 * 1024 * 1024) continue;
      
      const promise = new Promise<{ name: string; content: string }>((resolve) => {
        const reader = new FileReader();
        reader.onload = (e) => {
          resolve({
            name: file.name,
            content: (e.target?.result as string) || ''
          });
        };
        reader.readAsText(file);
      });
      fileLoadPromises.push(promise);
    }

    Promise.all(fileLoadPromises).then((results) => {
      setUploadedFiles((prev) => [...prev, ...results]);
    });
  };

  const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    processUploadedFiles(e.dataTransfer.files);
  };

  const handleFileInputChange = (e: ChangeEvent<HTMLInputElement>) => {
    processUploadedFiles(e.target.files);
  };

  const clearUploadedFiles = () => {
    setUploadedFiles([]);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
      {/* Tab Selectors */}
      <div className="flex border-b border-slate-100 pb-4">
        <button
          onClick={() => setActiveTab('url')}
          className={`flex items-center space-x-2 border-b-2 px-4 py-2 text-sm font-semibold transition-all duration-200 ${
            activeTab === 'url'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:border-slate-200 hover:text-slate-800'
          }`}
          id="tab-url-selector"
        >
          <Globe className="h-4 w-4" />
          <span>Web URL Scan</span>
        </button>

        <button
          onClick={() => setActiveTab('code')}
          className={`flex items-center space-x-2 border-b-2 px-4 py-2 text-sm font-semibold transition-all duration-200 ${
            activeTab === 'code'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:border-slate-200 hover:text-slate-800'
          }`}
          id="tab-code-selector"
        >
          <Code className="h-4 w-4" />
          <span>Paste Source Code</span>
        </button>

        <button
          onClick={() => setActiveTab('upload')}
          className={`flex items-center space-x-2 border-b-2 px-4 py-2 text-sm font-semibold transition-all duration-200 ${
            activeTab === 'upload'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-slate-500 hover:border-slate-200 hover:text-slate-800'
          }`}
          id="tab-upload-selector"
        >
          <UploadCloud className="h-4 w-4" />
          <span>Upload Project Files</span>
        </button>
      </div>

      {/* Tab Contents */}
      <div className="mt-5 min-h-[350px]">
        {/* URL Scanner Form */}
        {activeTab === 'url' && (
          <div className="space-y-4 animate-fadeIn">
            <div className="rounded-lg bg-indigo-50 border border-indigo-100/60 p-4">
              <div className="flex space-x-3">
                <Sparkles className="mt-0.5 h-4.5 w-4.5 text-indigo-600 shrink-0" />
                <div>
                  <h3 className="text-xs font-semibold text-indigo-900">Cognitive Landing Page Sniffer & Audit Suite</h3>
                  <p className="mt-1 text-xs text-indigo-700 leading-relaxed">
                    Analyzing contractor-hosted sites detects unmasked client-side API integrations (Google Maps, Firebase keys, Segment analytics, tracking codes) and audits secure TLS configurations.
                  </p>
                </div>
              </div>
            </div>

            {/* Mode Switcher */}
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <div>
                <span className="block text-xs font-bold uppercase tracking-wider text-slate-500">
                  Scanning Mode
                </span>
                <span className="text-[11px] text-slate-500">
                  Choose single site or parallel bulk audit
                </span>
              </div>
              <div className="flex rounded-lg bg-slate-100/80 p-0.5 border border-slate-200">
                <button
                  type="button"
                  onClick={() => setUrlMode('single')}
                  className={`rounded-md px-3.5 py-1 text-xs font-bold transition-all ${
                    urlMode === 'single'
                      ? 'bg-slate-900 text-white shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  } cursor-pointer`}
                >
                  Single Target
                </button>
                <button
                  type="button"
                  onClick={() => setUrlMode('batch')}
                  className={`rounded-md px-3.5 py-1 text-xs font-bold transition-all ${
                    urlMode === 'batch'
                      ? 'bg-slate-900 text-white shadow-xs'
                      : 'text-slate-600 hover:text-slate-900'
                  } cursor-pointer`}
                >
                  Batch Multi-Sites
                </button>
              </div>
            </div>

            <form onSubmit={handleUrlSubmit} className="space-y-4">
              {urlMode === 'single' ? (
                <div>
                  <label htmlFor="url-input" className="block text-xs font-bold uppercase tracking-wider text-slate-500">
                    Target Website URL
                  </label>
                  <div className="relative mt-2 rounded-xl shadow-xs">
                    <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3">
                      <Globe className="h-5 w-5 text-slate-400" />
                    </div>
                    <input
                      type="text"
                      id="url-input"
                      value={urlInput}
                      onChange={(e) => setUrlInput(e.target.value)}
                      placeholder="e.g. corporate-locator.net or https://mycorp-app.cloud.run"
                      disabled={isLoading}
                      className="block w-full rounded-xl border border-slate-300 py-3 pl-11 pr-4 text-sm text-slate-950 placeholder-slate-400 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 disabled:opacity-60"
                    />
                  </div>
                </div>
              ) : (
                <div className="space-y-2 animate-fadeIn">
                  <div className="flex justify-between items-center">
                    <label htmlFor="batch-urls-textarea" className="block text-xs font-bold uppercase tracking-wider text-slate-500">
                      Target Websites (One per line or comma separated)
                    </label>
                    <button
                      type="button"
                      onClick={() => setBatchUrlsInput("demo-payment-v2.net\ncorp-store-locator.org\nfirebase-internal-gateway.io")}
                      className="text-[11px] font-semibold text-indigo-600 hover:underline cursor-pointer"
                    >
                      Load demo target batch
                    </button>
                  </div>
                  <textarea
                    id="batch-urls-textarea"
                    rows={5}
                    value={batchUrlsInput}
                    onChange={(e) => setBatchUrlsInput(e.target.value)}
                    placeholder="e.g.&#10;corporate-locator.net&#10;mycorp-web-portal.com&#10;contractor-sandbox.io"
                    disabled={isLoading}
                    className="w-full rounded-xl border border-slate-300 font-mono text-xs p-3.5 text-slate-950 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 bg-white placeholder-slate-400"
                  />
                  <div className="flex items-center justify-between text-[11px] text-slate-500 font-medium pb-1.5">
                    <span>Audit up to 5 domains of public landing pages in parallel.</span>
                    <span className="font-bold text-indigo-600 bg-indigo-50 border border-indigo-100 px-2 py-0.5 rounded-md">
                      {batchUrlsInput.split(/[\n,]+/).map(u => u.trim()).filter(Boolean).length} targets entered
                    </span>
                  </div>
                </div>
              )}

              <button
                type="submit"
                disabled={isLoading || (urlMode === 'single' ? !urlInput.trim() : !batchUrlsInput.trim())}
                className="flex w-full items-center justify-center space-x-2 rounded-xl bg-slate-900 py-3 text-sm font-bold text-white shadow-md hover:bg-slate-800 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 disabled:opacity-50 transition-colors cursor-pointer"
                id="btn-trigger-url-scan"
              >
                <Play className="h-4 w-4" />
                <span>
                  {isLoading 
                    ? (urlMode === 'batch' ? 'Executing Concurrent Batch Scans...' : 'Running Compliance Audit...')
                    : (urlMode === 'batch' ? 'Launch Batch Network Audit' : 'Start Audit Sniffing')}
                </span>
              </button>
            </form>
          </div>
        )}

        {/* Code Snippet Editor / Paste Zone */}
        {activeTab === 'code' && (
          <div className="space-y-4 animate-fadeIn">
            {/* Quick Demo Template Selectors */}
            <div>
              <span className="block text-xs font-bold uppercase tracking-wider text-slate-500 mb-2">
                Quick Demonstration Templates
              </span>
              <div className="flex flex-wrap gap-2">
                {TEMPLATES.map((tpl, i) => (
                  <button
                    key={tpl.name}
                    type="button"
                    onClick={() => selectTemplate(i)}
                    className="rounded-lg bg-slate-50 border border-slate-200 text-slate-700 px-3 py-1.5 text-xs font-medium hover:bg-slate-100 transition-colors cursor-pointer"
                  >
                    {tpl.name}
                  </button>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <div>
                <label htmlFor="filename-input" className="block text-xs font-bold uppercase tracking-wider text-slate-500">
                  Mock Filename
                </label>
                <input
                  type="text"
                  id="filename-input"
                  value={customFilename}
                  onChange={(e) => setCustomFilename(e.target.value)}
                  placeholder="paymentService.js"
                  disabled={isLoading}
                  className="mt-1.5 block w-full rounded-lg border border-slate-300 px-3 py-2 text-sm font-medium text-slate-900 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                />
              </div>
            </div>

            <div>
              <label htmlFor="code-textarea" className="block text-xs font-bold uppercase tracking-wider text-slate-500 mb-1.5">
                Paste Source Code / Configuration File
              </label>
              <textarea
                id="code-textarea"
                rows={10}
                value={pastedCode}
                onChange={(e) => setPastedCode(e.target.value)}
                disabled={isLoading}
                className="w-full rounded-xl border border-slate-300 font-mono text-xs p-4 text-slate-900 focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 bg-slate-50 disabled:opacity-60"
                placeholder="Paste code blocks here..."
              />
            </div>

            <button
              onClick={handleCodeSubmit}
              disabled={isLoading || !pastedCode.trim()}
              className="flex w-full items-center justify-center space-x-2 rounded-xl bg-slate-900 py-3 text-sm font-bold text-white shadow-md hover:bg-slate-800 disabled:opacity-50 transition-colors cursor-pointer"
              id="btn-trigger-code-scan"
            >
              <Play className="h-4 w-4" />
              <span>{isLoading ? 'Analyzing Source Code...' : 'Execute Static SAST Audit'}</span>
            </button>
          </div>
        )}

        {/* Drag and Drop Upload Workspace */}
        {activeTab === 'upload' && (
          <div className="space-y-4 animate-fadeIn">
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`flex flex-col items-center justify-center rounded-xl border-2 border-dashed p-8 text-center transition-all duration-200 cursor-pointer ${
                isDragging
                  ? 'border-indigo-500 bg-indigo-50/50'
                  : 'border-slate-300 bg-slate-50 hover:border-slate-400 hover:bg-slate-100/50'
              }`}
            >
              <input
                type="file"
                ref={fileInputRef}
                onChange={handleFileInputChange}
                multiple
                className="hidden"
                accept=".js,.jsx,.ts,.tsx,.py,.html,.css,.json,.env,.example,.yaml,.yml,.ini"
              />
              <UploadCloud className="h-10 w-10 text-slate-400 mb-3" />
              <p className="text-sm font-semibold text-slate-700">
                Drag & drop files here, or <span className="text-indigo-600">click to browse</span>
              </p>
              <p className="mt-1 text-xs text-slate-500">
                Accepts JS/TS, Python, HTML/CSS, JSON, YAML, configs, and .env files (&lt;3MB)
              </p>
            </div>

            {/* List of loaded files awaiting scan */}
            {uploadedFiles.length > 0 && (
              <div className="rounded-xl border border-slate-150 p-4 bg-white space-y-2">
                <div className="flex items-center justify-between border-b border-slate-100 pb-2 mb-2">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-500">
                    Loaded Files ({uploadedFiles.length})
                  </span>
                  <button
                    onClick={clearUploadedFiles}
                    className="text-xs font-semibold text-red-600 hover:text-red-700 cursor-pointer"
                  >
                    Clear All
                  </button>
                </div>
                <div className="max-h-36 overflow-y-auto space-y-1.5 divide-y divide-slate-50">
                  {uploadedFiles.map((f, i) => (
                    <div key={`${f.name}-${i}`} className="flex items-center justify-between py-1 text-xs text-slate-700 font-medium">
                      <div className="flex items-center space-x-2">
                        <FileCode className="h-3.5 w-3.5 text-slate-400" />
                        <span className="truncate max-w-[200px]">{f.name}</span>
                      </div>
                      <span className="text-[10px] text-slate-400">
                        {Math.ceil(f.content.length / 1024)} KB
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <button
              onClick={handleUploadSubmit}
              disabled={isLoading || uploadedFiles.length === 0}
              className="flex w-full items-center justify-center space-x-2 rounded-xl bg-slate-900 py-3 text-sm font-bold text-white shadow-md hover:bg-slate-800 disabled:opacity-50 transition-colors cursor-pointer"
              id="btn-trigger-upload-scan"
            >
              <Play className="h-4 w-4" />
              <span>{isLoading ? 'Scanning Loaded Workspaces...' : `Scan ${uploadedFiles.length} Uploaded Files`}</span>
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
