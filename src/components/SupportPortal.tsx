import { useState, FormEvent } from 'react';
import { 
  ShieldCheck, HelpCircle, KeyRound, Terminal, Server, Send, 
  MessageSquare, UserCheck, Layers, BookOpen, AlertCircle, CheckCircle, ArrowRight
} from 'lucide-react';

interface SupportQA {
  sender: 'user' | 'system';
  text: string;
  timestamp: string;
}

export default function SupportPortal() {
  const [activeCategory, setActiveCategory] = useState<'all' | 'gcp' | 'aws' | 'stripe' | 'database'>('all');
  
  // Custom ticket / interactive support simulator
  const [chatLog, setChatLog] = useState<SupportQA[]>([
    {
      sender: 'system',
      text: 'Welcome to the DevSecOps Compliance Support Desk. Submit a contractor query or ask how to secure a specific API endpoint.',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }
  ]);
  const [chatInput, setChatInput] = useState('');
  const [isAnswering, setIsAnswering] = useState(false);

  const GUIDELINES = [
    {
      id: 'guide-1',
      title: 'Restricting Google Maps API Keys',
      category: 'gcp',
      difficulty: 'Medium',
      steps: [
        'Navigate to the Google Cloud Console Console & selection Credentials.',
        'Select the exposed API key identifying target constraints.',
        'Under "Key restrictions", toggle "Application restrictions" to "Web sites (HTTP referrers)".',
        'Add the absolute corporate host domain pattern (e.g. *.mycoporation.com/*). This shuts down any unauthorized server uses from direct contractor machines or external scanners.'
      ],
      codeSample: `// Wrap Maps script safely in frontend with HTTP restriction enabled
<script src="https://maps.googleapis.com/maps/api/js?key=AIzaSy_RESTRICTED_KEY_HERE&callback=initMap" async defer></script>`
    },
    {
      id: 'guide-2',
      title: 'Migrating Secret keys to Server Proxy Routers',
      category: 'stripe',
      difficulty: 'High Priority',
      steps: [
        'Take Stripe SK credentials entirely out of client repository files.',
        'Place the secret keys inside server environments, e.g. .env elements.',
        'Create a proxy router inside server.ts (e.g., /api/checkout) that handshakes the Stripe API server-side.',
        'Call the server proxy router from the front-end page instead of loading stripe.js with live secret credentials.'
      ],
      codeSample: `// ✅ Good Pattern inside server.ts - Key never sent to client
app.post('/api/checkout', async (req, res) => {
  const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
  const charge = await stripe.charges.create({ ... });
  res.json(charge);
});`
    },
    {
      id: 'guide-3',
      title: 'Database connection credential quarantine',
      category: 'database',
      difficulty: 'High Priority',
      steps: [
        'Inspect contractor python/node code for connection string variables including passwords.',
        'Add database URLs to system environment parameters or secure parameters workspace.',
        'Pass the parameters into containers at runtime rather than leaving plaintext files inside build volumes.'
      ],
      codeSample: `// ✅ Good Node connection string query in server.js
const { Client } = require('pg');
const client = new Client({
  connectionString: process.env.DATABASE_URL, // Dynamic runtime environment injection
  ssl: { rejectUnauthorized: true }
});`
    },
    {
      id: 'guide-4',
      title: 'AWS S3 Access Key containment',
      category: 'aws',
      difficulty: 'Critical',
      steps: [
        'Revoke the static IAM credentials exposed immediately.',
        'Provision a secure AWS Secrets Manager parameters path or use AWS IAM Roles.',
        'Apply restricted AWS Policy scopes limit to read/write specific buckets only, block root actions.'
      ],
      codeSample: `# AWS SDK initialization mapping using runtime environment strings
import boto3
import os

s3 = boto3.client(
    's3',
    aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
)`
    }
  ];

  const filteredGuides = activeCategory === 'all' 
    ? GUIDELINES 
    : GUIDELINES.filter(g => g.category === activeCategory);

  const handleSendMessage = (e: FormEvent) => {
    e.preventDefault();
    if (!chatInput.trim() || isAnswering) return;

    const userMsg: SupportQA = {
      sender: 'user',
      text: chatInput,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setChatLog(prev => [...prev, userMsg]);
    const originalQuery = chatInput;
    setChatInput('');
    setIsAnswering(true);

    // Simulate smart compliant advice system answering
    setTimeout(() => {
      let advice = 'To secure this pattern, remove hardcoded tokens instantly and save them to server-side environments using process.env configurations. Apply IP/domain restrict constraints where absolute frontend inclusion is required.';
      
      const normalized = originalQuery.toLowerCase();
      if (normalized.includes('map') || normalized.includes('google') || normalized.includes('gcp')) {
        advice = 'For Google Maps / GCP keys: Add HTTP Referrer restricts inside Google Developer Console. Contractor-facing applications should only access GCP boundaries when mapped to your verified staging domain. Avoid giving contractors top-level owner IAM access.';
      } else if (normalized.includes('stripe') || normalized.includes('payment') || normalized.includes('checkout')) {
        advice = 'Stripe Secret keys must never live inside javascript components or mobile codes. Use server-side proxy route handshakes (for example, create a secure express node "/api/charge" controller). Stripe secret keys config must strictly remain on server containers.';
      } else if (normalized.includes('database') || normalized.includes('postgres') || normalized.includes('connect')) {
        advice = 'Database passwords or URL URIs discovered in python / node config scripts represent critical threat vectors. Enforce database transport TLS configurations. Change DB account names and reset user tables that contractors utilized immediately.';
      } else if (normalized.includes('aws') || normalized.includes('s3') || normalized.includes('bucket')) {
        advice = 'Active AWS Key Exposure enables deep corporate file harvesting. Revoke exposed keys via AWS Identity Access Manager (IAM) dashboard instantly. Setup automated IAM policy audits and run code-scanning pre-push hooks.';
      }

      const systemMsg: SupportQA = {
        sender: 'system',
        text: advice,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };

      setChatLog(prev => [...prev, systemMsg]);
      setIsAnswering(false);
    }, 1200);
  };

  return (
    <div className="grid grid-cols-1 gap-8 lg:grid-cols-3 animate-fadeIn">
      {/* Left: Interactive Remediation Tutorials & Guidelines */}
      <div className="lg:col-span-2 space-y-6">
        <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm space-y-4">
          <div className="flex items-center space-x-2 border-b border-slate-150 pb-3">
            <BookOpen className="h-5 w-5 text-indigo-600" />
            <h3 className="text-sm font-bold text-slate-900">Interactive Securing Helpbooks</h3>
          </div>

          {/* Quick Filter buttons */}
          <div className="flex flex-wrap gap-1.5 pb-2">
            {[
              { id: 'all', label: 'All Frameworks' },
              { id: 'gcp', label: 'Google Cloud/Maps' },
              { id: 'aws', label: 'AWS Config' },
              { id: 'stripe', label: 'Stripe Payments' },
              { id: 'database', label: 'Database Parameters' }
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveCategory(tab.id as any)}
                className={`rounded-lg py-1 px-3.5 text-xs font-semibold border transition ${
                  activeCategory === tab.id 
                    ? 'bg-slate-900 text-white border-slate-900' 
                    : 'bg-slate-50 text-slate-650 border-slate-200 hover:bg-slate-100'
                } cursor-pointer`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Guide list */}
          <div className="space-y-6">
            {filteredGuides.map(guide => (
              <div key={guide.id} className="rounded-xl border border-slate-150 p-5 bg-slate-50/50 space-y-4 hover:border-slate-300 transition duration-200">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center space-x-1.5">
                    <KeyRound className="h-4.5 w-4.5 text-indigo-500" />
                    <span>{guide.title}</span>
                  </h4>
                  <span className={`rounded-md px-2 py-0.5 text-[10px] font-bold uppercase border ${
                    guide.difficulty === 'Critical' || guide.difficulty === 'High Priority'
                      ? 'bg-rose-50 text-rose-700 border-rose-150 animate-pulse'
                      : 'bg-blue-50 text-blue-700 border-blue-150'
                  }`}>
                    {guide.difficulty}
                  </span>
                </div>

                <div className="space-y-2">
                  <p className="text-[11px] font-bold text-slate-550 uppercase select-none">Remediation Steps Checklist:</p>
                  <ol className="list-decimal list-inside text-xs text-slate-700 space-y-1.5 font-normal leading-relaxed pl-1">
                    {guide.steps.map((st, i) => (
                      <li key={i}>{st}</li>
                    ))}
                  </ol>
                </div>

                {/* Code highlight */}
                <div className="rounded-lg border border-slate-200 bg-slate-900 text-[11px] p-4 text-slate-300 font-mono overflow-x-auto whitespace-pre">
                  <code>{guide.codeSample}</code>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Right Column: Simulated compliance ticket advice chat desk */}
      <div className="lg:col-span-1 space-y-6">
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-4">
          <div className="flex items-center space-x-2 border-b border-slate-100 pb-3">
            <MessageSquare className="h-4.5 w-4.5 text-indigo-650" />
            <h3 className="text-sm font-bold text-slate-950">Contractor Audit Desk</h3>
          </div>

          <p className="text-xs text-slate-550 leading-relaxed font-normal">
            Explain a specific credential exposure or ask for advice on secure architectural handshakes.
          </p>

          {/* Chat log wrapper */}
          <div className="rounded-xl border border-slate-150 bg-slate-50/50 p-3 h-72 overflow-y-auto space-y-3 flex flex-col justify-start">
            {chatLog.map((log, i) => (
              <div 
                key={i} 
                className={`max-w-[85%] rounded-xl p-3 text-xs leading-relaxed font-normal ${
                  log.sender === 'system' 
                    ? 'bg-white border border-slate-150 text-slate-800' 
                    : 'bg-indigo-600 text-white rounded-br-none self-end'
                }`}
              >
                <p>{log.text}</p>
                <span className={`block text-[9px] mt-1 text-right font-medium ${
                  log.sender === 'system' ? 'text-slate-400' : 'text-indigo-200'
                }`}>
                  {log.timestamp}
                </span>
              </div>
            ))}

            {isAnswering && (
              <div className="bg-white border border-slate-150 text-slate-500 max-w-[80%] rounded-xl p-3 text-xs select-none italic font-semibold">
                Sentry Advisor is analyzing request...
              </div>
            )}
          </div>

          {/* Chat trigger input */}
          <form onSubmit={handleSendMessage} className="flex space-x-2">
            <input
              type="text"
              placeholder="Ask about Firebase, AWS key limits..."
              value={chatInput}
              onChange={(e) => setChatInput(e.target.value)}
              disabled={isAnswering}
              className="block w-full rounded-xl border border-slate-300 py-2.5 px-3.5 text-xs text-slate-900 focus:border-indigo-550 focus:outline-none focus:ring-1 focus:ring-indigo-500 disabled:opacity-60"
            />
            <button
              type="submit"
              disabled={!chatInput.trim() || isAnswering}
              className="flex h-10 w-10 items-center justify-center rounded-xl bg-slate-900 text-white hover:bg-slate-800 disabled:opacity-50 transition-colors cursor-pointer shrink-0"
            >
              <Send className="h-4 w-4" />
            </button>
          </form>

          {/* Quick FAQ queries */}
          <div className="pt-2">
            <p className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-2">Suggested Scenarios:</p>
            <div className="flex flex-wrap gap-1.5">
              {[
                'How do I restrict AWS keys?',
                'Google Maps referrers guide',
                'Stripe server proxy patterns'
              ].map(query => (
                <button
                  key={query}
                  type="button"
                  onClick={() => setChatInput(query)}
                  className="rounded bg-slate-100 hover:bg-indigo-50 text-[10px] font-bold text-slate-700 hover:text-indigo-700 px-2 py-1 text-left transition duration-150 cursor-pointer"
                >
                  {query}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Contractor SLA Compliance Metric Panel */}
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm space-y-4">
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 flex items-center space-x-1.5">
            <UserCheck className="h-4 w-4 text-emerald-600" />
            <span>Developer SLA Standards</span>
          </h4>
          <ul className="text-xs text-slate-650 space-y-2.5 leading-relaxed font-normal">
            <li className="flex items-start space-x-2">
              <CheckCircle className="h-4 w-4 text-emerald-600 shrink-0 mt-0.5" />
              <span><strong>M1: Secret Mask Mandates:</strong> No unmasked keys shall reside on commits.</span>
            </li>
            <li className="flex items-start space-x-2">
              <CheckCircle className="h-4 w-4 text-emerald-600 shrink-0 mt-0.5" />
              <span><strong>M2: Cryptographic SSL limits:</strong> External data channels must strictly use HTTPS/TLS protocols.</span>
            </li>
            <li className="flex items-start space-x-2">
              <CheckCircle className="h-4 w-4 text-emerald-600 shrink-0 mt-0.5" />
              <span><strong>M3: Key scope bounds:</strong> Keys must limit write/delete attributes.</span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
}
