import { useState, useEffect, FormEvent } from 'react';
import { VaultItem } from '../types';
import { 
  Lock, Unlock, ShieldAlert, KeyRound, Eye, EyeOff, Save, 
  Trash2, Plus, CheckCircle, HelpCircle, FileJson, FileEdit, AlertCircle, Sparkles, Layers, Cloud, Code
} from 'lucide-react';
import { PARENT_CATEGORIES, getParentCategory, CategoryKey } from '../utils/categoryHelper';

interface VaultViewProps {
  onAddManualItem?: (item: VaultItem) => void;
}

export default function VaultView({}: VaultViewProps) {
  const [vaultItems, setVaultItems] = useState<VaultItem[]>([]);
  const [isUnlocked, setIsUnlocked] = useState(false);
  const [pinInput, setPinInput] = useState('');
  const [pinError, setPinError] = useState<string | null>(null);
  
  // Category filter state
  const [selectedCategoryFilter, setSelectedCategoryFilter] = useState<'all' | CategoryKey>('all');

  // Custom configured Admin PIN
  const [adminPin, setAdminPin] = useState(() => {
    return localStorage.getItem('sentry_admin_pin') || 'admin123';
  });

  const [isPinSetup, setIsPinSetup] = useState(() => {
    return !localStorage.getItem('sentry_admin_pin');
  });

  const [newPin, setNewPin] = useState('');

  // Editing notes state
  const [editingNotes, setEditingNotes] = useState<Record<string, string>>({});
  const [revealedSecrets, setRevealedSecrets] = useState<Record<string, boolean>>({});

  // Form state for manually adding key
  const [showAddForm, setShowAddForm] = useState(false);
  const [newKeyForm, setNewKeyForm] = useState({
    title: '',
    category: 'Client / IDE API',
    secretValue: '',
    origin: '',
    severity: 'high' as const,
    notes: ''
  });

  // Load vault items
  useEffect(() => {
    const loaded = localStorage.getItem('sentry_keys_vault');
    if (loaded) {
      try {
        setVaultItems(JSON.parse(loaded));
      } catch (err) {
        console.error('Error loading vault:', err);
      }
    }
  }, []);

  const saveVault = (items: VaultItem[]) => {
    setVaultItems(items);
    localStorage.setItem('sentry_keys_vault', JSON.stringify(items));
  };

  // Auth Handlers
  const handleUnlock = (e: FormEvent) => {
    e.preventDefault();
    if (pinInput === adminPin) {
      setIsUnlocked(true);
      setPinError(null);
      setPinInput('');
    } else {
      setPinError('Invalid security access credentials. Use the default passcode "admin123" or configure a customized password.');
    }
  };

  const handleSetupPin = (e: FormEvent) => {
    e.preventDefault();
    if (newPin.trim().length < 4) {
      setPinError('Security passcode must be at least 4 characters long.');
      return;
    }
    localStorage.setItem('sentry_admin_pin', newPin);
    setAdminPin(newPin);
    setIsPinSetup(false);
    setIsUnlocked(true);
    setPinError(null);
    setNewPin('');
  };

  const handleLock = () => {
    setIsUnlocked(false);
    setPinInput('');
  };

  // Vault Actions
  const handleToggleCompromised = (id: string) => {
    const updated = vaultItems.map(item => {
      if (item.id === id) {
        return { ...item, compromised: !item.compromised };
      }
      return item;
    });
    saveVault(updated);
  };

  const handleDeleteItem = (id: string) => {
    const filtered = vaultItems.filter(item => item.id !== id);
    saveVault(filtered);
  };

  const handleSaveNotes = (id: string) => {
    const notesToSave = editingNotes[id] || '';
    const updated = vaultItems.map(item => {
      if (item.id === id) {
        return { ...item, notes: notesToSave };
      }
      return item;
    });
    saveVault(updated);
    
    // Clear editing state for visual feedback
    const nextEditing = { ...editingNotes };
    delete nextEditing[id];
    setEditingNotes(nextEditing);
  };

  const handleManualAdd = (e: FormEvent) => {
    e.preventDefault();
    if (!newKeyForm.title || !newKeyForm.secretValue) return;

    const newItem: VaultItem = {
      id: `manual-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date().toISOString(),
      title: newKeyForm.title,
      category: newKeyForm.category,
      secretValue: newKeyForm.secretValue,
      evidence: `Manually cataloged asset: ${newKeyForm.secretValue.substring(0, 5)}...`,
      origin: newKeyForm.origin || 'Admin Manual Inventory',
      severity: newKeyForm.severity,
      compromised: false,
      notes: newKeyForm.notes
    };

    saveVault([newItem, ...vaultItems]);
    setShowAddForm(false);
    setNewKeyForm({
      title: '',
      category: 'Custom API Key',
      secretValue: '',
      origin: '',
      severity: 'high',
      notes: ''
    });
  };

  const exportVault = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(vaultItems, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", "sentry_admin_vault_backup.json");
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const toggleReveal = (id: string) => {
    setRevealedSecrets(prev => ({ ...prev, [id]: !prev[id] }));
  };

  const filteredVaultItems = vaultItems.filter(item => {
    if (selectedCategoryFilter === 'all') return true;
    return getParentCategory(item.category, item.title, item.secretValue) === selectedCategoryFilter;
  });

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm min-h-[500px]">
      
      {/* Locked Authentication State */}
      {!isUnlocked ? (
        <div className="flex flex-col items-center justify-center py-16 text-center max-w-sm mx-auto space-y-6">
          <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-indigo-50 border border-indigo-150 text-indigo-600 shadow-xs animate-bounce">
            <Lock className="h-7 w-7" />
          </div>

          <div>
            <h2 className="text-xl font-bold tracking-tight text-slate-900">
              Admin Vault Authorization
            </h2>
            <p className="mt-2 text-xs text-slate-500 font-medium">
              This repository contains escrowed corporate secrets and exposed keys tracked by compliance officers. Authenticate to unlock.
            </p>
          </div>

          {pinError && (
            <div className="w-full text-xs bg-rose-50 border border-rose-100 text-rose-700 px-3 py-2.5 rounded-lg font-semibold leading-relaxed">
              {pinError}
            </div>
          )}

          {isPinSetup ? (
            <form onSubmit={handleSetupPin} className="w-full space-y-3">
              <div>
                <label className="block text-left text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1">
                  Configure Initial Passphrase
                </label>
                <input
                  type="password"
                  placeholder="Create your admin passcode"
                  value={newPin}
                  onChange={(e) => setNewPin(e.target.value)}
                  className="block w-full rounded-xl border border-slate-300 py-2.5 px-3.5 text-center text-sm font-semibold select-all focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                />
              </div>
              <button
                type="submit"
                className="w-full rounded-xl bg-slate-900 py-2.5 text-xs font-bold text-white hover:bg-slate-800 transition-colors cursor-pointer"
              >
                Set Administrative Pin & Unlock
              </button>
            </form>
          ) : (
            <form onSubmit={handleUnlock} className="w-full space-y-3">
              <div>
                <label className="block text-left text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1">
                  Secure Passkey
                </label>
                <input
                  type="password"
                  placeholder="Enter administrator passcode"
                  value={pinInput}
                  onChange={(e) => setPinInput(e.target.value)}
                  className="block w-full rounded-xl border border-slate-300 py-2.5 px-3.5 text-center text-sm font-semibold focus:border-indigo-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                />
                <span className="mt-1 block text-left text-[10px] text-slate-400 font-semibold italic">
                  Default developer passkey is: <code className="bg-slate-100 px-1 py-0.5 rounded text-indigo-600 font-bold font-mono">admin123</code>
                </span>
              </div>
              <button
                type="submit"
                className="w-full rounded-xl bg-slate-900 py-2.5 text-xs font-bold text-white hover:bg-slate-800 transition-colors cursor-pointer"
              >
                Authenticate Session
              </button>
            </form>
          )}
        </div>
      ) : (
        /* Unlocked Admin Workspace Board */
        <div className="space-y-6 animate-fadeIn">
          
          {/* Unlocked Banner Control */}
          <div className="flex flex-col justify-between items-start border-b border-slate-100 pb-5 sm:flex-row sm:items-center space-y-4 sm:space-y-0">
            <div>
              <div className="flex items-center space-x-2">
                <span className="inline-flex h-2.5 w-2.5 rounded-full bg-emerald-500 animate-pulse"></span>
                <h2 className="text-lg font-bold text-slate-950 flex items-center space-x-2">
                  <Unlock className="h-4.5 w-4.5 text-indigo-600" />
                  <span>Admin Credentials Escrow Vault</span>
                </h2>
              </div>
              <p className="text-xs text-slate-500 font-medium mt-0.5">
                Centralized ledger tracking exposed credentials, rotation audits, and contractor alignment notes.
              </p>
            </div>

            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => setShowAddForm(!showAddForm)}
                className="flex items-center space-x-1.5 rounded-xl border border-slate-205 bg-slate-50 px-3 py-2 text-xs font-bold text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer"
              >
                <Plus className="h-3.5 w-3.5 text-indigo-600" />
                <span>Add Key manually</span>
              </button>

              <button
                onClick={exportVault}
                disabled={vaultItems.length === 0}
                className="flex items-center space-x-1.5 rounded-xl border border-slate-205 bg-slate-50 px-3 py-2 text-xs font-bold text-slate-700 hover:bg-slate-100 transition-colors disabled:opacity-40 cursor-pointer"
              >
                <FileJson className="h-3.5 w-3.5 text-slate-500" />
                <span>Export Ledger</span>
              </button>

              <button
                onClick={handleLock}
                className="flex items-center space-x-1.5 rounded-xl bg-slate-900 px-3.5 py-2 text-xs font-bold text-white hover:bg-slate-800 transition-colors cursor-pointer"
              >
                <Lock className="h-3.5 w-3.5 text-indigo-400" />
                <span>Lock Vault</span>
              </button>
            </div>
          </div>

          {/* Category Filter Metrics & Navigation Tabs */}
          <div className="bg-slate-50/85 border border-slate-200 rounded-xl p-4.5 space-y-3.5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1.5 border-b border-slate-200 pb-2">
              <span className="text-[11px] font-extrabold uppercase tracking-wider text-slate-500">
                Administrative Classification Filter
              </span>
              <span className="text-[11px] text-slate-500 font-bold bg-slate-200/50 px-2 py-0.5 rounded-md">
                Showing {filteredVaultItems.length} of {vaultItems.length} escrowed secrets
              </span>
            </div>

            <div className="flex flex-wrap gap-2">
              {/* ALL */}
              <button
                type="button"
                onClick={() => setSelectedCategoryFilter('all')}
                className={`flex items-center space-x-2 rounded-lg border px-3 py-1.5 text-xs font-bold transition-all cursor-pointer ${
                  selectedCategoryFilter === 'all'
                    ? 'bg-slate-900 border-slate-900 text-white shadow-xs'
                    : 'bg-white border-slate-200 text-slate-700 hover:bg-slate-100/80'
                }`}
              >
                <KeyRound className="h-3.5 w-3.5" />
                <span>All Secrets</span>
                <span className={`text-[10px] font-extrabold px-1.5 py-0.5 rounded ${
                  selectedCategoryFilter === 'all' ? 'bg-slate-800 text-indigo-300' : 'bg-slate-100 text-slate-600'
                }`}>
                  {vaultItems.length}
                </span>
              </button>

              {/* Client / IDE API */}
              <button
                type="button"
                onClick={() => setSelectedCategoryFilter('client_ide')}
                className={`flex items-center space-x-2 rounded-lg border px-3 py-1.5 text-xs font-bold transition-all cursor-pointer ${
                  selectedCategoryFilter === 'client_ide'
                    ? 'bg-emerald-600 border-emerald-600 text-white shadow-xs'
                    : 'bg-white border-slate-200 text-slate-705 hover:bg-slate-100/80'
                }`}
              >
                <Code className="h-3.5 w-3.5" />
                <span>Client / IDE API</span>
                <span className={`text-[10px] font-extrabold px-1.5 py-0.5 rounded ${
                  selectedCategoryFilter === 'client_ide' ? 'bg-emerald-800 text-emerald-200' : 'bg-emerald-50 text-emerald-700'
                }`}>
                  {vaultItems.filter(item => getParentCategory(item.category, item.title, item.secretValue) === 'client_ide').length}
                </span>
              </button>

              {/* Backend Firebase API */}
              <button
                type="button"
                onClick={() => setSelectedCategoryFilter('firebase')}
                className={`flex items-center space-x-2 rounded-lg border px-3 py-1.5 text-xs font-bold transition-all cursor-pointer ${
                  selectedCategoryFilter === 'firebase'
                    ? 'bg-orange-600 border-orange-650 text-white shadow-xs'
                    : 'bg-white border-slate-200 text-slate-755 hover:bg-slate-100/80'
                }`}
              >
                <Layers className="h-3.5 w-3.5" />
                <span>Backend Firebase API</span>
                <span className={`text-[10px] font-extrabold px-1.5 py-0.5 rounded ${
                  selectedCategoryFilter === 'firebase' ? 'bg-orange-800 text-orange-200' : 'bg-orange-50 text-orange-700'
                }`}>
                  {vaultItems.filter(item => getParentCategory(item.category, item.title, item.secretValue) === 'firebase').length}
                </span>
              </button>

              {/* AWS API */}
              <button
                type="button"
                onClick={() => setSelectedCategoryFilter('aws')}
                className={`flex items-center space-x-2 rounded-lg border px-3 py-1.5 text-xs font-bold transition-all cursor-pointer ${
                  selectedCategoryFilter === 'aws'
                    ? 'bg-amber-600 border-amber-600 text-white shadow-xs'
                    : 'bg-white border-slate-200 text-slate-705 hover:bg-slate-100/80'
                }`}
              >
                <Cloud className="h-3.5 w-3.5" />
                <span>AWS API</span>
                <span className={`text-[10px] font-extrabold px-1.5 py-0.5 rounded ${
                  selectedCategoryFilter === 'aws' ? 'bg-amber-800 text-amber-200' : 'bg-amber-50 text-amber-700'
                }`}>
                  {vaultItems.filter(item => getParentCategory(item.category, item.title, item.secretValue) === 'aws').length}
                </span>
              </button>

              {/* AI Generative API */}
              <button
                type="button"
                onClick={() => setSelectedCategoryFilter('ai')}
                className={`flex items-center space-x-2 rounded-lg border px-3 py-1.5 text-xs font-bold transition-all cursor-pointer ${
                  selectedCategoryFilter === 'ai'
                    ? 'bg-indigo-650 border-indigo-650 text-white shadow-xs'
                    : 'bg-white border-slate-200 text-slate-705 hover:bg-slate-100/80'
                }`}
              >
                <Sparkles className="h-3.5 w-3.5" />
                <span>AI Generative API</span>
                <span className={`text-[10px] font-extrabold px-1.5 py-0.5 rounded ${
                  selectedCategoryFilter === 'ai' ? 'bg-indigo-805 text-indigo-200' : 'bg-indigo-50 text-indigo-700'
                }`}>
                  {vaultItems.filter(item => getParentCategory(item.category, item.title, item.secretValue) === 'ai').length}
                </span>
              </button>

              {/* All other APIs */}
              <button
                type="button"
                onClick={() => setSelectedCategoryFilter('other')}
                className={`flex items-center space-x-2 rounded-lg border px-3 py-1.5 text-xs font-bold transition-all cursor-pointer ${
                  selectedCategoryFilter === 'other'
                    ? 'bg-slate-600 border-slate-650 text-white shadow-xs'
                    : 'bg-white border-slate-200 text-slate-705 hover:bg-slate-100/80'
                }`}
              >
                <Lock className="h-3.5 w-3.5" />
                <span>All other APIs</span>
                <span className={`text-[10px] font-extrabold px-1.5 py-0.5 rounded ${
                  selectedCategoryFilter === 'other' ? 'bg-slate-800 text-slate-200' : 'bg-slate-100 text-slate-600'
                }`}>
                  {vaultItems.filter(item => getParentCategory(item.category, item.title, item.secretValue) === 'other').length}
                </span>
              </button>
            </div>

            {selectedCategoryFilter !== 'all' && (
              <p className="text-[11px] text-slate-600 leading-normal bg-white border border-slate-150 rounded-lg p-2.5 animate-fadeIn shadow-xs font-medium">
                <strong>Platform Info:</strong> {PARENT_CATEGORIES[selectedCategoryFilter].desc}
              </p>
            )}
          </div>

          {/* Interactive Form: Manually Add Key */}
          {showAddForm && (
            <form onSubmit={handleManualAdd} className="rounded-xl border border-slate-200 bg-slate-50/60 p-5 space-y-4 animate-fadeIn">
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 border-b border-slate-100 pb-2 flex items-center space-x-1.5">
                <KeyRound className="h-4 w-4 text-indigo-600" />
                <span>Manually Escrow Security Credential</span>
              </h3>
              
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                <div>
                  <label className="block text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1">
                    Label Name
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. AWS Production Key"
                    value={newKeyForm.title}
                    onChange={(e) => setNewKeyForm({ ...newKeyForm, title: e.target.value })}
                    className="block w-full rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs text-slate-800 focus:outline-indigo-500"
                  />
                </div>

                <div>
                  <label className="block text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1">
                    Platform Category
                  </label>
                  <select
                    value={newKeyForm.category}
                    onChange={(e) => setNewKeyForm({ ...newKeyForm, category: e.target.value })}
                    className="block w-full rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs text-slate-800 focus:outline-indigo-500 font-semibold text-slate-700"
                  >
                    <option value="Client / IDE API">Client / IDE API — Web SDKs & Maps Platform</option>
                    <option value="Backend Firebase API">Backend Firebase API — Firebase / Firestore</option>
                    <option value="AWS API">AWS API — Amazon Cloud Web Services</option>
                    <option value="AI Generative API">AI Generative API — Gemini / OpenAI / LLM hosts</option>
                    <option value="All other APIs">All other APIs — Connection URLs, Databases & Webhooks</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1">
                    Key Severity Threat
                  </label>
                  <select
                    value={newKeyForm.severity}
                    onChange={(e) => setNewKeyForm({ ...newKeyForm, severity: e.target.value as any })}
                    className="block w-full rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs text-slate-800 focus:outline-indigo-500"
                  >
                    <option value="high">High Risk</option>
                    <option value="medium">Medium Risk</option>
                    <option value="low">Low Risk</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div>
                  <label className="block text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1">
                    Raw Secret Token Value
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="Paste actual private key or connection password..."
                    value={newKeyForm.secretValue}
                    onChange={(e) => setNewKeyForm({ ...newKeyForm, secretValue: e.target.value })}
                    className="block w-full rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs text-slate-800 focus:outline-indigo-500 font-mono"
                  />
                </div>

                <div>
                  <label className="block text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1">
                    Origin Hosting Hostname / Filename
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. config.py, billing-service.net"
                    value={newKeyForm.origin}
                    onChange={(e) => setNewKeyForm({ ...newKeyForm, origin: e.target.value })}
                    className="block w-full rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs text-slate-800 focus:outline-indigo-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1">
                  Administrative Resolution Notes
                </label>
                <textarea
                  rows={2}
                  placeholder="e.g. To be rotated in AWS console and set inside env variables on next deploy cycle."
                  value={newKeyForm.notes}
                  onChange={(e) => setNewKeyForm({ ...newKeyForm, notes: e.target.value })}
                  className="block w-full rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs text-slate-800 focus:outline-indigo-500"
                />
              </div>

              <div className="flex items-center space-x-2 pt-2">
                <button
                  type="submit"
                  className="rounded-lg bg-indigo-600 px-4 py-2 text-xs font-bold text-white hover:bg-indigo-700 cursor-pointer"
                >
                  Save to Vault
                </button>
                <button
                  type="button"
                  onClick={() => setShowAddForm(false)}
                  className="rounded-lg border border-slate-200 px-4 py-2 text-xs font-bold text-slate-600 hover:bg-slate-100 cursor-pointer"
                >
                  Cancel
                </button>
              </div>
            </form>
          )}

          {/* List display */}
          {filteredVaultItems.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-center rounded-xl border border-dashed border-slate-205 p-6 bg-slate-50/40">
              <KeyRound className="h-10 w-10 text-slate-305 mb-2" />
              <h4 className="text-sm font-bold text-slate-900">No Credentials Found</h4>
              <p className="max-w-md text-xs text-slate-550 leading-relaxed font-normal mt-1">
                {selectedCategoryFilter === 'all' 
                  ? 'You do not have any saved findings. Execute a scan and escrow credentials, or click "Add Key manually" above.'
                  : `There are currently no active secrets categorizing under "${PARENT_CATEGORIES[selectedCategoryFilter].label}".`}
              </p>
              {selectedCategoryFilter !== 'all' && (
                <button
                  type="button"
                  onClick={() => setSelectedCategoryFilter('all')}
                  className="mt-4 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-xs font-bold font-sans transition-all cursor-pointer"
                >
                  Clear filter selection
                </button>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              {filteredVaultItems.map((item) => (
                <div 
                  key={item.id} 
                  className={`rounded-xl border p-5 bg-white shadow-xs space-y-4 transition ${
                    item.compromised 
                      ? 'border-rose-150 bg-rose-50/10' 
                      : 'border-slate-200 hover:border-slate-300'
                  }`}
                >
                  {/* Item metadata row */}
                  <div className="flex flex-col justify-between sm:flex-row sm:items-center space-y-2.5 sm:space-y-0">
                    <div>
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-sm font-bold text-slate-950">{item.title}</span>
                        {(() => {
                          const parentCatKey = getParentCategory(item.category, item.title, item.secretValue);
                          const catSpec = PARENT_CATEGORIES[parentCatKey];
                          return (
                            <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[10px] font-bold ${catSpec.color}`} title={catSpec.desc}>
                              {catSpec.label}
                            </span>
                          );
                        })()}
                        <span className="rounded bg-slate-100 px-2 py-0.5 text-[10px] font-semibold text-slate-500 font-mono">
                          {item.category}
                        </span>
                        {item.compromised ? (
                          <span className="inline-flex items-center space-x-1 rounded-sm bg-rose-50 px-2 py-0.5 text-[10px] font-bold text-rose-700 border border-rose-150">
                            <ShieldAlert className="h-3 w-3" />
                            <span>Risk Confirmed</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center space-x-1 rounded-sm bg-emerald-50 px-2 py-0.5 text-[10px] font-bold text-emerald-700 border border-emerald-150">
                            <CheckCircle className="h-3 w-3" />
                            <span>Remediated / Passive</span>
                          </span>
                        )}
                      </div>
                      <div className="text-[10px] text-slate-500 mt-1 font-semibold">
                        Discovered Origin: <span className="text-slate-800">{item.origin}</span> &bull; Cataloged: {new Date(item.timestamp).toLocaleString()}
                      </div>
                    </div>

                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => handleToggleCompromised(item.id)}
                        className={`rounded-lg px-3 py-1.5 text-xs font-bold border transition-colors cursor-pointer ${
                          item.compromised 
                            ? 'bg-rose-50 text-rose-700 border-rose-200 hover:bg-rose-100' 
                            : 'bg-slate-50 text-slate-600 border-slate-200 hover:bg-slate-100'
                        }`}
                      >
                        {item.compromised ? 'Mark Remediated' : 'Mark active risk'}
                      </button>

                      <button
                        onClick={() => handleDeleteItem(item.id)}
                        className="rounded-lg p-2 text-slate-400 hover:text-red-650 hover:bg-red-50 border border-transparent transition-colors cursor-pointer"
                        title="Delete from Vault"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </div>

                  {/* Secret Block Display */}
                  <div className="rounded-lg border border-slate-200 bg-slate-900 text-[11px] font-mono p-3 flex items-center justify-between">
                    <span className="text-slate-300 truncate font-semibold select-all">
                      {revealedSecrets[item.id] ? item.secretValue : '************************************************'}
                    </span>
                    <button
                      type="button"
                      onClick={() => toggleReveal(item.id)}
                      className="text-indigo-400 hover:text-indigo-300 flex items-center text-[10px] font-bold shrink-0 ml-4 cursor-pointer"
                    >
                      {revealedSecrets[item.id] ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                    </button>
                  </div>

                  {/* Administrative Remarks/Notes editor */}
                  <div className="pt-2">
                    <label className="block text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1">
                      Administrative Action History / Notes
                    </label>
                    <div className="flex items-start space-x-2">
                      <textarea
                        rows={1}
                        placeholder="Add a remark here..."
                        value={editingNotes[item.id] !== undefined ? editingNotes[item.id] : (item.notes || '')}
                        onChange={(e) => setEditingNotes({ ...editingNotes, [item.id]: e.target.value })}
                        className="block w-full rounded-lg border border-slate-200 bg-slate-50 py-1.5 px-3 text-xs text-slate-800 focus:bg-white focus:outline-indigo-500"
                      />
                      <button
                        onClick={() => handleSaveNotes(item.id)}
                        disabled={editingNotes[item.id] === undefined}
                        className="flex items-center space-x-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 disabled:opacity-40 text-white font-bold text-xs py-1.5 px-3 shrink-0 cursor-pointer"
                      >
                        <Save className="h-3 w-3" />
                        <span>Save Note</span>
                      </button>
                    </div>
                  </div>

                </div>
              ))}
            </div>
          )}

        </div>
      )}

    </div>
  );
}
