import React, { useState, useEffect, useRef, useCallback } from 'react';
import { createRoot } from 'react-dom/client';
import { 
  Lock, Unlock, Plus, Trash2, Copy, Eye, EyeOff, 
  Search, Save, X, RefreshCw, Key, ShieldCheck, LogOut,
  ExternalLink, FileText, AlertTriangle, Clock, Github, Cloud, CloudOff
} from 'lucide-react';

// --- CRYPTO UTILITIES ---

const PBKDF2_ITERATIONS = 100000;
const SALT_SIZE = 16;
const IV_SIZE = 12; // 96 bits for GCM
const KEY_ALGO = 'AES-GCM';
const KEY_LENGTH = 256;
const AUTO_LOCK_TIMEOUT = 30 * 1000; // 30 secondi
const CLIPBOARD_CLEAR_TIMEOUT = 10 * 1000; // 10 secondi
const MAX_LOGIN_ATTEMPTS = 3;
const LOCKOUT_DURATION = 30; // 30 secondi

// GitHub Config
const VAULT_FILENAME = 'vault.enc.json';

// Helper: ArrayBuffer to Base64
function bufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

// Helper: Base64 to ArrayBuffer
function base64ToBuffer(base64: string): ArrayBuffer {
  const binary = window.atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// Helper: Generate Random Salt
function generateSalt(): Uint8Array {
  return window.crypto.getRandomValues(new Uint8Array(SALT_SIZE));
}

// Helper: Generate Random IV
function generateIV(): Uint8Array {
  return window.crypto.getRandomValues(new Uint8Array(IV_SIZE));
}

// 1. Derive Key from Password and Salt using PBKDF2
async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  if (!window.crypto || !window.crypto.subtle) {
    throw new Error("Web Crypto API non supportata. Assicurati di usare HTTPS o localhost.");
  }

  const enc = new TextEncoder();
  const keyMaterial = await window.crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return window.crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: KEY_ALGO, length: KEY_LENGTH },
    false,
    ["encrypt", "decrypt"]
  );
}

// 2. Encrypt Data
async function encryptData(key: CryptoKey, data: any): Promise<{ ciphertext: string, iv: string }> {
  const iv = generateIV();
  const enc = new TextEncoder();
  const encodedData = enc.encode(JSON.stringify(data));

  const encryptedContent = await window.crypto.subtle.encrypt(
    { name: KEY_ALGO, iv: iv },
    key,
    encodedData
  );

  return {
    iv: bufferToBase64(iv.buffer),
    ciphertext: bufferToBase64(encryptedContent),
  };
}

// 3. Decrypt Data
async function decryptData(key: CryptoKey, ivBase64: string, ciphertextBase64: string): Promise<any> {
  const iv = base64ToBuffer(ivBase64);
  const ciphertext = base64ToBuffer(ciphertextBase64);

  try {
    const decryptedContent = await window.crypto.subtle.decrypt(
      { name: KEY_ALGO, iv: new Uint8Array(iv) },
      key,
      ciphertext
    );

    const dec = new TextDecoder();
    return JSON.parse(dec.decode(decryptedContent));
  } catch (e) {
    console.error("Decryption failed:", e);
    throw new Error("Password errata o dati corrotti");
  }
}

// --- GITHUB API UTILITIES ---

interface GitHubCredentials {
  owner: string;
  repo: string;
  token: string;
}

interface GitHubFileResponse {
  content: string;
  sha: string;
}

async function githubGetFile(creds: GitHubCredentials): Promise<GitHubFileResponse | null> {
  const url = `https://api.github.com/repos/${creds.owner}/${creds.repo}/contents/${VAULT_FILENAME}`;
  
  const response = await fetch(url, {
    headers: {
      'Authorization': `Bearer ${creds.token}`,
      'Accept': 'application/vnd.github.v3+json',
    },
  });

  if (response.status === 404) {
    return null; // File doesn't exist
  }

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.message || 'Errore GitHub API');
  }

  const data = await response.json();
  return {
    content: atob(data.content.replace(/\n/g, '')), // GitHub returns base64 encoded
    sha: data.sha,
  };
}

async function githubSaveFile(
  creds: GitHubCredentials, 
  content: string, 
  sha: string | null,
  message: string = 'Update vault'
): Promise<string> {
  const url = `https://api.github.com/repos/${creds.owner}/${creds.repo}/contents/${VAULT_FILENAME}`;
  
  const body: any = {
    message,
    content: btoa(content), // Base64 encode for GitHub
  };

  if (sha) {
    body.sha = sha; // Required for updates
  }

  const response = await fetch(url, {
    method: 'PUT',
    headers: {
      'Authorization': `Bearer ${creds.token}`,
      'Accept': 'application/vnd.github.v3+json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.message || 'Errore salvataggio su GitHub');
  }

  const data = await response.json();
  return data.content.sha; // Return new SHA for future updates
}

async function githubTestConnection(creds: GitHubCredentials): Promise<boolean> {
  const url = `https://api.github.com/repos/${creds.owner}/${creds.repo}`;
  
  const response = await fetch(url, {
    headers: {
      'Authorization': `Bearer ${creds.token}`,
      'Accept': 'application/vnd.github.v3+json',
    },
  });

  return response.ok;
}

// --- TYPES & CONSTANTS ---

interface VaultEntry {
  id: string;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  updatedAt: number;
}

interface VaultStorage {
  salt: string;
  iv: string;
  ciphertext: string;
}

// --- COMPONENTS ---

const App = () => {
  // Application State - now includes 'github_login' as first step
  const [status, setStatus] = useState<'github_login' | 'loading' | 'setup' | 'locked' | 'unlocked'>('github_login');
  const [entries, setEntries] = useState<VaultEntry[]>([]);
  
  // GitHub credentials (stored in ref for security)
  const githubCredsRef = useRef<GitHubCredentials | null>(null);
  const fileShaRef = useRef<string | null>(null);
  
  // Sync status
  const [syncStatus, setSyncStatus] = useState<'idle' | 'syncing' | 'error'>('idle');
  
  // Master key ref
  const masterKeyRef = useRef<CryptoKey | null>(null);
  // Salt ref (needed to re-encrypt with same salt)
  const saltRef = useRef<string | null>(null);
  
  const [searchQuery, setSearchQuery] = useState('');
  
  // Modals / Overlays
  const [isEditing, setIsEditing] = useState(false);
  const [editingItem, setEditingItem] = useState<VaultEntry | null>(null);
  const [showGenerator, setShowGenerator] = useState(false);
  const [itemToDelete, setItemToDelete] = useState<string | null>(null);

  // Auto-Lock Timer
  const autoLockTimerRef = useRef<number | null>(null);

  const resetAutoLockTimer = useCallback(() => {
    if (autoLockTimerRef.current) clearTimeout(autoLockTimerRef.current);
    if (status === 'unlocked') {
      autoLockTimerRef.current = window.setTimeout(() => {
        handleLock();
        console.log("Auto-locked due to inactivity");
      }, AUTO_LOCK_TIMEOUT);
    }
  }, [status]);

  // Setup Activity Listeners for Auto-Lock
  useEffect(() => {
    const events = ['mousedown', 'keydown', 'scroll', 'touchstart'];
    const handler = () => resetAutoLockTimer();
    
    if (status === 'unlocked') {
      events.forEach(e => window.addEventListener(e, handler));
      resetAutoLockTimer();
    }

    return () => {
      events.forEach(e => window.removeEventListener(e, handler));
      if (autoLockTimerRef.current) clearTimeout(autoLockTimerRef.current);
    };
  }, [status, resetAutoLockTimer]);

  // --- GITHUB LOGIN ---
  const handleGitHubLogin = async (owner: string, repo: string, token: string): Promise<void> => {
    const creds: GitHubCredentials = { owner, repo, token };
    
    // Test connection
    const isValid = await githubTestConnection(creds);
    if (!isValid) {
      throw new Error("Impossibile connettersi al repository. Verifica owner, repo e token.");
    }
    
    githubCredsRef.current = creds;
    setStatus('loading');
    
    // Check if vault exists
    const existingFile = await githubGetFile(creds);
    
    if (existingFile) {
      fileShaRef.current = existingFile.sha;
      // Vault exists, go to unlock
      setStatus('locked');
    } else {
      // No vault, go to setup
      setStatus('setup');
    }
  };

  // --- ACTIONS ---

  const handleSetup = async (password: string): Promise<void> => {
    if (!githubCredsRef.current) throw new Error("GitHub non configurato");
    
    const salt = generateSalt();
    const key = await deriveKey(password, salt);
    const initialData: VaultEntry[] = [];
    const encrypted = await encryptData(key, initialData);

    const storageData: VaultStorage = {
      salt: bufferToBase64(salt.buffer),
      iv: encrypted.iv,
      ciphertext: encrypted.ciphertext
    };

    // Save to GitHub
    setSyncStatus('syncing');
    try {
      const newSha = await githubSaveFile(
        githubCredsRef.current,
        JSON.stringify(storageData, null, 2),
        null,
        'Initialize vault'
      );
      fileShaRef.current = newSha;
      saltRef.current = storageData.salt;
      setSyncStatus('idle');
    } catch (e) {
      setSyncStatus('error');
      throw e;
    }
    
    masterKeyRef.current = key;
    setEntries(initialData);
    setStatus('unlocked');
  };

  const handleUnlock = async (password: string): Promise<void> => {
    if (!githubCredsRef.current) throw new Error("GitHub non configurato");
    
    // Fetch latest from GitHub
    setSyncStatus('syncing');
    const file = await githubGetFile(githubCredsRef.current);
    setSyncStatus('idle');
    
    if (!file) throw new Error("Vault non trovato su GitHub");
    
    fileShaRef.current = file.sha;
    const stored: VaultStorage = JSON.parse(file.content);
    const salt = new Uint8Array(base64ToBuffer(stored.salt));
    
    const key = await deriveKey(password, salt);
    const data = await decryptData(key, stored.iv, stored.ciphertext);
    
    saltRef.current = stored.salt;
    masterKeyRef.current = key;
    setEntries(data);
    setStatus('unlocked');
  };

  const handleLock = () => {
    masterKeyRef.current = null;
    saltRef.current = null;
    setEntries([]);
    setStatus('locked');
  };

  const handleLogout = () => {
    masterKeyRef.current = null;
    saltRef.current = null;
    githubCredsRef.current = null;
    fileShaRef.current = null;
    setEntries([]);
    setStatus('github_login');
  };

  const saveVault = async (newEntries: VaultEntry[]) => {
    if (!masterKeyRef.current || !githubCredsRef.current || !saltRef.current) return;
    
    setEntries(newEntries);
    setSyncStatus('syncing');

    try {
      const encrypted = await encryptData(masterKeyRef.current, newEntries);

      const newStorage: VaultStorage = {
        salt: saltRef.current,
        iv: encrypted.iv, 
        ciphertext: encrypted.ciphertext
      };

      const newSha = await githubSaveFile(
        githubCredsRef.current,
        JSON.stringify(newStorage, null, 2),
        fileShaRef.current,
        `Update vault - ${new Date().toISOString()}`
      );
      
      fileShaRef.current = newSha;
      setSyncStatus('idle');
    } catch (e) {
      console.error("Errore salvataggio:", e);
      setSyncStatus('error');
      alert("Errore durante il salvataggio su GitHub. Riprova.");
    }
  };

  const addOrUpdateEntry = (entry: VaultEntry) => {
    let newEntries;
    if (entries.find(e => e.id === entry.id)) {
      newEntries = entries.map(e => e.id === entry.id ? entry : e);
    } else {
      newEntries = [...entries, entry];
    }
    saveVault(newEntries);
    setIsEditing(false);
    setEditingItem(null);
  };

  const confirmDelete = () => {
    if (!itemToDelete) return;
    const newEntries = entries.filter(e => e.id !== itemToDelete);
    saveVault(newEntries);
    setItemToDelete(null);
  };

  // --- RENDERERS ---

  if (status === 'github_login') {
    return <GitHubLoginScreen onLogin={handleGitHubLogin} />;
  }

  if (status === 'loading') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-900 text-slate-200">
        <div className="flex items-center gap-3">
          <RefreshCw className="w-6 h-6 animate-spin text-emerald-400" />
          <span>Connessione a GitHub...</span>
        </div>
      </div>
    );
  }

  if (status === 'setup') {
    return <SetupScreen onSetup={handleSetup} onBack={handleLogout} />;
  }

  if (status === 'locked') {
    return <UnlockScreen 
      onUnlock={handleUnlock} 
      onBack={handleLogout} 
      syncStatus={syncStatus}
      githubCreds={githubCredsRef.current}
    />;
  }

  // UNLOCKED DASHBOARD
  const filteredEntries = entries.filter(e => 
    e.title.toLowerCase().includes(searchQuery.toLowerCase()) || 
    e.username.toLowerCase().includes(searchQuery.toLowerCase()) ||
    e.url.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="min-h-screen flex flex-col bg-slate-900 text-slate-100 font-sans selection:bg-indigo-500 selection:text-white">
      {/* HEADER */}
      <header className="bg-slate-800 border-b border-slate-700 sticky top-0 z-10 shadow-lg">
        <div className="max-w-5xl mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-8 h-8 text-emerald-400" />
            <h1 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-emerald-400 to-teal-500">
              ZK Vault
            </h1>
            {/* Sync Status Indicator */}
            <div className="ml-3 flex items-center gap-1">
              {syncStatus === 'syncing' && (
                <span className="flex items-center gap-1 text-xs text-amber-400">
                  <RefreshCw className="w-3 h-3 animate-spin" /> Sync...
                </span>
              )}
              {syncStatus === 'idle' && (
                <span className="flex items-center gap-1 text-xs text-emerald-400">
                  <Cloud className="w-3 h-3" />
                </span>
              )}
              {syncStatus === 'error' && (
                <span className="flex items-center gap-1 text-xs text-rose-400">
                  <CloudOff className="w-3 h-3" /> Errore
                </span>
              )}
            </div>
          </div>
          
          <div className="flex items-center gap-4">
             <button 
              onClick={() => setShowGenerator(true)}
              className="p-2 text-slate-400 hover:text-white transition-colors"
              title="Generatore Password"
            >
              <RefreshCw className="w-5 h-5" />
            </button>
            <div className="h-6 w-px bg-slate-700 mx-2 hidden sm:block"></div>
            <button 
              onClick={handleLock}
              className="flex items-center gap-2 px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg text-sm font-medium transition-all"
              title="Blocca vault"
            >
              <Lock className="w-4 h-4" />
              <span className="hidden sm:inline">Blocca</span>
            </button>
          </div>
        </div>
      </header>

      {/* MAIN CONTENT */}
      <main className="flex-1 w-full max-w-5xl mx-auto px-4 py-8">
        
        {/* TOOLBAR */}
        <div className="flex flex-col sm:flex-row gap-4 mb-8 justify-between">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" />
            <input 
              type="text" 
              placeholder="Cerca credenziali..." 
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-3 bg-slate-800 border border-slate-700 rounded-xl focus:ring-2 focus:ring-emerald-500 focus:border-transparent outline-none transition-all placeholder:text-slate-500"
            />
          </div>
          <button 
            onClick={() => { setEditingItem(null); setIsEditing(true); }}
            className="flex items-center justify-center gap-2 px-6 py-3 bg-emerald-600 hover:bg-emerald-500 text-white rounded-xl font-medium shadow-lg shadow-emerald-900/20 transition-all active:scale-95"
          >
            <Plus className="w-5 h-5" />
            Aggiungi
          </button>
        </div>

        {/* LIST */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredEntries.length === 0 ? (
            <div className="col-span-full text-center py-20 text-slate-500 bg-slate-800/50 rounded-2xl border-2 border-dashed border-slate-700">
              <Search className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p className="text-lg font-medium">Nessuna credenziale trovata</p>
              <p className="text-sm">Inizia aggiungendo la tua prima password sicura.</p>
            </div>
          ) : (
            filteredEntries.map(entry => (
              <CredentialCard 
                key={entry.id} 
                entry={entry} 
                onEdit={() => { setEditingItem(entry); setIsEditing(true); }}
                onDelete={() => setItemToDelete(entry.id)}
              />
            ))
          )}
        </div>
      </main>

      <footer className="pt-6 pb-20 text-center text-xs text-slate-600 border-t border-slate-800/50 mt-auto">
        <div className="flex items-center justify-center gap-2">
          <Github className="w-3 h-3" />
          <span>Auto-Sync • Zero-Knowledge • AES-256-GCM • Auto-Lock</span>
        </div>
      </footer>

      {/* MODALS */}
      {isEditing && (
        <EditorModal 
          initialData={editingItem} 
          onSave={addOrUpdateEntry} 
          onClose={() => setIsEditing(false)} 
        />
      )}

      {showGenerator && (
        <PasswordGeneratorModal onClose={() => setShowGenerator(false)} />
      )}

      {itemToDelete && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-800 w-full max-w-sm rounded-2xl shadow-2xl border border-slate-700 p-6">
            <div className="flex flex-col items-center text-center mb-6">
              <div className="w-12 h-12 rounded-full bg-rose-500/10 text-rose-500 flex items-center justify-center mb-4">
                <Trash2 className="w-6 h-6" />
              </div>
              <h3 className="text-xl font-bold text-white mb-2">Elimina Credenziale</h3>
              <p className="text-slate-400 text-sm">
                Sei sicuro di voler eliminare questa voce? L'azione è irreversibile.
              </p>
            </div>
            <div className="flex gap-3">
              <button 
                onClick={() => setItemToDelete(null)}
                className="flex-1 py-2 text-slate-300 hover:text-white font-medium bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
              >
                Annulla
              </button>
              <button 
                onClick={confirmDelete}
                className="flex-1 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg font-bold shadow-lg shadow-rose-900/20 transition-colors"
              >
                Elimina
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// --- SUB-COMPONENTS ---

const GitHubLoginScreen = ({ onLogin }: { onLogin: (owner: string, repo: string, token: string) => Promise<void> }) => {
  const [owner, setOwner] = useState('Ferio89-eng');
  const [repo, setRepo] = useState('zk-vault-data');
  const [token, setToken] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showToken, setShowToken] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    
    if (!owner.trim() || !repo.trim() || !token.trim()) {
      setError("Tutti i campi sono obbligatori.");
      return;
    }

    setLoading(true);
    try {
      await onLogin(owner.trim(), repo.trim(), token.trim());
    } catch (err: any) {
      console.error(err);
      setError(err.message || "Errore di connessione a GitHub.");
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-900 p-4">
      <div className="w-full max-w-md bg-slate-800 p-8 rounded-2xl shadow-2xl border border-slate-700">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-slate-700 text-white mb-4">
            <Github className="w-8 h-8" />
          </div>
          <h1 className="text-2xl font-bold text-white mb-2">Connessione al tuo Vault</h1>
        </div>
        
        {error && (
          <div className="mb-4 p-3 bg-rose-500/10 border border-rose-500/20 rounded-lg flex items-center gap-3 text-rose-200 text-sm">
            <AlertTriangle className="w-5 h-5 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-400 mb-1">Username (Owner)</label>
            <input 
              type="text" 
              required
              className="w-full px-4 py-3 bg-slate-900 border border-slate-700 rounded-lg focus:ring-2 focus:ring-emerald-500 outline-none text-white"
              value={owner}
              onChange={e => setOwner(e.target.value)}
              placeholder="es. Ferio89-eng"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-400 mb-1">Repository</label>
            <input 
              type="text" 
              required
              className="w-full px-4 py-3 bg-slate-900 border border-slate-700 rounded-lg focus:ring-2 focus:ring-emerald-500 outline-none text-white"
              value={repo}
              onChange={e => setRepo(e.target.value)}
              placeholder="es. zk-vault-data"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-400 mb-1">Personal Access Token</label>
            <div className="relative">
              <input 
                type={showToken ? 'text' : 'password'}
                required
                className="w-full px-4 py-3 bg-slate-900 border border-slate-700 rounded-lg focus:ring-2 focus:ring-emerald-500 outline-none text-white pr-12 font-mono text-sm"
                value={token}
                onChange={e => setToken(e.target.value)}
                placeholder="github_pat_..."
              />
              <button 
                type="button"
                onClick={() => setShowToken(!showToken)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white"
              >
                {showToken ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            <p className="text-xs text-slate-500 mt-1">
              Il token NON verrà salvato. Dovrai inserirlo ad ogni avvio.
            </p>
          </div>
          <button 
            type="submit" 
            disabled={loading}
            className="w-full py-3 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-bold transition-all disabled:opacity-50 disabled:cursor-not-allowed mt-4 flex justify-center items-center gap-2"
          >
            {loading && <RefreshCw className="w-4 h-4 animate-spin" />}
            {loading ? 'Connessione...' : 'Connetti'}
          </button>
        </form>
      </div>
    </div>
  );
};

const SetupScreen = ({ onSetup, onBack }: { onSetup: (pw: string) => Promise<void>, onBack: () => void }) => {
  const [p1, setP1] = useState('');
  const [p2, setP2] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    
    if (p1.length < 8) {
      setError("La password deve essere di almeno 8 caratteri.");
      return;
    }
    if (p1 !== p2) {
      setError("Le password non coincidono.");
      return;
    }

    setLoading(true);
    try {
      await new Promise(resolve => setTimeout(resolve, 50));
      await onSetup(p1);
    } catch (err: any) {
      console.error(err);
      setError(err.message || "Errore sconosciuto durante il setup.");
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-900 p-4">
      <div className="w-full max-w-md bg-slate-800 p-8 rounded-2xl shadow-2xl border border-slate-700">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-emerald-500/10 text-emerald-500 mb-4">
            <ShieldCheck className="w-8 h-8" />
          </div>
          <h1 className="text-2xl font-bold text-white mb-2">Crea il tuo Vault</h1>
          <p className="text-slate-400 text-sm">
            I tuoi dati saranno cifrati e salvati su GitHub. <br/>
            <strong className="text-rose-400">Non perdere la Master Password</strong>: non può essere recuperata.
          </p>
        </div>
        
        {error && (
          <div className="mb-4 p-3 bg-rose-500/10 border border-rose-500/20 rounded-lg flex items-center gap-3 text-rose-200 text-sm">
            <AlertTriangle className="w-5 h-5 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-400 mb-1">Master Password</label>
            <input 
              type="password" 
              required
              className="w-full px-4 py-3 bg-slate-900 border border-slate-700 rounded-lg focus:ring-2 focus:ring-emerald-500 outline-none text-white"
              value={p1}
              onChange={e => setP1(e.target.value)}
              placeholder="Minimo 8 caratteri"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-400 mb-1">Conferma Password</label>
            <input 
              type="password" 
              required
              className="w-full px-4 py-3 bg-slate-900 border border-slate-700 rounded-lg focus:ring-2 focus:ring-emerald-500 outline-none text-white"
              value={p2}
              onChange={e => setP2(e.target.value)}
              placeholder="Ripeti la password"
            />
          </div>
          <button 
            type="submit" 
            disabled={loading}
            className="w-full py-3 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-bold transition-all disabled:opacity-50 disabled:cursor-not-allowed mt-4 flex justify-center items-center gap-2"
          >
            {loading && <RefreshCw className="w-4 h-4 animate-spin" />}
            {loading ? 'Creazione vault...' : 'Crea Vault Sicuro'}
          </button>
        </form>
        
        <div className="mt-6 text-center">
          <button onClick={onBack} className="text-sm text-slate-500 hover:text-slate-300">
            ← Cambia Vault
          </button>
        </div>
      </div>
    </div>
  );
};

const UnlockScreen = ({ onUnlock, onBack, syncStatus, githubCreds }: { 
  onUnlock: (pw: string) => Promise<void>, 
  onBack: () => void,
  syncStatus: 'idle' | 'syncing' | 'error',
  githubCreds: GitHubCredentials | null
}) => {
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showChangePassword, setShowChangePassword] = useState(false);
  
  const [attempts, setAttempts] = useState(0);
  const [lockoutTime, setLockoutTime] = useState(0);

  useEffect(() => {
    let timer: number;
    if (lockoutTime > 0) {
      timer = window.setInterval(() => {
        setLockoutTime(prev => prev - 1);
      }, 1000);
    }
    return () => clearInterval(timer);
  }, [lockoutTime]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (lockoutTime > 0) return;

    setLoading(true);
    setError(null);
    try {
      await new Promise(resolve => setTimeout(resolve, 50));
      await onUnlock(password);
      setAttempts(0);
    } catch (err: any) {
      console.error(err);
      
      const newAttempts = attempts + 1;
      setAttempts(newAttempts);
      
      let errorMsg = err.message || "Password errata.";
      
      if (newAttempts >= MAX_LOGIN_ATTEMPTS) {
        setLockoutTime(LOCKOUT_DURATION);
        errorMsg = `Troppi tentativi. Attendi ${LOCKOUT_DURATION}s.`;
      } else {
         errorMsg += ` (${MAX_LOGIN_ATTEMPTS - newAttempts} tentativi rimanenti)`;
      }

      setError(errorMsg);
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-900 p-4">
      <div className="w-full max-w-md bg-slate-800 p-8 rounded-2xl shadow-2xl border border-slate-700">
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-blue-500/10 text-blue-500 mb-4">
            <Lock className="w-8 h-8" />
          </div>
          <h1 className="text-2xl font-bold text-white mb-2">Vault Bloccato</h1>
          <p className="text-slate-400 text-sm">Inserisci la Master Password per decifrare i dati.</p>
          {syncStatus === 'syncing' && (
            <p className="text-xs text-amber-400 mt-2 flex items-center justify-center gap-1">
              <RefreshCw className="w-3 h-3 animate-spin" /> Sincronizzazione con GitHub...
            </p>
          )}
        </div>

        {error && (
          <div className="mb-4 p-3 bg-rose-500/10 border border-rose-500/20 rounded-lg flex items-center gap-3 text-rose-200 text-sm">
            <AlertTriangle className="w-5 h-5 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <input 
            type="password" 
            required
            autoFocus
            disabled={lockoutTime > 0}
            className="w-full px-4 py-3 bg-slate-900 border border-slate-700 rounded-lg focus:ring-2 focus:ring-blue-500 outline-none text-white text-center tracking-widest disabled:opacity-50 disabled:cursor-not-allowed"
            value={password}
            onChange={e => setPassword(e.target.value)}
            placeholder="••••••••"
          />
          <button 
            type="submit" 
            disabled={loading || lockoutTime > 0}
            className={`w-full py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-bold transition-all disabled:opacity-50 flex justify-center items-center gap-2 ${lockoutTime > 0 ? 'cursor-not-allowed' : ''}`}
          >
            {lockoutTime > 0 ? (
              <><Clock className="w-4 h-4 animate-pulse" /> Riprova tra {lockoutTime}s</>
            ) : loading ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <><Unlock className="w-4 h-4"/> Sblocca</>
            )}
            {loading && !lockoutTime && 'Decifratura...'}
          </button>
        </form>
        
        <div className="mt-6 text-center space-y-2">
          <button 
            onClick={() => setShowChangePassword(true)} 
            className="text-sm text-slate-500 hover:text-slate-300 block mx-auto"
          >
            Cambia Password
          </button>
          <button onClick={onBack} className="text-sm text-slate-500 hover:text-slate-300 block mx-auto">
            ← Cambia Vault
          </button>
        </div>
      </div>

      {showChangePassword && githubCreds && (
        <ChangePasswordModal 
          githubCreds={githubCreds}
          onClose={() => setShowChangePassword(false)}
          onSuccess={() => {
            setShowChangePassword(false);
            alert("Password cambiata con successo! Usa la nuova password per sbloccare.");
          }}
        />
      )}
    </div>
  );
};

const CredentialCard: React.FC<{ entry: VaultEntry, onEdit: () => void, onDelete: () => void }> = ({ entry, onEdit, onDelete }) => {
  const [showPassword, setShowPassword] = useState(false);
  const [copied, setCopied] = useState<'user' | 'pass' | null>(null);

  const copyToClipboard = (text: string, type: 'user' | 'pass') => {
    navigator.clipboard.writeText(text);
    setCopied(type);
    
    setTimeout(() => setCopied(null), 2000);

    setTimeout(() => {
      navigator.clipboard.writeText('');
    }, CLIPBOARD_CLEAR_TIMEOUT);
  };

  return (
    <div className="bg-slate-800 rounded-xl border border-slate-700 hover:border-slate-600 transition-all shadow-sm hover:shadow-md group flex flex-col">
      <div className="p-5 flex-1">
        <div className="flex justify-between items-start mb-3">
          <div className="flex items-center gap-3">
             <div className="w-10 h-10 rounded-lg bg-slate-700 flex items-center justify-center text-slate-300 font-bold text-lg select-none">
                {entry.title.substring(0, 2).toUpperCase()}
             </div>
             <div>
               <h3 className="font-bold text-white leading-tight">{entry.title}</h3>
               {entry.url && (
                 <a href={entry.url} target="_blank" rel="noopener noreferrer" className="text-xs text-blue-400 hover:underline flex items-center gap-1 mt-0.5">
                   {new URL(entry.url).hostname} <ExternalLink className="w-2.5 h-2.5" />
                 </a>
               )}
             </div>
          </div>
          <button type="button" onClick={onEdit} className="text-slate-500 hover:text-white transition-colors">
            <Search className="w-4 h-4 opacity-0 group-hover:opacity-100" />
          </button>
        </div>

        <div className="space-y-3 mt-4">
          <div className="bg-slate-900/50 rounded-lg p-2 flex items-center justify-between border border-slate-700/50">
            <span className="text-sm text-slate-300 truncate font-mono px-1">{entry.username}</span>
            <button 
              type="button"
              onClick={() => copyToClipboard(entry.username, 'user')}
              className="p-1.5 text-slate-500 hover:text-white hover:bg-slate-700 rounded transition-colors relative"
              title="Copia Username"
            >
              {copied === 'user' ? <span className="text-xs font-bold text-emerald-500">Copied</span> : <Copy className="w-4 h-4" />}
            </button>
          </div>

          <div className="bg-slate-900/50 rounded-lg p-2 flex items-center justify-between border border-slate-700/50">
            <div className="flex-1 flex items-center gap-2 overflow-hidden px-1">
               <button type="button" onClick={() => setShowPassword(!showPassword)} className="text-slate-500 hover:text-slate-300">
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
               </button>
               <span className="text-sm text-slate-300 font-mono truncate">
                 {showPassword ? entry.password : '••••••••••••••••'}
               </span>
            </div>
            <button 
              type="button"
              onClick={() => copyToClipboard(entry.password, 'pass')}
              className="p-1.5 text-slate-500 hover:text-white hover:bg-slate-700 rounded transition-colors relative"
              title="Copia Password"
            >
              {copied === 'pass' ? <span className="text-xs font-bold text-emerald-500">Copied</span> : <Copy className="w-4 h-4" />}
            </button>
          </div>
        </div>
      </div>
      
      <div className="px-5 py-3 border-t border-slate-700/50 flex justify-between items-center bg-slate-800/50 rounded-b-xl">
        <span className="text-xs text-slate-500">Modificato {new Date(entry.updatedAt).toLocaleDateString()}</span>
        <div className="flex gap-2">
           <button type="button" onClick={onEdit} className="text-xs text-slate-400 hover:text-white font-medium px-2 py-1 hover:bg-slate-700 rounded transition-colors">
             Modifica
           </button>
           <button type="button" onClick={onDelete} className="text-xs text-rose-400 hover:text-rose-300 font-medium px-2 py-1 hover:bg-rose-900/30 rounded transition-colors">
             Elimina
           </button>
        </div>
      </div>
    </div>
  );
};

const EditorModal = ({ initialData, onSave, onClose }: { initialData: VaultEntry | null, onSave: (e: VaultEntry) => void, onClose: () => void }) => {
  const [title, setTitle] = useState(initialData?.title || '');
  const [username, setUsername] = useState(initialData?.username || '');
  const [password, setPassword] = useState(initialData?.password || '');
  const [url, setUrl] = useState(initialData?.url || '');
  const [notes, setNotes] = useState(initialData?.notes || '');
  const [showPass, setShowPass] = useState(false);

  const generateRandom = () => {
    const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+";
    const array = new Uint32Array(16);
    window.crypto.getRandomValues(array);
    let pass = "";
    for (let i = 0; i < 16; i++) {
      pass += chars.charAt(array[i] % chars.length);
    }
    setPassword(pass);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSave({
      id: initialData?.id || crypto.randomUUID(),
      title,
      username,
      password,
      url,
      notes,
      updatedAt: Date.now()
    });
  };

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-800 w-full max-w-lg rounded-2xl shadow-2xl border border-slate-700 flex flex-col max-h-[90vh]">
        <div className="p-6 border-b border-slate-700 flex justify-between items-center">
          <h2 className="text-xl font-bold text-white">{initialData ? 'Modifica Credenziale' : 'Nuova Credenziale'}</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-white"><X className="w-6 h-6" /></button>
        </div>
        
        <form onSubmit={handleSubmit} className="p-6 overflow-y-auto space-y-4">
          <div>
            <label className="block text-xs font-bold text-slate-500 uppercase tracking-wider mb-1">Titolo</label>
            <input 
              required
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-emerald-500 outline-none"
              value={title}
              onChange={e => setTitle(e.target.value)}
              placeholder="es. Google, Amazon, Banca..."
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-bold text-slate-500 uppercase tracking-wider mb-1">Username/Email</label>
              <input 
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-emerald-500 outline-none"
                value={username}
                onChange={e => setUsername(e.target.value)}
              />
            </div>
            <div>
              <label className="block text-xs font-bold text-slate-500 uppercase tracking-wider mb-1">URL (Opzionale)</label>
              <input 
                type="url"
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-emerald-500 outline-none"
                value={url}
                onChange={e => setUrl(e.target.value)}
                placeholder="https://..."
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-500 uppercase tracking-wider mb-1">Password</label>
            <div className="relative">
              <input 
                type={showPass ? 'text' : 'password'}
                required
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-emerald-500 outline-none pr-20 font-mono"
                value={password}
                onChange={e => setPassword(e.target.value)}
              />
              <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
                 <button type="button" onClick={() => setShowPass(!showPass)} className="p-1 text-slate-400 hover:text-white">
                   {showPass ? <EyeOff className="w-4 h-4"/> : <Eye className="w-4 h-4"/>}
                 </button>
                 <button type="button" onClick={generateRandom} className="p-1 text-emerald-400 hover:text-emerald-300" title="Genera">
                   <RefreshCw className="w-4 h-4" />
                 </button>
              </div>
            </div>
          </div>

          <div>
            <label className="block text-xs font-bold text-slate-500 uppercase tracking-wider mb-1">Note</label>
            <textarea 
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-white focus:ring-2 focus:ring-emerald-500 outline-none min-h-[80px]"
              value={notes}
              onChange={e => setNotes(e.target.value)}
              placeholder="Domande di sicurezza, PIN, ecc..."
            />
          </div>
        </form>

        <div className="p-6 border-t border-slate-700 flex justify-end gap-3">
          <button onClick={onClose} className="px-4 py-2 text-slate-300 hover:text-white font-medium">Annulla</button>
          <button onClick={handleSubmit} className="px-6 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-bold shadow-lg shadow-emerald-900/20">
            Salva
          </button>
        </div>
      </div>
    </div>
  );
};

const PasswordGeneratorModal = ({ onClose }: { onClose: () => void }) => {
  const [length, setLength] = useState(16);
  const [useNumbers, setUseNumbers] = useState(true);
  const [useSymbols, setUseSymbols] = useState(true);
  const [useUpper, setUseUpper] = useState(true);
  const [password, setPassword] = useState('');

  const generate = () => {
    let charset = "abcdefghijklmnopqrstuvwxyz";
    if (useUpper) charset += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (useNumbers) charset += "0123456789";
    if (useSymbols) charset += "!@#$%^&*()_+~`|}{[]:;?><,./-=";
    
    let retVal = "";
    const array = new Uint32Array(length);
    window.crypto.getRandomValues(array);
    for (let i = 0; i < length; i++) {
        retVal += charset[array[i] % charset.length];
    }
    setPassword(retVal);
  };

  useEffect(() => {
    generate();
  }, [length, useNumbers, useSymbols, useUpper]);

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-800 w-full max-w-md rounded-2xl shadow-2xl border border-slate-700 p-6">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Key className="w-5 h-5 text-emerald-400" /> Generatore Password
          </h2>
          <button onClick={onClose}><X className="w-6 h-6 text-slate-400 hover:text-white"/></button>
        </div>

        <div className="bg-slate-900 p-4 rounded-xl mb-6 border border-slate-700 flex items-center justify-between">
           <span className="font-mono text-lg text-white break-all">{password}</span>
           <button 
             onClick={() => { navigator.clipboard.writeText(password); onClose(); }} 
             className="ml-4 p-2 bg-slate-800 hover:bg-slate-700 rounded-lg text-slate-300 hover:text-white transition-colors"
             title="Copia"
           >
             <Copy className="w-5 h-5" />
           </button>
        </div>

        <div className="space-y-4">
           <div>
             <div className="flex justify-between text-sm text-slate-400 mb-2">
               <span>Lunghezza</span>
               <span>{length}</span>
             </div>
             <input 
               type="range" min="8" max="64" value={length} onChange={e => setLength(parseInt(e.target.value))}
               className="w-full accent-emerald-500 h-2 bg-slate-700 rounded-lg appearance-none cursor-pointer"
             />
           </div>
           
           <div className="flex flex-col gap-3">
             <label className="flex items-center gap-3 cursor-pointer">
               <input type="checkbox" checked={useUpper} onChange={e => setUseUpper(e.target.checked)} className="w-5 h-5 rounded border-slate-600 bg-slate-700 text-emerald-500 focus:ring-emerald-500 focus:ring-offset-slate-800" />
               <span className="text-slate-300">Maiuscole (A-Z)</span>
             </label>
             <label className="flex items-center gap-3 cursor-pointer">
               <input type="checkbox" checked={useNumbers} onChange={e => setUseNumbers(e.target.checked)} className="w-5 h-5 rounded border-slate-600 bg-slate-700 text-emerald-500 focus:ring-emerald-500 focus:ring-offset-slate-800" />
               <span className="text-slate-300">Numeri (0-9)</span>
             </label>
             <label className="flex items-center gap-3 cursor-pointer">
               <input type="checkbox" checked={useSymbols} onChange={e => setUseSymbols(e.target.checked)} className="w-5 h-5 rounded border-slate-600 bg-slate-700 text-emerald-500 focus:ring-emerald-500 focus:ring-offset-slate-800" />
               <span className="text-slate-300">Simboli (!@#$)</span>
             </label>
           </div>
        </div>

        <button 
           onClick={generate} 
           className="w-full mt-8 py-3 bg-slate-700 hover:bg-slate-600 text-white rounded-lg font-bold transition-all flex items-center justify-center gap-2"
        >
          <RefreshCw className="w-4 h-4" /> Rigenera
        </button>
      </div>
    </div>
  );
};

const ChangePasswordModal = ({ githubCreds, onClose, onSuccess }: {
  githubCreds: GitHubCredentials,
  onClose: () => void,
  onSuccess: () => void
}) => {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showPasswords, setShowPasswords] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    // Validazioni
    if (newPassword.length < 8) {
      setError("La nuova password deve essere di almeno 8 caratteri.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setError("Le nuove password non coincidono.");
      return;
    }
    if (currentPassword === newPassword) {
      setError("La nuova password deve essere diversa da quella attuale.");
      return;
    }

    setLoading(true);

    try {
      // 1. Scarica il vault attuale da GitHub
      const file = await githubGetFile(githubCreds);
      if (!file) {
        throw new Error("Vault non trovato su GitHub.");
      }

      const stored: VaultStorage = JSON.parse(file.content);
      const currentSalt = new Uint8Array(base64ToBuffer(stored.salt));

      // 2. Verifica la password attuale
      const currentKey = await deriveKey(currentPassword, currentSalt);
      let entries: VaultEntry[];
      try {
        entries = await decryptData(currentKey, stored.iv, stored.ciphertext);
      } catch {
        throw new Error("Password attuale errata.");
      }

      // 3. Genera nuovo salt e deriva nuova chiave
      const newSalt = generateSalt();
      const newKey = await deriveKey(newPassword, newSalt);

      // 4. Re-cifra i dati con la nuova chiave
      const encrypted = await encryptData(newKey, entries);

      const newStorage: VaultStorage = {
        salt: bufferToBase64(newSalt.buffer),
        iv: encrypted.iv,
        ciphertext: encrypted.ciphertext
      };

      // 5. Salva su GitHub
      await githubSaveFile(
        githubCreds,
        JSON.stringify(newStorage, null, 2),
        file.sha,
        'Change master password'
      );

      onSuccess();
    } catch (err: any) {
      console.error(err);
      setError(err.message || "Errore durante il cambio password.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-800 w-full max-w-md rounded-2xl shadow-2xl border border-slate-700 p-6">
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Key className="w-5 h-5 text-emerald-400" /> Cambia Password
          </h2>
          <button onClick={onClose} disabled={loading}>
            <X className="w-6 h-6 text-slate-400 hover:text-white"/>
          </button>
        </div>

        {error && (
          <div className="mb-4 p-3 bg-rose-500/10 border border-rose-500/20 rounded-lg flex items-center gap-3 text-rose-200 text-sm">
            <AlertTriangle className="w-5 h-5 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-400 mb-1">Password Attuale</label>
            <input 
              type={showPasswords ? 'text' : 'password'}
              required
              disabled={loading}
              className="w-full px-4 py-3 bg-slate-900 border border-slate-700 rounded-lg focus:ring-2 focus:ring-emerald-500 outline-none text-white"
              value={currentPassword}
              onChange={e => setCurrentPassword(e.target.value)}
              placeholder="••••••••"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-400 mb-1">Nuova Password</label>
            <input 
              type={showPasswords ? 'text' : 'password'}
              required
              disabled={loading}
              className="w-full px-4 py-3 bg-slate-900 border border-slate-700 rounded-lg focus:ring-2 focus:ring-emerald-500 outline-none text-white"
              value={newPassword}
              onChange={e => setNewPassword(e.target.value)}
              placeholder="Minimo 8 caratteri"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-400 mb-1">Conferma Nuova Password</label>
            <input 
              type={showPasswords ? 'text' : 'password'}
              required
              disabled={loading}
              className="w-full px-4 py-3 bg-slate-900 border border-slate-700 rounded-lg focus:ring-2 focus:ring-emerald-500 outline-none text-white"
              value={confirmPassword}
              onChange={e => setConfirmPassword(e.target.value)}
              placeholder="Ripeti la nuova password"
            />
          </div>

          <label className="flex items-center gap-2 text-sm text-slate-400 cursor-pointer">
            <input 
              type="checkbox" 
              checked={showPasswords}
              onChange={e => setShowPasswords(e.target.checked)}
              className="rounded border-slate-600 bg-slate-700 text-emerald-500"
            />
            Mostra password
          </label>

          <button 
            type="submit" 
            disabled={loading}
            className="w-full py-3 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg font-bold transition-all disabled:opacity-50 flex justify-center items-center gap-2 mt-6"
          >
            {loading ? (
              <><RefreshCw className="w-4 h-4 animate-spin" /> Cambio in corso...</>
            ) : (
              'Cambia Password'
            )}
          </button>
        </form>
      </div>
    </div>
  );
};

const container = document.getElementById('root');
const root = createRoot(container!);
root.render(<App />);
