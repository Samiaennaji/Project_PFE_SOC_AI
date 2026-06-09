import React, { useState, useEffect, useRef } from 'react';
import { Shield, LayoutDashboard, Database, Activity, Settings as SettingsIcon, AlertOctagon, Sun, Moon } from 'lucide-react';
import Dashboard from './components/Dashboard';
import LogsTable from './components/LogsTable';
import Analyzer from './components/Analyzer';
import Settings from './components/Settings';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:5000/api';

function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [theme, setTheme] = useState(localStorage.getItem('theme') || 'dark');
  const [stats, setStats] = useState({
    total: 0,
    attacks: 0,
    false_positives: 0,
    normal: 0,
    average_risk: 0,
    timeline: [],
    top_rules: [],
    scatter: []
  });
  const [logs, setLogs] = useState([]);
  const [totalLogsCount, setTotalLogsCount] = useState(0);
  const [selectedLog, setSelectedLog] = useState(null);
  const [settings, setSettings] = useState({
    attack_threshold: 0.15,
    simulation_active: false,
    simulation_speed: 1.5,
    groq_api_key: ''
  });
  const [isConnected, setIsConnected] = useState(false);

  useEffect(() => {
    if (theme === 'light') {
      document.body.classList.add('light-mode');
    } else {
      document.body.classList.remove('light-mode');
    }
    localStorage.setItem('theme', theme);
  }, [theme]);

  // References to keep state available in EventSource callbacks
  const logsRef = useRef(logs);
  logsRef.current = logs;

  // Fetch initial stats and settings
  const fetchStats = async () => {
    try {
      const res = await fetch(`${API_BASE}/stats`);
      const data = await res.json();
      setStats(data);
    } catch (err) {
      console.error('Error fetching stats:', err);
    }
  };

  const fetchSettings = async () => {
    try {
      const res = await fetch(`${API_BASE}/settings`);
      const data = await res.json();
      setSettings(data);
    } catch (err) {
      console.error('Error fetching settings:', err);
    }
  };

  const fetchLogs = async () => {
    try {
      const res = await fetch(`${API_BASE}/logs?limit=50`);
      const data = await res.json();
      setLogs(data.logs);
      setTotalLogsCount(data.total);
    } catch (err) {
      console.error('Error fetching logs:', err);
    }
  };

  useEffect(() => {
    fetchStats();
    fetchSettings();
    fetchLogs();

    // Set up Server-Sent Events (SSE) connection
    console.log('Connecting to SSE Stream...');
    const eventSource = new EventSource(`${API_BASE}/stream`);

    eventSource.onopen = () => {
      console.log('SSE Stream connected.');
      setIsConnected(true);
    };

    eventSource.onerror = (err) => {
      console.error('SSE Stream error:', err);
      setIsConnected(false);
    };

    // Listen to standard message events
    eventSource.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        const { event: eventType, data } = payload;

        if (eventType === 'new_log') {
          // Prepend new log
          setLogs((prev) => [data, ...prev].slice(0, 1000));
          setTotalLogsCount((prev) => prev + 1);
          // Refresh statistics and graphs
          fetchStats();
        } else if (eventType === 'update_log') {
          // Update specific log
          setLogs((prev) =>
            prev.map((log) => (log.id === data.id ? data : log))
          );
          setSelectedLog((prev) => (prev && prev.id === data.id ? data : prev));
          fetchStats();
        } else if (eventType === 'settings_update') {
          setSettings(data);
        } else if (eventType === 'clear_logs') {
          setLogs([]);
          setTotalLogsCount(0);
          setSelectedLog(null);
          setStats({
            total: 0,
            attacks: 0,
            false_positives: 0,
            normal: 0,
            average_risk: 0,
            timeline: [],
            top_rules: [],
            scatter: []
          });
        }
      } catch (err) {
        console.error('Failed to parse SSE payload:', err);
      }
    };

    return () => {
      eventSource.close();
      console.log('SSE Stream closed.');
    };
  }, []);

  const handleInject = async (type) => {
    try {
      await fetch(`${API_BASE}/inject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ class: type })
      });
    } catch (err) {
      console.error('Failed to inject log:', err);
    }
  };

  return (
    <div className="app-container">
      {/* Sidebar Navigation */}
      <aside className="sidebar">
        <div style={{ padding: '24px 20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--border-standard)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <img src="/logo.png" alt="EXIA SOC-AI Logo" style={{ width: '32px', height: '32px', borderRadius: '6px', objectFit: 'cover', filter: 'drop-shadow(0 0 8px var(--color-primary-glow))' }} />
            <div>
              <h2 style={{ fontSize: '16px', fontWeight: 700, letterSpacing: '0.02em', color: 'var(--text-main)' }}>EXIA SOC-AI</h2>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '2px' }}>
                <span className={isConnected ? "pulse-red" : ""} style={{ width: '6px', height: '6px', background: isConnected ? 'var(--color-normal)' : 'var(--color-attack)', boxShadow: isConnected ? '0 0 8px var(--color-normal)' : 'none', margin: 0 }}></span>
                <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase' }}>
                  {isConnected ? 'Temps réel' : 'Hors ligne'}
                </span>
              </div>
            </div>
          </div>
          <button
            onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            title={theme === 'dark' ? 'Activer le mode clair' : 'Activer le mode sombre'}
            style={{
              background: 'transparent', border: 0, padding: '6px', borderRadius: '6px', cursor: 'pointer',
              display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-muted)',
              transition: 'background-color 0.2s', alignSelf: 'center'
            }}
            onMouseEnter={(e) => e.currentTarget.style.backgroundColor = 'rgba(127, 119, 221, 0.08)'}
            onMouseLeave={(e) => e.currentTarget.style.backgroundColor = 'transparent'}
          >
            {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
          </button>
        </div>

        <nav style={{ padding: '20px 12px', flex: 1, display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <button
            onClick={() => setActiveTab('dashboard')}
            style={{
              display: 'flex', alignItems: 'center', gap: '12px', width: '100%', padding: '12px 16px', borderRadius: '8px', border: 0,
              background: activeTab === 'dashboard' ? 'rgba(127, 119, 221, 0.12)' : 'transparent',
              color: activeTab === 'dashboard' ? 'var(--color-primary)' : 'var(--text-muted)',
              fontSize: '14px', fontWeight: 600, textAlign: 'left', cursor: 'pointer', transition: 'all 0.2s'
            }}
          >
            <LayoutDashboard size={18} /> Dashboard
          </button>
          <button
            onClick={() => setActiveTab('logs')}
            style={{
              display: 'flex', alignItems: 'center', gap: '12px', width: '100%', padding: '12px 16px', borderRadius: '8px', border: 0,
              background: activeTab === 'logs' ? 'rgba(127, 119, 221, 0.12)' : 'transparent',
              color: activeTab === 'logs' ? 'var(--color-primary)' : 'var(--text-muted)',
              fontSize: '14px', fontWeight: 600, textAlign: 'left', cursor: 'pointer', transition: 'all 0.2s'
            }}
          >
            <Database size={18} /> Base d'alertes
          </button>
          <button
            onClick={() => setActiveTab('analyzer')}
            style={{
              display: 'flex', alignItems: 'center', gap: '12px', width: '100%', padding: '12px 16px', borderRadius: '8px', border: 0,
              background: activeTab === 'analyzer' ? 'rgba(127, 119, 221, 0.12)' : 'transparent',
              color: activeTab === 'analyzer' ? 'var(--color-primary)' : 'var(--text-muted)',
              fontSize: '14px', fontWeight: 600, textAlign: 'left', cursor: 'pointer', transition: 'all 0.2s'
            }}
          >
            <Activity size={18} /> Analyseur de logs
          </button>
          <button
            onClick={() => setActiveTab('settings')}
            style={{
              display: 'flex', alignItems: 'center', gap: '12px', width: '100%', padding: '12px 16px', borderRadius: '8px', border: 0,
              background: activeTab === 'settings' ? 'rgba(127, 119, 221, 0.12)' : 'transparent',
              color: activeTab === 'settings' ? 'var(--color-primary)' : 'var(--text-muted)',
              fontSize: '14px', fontWeight: 600, textAlign: 'left', cursor: 'pointer', transition: 'all 0.2s'
            }}
          >
            <SettingsIcon size={18} /> Configuration
          </button>
        </nav>

        {/* Quick Simulator injection controls */}
        <div style={{ padding: '20px', borderTop: '1px solid var(--border-standard)', background: 'rgba(9, 11, 17, 0.4)' }}>
          <h4 style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '10px' }}>Simulation Forcée</h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <button
              onClick={() => handleInject('attack')}
              style={{
                width: '100%', padding: '8px 12px', background: 'rgba(226, 75, 74, 0.1)', border: '1px solid rgba(226, 75, 74, 0.3)',
                borderRadius: '6px', color: 'var(--color-attack)', fontSize: '12px', fontWeight: 600, cursor: 'pointer', transition: 'all 0.2s'
              }}
            >
              💥 Injecter Attaque
            </button>
            <button
              onClick={() => handleInject('false_positive')}
              style={{
                width: '100%', padding: '8px 12px', background: 'rgba(239, 159, 39, 0.1)', border: '1px solid rgba(239, 159, 39, 0.3)',
                borderRadius: '6px', color: 'var(--color-fp)', fontSize: '12px', fontWeight: 600, cursor: 'pointer', transition: 'all 0.2s'
              }}
            >
              ⚠️ Injecter Faux Positif
            </button>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="main-content">
        {activeTab === 'dashboard' && (
          <Dashboard stats={stats} />
        )}
        
        {activeTab === 'logs' && (
          <LogsTable 
            logs={logs} 
            total={totalLogsCount} 
            setSelectedLog={(log) => {
              setSelectedLog(log);
              setActiveTab('analyzer');
            }} 
            API_BASE={API_BASE}
            fetchLogs={fetchLogs}
          />
        )}
        
        {activeTab === 'analyzer' && (
          <Analyzer 
            selectedLog={selectedLog} 
            setSelectedLog={setSelectedLog}
            API_BASE={API_BASE}
          />
        )}
        
        {activeTab === 'settings' && (
          <Settings 
            settings={settings} 
            setSettings={setSettings} 
            API_BASE={API_BASE} 
          />
        )}
      </main>
    </div>
  );
}

export default App;
