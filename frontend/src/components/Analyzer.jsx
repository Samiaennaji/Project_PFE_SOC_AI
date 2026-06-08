import React, { useState, useEffect } from 'react';
import { Play, Clipboard, RotateCcw, Brain, ShieldAlert, Cpu, AlertTriangle, CheckCircle, Terminal, HelpCircle, ArrowLeft } from 'lucide-react';

const CLS_THEME = {
  normal: { label: 'Normal', color: 'var(--color-normal)', bg: 'rgba(29, 158, 117, 0.12)', border: 'rgba(29, 158, 117, 0.3)' },
  false_positive: { label: 'Faux Positif', color: 'var(--color-fp)', bg: 'rgba(239, 159, 39, 0.12)', border: 'rgba(239, 159, 39, 0.3)' },
  attack: { label: 'Attaque / Incident', color: 'var(--color-attack)', bg: 'rgba(226, 75, 74, 0.12)', border: 'rgba(226, 75, 74, 0.3)' }
};

const EXAMPLES = {
  ssh_brute: {
    alert_name: "SSH Brute Force",
    description: "SSH Brute Force attempt detected",
    src_ip: "192.168.126.133",
    dst_ip: "192.168.126.139",
    src_port: 49832,
    dst_port: 22,
    dst_service: "ssh",
    protocol: "TCP",
    freq_per_min: 156,
    time_context: "after_hours",
    severity: "HIGH",
    severity_score: 3,
    src_is_internal: 1,
    dst_is_internal: 1,
    is_internal_to_internal: 1,
    same_subnet: 1,
    is_high_freq: 1
  },
  sql_inj: {
    alert_name: "SQL Injection pattern",
    description: "SQL Injection attack signature detected in HTTP GET parameter",
    src_ip: "192.168.126.133",
    dst_ip: "192.168.126.128",
    src_port: 50122,
    dst_port: 80,
    dst_service: "http",
    protocol: "TCP",
    freq_per_min: 85,
    time_context: "business_hours",
    severity: "CRITICAL",
    severity_score: 4,
    src_is_internal: 1,
    dst_is_internal: 1,
    is_internal_to_internal: 1,
    same_subnet: 1,
    is_high_freq: 1
  },
  normal_http: {
    alert_name: "http",
    description: "Normal HTTP GET request to standard web server",
    src_ip: "192.168.1.50",
    dst_ip: "10.0.0.1",
    src_port: 53421,
    dst_port: 80,
    dst_service: "http",
    protocol: "TCP",
    freq_per_min: 4,
    time_context: "business_hours",
    severity: "INFO",
    severity_score: 0,
    src_is_internal: 1,
    dst_is_internal: 1,
    is_internal_to_internal: 1,
    same_subnet: 0,
    is_high_freq: 0
  }
};

function Analyzer({ selectedLog, setSelectedLog, API_BASE }) {
  const [rawInput, setRawInput] = useState('');
  const [inputError, setInputError] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isLlmRunning, setIsLlmRunning] = useState(false);
  const [activeLog, setActiveLog] = useState(null);
  
  // Interactive checklist state (stores completed recommendation index/text)
  const [checklist, setChecklist] = useState({});

  const getRawLogDisplay = () => {
    if (!activeLog) return '';
    const raw = activeLog.raw_log || activeLog;
    let parsed = raw;
    if (typeof parsed === 'string') {
      try {
        parsed = JSON.parse(parsed);
        if (typeof parsed === 'string') {
          parsed = JSON.parse(parsed);
        }
      } catch (e) {
        return raw;
      }
    }
    const cleanLog = typeof parsed === 'object' && parsed !== null ? { ...parsed } : {};
    const dbKeys = ['id', 'prediction', 'proba_attack', 'proba_fp', 'proba_normal', 'risk_score', 'threshold_used', 'timestamp', 'llm_analyzed', 'llm_summary', 'llm_risk_level', 'llm_attack_type', 'llm_mitre', 'llm_recommendations', 'llm_iocs'];
    dbKeys.forEach(k => delete cleanLog[k]);
    return JSON.stringify(cleanLog, null, 2);
  };

  // Sync active log with the parent's selectedLog selection
  useEffect(() => {
    if (selectedLog) {
      setActiveLog(selectedLog);
      // Reset checklist for new log
      setChecklist({});
    }
  }, [selectedLog]);

  const loadExample = (key) => {
    setRawInput(JSON.stringify(EXAMPLES[key], null, 2));
    setInputError('');
  };

  const handleManualAnalyze = async () => {
    setInputError('');
    setIsAnalyzing(true);
    
    let parsedLog;
    try {
      parsedLog = JSON.parse(rawInput);
    } catch (err) {
      setInputError('JSON Invalide: Vérifiez la syntaxe (virgules, accolades).');
      setIsAnalyzing(false);
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(parsedLog)
      });
      if (!res.ok) throw new Error('Response error from server');
      const data = await res.json();
      setActiveLog(data);
      setChecklist({});
    } catch (err) {
      console.error(err);
      setInputError('Erreur de communication avec le serveur Flask.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const triggerLlmAnalysis = async () => {
    if (!activeLog) return;
    setIsLlmRunning(true);
    try {
      const res = await fetch(`${API_BASE}/analyze-llm/${activeLog.id}`, {
        method: 'POST'
      });
      const data = await res.json();
      
      // Update active log with LLM analysis output
      setActiveLog(prev => ({
        ...prev,
        llm_analyzed: 1,
        llm_summary: data.summary,
        llm_risk_level: data.risk_level,
        llm_attack_type: data.attack_type,
        llm_mitre: data.mitre,
        llm_recommendations: data.recommendations,
        llm_iocs: data.iocs
      }));
    } catch (err) {
      console.error('Failed to run LLM advisor:', err);
    } finally {
      setIsLlmRunning(false);
    }
  };

  const toggleChecklistItem = (index) => {
    setChecklist(prev => ({
      ...prev,
      [index]: !prev[index]
    }));
  };

  const handleBackToInput = () => {
    setActiveLog(null);
    setSelectedLog(null);
    setRawInput('');
    setInputError('');
  };

  // ----------------------------------------------------
  // RENDER COMPONENT
  // ----------------------------------------------------

  // View Mode: Viewing classified log
  if (activeLog) {
    const clsTheme = CLS_THEME[activeLog.prediction] || { label: activeLog.prediction, color: '#fff', bg: 'rgba(255,255,255,0.1)' };
    const formattedProba = (val) => val ? `${(val * 100).toFixed(1)}%` : '0.0%';

    return (
      <div>
        {/* Back and title bar */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
          <button
            onClick={handleBackToInput}
            style={{
              display: 'flex', alignItems: 'center', gap: '8px', padding: '8px 14px', borderRadius: '8px',
              background: 'rgba(240,246,252,0.03)', border: '1px solid var(--border-standard)',
              color: 'var(--text-muted)', fontSize: '13px', fontWeight: 600, cursor: 'pointer', transition: 'all 0.2s'
            }}
          >
            <ArrowLeft size={16} /> Nouveau log / Retour
          </button>
          
          <div style={{ display: 'flex', gap: '10px' }}>
            <span style={{ fontSize: '13px', color: 'var(--text-muted)', background: 'rgba(9, 11, 17, 0.4)', padding: '6px 12px', borderRadius: '6px', border: '1px solid var(--border-standard)' }}>
              Log ID: <b>#{activeLog.id}</b>
            </span>
            <span style={{ fontSize: '13px', color: 'var(--text-muted)', background: 'rgba(9, 11, 17, 0.4)', padding: '6px 12px', borderRadius: '6px', border: '1px solid var(--border-standard)' }}>
              Date: <b>{activeLog.timestamp}</b>
            </span>
          </div>
        </div>

        {/* Alert Header Banner */}
        <div className="glass-panel" style={{ padding: '24px', marginBottom: '30px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderLeft: `4px solid ${clsTheme.color}` }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <h2 style={{ fontSize: '20px', fontWeight: 700 }}>{activeLog.alert_name}</h2>
              <span className="badge" style={{ background: clsTheme.bg, color: clsTheme.color, border: `1px solid ${clsTheme.border}` }}>
                {clsTheme.label}
              </span>
            </div>
            <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '6px', maxWidth: '800px' }}>{activeLog.description}</p>
          </div>

          <div style={{ textAlign: 'right' }}>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Score de risque global</span>
            <div style={{ fontSize: '32px', fontWeight: 800, color: activeLog.risk_score >= 70 ? 'var(--color-attack)' : activeLog.risk_score >= 30 ? 'var(--color-fp)' : 'var(--color-normal)' }}>
              {activeLog.risk_score}%
            </div>
          </div>
        </div>

        {/* Main Grid: Details vs AI Remediation */}
        <div className="analyzer-columns">
          
          {/* Left Column: Metrics & ML Probability Analysis */}
          <div className="analyzer-left-col">
            
            {/* Log Fields & Network details */}
            <div className="glass-panel" style={{ padding: '20px' }}>
              <h3 style={{ fontSize: '14px', fontWeight: 600, color: '#fff', borderBottom: '1px solid var(--border-standard)', paddingBottom: '10px', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Terminal size={16} color="var(--color-primary)" /> Paramètres Réseau & Wazuh
              </h3>
              
              <div className="network-params-grid">
                <div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>IP Source</div>
                  <div style={{ fontFamily: 'monospace', fontSize: '14px', fontWeight: 600, color: '#e2e8f0', marginTop: '2px' }}>{activeLog.src_ip || 'N/A'}</div>
                </div>
                <div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>IP Destination</div>
                  <div style={{ fontFamily: 'monospace', fontSize: '14px', fontWeight: 600, color: '#e2e8f0', marginTop: '2px' }}>{activeLog.dst_ip || 'N/A'}</div>
                </div>
                <div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Port Source / Destination</div>
                  <div style={{ fontFamily: 'monospace', fontSize: '14px', color: '#cbd5e1', marginTop: '2px' }}>
                    {activeLog.src_port || 'N/A'} &rarr; {activeLog.dst_port || 'N/A'} ({activeLog.dst_service || 'N/A'})
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Protocole</div>
                  <div style={{ fontSize: '14px', fontWeight: 600, color: '#cbd5e1', marginTop: '2px' }}>{activeLog.protocol || 'TCP'}</div>
                </div>
                <div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Fréquence des alertes</div>
                  <div style={{ fontSize: '14px', fontWeight: 600, color: '#cbd5e1', marginTop: '2px' }}>{activeLog.freq_per_min} / min</div>
                </div>
                <div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Contexte Temporel</div>
                  <div style={{ fontSize: '14px', color: '#cbd5e1', marginTop: '2px', textTransform: 'capitalize' }}>
                    {activeLog.time_context?.replace('_', ' ') || 'Normal'}
                  </div>
                </div>
              </div>
            </div>

            {/* XGBoost Probabilities Cards */}
            <div className="glass-panel" style={{ padding: '20px' }}>
              <h3 style={{ fontSize: '14px', fontWeight: 600, color: '#fff', borderBottom: '1px solid var(--border-standard)', paddingBottom: '10px', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Cpu size={16} color="var(--color-primary)" /> Probabilités Modèle XGBoost
              </h3>
              
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                {/* Attack Bar */}
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: '6px' }}>
                    <span style={{ fontWeight: 600, color: 'var(--color-attack)' }}>Probabilité d'Attaque (Incident)</span>
                    <span style={{ fontWeight: 700 }}>{formattedProba(activeLog.proba_attack)}</span>
                  </div>
                  <div style={{ height: '8px', background: 'rgba(240, 246, 252, 0.04)', borderRadius: '4px', overflow: 'hidden' }}>
                    <div style={{ height: '100%', width: `${(activeLog.proba_attack || 0) * 100}%`, background: 'var(--color-attack)', borderRadius: '4px' }}></div>
                  </div>
                </div>

                {/* False Positive Bar */}
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: '6px' }}>
                    <span style={{ fontWeight: 600, color: 'var(--color-fp)' }}>Probabilité de Faux Positif</span>
                    <span style={{ fontWeight: 700 }}>{formattedProba(activeLog.proba_fp)}</span>
                  </div>
                  <div style={{ height: '8px', background: 'rgba(240, 246, 252, 0.04)', borderRadius: '4px', overflow: 'hidden' }}>
                    <div style={{ height: '100%', width: `${(activeLog.proba_fp || 0) * 100}%`, background: 'var(--color-fp)', borderRadius: '4px' }}></div>
                  </div>
                </div>

                {/* Normal Bar */}
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', marginBottom: '6px' }}>
                    <span style={{ fontWeight: 600, color: 'var(--color-normal)' }}>Probabilité de Trafic Normal</span>
                    <span style={{ fontWeight: 700 }}>{formattedProba(activeLog.proba_normal)}</span>
                  </div>
                  <div style={{ height: '8px', background: 'rgba(240, 246, 252, 0.04)', borderRadius: '4px', overflow: 'hidden' }}>
                    <div style={{ height: '100%', width: `${(activeLog.proba_normal || 0) * 100}%`, background: 'var(--color-normal)', borderRadius: '4px' }}></div>
                  </div>
                </div>
              </div>
            </div>

            {/* Raw JSON display */}
            <div className="glass-panel" style={{ padding: '20px' }}>
              <h3 style={{ fontSize: '14px', fontWeight: 600, color: '#fff', borderBottom: '1px solid var(--border-standard)', paddingBottom: '10px', marginBottom: '12px' }}>
                Log Wazuh JSON Brut
              </h3>
              <pre style={{
                maxHeight: '220px', overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                background: 'rgba(9, 11, 17, 0.6)', border: '1px solid var(--border-standard)',
                borderRadius: '8px', padding: '12px', fontSize: '11px', color: '#8892b0', fontFamily: 'Consolas, monospace', lineHeight: '1.4'
              }}>
                {getRawLogDisplay()}
              </pre>
            </div>

          </div>

          {/* Right Column: AI Assistant Advisor */}
          <div className="glass-panel analyzer-right-col" style={{ padding: '24px' }}>
            
            {/* If LLM analysis has NOT been run yet */}
            {activeLog.llm_analyzed !== 1 ? (
              <div style={{ padding: '20px 0', textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '20px', width: '100%' }}>
                <div style={{
                  width: '64px', height: '64px', borderRadius: '50%', background: 'rgba(127, 119, 221, 0.1)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid rgba(127, 119, 221, 0.3)',
                  boxShadow: '0 0 20px rgba(127, 119, 221, 0.15)'
                }}>
                  <Brain size={32} color="var(--color-primary)" />
                </div>
                
                <div>
                  <h3 style={{ fontSize: '17px', fontWeight: 700, marginBottom: '8px' }}>Rapport AI non disponible</h3>
                  <p style={{ fontSize: '13px', color: 'var(--text-muted)', lineHeight: '1.5', maxWidth: '340px', margin: '0 auto' }}>
                    Solliciter l'LLM LLaMA-3.3-70b / Gemini pour caractériser l'alerte, identifier la menace, référencer MITRE ATT&CK et générer les actions de remédiation adaptées.
                  </p>
                </div>

                <button
                  onClick={triggerLlmAnalysis}
                  disabled={isLlmRunning}
                  style={{
                    padding: '12px 24px', background: 'var(--color-primary)', border: 0, borderRadius: '8px',
                    color: '#fff', fontSize: '14px', fontWeight: 600, cursor: isLlmRunning ? 'not-allowed' : 'pointer',
                    display: 'flex', alignItems: 'center', gap: '8px', transition: 'all 0.2s',
                    boxShadow: '0 4px 15px rgba(127,119,221,0.25)'
                  }}
                >
                  <Brain size={16} />
                  {isLlmRunning ? 'Analyse en cours par l\'IA...' : 'Générer le rapport d\'incident AI'}
                </button>
              </div>
            ) : (
              /* If LLM analysis HAS BEEN run */
              <>
                
                {/* AI Header */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-standard)', paddingBottom: '14px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <Brain size={20} color="var(--color-primary)" />
                    <span style={{ fontWeight: 700, fontSize: '15px' }}>Rapport Expert IA</span>
                  </div>
                  
                  {/* Risk Tag */}
                  <span 
                    className="badge" 
                    style={{
                      background: activeLog.llm_risk_level?.toLowerCase() === 'high' || activeLog.llm_risk_level?.toLowerCase() === 'élevé' ? 'rgba(226, 75, 74, 0.15)' : 'rgba(239, 159, 39, 0.15)',
                      color: activeLog.llm_risk_level?.toLowerCase() === 'high' || activeLog.llm_risk_level?.toLowerCase() === 'élevé' ? 'var(--color-attack)' : 'var(--color-fp)',
                      border: '1px solid currentColor'
                    }}
                  >
                    Niveau: {activeLog.llm_risk_level}
                  </span>
                </div>

                {/* Classification & MITRE */}
                <div className="ai-details-grid" style={{ background: 'rgba(9, 11, 17, 0.4)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border-standard)' }}>
                  <div>
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Catégorie de menace</span>
                    <div style={{ fontSize: '13px', fontWeight: 600, color: '#e2e8f0', marginTop: '2px' }}>{activeLog.llm_attack_type || 'N/A'}</div>
                  </div>
                  <div>
                    <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase' }}>MITRE ATT&CK ID</span>
                    <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--color-primary)', marginTop: '2px' }}>{activeLog.llm_mitre || 'N/A'}</div>
                  </div>
                </div>

                {/* AI Summary */}
                <div>
                  <h4 style={{ fontSize: '12px', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '6px' }}>Synthèse de l'événement</h4>
                  <p style={{ fontSize: '13px', color: '#cbd5e1', lineHeight: '1.5', background: 'rgba(240, 246, 252, 0.01)', padding: '10px', borderRadius: '6px', borderLeft: '3px solid var(--color-primary)' }}>
                    {activeLog.llm_summary}
                  </p>
                </div>

                {/* IOCs list */}
                {activeLog.llm_iocs && activeLog.llm_iocs.length > 0 && (
                  <div>
                    <h4 style={{ fontSize: '12px', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '8px' }}>Indicateurs de compromission (IOCs)</h4>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                      {activeLog.llm_iocs.map((ioc, i) => (
                        <span key={i} style={{ fontSize: '11px', fontFamily: 'monospace', background: 'rgba(226, 75, 74, 0.08)', border: '1px solid rgba(226, 75, 74, 0.2)', color: 'var(--color-attack)', padding: '3px 8px', borderRadius: '4px' }}>
                          {ioc}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Interactive checklist */}
                {activeLog.llm_recommendations && activeLog.llm_recommendations.length > 0 && (
                  <div>
                    <h4 style={{ fontSize: '12px', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '10px' }}>Plan de Remédiation & Actions</h4>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {activeLog.llm_recommendations.map((rec, i) => {
                        const checked = !!checklist[i];
                        return (
                          <div 
                            key={i} 
                            onClick={() => toggleChecklistItem(i)}
                            style={{
                              display: 'flex', alignItems: 'flex-start', gap: '10px', padding: '10px',
                              borderRadius: '6px', background: checked ? 'rgba(29, 158, 117, 0.04)' : 'rgba(240, 246, 252, 0.02)',
                              border: checked ? '1px solid rgba(29, 158, 117, 0.2)' : '1px solid var(--border-standard)',
                              cursor: 'pointer', transition: 'all 0.2s'
                            }}
                          >
                            <input 
                              type="checkbox" 
                              checked={checked}
                              onChange={() => {}} // handled by outer click
                              style={{ marginTop: '3px', cursor: 'pointer', accentColor: 'var(--color-normal)' }}
                            />
                            <span style={{ 
                              fontSize: '13px', 
                              color: checked ? 'var(--text-muted)' : '#cbd5e1', 
                              textDecoration: checked ? 'line-through' : 'none' 
                            }}>
                              {rec}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

              </>
            )}

          </div>

        </div>
      </div>
    );
  }

  // ----------------------------------------------------
  // Default Input Mode: Raw Log paste form
  // ----------------------------------------------------
  return (
    <div>
      <div style={{ marginBottom: '24px' }}>
        <h1 style={{ fontSize: '24px', fontWeight: 700, letterSpacing: '-0.02em' }}>Analyseur de Log Manuel</h1>
        <p style={{ fontSize: '14px', color: 'var(--text-muted)' }}>
          Soumettre un log Wazuh au format JSON brut pour tester la détection de l'algorithme XGBoost et solliciter l'AI SOC Advisor.
        </p>
      </div>

      <div className="analyzer-input-columns">
        
        {/* Left Side: Textarea and examples */}
        <div className="glass-panel analyzer-input-left" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <span style={{ fontSize: '12px', fontWeight: 600, textTransform: 'uppercase', color: 'var(--text-muted)' }}>Log JSON Brut (Wazuh Format)</span>
            <button 
              onClick={() => { setRawInput(''); setInputError(''); }}
              style={{ background: 'transparent', border: 0, color: 'var(--color-attack)', fontSize: '12px', fontWeight: 600, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px' }}
            >
              <RotateCcw size={12} /> Effacer
            </button>
          </div>

          <textarea
            placeholder='Collez votre log JSON ici... Ex: { "alert_name": "SSH Brute Force", "src_ip": "192.168.126.133", ... }'
            value={rawInput}
            onChange={(e) => { setRawInput(e.target.value); setInputError(''); }}
            style={{
              width: '100%', height: '360px', background: 'rgba(9, 11, 17, 0.6)', border: '1px solid var(--border-standard)',
              borderRadius: '8px', padding: '16px', color: '#fff', fontSize: '13px', fontFamily: 'Consolas, monospace',
              lineHeight: '1.5', outline: 'none', resize: 'none', transition: 'border-color 0.2s'
            }}
          />

          {inputError && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-attack)', fontSize: '13px', marginTop: '12px', background: 'rgba(226, 75, 74, 0.08)', padding: '10px', borderRadius: '6px', border: '1px solid rgba(226, 75, 74, 0.2)' }}>
              <AlertTriangle size={16} />
              <span>{inputError}</span>
            </div>
          )}

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '20px' }}>
            <button
              onClick={handleManualAnalyze}
              disabled={isAnalyzing || !rawInput.trim()}
              className="glass-panel"
              style={{
                padding: '12px 24px', background: 'var(--color-primary)', border: 0, borderRadius: '8px',
                color: '#fff', fontSize: '13px', fontWeight: 600, cursor: isAnalyzing || !rawInput.trim() ? 'not-allowed' : 'pointer',
                display: 'flex', alignItems: 'center', gap: '8px', transition: 'all 0.2s'
              }}
            >
              <Play size={14} />
              {isAnalyzing ? 'Classification en cours...' : 'Exécuter la classification (XGBoost)'}
            </button>
          </div>
        </div>

        {/* Right Side: Examples list & information helper */}
        <div className="analyzer-input-right">
          
          {/* Examples Panel */}
          <div className="glass-panel" style={{ padding: '20px' }}>
            <h3 style={{ fontSize: '14px', fontWeight: 600, color: '#fff', borderBottom: '1px solid var(--border-standard)', paddingBottom: '10px', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Clipboard size={16} color="var(--color-primary)" /> Charger un exemple de test
            </h3>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              <button
                onClick={() => loadExample('ssh_brute')}
                style={{
                  width: '100%', padding: '12px', background: 'rgba(226, 75, 74, 0.04)', border: '1px solid rgba(226, 75, 74, 0.15)',
                  borderRadius: '8px', color: '#cbd5e1', fontSize: '13px', fontWeight: 600, cursor: 'pointer', textAlign: 'left',
                  display: 'flex', flexDirection: 'column', gap: '4px', transition: 'all 0.2s'
                }}
              >
                <span style={{ color: 'var(--color-attack)', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px' }}>💥 Attaque : Brute Force SSH</span>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 400 }}>Simule une attaque à haute fréquence sur le port 22.</span>
              </button>

              <button
                onClick={() => loadExample('sql_inj')}
                style={{
                  width: '100%', padding: '12px', background: 'rgba(239, 159, 39, 0.04)', border: '1px solid rgba(239, 159, 39, 0.15)',
                  borderRadius: '8px', color: '#cbd5e1', fontSize: '13px', fontWeight: 600, cursor: 'pointer', textAlign: 'left',
                  display: 'flex', flexDirection: 'column', gap: '4px', transition: 'all 0.2s'
                }}
              >
                <span style={{ color: 'var(--color-fp)', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px' }}>⚠️ Attaque : SQL Injection web</span>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 400 }}>Tentative d'injection SQL sur un serveur web interne.</span>
              </button>

              <button
                onClick={() => loadExample('normal_http')}
                style={{
                  width: '100%', padding: '12px', background: 'rgba(29, 158, 117, 0.04)', border: '1px solid rgba(29, 158, 117, 0.15)',
                  borderRadius: '8px', color: '#cbd5e1', fontSize: '13px', fontWeight: 600, cursor: 'pointer', textAlign: 'left',
                  display: 'flex', flexDirection: 'column', gap: '4px', transition: 'all 0.2s'
                }}
              >
                <span style={{ color: 'var(--color-normal)', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px' }}>✓ Normal : Requête HTTP légitime</span>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 400 }}>Trafic HTTP interne à faible fréquence sur le port 80.</span>
              </button>
            </div>
          </div>

          {/* Quick Help Info */}
          <div className="glass-panel" style={{ padding: '20px', background: 'rgba(127, 119, 221, 0.02)' }}>
            <h3 style={{ fontSize: '14px', fontWeight: 600, color: '#fff', borderBottom: '1px solid var(--border-standard)', paddingBottom: '10px', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <HelpCircle size={16} color="var(--color-primary)" /> Fonctionnement
            </h3>
            <ul style={{ fontSize: '12px', color: 'var(--text-muted)', paddingLeft: '16px', display: 'flex', flexDirection: 'column', gap: '10px', lineHeight: '1.4' }}>
              <li>Les logs Wazuh sont caractérisés par des variables réseau (IPs, ports, protocoles, fréquence).</li>
              <li>Le modèle <b>XGBoost</b> extrait les variables statistiques et calcule les probabilités d'appartenance aux classes.</li>
              <li>L'<b>AI Recommender</b> formule ensuite une analyse contextuelle en fonction de la prédiction du modèle.</li>
            </ul>
          </div>

        </div>

      </div>
    </div>
  );
}

export default Analyzer;
