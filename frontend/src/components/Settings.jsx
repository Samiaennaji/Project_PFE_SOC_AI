import React, { useState } from 'react';
import { Save, AlertTriangle, Key, ShieldAlert, Cpu, Trash2, RefreshCw } from 'lucide-react';

function Settings({ settings, setSettings, API_BASE }) {
  const [threshold, setThreshold] = useState(settings.attack_threshold);
  const [speed, setSpeed] = useState(settings.simulation_speed);
  const [simActive, setSimActive] = useState(settings.simulation_active);
  const [apiKey, setApiKey] = useState(settings.groq_api_key || '');
  
  const [isSaving, setIsSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
  
  const [isClearing, setIsClearing] = useState(false);
  const [clearSuccess, setClearSuccess] = useState(false);
  const [showClearConfirm, setShowClearConfirm] = useState(false);

  const handleSave = async (e) => {
    e.preventDefault();
    setIsSaving(true);
    setSaveSuccess(false);

    try {
      const res = await fetch(`${API_BASE}/settings`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          attack_threshold: parseFloat(threshold),
          simulation_speed: parseFloat(speed),
          simulation_active: Boolean(simActive),
          groq_api_key: apiKey
        })
      });
      const data = await res.json();
      setSettings(data);
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (err) {
      console.error('Failed to save settings:', err);
    } finally {
      setIsSaving(false);
    }
  };

  const handleClearDatabase = async () => {
    setIsClearing(true);
    setClearSuccess(false);
    try {
      const res = await fetch(`${API_BASE}/clear`, { method: 'POST' });
      if (res.ok) {
        setClearSuccess(true);
        setShowClearConfirm(false);
        setTimeout(() => setClearSuccess(false), 3000);
      }
    } catch (err) {
      console.error('Failed to clear database:', err);
    } finally {
      setIsClearing(false);
    }
  };

  return (
    <div style={{ maxWidth: '800px', margin: '0 auto' }}>
      <div style={{ marginBottom: '24px' }}>
        <h1 style={{ fontSize: '24px', fontWeight: 700, letterSpacing: '-0.02em' }}>Configuration du Système</h1>
        <p style={{ fontSize: '14px', color: 'var(--text-muted)' }}>
          Gérer les paramètres du classifieur XGBoost, le simulateur d'alertes en temps réel et la clé API LLM.
        </p>
      </div>

      <form onSubmit={handleSave} className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '24px', marginBottom: '24px' }}>
        
        {/* ML Classifier Tuning */}
        <div>
          <h3 style={{ fontSize: '15px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid var(--border-standard)', paddingBottom: '10px', marginBottom: '16px' }}>
            <Cpu size={18} color="var(--color-primary)" /> Ajustement du Modèle Machine Learning
          </h3>
          
          <div style={{ marginBottom: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
              <span style={{ fontSize: '13px', fontWeight: 500 }}>Seuil de détection d'attaque (Attack Threshold)</span>
              <span style={{ fontSize: '13px', color: 'var(--color-attack)', fontWeight: 700 }}>{threshold}</span>
            </div>
            <input 
              type="range" 
              min="0.01" 
              max="0.99" 
              step="0.01"
              value={threshold}
              onChange={(e) => setThreshold(e.target.value)}
              style={{
                width: '100%', height: '6px', background: 'rgba(9, 11, 17, 0.5)', outline: 'none',
                borderRadius: '3px', cursor: 'pointer', accentColor: 'var(--color-attack)'
              }}
            />
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '8px', lineHeight: '1.4' }}>
              Si la probabilité calculée par le modèle XGBoost dépasse ce seuil, l'événement est classifié comme une <b>Attaque</b> (Incident). Un seuil plus bas augmente la sensibilité (détecte plus d'attaques mais augmente le risque de faux positifs). Recommandé: <b>0.15</b>.
            </p>
          </div>
        </div>

        {/* Real-time Generator Simulator */}
        <div>
          <h3 style={{ fontSize: '15px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid var(--border-standard)', paddingBottom: '10px', marginBottom: '16px' }}>
            <ShieldAlert size={18} color="var(--color-fp)" /> Simulateur de Logs (Wazuh Simulator)
          </h3>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div>
                <div style={{ fontSize: '13px', fontWeight: 500 }}>Activer la simulation en arrière-plan</div>
                <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '2px' }}>Génère automatiquement de nouveaux logs Wazuh de test.</div>
              </div>
              <button
                type="button"
                onClick={() => setSimActive(!simActive)}
                style={{
                  padding: '8px 16px', borderRadius: '20px', border: 0,
                  background: simActive ? 'rgba(29, 158, 117, 0.15)' : 'rgba(240, 246, 252, 0.05)',
                  border: simActive ? '1px solid var(--color-normal)' : '1px solid var(--border-standard)',
                  color: simActive ? 'var(--color-normal)' : 'var(--text-muted)',
                  fontWeight: 600, fontSize: '13px', cursor: 'pointer', transition: 'all 0.2s'
                }}
              >
                {simActive ? 'Actif' : 'Inactif'}
              </button>
            </div>

            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                <span style={{ fontSize: '13px', fontWeight: 500 }}>Intervalle de génération</span>
                <span style={{ fontSize: '13px', color: 'var(--color-primary)', fontWeight: 700 }}>{speed} secondes</span>
              </div>
              <input 
                type="range" 
                min="0.5" 
                max="5.0" 
                step="0.5"
                value={speed}
                onChange={(e) => setSpeed(e.target.value)}
                style={{
                  width: '100%', height: '6px', background: 'rgba(9, 11, 17, 0.5)', outline: 'none',
                  borderRadius: '3px', cursor: 'pointer', accentColor: 'var(--color-primary)'
                }}
              />
            </div>
          </div>
        </div>

        {/* LLM API Keys */}
        <div>
          <h3 style={{ fontSize: '15px', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid var(--border-standard)', paddingBottom: '10px', marginBottom: '16px' }}>
            <Key size={18} color="var(--color-primary)" /> Configuration Clé API Intelligence Artificielle
          </h3>
          
          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 500, marginBottom: '6px' }}>Clé API Groq / Gemini (Optionnel)</label>
            <input 
              type="password"
              placeholder="gsk_..."
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              style={{
                width: '100%', padding: '10px 12px', background: 'rgba(9, 11, 17, 0.5)', 
                border: '1px solid var(--border-standard)', borderRadius: '8px', color: '#fff', fontSize: '13px',
                fontFamily: 'monospace'
              }}
            />
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '8px', lineHeight: '1.4' }}>
              Pour exécuter les descriptions détaillées d'alertes et recommandations avec LLaMA-3.3-70b-versatile. Si aucune clé n'est fournie, l'application fonctionnera en <b>mode démo simulé</b> avec des rapports d'explications fictifs générés localement.
            </p>
          </div>
        </div>

        {/* Save button / Status Messages */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', borderTop: '1px solid var(--border-standard)', paddingTop: '20px', marginTop: '10px' }}>
          <button
            type="submit"
            disabled={isSaving}
            className="glass-panel"
            style={{
              padding: '10px 20px', borderRadius: '8px', border: '1px solid var(--border-standard)',
              background: 'var(--color-primary)', color: '#fff', fontSize: '13px', fontWeight: 600,
              cursor: isSaving ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', gap: '8px'
            }}
          >
            {isSaving ? <RefreshCw size={15} style={{ animation: 'spin 1s linear infinite' }} /> : <Save size={15} />}
            {isSaving ? 'Enregistrement...' : 'Sauvegarder les modifications'}
          </button>
          
          {saveSuccess && (
            <span style={{ color: 'var(--color-normal)', fontSize: '13px', fontWeight: 600 }}>
              ✓ Paramètres sauvegardés avec succès !
            </span>
          )}
        </div>

      </form>

      {/* Danger Zone */}
      <div className="glass-panel" style={{ padding: '24px', border: '1px solid rgba(226, 75, 74, 0.2)', background: 'rgba(226, 75, 74, 0.02)' }}>
        <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--color-attack)', display: 'flex', alignItems: 'center', gap: '8px', borderBottom: '1px solid rgba(226, 75, 74, 0.1)', paddingBottom: '10px', marginBottom: '16px' }}>
          <AlertTriangle size={18} /> Zone de Danger (Maintenance)
        </h3>

        {!showClearConfirm ? (
          <div>
            <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginBottom: '16px', lineHeight: '1.4' }}>
              Cette action supprimera définitivement l'ensemble des données d'alertes collectées et stockées dans la base SQLite locale (<code>logs.db</code>). Cette action est irréversible.
            </p>
            <button
              onClick={() => setShowClearConfirm(true)}
              style={{
                padding: '10px 16px', background: 'rgba(226, 75, 74, 0.1)', border: '1px solid rgba(226, 75, 74, 0.3)',
                borderRadius: '8px', color: 'var(--color-attack)', fontSize: '13px', fontWeight: 600, cursor: 'pointer',
                display: 'inline-flex', alignItems: 'center', gap: '8px', transition: 'all 0.2s'
              }}
            >
              <Trash2 size={15} /> Vider la base de données
            </button>
          </div>
        ) : (
          <div>
            <p style={{ fontSize: '14px', fontWeight: 600, color: '#fff', marginBottom: '16px' }}>
              ⚠️ Êtes-vous absolument sûr de vouloir vider TOUTES les alertes de la base ?
            </p>
            <div style={{ display: 'flex', gap: '12px' }}>
              <button
                onClick={handleClearDatabase}
                disabled={isClearing}
                style={{
                  padding: '10px 16px', background: 'var(--color-attack)', border: 0,
                  borderRadius: '8px', color: '#fff', fontSize: '13px', fontWeight: 600, cursor: isClearing ? 'not-allowed' : 'pointer',
                  display: 'inline-flex', alignItems: 'center', gap: '8px'
                }}
              >
                {isClearing ? 'Nettoyage en cours...' : 'Oui, Supprimer définitivement'}
              </button>
              <button
                onClick={() => setShowClearConfirm(false)}
                style={{
                  padding: '10px 16px', background: 'rgba(240, 246, 252, 0.05)', border: '1px solid var(--border-standard)',
                  borderRadius: '8px', color: '#fff', fontSize: '13px', fontWeight: 600, cursor: 'pointer'
                }}
              >
                Annuler
              </button>
            </div>
          </div>
        )}

        {clearSuccess && (
          <p style={{ color: 'var(--color-normal)', fontSize: '13px', fontWeight: 600, marginTop: '12px' }}>
            ✓ Base de données réinitialisée avec succès !
          </p>
        )}
      </div>

      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}

export default Settings;
