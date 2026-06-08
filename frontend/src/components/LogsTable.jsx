import React, { useState, useEffect } from 'react';
import { Search, Filter, RotateCcw, ChevronLeft, ChevronRight, Eye, AlertOctagon, AlertTriangle, ShieldCheck, Download } from 'lucide-react';

const CLS_DETAILS = {
  normal: { label: 'Normal', color: 'var(--color-normal)', bg: 'rgba(29, 158, 117, 0.15)', border: 'rgba(29, 158, 117, 0.3)', icon: ShieldCheck },
  false_positive: { label: 'Faux Positif', color: 'var(--color-fp)', bg: 'rgba(239, 159, 39, 0.15)', border: 'rgba(239, 159, 39, 0.3)', icon: AlertTriangle },
  attack: { label: 'Attaque', color: 'var(--color-attack)', bg: 'rgba(226, 75, 74, 0.15)', border: 'rgba(226, 75, 74, 0.3)', icon: AlertOctagon }
};

function LogsTable({ logs: sseLogs, total: sseTotal, setSelectedLog, API_BASE, fetchLogs }) {
  // Filter States
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedClass, setSelectedClass] = useState('all');
  const [minRisk, setMinRisk] = useState(0);
  
  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const limit = 15;

  // Query results (if filters are active)
  const [filteredLogs, setFilteredLogs] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const [hasActiveFilters, setHasActiveFilters] = useState(false);

  // Check if any filters are active
  const checkFiltersActive = () => {
    return searchTerm.trim() !== '' || selectedClass !== 'all' || minRisk > 0 || currentPage > 1;
  };

  const fetchFilteredLogs = async () => {
    setIsLoading(true);
    try {
      const offset = (currentPage - 1) * limit;
      let url = `${API_BASE}/logs?limit=${limit}&offset=${offset}&min_risk=${minRisk}`;
      if (selectedClass !== 'all') {
        url += `&prediction=${selectedClass}`;
      }
      if (searchTerm.trim() !== '') {
        url += `&search=${encodeURIComponent(searchTerm)}`;
      }
      const res = await fetch(url);
      const data = await res.json();
      setFilteredLogs(data.logs);
      setTotalCount(data.total);
    } catch (err) {
      console.error('Error fetching filtered logs:', err);
    } finally {
      setIsLoading(false);
    }
  };

  // Determine which list to display
  const activeFilters = checkFiltersActive();

  useEffect(() => {
    setHasActiveFilters(activeFilters);
    if (activeFilters) {
      fetchFilteredLogs();
    } else {
      // No filters: display parent SSE logs
      setFilteredLogs([]);
      setTotalCount(sseTotal);
    }
  }, [searchTerm, selectedClass, minRisk, currentPage, sseLogs, sseTotal]);

  // Reset filters
  const handleReset = () => {
    setSearchTerm('');
    setSelectedClass('all');
    setMinRisk(0);
    setCurrentPage(1);
  };

  const displayedLogs = hasActiveFilters ? filteredLogs : sseLogs.slice(0, limit);
  const totalLogs = hasActiveFilters ? totalCount : sseTotal;
  const totalPages = Math.ceil(totalLogs / limit) || 1;

  // Handle Export to CSV
  const handleExport = () => {
    const csvRows = [];
    // CSV Header
    const headers = ['ID', 'Horodatage', 'Nom de l\'alerte', 'Source IP', 'Dest IP', 'Risque %', 'Prediction', 'Statut LLM'];
    csvRows.push(headers.join(','));

    const logsToExport = hasActiveFilters ? filteredLogs : sseLogs;
    logsToExport.forEach(log => {
      const values = [
        log.id,
        `"${log.timestamp}"`,
        `"${log.alert_name}"`,
        log.src_ip || '',
        log.dst_ip || '',
        log.risk_score,
        log.prediction,
        log.llm_analyzed ? 'Analysé' : 'Non Analysé'
      ];
      csvRows.push(values.join(','));
    });

    const csvContent = 'data:text/csv;charset=utf-8,\uFEFF' + csvRows.join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `soc_alerts_${new Date().toISOString().slice(0,10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <div>
          <h1 style={{ fontSize: '24px', fontWeight: 700, letterSpacing: '-0.02em' }}>Base d'alertes SOC</h1>
          <p style={{ fontSize: '14px', color: 'var(--text-muted)' }}>
            Consulter, filtrer et analyser l'historique complet des alertes de détection ({totalLogs} alertes au total)
          </p>
        </div>
        <button 
          onClick={handleExport}
          className="glass-panel"
          style={{ 
            display: 'flex', alignItems: 'center', gap: '8px', padding: '10px 16px', borderRadius: '8px',
            border: '1px solid var(--border-standard)', background: 'rgba(240, 246, 252, 0.03)',
            color: '#fff', fontSize: '13px', fontWeight: 600, cursor: 'pointer', transition: 'all 0.2s'
          }}
        >
          <Download size={16} /> Exporter en CSV
        </button>
      </div>

      {/* Filters Control Panel */}
      <div className="glass-panel" style={{ padding: '20px', marginBottom: '24px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '2fr 2fr 2fr 1fr', gap: '20px', alignItems: 'end' }}>
          
          {/* Text Search */}
          <div>
            <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', marginBottom: '8px' }}>Recherche textuelle</label>
            <div style={{ position: 'relative' }}>
              <Search size={16} style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input 
                type="text" 
                placeholder="IP, règle, description..."
                value={searchTerm}
                onChange={(e) => { setSearchTerm(e.target.value); setCurrentPage(1); }}
                style={{
                  width: '100%', padding: '10px 12px 10px 38px', background: 'rgba(9, 11, 17, 0.5)', 
                  border: '1px solid var(--border-standard)', borderRadius: '8px', color: '#fff', fontSize: '13px'
                }}
              />
            </div>
          </div>

          {/* Classification Class Filter */}
          <div>
            <label style={{ display: 'block', fontSize: '11px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', marginBottom: '8px' }}>Classification</label>
            <div style={{ display: 'flex', gap: '6px' }}>
              {['all', 'normal', 'false_positive', 'attack'].map((cls) => {
                const label = cls === 'all' ? 'Tous' : cls === 'normal' ? 'Normal' : cls === 'false_positive' ? 'Faux Positif' : 'Attaque';
                const active = selectedClass === cls;
                let activeStyle = { background: 'rgba(127, 119, 221, 0.15)', border: '1px solid var(--color-primary)', color: 'var(--color-primary)' };
                if (cls === 'normal' && active) activeStyle = { background: 'rgba(29, 158, 117, 0.15)', border: '1px solid var(--color-normal)', color: 'var(--color-normal)' };
                if (cls === 'false_positive' && active) activeStyle = { background: 'rgba(239, 159, 39, 0.15)', border: '1px solid var(--color-fp)', color: 'var(--color-fp)' };
                if (cls === 'attack' && active) activeStyle = { background: 'rgba(226, 75, 74, 0.15)', border: '1px solid var(--color-attack)', color: 'var(--color-attack)' };

                return (
                  <button
                    key={cls}
                    onClick={() => { setSelectedClass(cls); setCurrentPage(1); }}
                    style={{
                      flex: 1, padding: '10px 8px', borderRadius: '8px', border: '1px solid var(--border-standard)',
                      background: 'rgba(9, 11, 17, 0.3)', color: 'var(--text-muted)', fontSize: '12px', fontWeight: 600,
                      cursor: 'pointer', transition: 'all 0.2s', ...(active ? activeStyle : {})
                    }}
                  >
                    {label}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Risk Level Slider */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
              <label style={{ fontSize: '11px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)' }}>Score de Risque min</label>
              <span style={{ fontSize: '12px', color: 'var(--color-primary)', fontWeight: 700 }}>&ge; {minRisk}%</span>
            </div>
            <input 
              type="range" 
              min="0" 
              max="99" 
              value={minRisk}
              onChange={(e) => { setMinRisk(parseInt(e.target.value)); setCurrentPage(1); }}
              style={{
                width: '100%', height: '6px', background: 'rgba(9, 11, 17, 0.5)', outline: 'none',
                borderRadius: '3px', cursor: 'pointer', accentColor: 'var(--color-primary)'
              }}
            />
          </div>

          {/* Reset Filters */}
          <button
            onClick={handleReset}
            disabled={!hasActiveFilters}
            className="glass-panel"
            style={{
              padding: '10px 14px', borderRadius: '8px', border: '1px solid var(--border-standard)',
              background: hasActiveFilters ? 'rgba(127, 119, 221, 0.08)' : 'rgba(240, 246, 252, 0.01)',
              color: hasActiveFilters ? 'var(--color-primary)' : 'rgba(255, 255, 255, 0.15)',
              fontSize: '12px', fontWeight: 600, cursor: hasActiveFilters ? 'pointer' : 'not-allowed',
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px', height: '40px'
            }}
          >
            <RotateCcw size={14} /> Réinitialiser
          </button>

        </div>
      </div>

      {/* Table Container */}
      <div className="glass-panel" style={{ overflow: 'hidden' }}>
        {isLoading ? (
          <div style={{ padding: '80px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '16px' }}>
            <div className="pulse-red" style={{ width: '12px', height: '12px', background: 'var(--color-primary)' }}></div>
            <span style={{ fontSize: '14px', color: 'var(--text-muted)' }}>Recherche dans la base d'alertes...</span>
          </div>
        ) : displayedLogs.length === 0 ? (
          <div style={{ padding: '80px', textAlign: 'center', color: 'var(--text-muted)' }}>
            <p style={{ fontSize: '15px', fontWeight: 500, marginBottom: '6px' }}>Aucun incident trouvé</p>
            <p style={{ fontSize: '13px' }}>Modifiez vos critères de recherche ou réinitialisez les filtres.</p>
          </div>
        ) : (
          <table className="custom-table">
            <thead>
              <tr>
                <th style={{ width: '80px' }}>ID</th>
                <th style={{ width: '180px' }}>Horodatage</th>
                <th>Alerte / Règle</th>
                <th style={{ width: '160px' }}>Source IP</th>
                <th style={{ width: '160px' }}>Dest IP</th>
                <th style={{ width: '120px' }}>Risque XGB</th>
                <th style={{ width: '160px' }}>Classification</th>
                <th style={{ width: '120px' }}>Rapport AI</th>
                <th style={{ width: '100px', textAlign: 'center' }}>Inspecter</th>
              </tr>
            </thead>
            <tbody>
              {displayedLogs.map((log) => {
                const clsInfo = CLS_DETAILS[log.prediction] || { label: log.prediction, color: '#fff', bg: 'rgba(255,255,255,0.1)', icon: ShieldCheck };
                const IconComponent = clsInfo.icon;
                
                return (
                  <tr key={log.id}>
                    <td style={{ color: 'var(--text-muted)', fontWeight: 600 }}>#{log.id}</td>
                    <td style={{ fontSize: '13px', color: 'var(--text-muted)' }}>{log.timestamp}</td>
                    <td>
                      <div>
                        <div style={{ fontWeight: 600, color: '#fff' }}>{log.alert_name}</div>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px', textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap', maxWidth: '380px' }}>
                          {log.description}
                        </div>
                      </div>
                    </td>
                    <td style={{ fontFamily: 'monospace', fontSize: '13px', color: '#cbd5e1' }}>{log.src_ip || 'N/A'}</td>
                    <td style={{ fontFamily: 'monospace', fontSize: '13px', color: '#cbd5e1' }}>{log.dst_ip || 'N/A'}</td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ fontWeight: 700, fontSize: '14px', width: '36px' }}>{log.risk_score}%</span>
                        <div style={{ flex: 1, height: '4px', background: 'rgba(240, 246, 252, 0.05)', borderRadius: '2px', overflow: 'hidden', minWidth: '40px' }}>
                          <div 
                            style={{ 
                              height: '100%', 
                              width: `${log.risk_score}%`, 
                              background: log.risk_score >= 70 ? 'var(--color-attack)' : log.risk_score >= 30 ? 'var(--color-fp)' : 'var(--color-normal)'
                            }}
                          ></div>
                        </div>
                      </div>
                    </td>
                    <td>
                      <span className={`badge`} style={{ background: clsInfo.bg, color: clsInfo.color, border: `1px solid ${clsInfo.border}`, gap: '4px' }}>
                        <IconComponent size={12} />
                        {clsInfo.label}
                      </span>
                    </td>
                    <td>
                      {log.llm_analyzed ? (
                        <span style={{ fontSize: '12px', color: 'var(--color-primary)', fontWeight: 600, background: 'rgba(127, 119, 221, 0.12)', padding: '4px 8px', borderRadius: '4px' }}>
                          🧠 Rapport disponible
                        </span>
                      ) : (
                        <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Non généré</span>
                      )}
                    </td>
                    <td style={{ textAlign: 'center' }}>
                      <button
                        onClick={() => setSelectedLog(log)}
                        style={{
                          background: 'rgba(127, 119, 221, 0.1)', border: '1px solid rgba(127, 119, 221, 0.2)',
                          color: 'var(--color-primary)', width: '32px', height: '32px', borderRadius: '6px',
                          display: 'inline-flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', transition: 'all 0.2s'
                        }}
                        title="Ouvrir dans l'analyseur"
                      >
                        <Eye size={15} />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}

        {/* Pagination Footer */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '16px 20px', borderTop: '1px solid var(--border-standard)', background: 'rgba(9, 11, 17, 0.2)' }}>
          <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
            Affichage de <b>{displayedLogs.length}</b> alertes sur <b>{totalLogs}</b>
          </span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <button
              onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
              disabled={currentPage === 1}
              style={{
                background: 'rgba(240, 246, 252, 0.02)', border: '1px solid var(--border-standard)',
                color: currentPage === 1 ? 'rgba(255, 255, 255, 0.15)' : '#fff', padding: '6px 10px',
                borderRadius: '6px', cursor: currentPage === 1 ? 'not-allowed' : 'pointer',
                display: 'flex', alignItems: 'center', gap: '4px', fontSize: '13px'
              }}
            >
              <ChevronLeft size={16} /> Précédent
            </button>
            <span style={{ fontSize: '13px', fontWeight: 600 }}>
              Page {currentPage} sur {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
              disabled={currentPage === totalPages}
              style={{
                background: 'rgba(240, 246, 252, 0.02)', border: '1px solid var(--border-standard)',
                color: currentPage === totalPages ? 'rgba(255, 255, 255, 0.15)' : '#fff', padding: '6px 10px',
                borderRadius: '6px', cursor: currentPage === totalPages ? 'not-allowed' : 'pointer',
                display: 'flex', alignItems: 'center', gap: '4px', fontSize: '13px'
              }}
            >
              Suivant <ChevronRight size={16} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default LogsTable;
