import React from 'react';
import { 
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, BarChart, Bar, ScatterChart, Scatter, ZAxis
} from 'recharts';

const CLS_COLOR = {
  normal: '#1D9E75',
  false_positive: '#EF9F27',
  attack: '#E24B4A'
};

function Dashboard({ stats }) {
  const { 
    total = 0, 
    attacks = 0, 
    false_positives = 0, 
    normal = 0, 
    average_risk = 0, 
    timeline = [], 
    top_rules = [], 
    scatter = [] 
  } = stats || {};

  const cardData = [
    { label: 'Alertes totales', val: total, color: '#f0f6fc' },
    { label: 'Attaques détectées', val: attacks, color: 'var(--color-attack)' },
    { label: 'Faux positifs', val: false_positives, color: 'var(--color-fp)' },
    { label: 'Trafic normal', val: normal, color: 'var(--color-normal)' },
    { label: 'Risque moyen', val: `${average_risk}%`, color: '#7F77DD' }
  ];

  // Pie chart formatting
  const pieData = [
    { name: 'Normal', value: normal, color: CLS_COLOR.normal },
    { name: 'Faux Positifs', value: false_positives, color: CLS_COLOR.false_positive },
    { name: 'Attaques', value: attacks, color: CLS_COLOR.attack }
  ].filter(item => item.value > 0);

  // Scatter plot data formatting
  const formattedScatter = scatter.map(item => ({
    freq: item.freq_per_min,
    risk: item.risk_score,
    prediction: item.prediction,
    alert_name: item.alert_name,
    src_ip: item.src_ip
  }));

  // Timeline area formatting
  const formattedTimeline = timeline.map((item, idx) => ({
    index: idx + 1,
    risk: item.risk_score,
    alert_name: item.alert_name,
    prediction: item.prediction
  }));

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      const data = payload[0].payload;
      return (
        <div style={{ background: 'var(--bg-sidebar)', border: '1px solid var(--border-standard)', padding: '10px', borderRadius: '8px', color: 'var(--text-main)' }}>
          <p style={{ fontWeight: 600, fontSize: '13px' }}>{data.alert_name}</p>
          {data.src_ip && <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Source: {data.src_ip}</p>}
          <p style={{ fontSize: '12px', color: CLS_COLOR[data.prediction] || 'var(--text-main)', fontWeight: 600 }}>
            {data.prediction ? data.prediction.toUpperCase() : ''}
          </p>
          <p style={{ fontSize: '12px' }}>Risque: {data.risk || data.risk_score || data.y}%</p>
          {data.freq && <p style={{ fontSize: '12px' }}>Fréquence: {data.freq}/min</p>}
        </div>
      );
    }
    return null;
  };

  return (
    <div>
      <div style={{ marginBottom: '24px' }}>
        <h1 style={{ fontSize: '24px', fontWeight: 700, letterSpacing: '-0.02em' }}>SOC AI Detection Dashboard</h1>
      </div>

      {/* Metrics Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '20px', marginBottom: '30px' }}>
        {cardData.map((card, i) => (
          <div key={i} className="glass-panel" style={{ padding: '20px', textAlign: 'center' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>{card.label}</div>
            <div style={{ fontSize: '32px', fontWeight: 800, color: card.color, marginTop: '8px', filter: card.color !== '#f0f6fc' ? `drop-shadow(0 0 12px ${card.color}25)` : 'none' }}>
              {card.val}
            </div>
          </div>
        ))}
      </div>

      {/* Main Charts Row */}
      <div style={{ display: 'grid', gridTemplateColumns: '3fr 2fr', gap: '30px', marginBottom: '30px' }}>
        {/* Timeline Area Chart */}
        <div className="glass-panel" style={{ padding: '24px', height: '380px', display: 'flex', flexDirection: 'column' }}>
          <h3 style={{ fontSize: '15px', fontWeight: 600, marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="pulse-red" style={{ width: '8px', height: '8px', margin: 0 }}></span> Timeline des alertes (Risque)
          </h3>
          <div style={{ flex: 1, width: '100%' }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={formattedTimeline}>
                <defs>
                  <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--color-primary)" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="var(--color-primary)" stopOpacity={0.0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-standard)" />
                <XAxis dataKey="index" stroke="var(--text-muted)" fontSize={11} tickLine={false} />
                <YAxis stroke="var(--text-muted)" domain={[0, 100]} fontSize={11} tickLine={false} />
                <Tooltip content={<CustomTooltip />} />
                <Area type="monotone" dataKey="risk" stroke="var(--color-primary)" strokeWidth={2} fillOpacity={1} fill="url(#colorRisk)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Class Distribution Pie Chart */}
        <div className="glass-panel" style={{ padding: '24px', height: '380px', display: 'flex', flexDirection: 'column' }}>
          <h3 style={{ fontSize: '15px', fontWeight: 600, marginBottom: '20px' }}>Distribution des classes</h3>
          <div style={{ flex: 1, width: '100%', position: 'relative' }}>
            {pieData.length === 0 ? (
              <div style={{ display: 'flex', alignItems: 'center', justifyItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-muted)', fontSize: '14px' }}>
                Aucune alerte enregistrée
              </div>
            ) : (
              <>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={70}
                      outerRadius={95}
                      paddingAngle={4}
                      dataKey="value"
                    >
                      {pieData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
                <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', textAlign: 'center', pointerEvents: 'none' }}>
                  <div style={{ fontSize: '24px', fontWeight: 800 }}>{total}</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>Alertes</div>
                </div>
              </>
            )}
          </div>
          {pieData.length > 0 && (
            <div style={{ display: 'flex', justifyContent: 'center', gap: '16px', marginTop: '10px' }}>
              {pieData.map((item, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px' }}>
                  <span style={{ width: '10px', height: '10px', borderRadius: '50%', background: item.color }}></span>
                  <span style={{ color: 'var(--text-muted)' }}>{item.name} ({Math.round(item.value / total * 100)}%)</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Secondary Charts Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '30px' }}>
        {/* Risk Score vs Frequency Scatter Plot */}
        <div className="glass-panel" style={{ padding: '24px', height: '340px', display: 'flex', flexDirection: 'column' }}>
          <h3 style={{ fontSize: '15px', fontWeight: 600, marginBottom: '20px' }}>Score de Risque vs Fréquence/min</h3>
          <div style={{ flex: 1, width: '100%' }}>
            <ResponsiveContainer width="100%" height="100%">
              <ScatterChart margin={{ top: 10, right: 10, bottom: 10, left: -10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-standard)" />
                <XAxis type="number" dataKey="freq" name="Fréquence" stroke="var(--text-muted)" fontSize={11} tickLine={false} unit="/m" />
                <YAxis type="number" dataKey="risk" name="Risque" stroke="var(--text-muted)" fontSize={11} tickLine={false} unit="%" domain={[0, 100]} />
                <Tooltip content={<CustomTooltip />} />
                {Object.keys(CLS_COLOR).map((cls) => {
                  const dataForClass = formattedScatter.filter(item => item.prediction === cls);
                  return (
                    <Scatter
                      key={cls}
                      name={cls}
                      data={dataForClass}
                      fill={CLS_COLOR[cls]}
                      shape="circle"
                      opacity={0.7}
                    />
                  );
                })}
              </ScatterChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Top Triggered Rules Bar Chart */}
        <div className="glass-panel" style={{ padding: '24px', height: '340px', display: 'flex', flexDirection: 'column' }}>
          <h3 style={{ fontSize: '15px', fontWeight: 600, marginBottom: '20px' }}>Top 5 Alertes déclenchées</h3>
          <div style={{ flex: 1, width: '100%' }}>
            {top_rules.length === 0 ? (
              <div style={{ display: 'flex', alignItems: 'center', justifyItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--text-muted)', fontSize: '14px' }}>
                Aucune alerte enregistrée
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={top_rules} layout="vertical" margin={{ top: 10, right: 10, bottom: 10, left: 30 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border-standard)" />
                  <XAxis type="number" stroke="var(--text-muted)" fontSize={11} tickLine={false} />
                  <YAxis type="category" dataKey="alert_name" stroke="var(--text-muted)" fontSize={11} tickLine={false} width={100} />
                  <Tooltip />
                  <Bar dataKey="count" fill="var(--color-primary)" radius={[0, 4, 4, 0]} barSize={14} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;
