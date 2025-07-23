import React, { useState, useEffect } from 'react';
import axios from 'axios';
import ThreatLookup from './ThreatLookup';
import StatsCards from './StatsCards';
import HistoryTable from './HistoryTable';

const API_BASE = process.env.REACT_APP_API_URL;

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [refresh, setRefresh] = useState(0);

  useEffect(() => {
    axios.get(\`\${API_BASE}/api/stats\`).then(res => setStats(res.data));
    axios.get(\`\${API_BASE}/api/history\`).then(res => setHistory(res.data.scans));
  }, [refresh]);

  return (
    <div className="p-4 space-y-8">
      {stats && <StatsCards stats={stats} />}
      <ThreatLookup onResult={() => setRefresh(r=>r+1)} />
      {history.length>0 && <HistoryTable history={history} />}
    </div>
  );
}
