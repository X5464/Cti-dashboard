import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import ThreatLookup from './ThreatLookup';
import HistoryTable from './HistoryTable';
import StatsCards from './StatsCards';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

function Dashboard() {
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  const fetchStats = useCallback(async () => {
    try {
      const response = await axios.get(`${API_BASE}/api/stats`, { timeout: 10000 });
      if (response.data && response.data.status !== 'error') {
        setStats(response.data);
      }
    } catch (error) {
      console.error('Stats error:', error);
      setError('Failed to load statistics');
    }
  }, []);

  const fetchHistory = useCallback(async () => {
    try {
      const response = await axios.get(`${API_BASE}/api/history`, { timeout: 10000 });
      if (response.data && Array.isArray(response.data.scans)) {
        setHistory(response.data.scans);
      }
    } catch (error) {
      console.error('History error:', error);
      setError('Failed to load scan history');
    }
  }, []);

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      try {
        await Promise.all([fetchStats(), fetchHistory()]);
      } catch (error) {
        console.error('Error loading dashboard data:', error);
      } finally {
        setLoading(false);
      }
    };

    loadData();
  }, [refreshTrigger, fetchStats, fetchHistory]);

  const handleNewScan = useCallback(() => {
    setRefreshTrigger(prev => prev + 1);
  }, []);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900">
      {/* Animated Background */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -inset-10 opacity-50">
          <div className="absolute top-0 -left-4 w-72 h-72 bg-purple-300 rounded-full mix-blend-multiply filter blur-xl opacity-70 animate-blob"></div>
          <div className="absolute top-0 -right-4 w-72 h-72 bg-yellow-300 rounded-full mix-blend-multiply filter blur-xl opacity-70 animate-blob animation-delay-2000"></div>
          <div className="absolute -bottom-8 left-20 w-72 h-72 bg-pink-300 rounded-full mix-blend-multiply filter blur-xl opacity-70 animate-blob animation-delay-4000"></div>
        </div>
      </div>

      <div className="relative z-10">
        {/* Header */}
        <header className="bg-black/20 backdrop-blur-lg border-b border-white/10 shadow-2xl">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-4xl font-bold bg-gradient-to-r from-cyan-400 via-purple-400 to-pink-400 bg-clip-text text-transparent">
                  🛡️ CTI Dashboard
                </h1>
                <p className="text-gray-300 mt-2 text-lg">Advanced Cyber Threat Intelligence Portal</p>
              </div>
              <div className="flex items-center space-x-6">
                <div className="flex items-center space-x-3 bg-green-900/30 px-4 py-2 rounded-full border border-green-500/30">
                  <div className="w-3 h-3 bg-green-400 rounded-full animate-pulse"></div>
                  <span className="text-green-300 font-medium">Live</span>
                </div>
              </div>
            </div>
          </div>
        </header>

        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
          {error && (
            <div className="bg-red-900/30 border border-red-500/50 text-red-200 px-6 py-4 rounded-xl backdrop-blur-sm">
              <div className="flex items-center space-x-3">
                <span className="text-xl">⚠️</span>
                <span>{error}</span>
              </div>
            </div>
          )}

          {/* Stats Cards */}
          {stats ? (
            <StatsCards stats={stats} />
          ) : loading ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
              {[...Array(4)].map((_, i) => (
                <div key={i} className="bg-white/5 backdrop-blur-lg rounded-2xl p-6 border border-white/10 animate-pulse">
                  <div className="h-16 bg-white/10 rounded-lg"></div>
                </div>
              ))}
            </div>
          ) : null}

          {/* Threat Lookup */}
          <div className="bg-white/5 backdrop-blur-lg rounded-2xl p-8 border border-white/10 shadow-2xl">
            <ThreatLookup onNewScan={handleNewScan} />
          </div>

          {/* History Table */}
          <div className="bg-white/5 backdrop-blur-lg rounded-2xl p-8 border border-white/10 shadow-2xl">
            <HistoryTable history={history} />
          </div>
        </main>

        {/* Footer */}
        <footer className="bg-black/20 backdrop-blur-lg border-t border-white/10 mt-16">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <div className="text-center">
              <p className="text-gray-300 text-lg">
                🧠 Built by <span className="text-transparent bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text font-semibold">Rajarshi Chakraborty</span> – Cybersecurity Intern
              </p>
              <p className="text-gray-400 mt-2">
                Powered by VirusTotal & AbuseIPDB APIs | Real-time Threat Intelligence
              </p>
            </div>
          </div>
        </footer>
      </div>
    </div>
  );
}

export default Dashboard;
