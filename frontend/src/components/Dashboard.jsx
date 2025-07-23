import React, { useState, useEffect } from 'react';
import axios from 'axios';
import io from 'socket.io-client';
import ThreatLookup from './ThreatLookup';
import StatsCards from './StatsCards';
import HistoryTable from './HistoryTable';
import ThreatMap from './ThreatMap';
import AIInsights from './AIInsights';
import ROIAnalysis from './ROIAnalysis';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [activeTab, setActiveTab] = useState('overview');
  const [realTimeAlerts, setRealTimeAlerts] = useState([]);
  const [socket, setSocket] = useState(null);

  useEffect(() => {
    // Initialize socket connection
    const newSocket = io(API_BASE);
    setSocket(newSocket);

    newSocket.on('connected', (data) => {
      console.log('Connected to real-time monitoring:', data);
    });

    newSocket.on('threat_alert', (alert) => {
      setRealTimeAlerts(prev => [alert, ...prev.slice(0, 9)]);
    });

    return () => newSocket.close();
  }, []);

  useEffect(() => {
    fetchStats();
    fetchHistory();
  }, []);

  const fetchStats = async () => {
    try {
      const response = await axios.get(`${API_BASE}/api/stats`);
      setStats(response.data);
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  };

  const fetchHistory = async () => {
    try {
      const response = await axios.get(`${API_BASE}/api/history`);
      setHistory(response.data.scans || []);
    } catch (error) {
      console.error('Error fetching history:', error);
    }
  };

  const handleNewScan = () => {
    fetchStats();
    fetchHistory();
  };

  const tabs = [
    { id: 'overview', label: '📊 Overview', component: 'overview' },
    { id: 'scanner', label: '🔍 AI Scanner', component: 'scanner' },
    { id: 'map', label: '🌍 Threat Map', component: 'map' },
    { id: 'insights', label: '🤖 AI Insights', component: 'insights' },
    { id: 'roi', label: '💰 ROI Analysis', component: 'roi' },
    { id: 'history', label: '📈 History', component: 'history' }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-blue-900 to-purple-900">
      {/* Real-time Alerts */}
      {realTimeAlerts.length > 0 && (
        <div className="fixed top-4 right-4 z-50 space-y-2">
          {realTimeAlerts.slice(0, 3).map((alert, index) => (
            <div key={index} className="bg-red-600 text-white p-4 rounded-lg shadow-lg animate-pulse">
              <div className="font-bold">🚨 High Threat Detected!</div>
              <div>IP: {alert.ip}</div>
              <div>Score: {alert.threat_score}/100</div>
            </div>
          ))}
        </div>
      )}

      {/* Header */}
      <header className="bg-black/20 backdrop-blur-lg border-b border-white/10">
        <div className="max-w-7xl mx-auto px-4 py-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-4xl font-bold bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
                🤖 AI-Enhanced CTI Dashboard
              </h1>
              <p className="text-gray-300 mt-2">Advanced Threat Intelligence with Machine Learning</p>
            </div>
            <div className="flex items-center space-x-4">
              <div className="bg-green-500/20 px-4 py-2 rounded-full border border-green-500/30">
                <span className="text-green-300">🟢 AI Online</span>
              </div>
              <div className="bg-blue-500/20 px-4 py-2 rounded-full border border-blue-500/30">
                <span className="text-blue-300">📡 Real-time Monitoring</span>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="bg-black/10 backdrop-blur-sm border-b border-white/10">
        <div className="max-w-7xl mx-auto px-4">
          <div className="flex space-x-0 overflow-x-auto">
            {tabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-6 py-4 font-semibold transition-all duration-300 border-b-2 ${
                  activeTab === tab.id
                    ? 'text-cyan-400 border-cyan-400 bg-cyan-400/10'
                    : 'text-gray-300 border-transparent hover:text-white hover:bg-white/5'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 py-8">
        {activeTab === 'overview' && (
          <div className="space-y-8">
            {stats && <StatsCards stats={stats} />}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              <div className="bg-white/5 backdrop-blur-lg rounded-2xl p-6 border border-white/10">
                <h3 className="text-xl font-bold text-white mb-4">🎯 Quick Threat Scan</h3>
                <ThreatLookup onNewScan={handleNewScan} compact={true} />
              </div>
              <div className="bg-white/5 backdrop-blur-lg rounded-2xl p-6 border border-white/10">
                <h3 className="text-xl font-bold text-white mb-4">🚨 Recent Alerts</h3>
                <div className="space-y-2">
                  {realTimeAlerts.slice(0, 5).map((alert, index) => (
                    <div key={index} className="bg-red-500/20 p-3 rounded border border-red-500/30">
                      <div className="text-sm">
                        <span className="font-bold text-red-300">{alert.ip}</span>
                        <span className="text-gray-300 ml-2">Score: {alert.threat_score}</span>
                      </div>
                    </div>
                  ))}
                  {realTimeAlerts.length === 0 && (
                    <div className="text-gray-400 text-center py-4">No recent alerts</div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'scanner' && (
          <div className="bg-white/5 backdrop-blur-lg rounded-2xl p-8 border border-white/10">
            <ThreatLookup onNewScan={handleNewScan} />
          </div>
        )}

        {activeTab === 'map' && (
          <div className="bg-white/5 backdrop-blur-lg rounded-2xl p-8 border border-white/10">
            <ThreatMap />
          </div>
        )}

        {activeTab === 'insights' && (
          <div className="bg-white/5 backdrop-blur-lg rounded-2xl p-8 border border-white/10">
            <AIInsights history={history} />
          </div>
        )}

        {activeTab === 'roi' && (
          <div className="bg-white/5 backdrop-blur-lg rounded-2xl p-8 border border-white/10">
            <ROIAnalysis />
          </div>
        )}

        {activeTab === 'history' && (
          <div className="bg-white/5 backdrop-blur-lg rounded-2xl p-8 border border-white/10">
            <HistoryTable history={history} />
          </div>
        )}
      </main>
    </div>
  );
}
