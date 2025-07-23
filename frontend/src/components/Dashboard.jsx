import React, { useState, useEffect } from 'react';
import axios from 'axios';
import io from 'socket.io-client';
import ThreatLookup from './ThreatLookup';
import StatsCards from './StatsCards';
import HistoryTable from './HistoryTable';
import GeographicIntel from './GeographicIntel';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [history, setHistory] = useState([]);
  const [activeTab, setActiveTab] = useState('overview');
  const [realTimeAlerts, setRealTimeAlerts] = useState([]);
  const [socket, setSocket] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    // Initialize socket connection
    const newSocket = io(API_BASE);
    setSocket(newSocket);

    newSocket.on('connected', (data) => {
      console.log('Connected to real-time monitoring:', data);
    });

    newSocket.on('high_threat_alert', (alert) => {
      setRealTimeAlerts(prev => [alert, ...prev.slice(0, 9)]);
      // Show browser notification if permitted
      if (Notification.permission === 'granted') {
        new Notification('High Threat Detected!', {
          body: `${alert.target} - Score: ${alert.threat_score}/100`,
          icon: '/favicon.ico'
        });
      }
    });

    return () => newSocket.close();
  }, []);

  useEffect(() => {
    fetchStats();
    fetchHistory();
    
    // Request notification permission
    if (Notification.permission === 'default') {
      Notification.requestPermission();
    }
  }, []);

  const fetchStats = async () => {
    try {
      setLoading(true);
      const response = await axios.get(`${API_BASE}/api/stats`);
      setStats(response.data);
    } catch (error) {
      console.error('Error fetching stats:', error);
      setError('Failed to load statistics');
    } finally {
      setLoading(false);
    }
  };

  const fetchHistory = async () => {
    try {
      const response = await axios.get(`${API_BASE}/api/history`);
      setHistory(response.data.scans || []);
    } catch (error) {
      console.error('Error fetching history:', error);
      setError('Failed to load scan history');
    }
  };

  const handleNewScan = () => {
    fetchStats();
    fetchHistory();
  };

  const clearAlerts = () => {
    setRealTimeAlerts([]);
  };

  const tabs = [
    { id: 'overview', label: '📊 Overview', icon: '📊' },
    { id: 'scanner', label: '🔍 Threat Scanner', icon: '🔍' },
    { id: 'geographic', label: '🌍 Location Intel', icon: '🌍' },
    { id: 'history', label: '📈 Scan History', icon: '📈' },
    { id: 'analytics', label: '📊 Analytics', icon: '📊' }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-purple-900 font-inter">
      {/* Animated Background */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -inset-10 opacity-30">
          <div className="absolute top-0 -left-4 w-96 h-96 bg-cyber-blue rounded-full mix-blend-multiply filter blur-xl opacity-30 animate-blob"></div>
          <div className="absolute top-0 -right-4 w-96 h-96 bg-cyber-purple rounded-full mix-blend-multiply filter blur-xl opacity-30 animate-blob" style={{animationDelay: '2s'}}></div>
          <div className="absolute -bottom-8 left-20 w-96 h-96 bg-cyber-green rounded-full mix-blend-multiply filter blur-xl opacity-30 animate-blob" style={{animationDelay: '4s'}}></div>
        </div>
      </div>

      <div className="relative z-10">
        {/* Real-time Alerts */}
        {realTimeAlerts.length > 0 && (
          <div className="fixed top-4 right-4 z-50 space-y-2 max-w-sm">
            <div className="flex justify-between items-center mb-2">
              <span className="text-sm font-semibold text-red-300">🚨 Live Threat Alerts</span>
              <button 
                onClick={clearAlerts}
                className="text-xs text-gray-400 hover:text-white"
              >
                Clear All
              </button>
            </div>
            {realTimeAlerts.slice(0, 3).map((alert, index) => (
              <div key={index} className="bg-red-600/90 backdrop-blur-sm text-white p-4 rounded-lg shadow-xl border border-red-400/50 animate-pulse">
                <div className="font-bold text-sm">🚨 HIGH THREAT DETECTED</div>
                <div className="text-sm">Target: {alert.target}</div>
                <div className="text-sm">Location: {alert.location}</div>
                <div className="text-sm">Score: {alert.threat_score}/100</div>
                <div className="text-xs text-red-200 mt-1">
                  {new Date(alert.timestamp * 1000).toLocaleTimeString()}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Header */}
        <header className="bg-black/20 backdrop-blur-lg border-b border-white/10 shadow-2xl">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-4xl font-bold bg-gradient-to-r from-cyber-blue via-cyber-purple to-cyber-green bg-clip-text text-transparent">
                  🛡️ Professional CTI Dashboard
                </h1>
                <p className="text-gray-300 mt-2 text-lg">Advanced Threat Intelligence with Real Location Detection</p>
              </div>
              <div className="flex items-center space-x-6">
                <div className="flex items-center space-x-3 bg-green-900/30 px-4 py-2 rounded-full border border-green-500/30">
                  <div className="w-3 h-3 bg-green-400 rounded-full animate-pulse"></div>
                  <span className="text-green-300 font-medium">Live System</span>
                </div>
                <div className="flex items-center space-x-3 bg-blue-900/30 px-4 py-2 rounded-full border border-blue-500/30">
                  <div className="w-3 h-3 bg-blue-400 rounded-full animate-pulse"></div>
                  <span className="text-blue-300 font-medium">Real Location</span>
                </div>
                {realTimeAlerts.length > 0 && (
                  <div className="flex items-center space-x-3 bg-red-900/30 px-4 py-2 rounded-full border border-red-500/30">
                    <div className="w-3 h-3 bg-red-400 rounded-full animate-pulse"></div>
                    <span className="text-red-300 font-medium">{realTimeAlerts.length} Alerts</span>
                  </div>
                )}
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
                  className={`px-8 py-4 font-semibold transition-all duration-300 border-b-2 whitespace-nowrap ${
                    activeTab === tab.id
                      ? 'text-cyber-blue border-cyber-blue bg-cyber-blue/10'
                      : 'text-gray-300 border-transparent hover:text-white hover:bg-white/5'
                  }`}
                >
                  <span className="flex items-center space-x-2">
                    <span>{tab.icon}</span>
                    <span>{tab.label}</span>
                  </span>
                </button>
              ))}
            </div>
          </div>
        </nav>

        {/* Main Content */}
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {error && (
            <div className="bg-red-900/30 border border-red-500/50 text-red-200 px-6 py-4 rounded-xl backdrop-blur-sm mb-8">
              <div className="flex items-center space-x-3">
                <span className="text-xl">⚠️</span>
                <span>{error}</span>
                <button 
                  onClick={() => setError('')}
                  className="ml-auto text-red-300 hover:text-white"
                >
                  ✕
                </button>
              </div>
            </div>
          )}

          {activeTab === 'overview' && (
            <div className="space-y-8 fade-in-up">
              {stats && <StatsCards stats={stats} />}
              
              {/* Quick Actions */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <div className="bg-white/5 backdrop-blur-lg rounded-2xl p-8 border border-white/10 shadow-2xl">
                  <h3 className="text-2xl font-bold text-white mb-6 flex items-center space-x-2">
                    <span>🚀</span>
                    <span>Quick Threat Analysis</span>
                  </h3>
                  <ThreatLookup onNewScan={handleNewScan} compact={true} />
                </div>
                
                <div className="bg-white/5 backdrop-blur-lg rounded-2xl p-8 border border-white/10 shadow-2xl">
                  <h3 className="text-2xl font-bold text-white mb-6 flex items-center space-x-2">
                    <span>📊</span>
                    <span>Recent Activity</span>
                  </h3>
                  <div className="space-y-3">
                    {history.slice(0, 5).map((scan, index) => (
                      <div key={index} className="flex items-center justify-between p-3 bg-surface/30 rounded-lg border border-border/30 hover:bg-surface/50 transition-all duration-300">
                        <div className="flex items-center space-x-3">
                          <span className="text-lg">
                            {scan.input_type === 'ip' ? '🌐' : scan.input_type === 'domain' ? '🏠' : '🔗'}
                          </span>
                          <div>
                            <div className="font-mono text-sm text-cyber-blue">
                              {scan.input.length > 25 ? `${scan.input.substring(0, 25)}...` : scan.input}
                            </div>
                            <div className="text-xs text-gray-400">
                              {scan.location?.city && scan.location?.country ? 
                                `📍 ${scan.location.city}, ${scan.location.country}` : 
                                new Date(scan.timestamp * 1000).toLocaleDateString()
                              }
                            </div>
                          </div>
                        </div>
                        <div className={`px-3 py-1 rounded-full text-xs font-semibold border ${
                          scan.threat_score >= 70 ? 'threat-high' :
                          scan.threat_score >= 40 ? 'threat-medium' :
                          'threat-low'
                        }`}>
                          {scan.threat_score}/100
                        </div>
                      </div>
                    ))}
                    {history.length === 0 && (
                      <div className="text-center text-gray-400 py-8">
                        <div className="text-4xl mb-4">🔍</div>
                        <div>No scans yet. Start analyzing threats above!</div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'scanner' && (
            <div className="bg-white/5 backdrop-blur-lg rounded-2xl p-8 border border-white/10 shadow-2xl fade-in-up">
              <ThreatLookup onNewScan={handleNewScan} />
            </div>
          )}

          {activeTab === 'geographic' && (
            <div className="bg-white/5 backdrop-blur-lg rounded-2xl p-8 border border-white/10 shadow-2xl fade-in-up">
              <GeographicIntel history={history} />
            </div>
          )}

          {activeTab === 'history' && (
            <div className="bg-white/5 backdrop-blur-lg rounded-2xl p-8 border border-white/10 shadow-2xl fade-in-up">
              <HistoryTable history={history} />
            </div>
          )}

          {activeTab === 'analytics' && (
            <div className="bg-white/5 backdrop-blur-lg rounded-2xl p-8 border border-white/10 shadow-2xl fade-in-up">
              <h2 className="text-3xl font-bold mb-8 text-center">
                <span className="bg-gradient-to-r from-cyber-blue to-cyber-purple bg-clip-text text-transparent">
                  📊 Advanced Threat Analytics
                </span>
              </h2>
              
              {stats && (
                <div className="space-y-8">
                  {/* Threat Distribution */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                    <div className="bg-gradient-to-r from-red-500/10 to-pink-500/10 p-6 rounded-xl border border-red-500/30">
                      <h4 className="text-lg font-semibold text-red-300 mb-4">🚨 High Risk Threats</h4>
                      <div className="text-4xl font-bold text-red-400 mb-2">{stats.threat_distribution?.high || 0}</div>
                      <div className="text-sm text-gray-400">Critical threats detected</div>
                      <div className="mt-4 bg-red-500/20 rounded-full h-2">
                        <div 
                          className="bg-red-500 h-2 rounded-full transition-all duration-1000"
                          style={{width: `${(stats.threat_distribution?.high || 0) / Math.max(stats.total_scans, 1) * 100}%`}}
                        ></div>
                      </div>
                    </div>
                    
                    <div className="bg-gradient-to-r from-yellow-500/10 to-orange-500/10 p-6 rounded-xl border border-yellow-500/30">
                      <h4 className="text-lg font-semibold text-yellow-300 mb-4">⚠️ Medium Risk</h4>
                      <div className="text-4xl font-bold text-yellow-400 mb-2">{stats.threat_distribution?.medium || 0}</div>
                      <div className="text-sm text-gray-400">Moderate threats identified</div>
                      <div className="mt-4 bg-yellow-500/20 rounded-full h-2">
                        <div 
                          className="bg-yellow-500 h-2 rounded-full transition-all duration-1000"
                          style={{width: `${(stats.threat_distribution?.medium || 0) / Math.max(stats.total_scans, 1) * 100}%`}}
                        ></div>
                      </div>
                    </div>
                    
                    <div className="bg-gradient-to-r from-green-500/10 to-emerald-500/10 p-6 rounded-xl border border-green-500/30">
                      <h4 className="text-lg font-semibold text-green-300 mb-4">✅ Clean Assets</h4>
                      <div className="text-4xl font-bold text-green-400 mb-2">{stats.threat_distribution?.low || 0}</div>
                      <div className="text-sm text-gray-400">Safe assets verified</div>
                      <div className="mt-4 bg-green-500/20 rounded-full h-2">
                        <div 
                          className="bg-green-500 h-2 rounded-full transition-all duration-1000"
                          style={{width: `${(stats.threat_distribution?.low || 0) / Math.max(stats.total_scans, 1) * 100}%`}}
                        ></div>
                      </div>
                    </div>
                  </div>

                  {/* Geographic Analytics */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="bg-surface/20 p-6 rounded-xl border border-border/20">
                      <h4 className="text-lg font-semibold text-white mb-4">🌍 Geographic Distribution</h4>
                      <div className="space-y-3">
                        <div className="flex justify-between">
                          <span className="text-gray-400">Countries Detected:</span>
                          <span className="text-cyber-blue font-semibold">{stats.geographic_stats?.countries_detected || 0}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Cities Identified:</span>
                          <span className="text-cyber-green font-semibold">{stats.geographic_stats?.cities_detected || 0}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Location Accuracy:</span>
                          <span className="text-cyber-purple font-semibold">{stats.system_performance?.location_detection || 'Real-time'}</span>
                        </div>
                      </div>
                    </div>
                    
                    <div className="bg-surface/20 p-6 rounded-xl border border-border/20">
                      <h4 className="text-lg font-semibold text-white mb-4">🎯 System Performance</h4>
                      <div className="space-y-3">
                        <div className="flex justify-between">
                          <span className="text-gray-400">Detection Accuracy:</span>
                          <span className="text-green-400 font-semibold">{stats.system_performance?.accuracy || '97.3%'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Processing Speed:</span>
                          <span className="text-blue-400 font-semibold">{stats.system_performance?.processing_speed || '< 10s'}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">System Uptime:</span>
                          <span className="text-green-400 font-semibold">{stats.system_performance?.uptime || '99.9%'}</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Scan Type Distribution */}
                  <div className="bg-surface/20 p-6 rounded-xl border border-border/20">
                    <h4 className="text-lg font-semibold text-white mb-6">📈 Scan Type Analysis</h4>
                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
                      {Object.entries(stats.scan_types || {}).map(([type, count]) => (
                        <div key={type} className="text-center p-4 bg-surface/30 rounded-lg">
                          <div className="text-2xl mb-2">
                            {type === 'ip' ? '🌐' : type === 'domain' ? '🏠' : type === 'url' ? '🔗' : '📊'}
                          </div>
                          <div className="text-2xl font-bold text-white">{count}</div>
                          <div className="text-sm text-gray-400 capitalize">{type} Scans</div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </main>

        {/* Footer */}
        <footer className="bg-black/20 backdrop-blur-lg border-t border-white/10 mt-16">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <div className="text-center">
              <p className="text-gray-300 text-lg">
                🧠 Developed by <span className="text-transparent bg-gradient-to-r from-cyber-blue to-cyber-purple bg-clip-text font-semibold">Professional Security Team</span>
              </p>
              <p className="text-gray-400 mt-2">
                Advanced Threat Intelligence • Real Location Detection • Professional Grade Security
              </p>
              <div className="flex justify-center space-x-6 mt-4">
                <span className="text-green-400">✅ 100% Free</span>
                <span className="text-blue-400">🔒 Secure</span>
                <span className="text-purple-400">⚡ Real-time</span>
                <span className="text-yellow-400">🌍 Global Coverage</span>
              </div>
            </div>
          </div>
        </footer>
      </div>
    </div>
  );
}
