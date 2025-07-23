import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

export default function ThreatMap() {
  const [threatData, setThreatData] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchThreatMapData();
  }, []);

  const fetchThreatMapData = async () => {
    try {
      const response = await axios.get(`${API_BASE}/api/threat-map-data`);
      setThreatData(response.data.threats || []);
    } catch (error) {
      console.error('Error fetching threat map data:', error);
    } finally {
      setLoading(false);
    }
  };

  const getThreatColor = (score) => {
    if (score >= 70) return '#ef4444';
    if (score >= 30) return '#f59e0b';
    return '#10b981';
  };

  return (
    <div>
      <h2 className="text-3xl font-bold mb-8 text-center">
        <span className="bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
          🌍 Global Threat Intelligence Map
        </span>
      </h2>

      {loading ? (
        <div className="text-center py-12">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-400 mx-auto"></div>
          <p className="text-gray-300 mt-4">Loading threat data...</p>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Statistics */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-blue-500/20 p-6 rounded-xl border border-blue-500/30">
              <div className="text-center">
                <div className="text-3xl font-bold text-blue-300">{threatData.length}</div>
                <div className="text-blue-200">Total Threats</div>
              </div>
            </div>
            <div className="bg-red-500/20 p-6 rounded-xl border border-red-500/30">
              <div className="text-center">
                <div className="text-3xl font-bold text-red-300">
                  {threatData.filter(t => t.threat_score >= 70).length}
                </div>
                <div className="text-red-200">High Risk</div>
              </div>
            </div>
            <div className="bg-green-500/20 p-6 rounded-xl border border-green-500/30">
              <div className="text-center">
                <div className="text-3xl font-bold text-green-300">
                  {new Set(threatData.map(t => t.country)).size}
                </div>
                <div className="text-green-200">Countries</div>
              </div>
            </div>
          </div>

          {/* Threat List */}
          <div className="bg-gray-800/30 rounded-xl border border-gray-600/30">
            <div className="p-6 border-b border-gray-600/30">
              <h3 className="text-xl font-semibold text-white">Recent Threat Detections</h3>
            </div>
            <div className="p-6">
              <div className="space-y-4">
                {threatData.slice(0, 10).map((threat, index) => (
                  <div key={index} className="flex items-center justify-between p-4 bg-gray-700/30 rounded-lg">
                    <div className="flex items-center space-x-4">
                      <div 
                        className="w-4 h-4 rounded-full"
                        style={{ backgroundColor: getThreatColor(threat.threat_score) }}
                      ></div>
                      <div>
                        <div className="font-mono text-cyan-400">{threat.ip}</div>
                        <div className="text-sm text-gray-400">{threat.country}</div>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="font-bold text-white">{threat.threat_score}/100</div>
                      <div className="text-sm text-gray-400">
                        {new Date(threat.timestamp * 1000).toLocaleTimeString()}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Geographic Distribution */}
          <div className="bg-gray-800/30 rounded-xl border border-gray-600/30 p-6">
            <h3 className="text-xl font-semibold text-white mb-4">Geographic Distribution</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {Object.entries(
                threatData.reduce((acc, threat) => {
                  acc[threat.country] = (acc[threat.country] || 0) + 1;
                  return acc;
                }, {})
              ).slice(0, 8).map(([country, count]) => (
                <div key={country} className="bg-gray-700/50 p-3 rounded-lg text-center">
                  <div className="text-2xl font-bold text-white">{count}</div>
                  <div className="text-sm text-gray-300">{country}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
