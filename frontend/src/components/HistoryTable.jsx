import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

export default function HistoryTable() {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Fetch scan history on component mount
  useEffect(() => {
    const fetchHistory = async () => {
      try {
        setLoading(true);
        const response = await axios.get(`${API_BASE}/api/history?limit=50`);
        
        if (response.data && response.data.scans) {
          setHistory(response.data.scans);
        } else {
          setHistory([]);
        }
      } catch (error) {
        console.error('Failed to fetch scan history:', error);
        setError('Failed to load scan history');
        setHistory([]);
      } finally {
        setLoading(false);
      }
    };

    fetchHistory();
  }, []);

  const formatDate = (timestamp) => {
    if (!timestamp) return 'N/A';
    return new Date(timestamp * 1000).toLocaleString();
  };

  const getThreatBadge = (score, level) => {
    if (score >= 70) {
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-500/20 text-red-400 border border-red-500/50">
          🚨 HIGH ({score})
        </span>
      );
    } else if (score >= 40) {
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-500/20 text-yellow-400 border border-yellow-500/50">
          ⚠️ MEDIUM ({score})
        </span>
      );
    } else {
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-500/20 text-green-400 border border-green-500/50">
          ✅ LOW ({score})
        </span>
      );
    }
  };

  if (loading) {
    return (
      <div className="w-full max-w-7xl mx-auto px-3 sm:px-4 lg:px-6">
        <div className="bg-surface/30 backdrop-blur-sm rounded-lg sm:rounded-xl border border-border/30 p-6">
          <h2 className="text-2xl sm:text-3xl font-bold mb-6 text-white text-center">
            📜 Scan History
          </h2>
          <div className="flex items-center justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-cyber-blue"></div>
            <span className="ml-3 text-gray-400">Loading scan history...</span>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="w-full max-w-7xl mx-auto px-3 sm:px-4 lg:px-6">
        <div className="bg-surface/30 backdrop-blur-sm rounded-lg sm:rounded-xl border border-border/30 p-6">
          <h2 className="text-2xl sm:text-3xl font-bold mb-6 text-white text-center">
            📜 Scan History
          </h2>
          <div className="bg-red-500/20 border border-red-500/50 text-red-200 px-4 py-3 rounded-xl text-center">
            <span className="text-xl">❌</span>
            <div className="mt-2">{error}</div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full max-w-7xl mx-auto px-3 sm:px-4 lg:px-6">
      <div className="bg-surface/30 backdrop-blur-sm rounded-lg sm:rounded-xl border border-border/30 p-4 sm:p-6">
        <h2 className="text-2xl sm:text-3xl font-bold mb-6 text-white text-center">
          📜 Scan History
        </h2>

        {history.length === 0 ? (
          <div className="text-center py-12">
            <span className="text-6xl mb-4 block">🔍</span>
            <h3 className="text-xl font-semibold text-gray-300 mb-2">No scans yet</h3>
            <p className="text-gray-400">Start by analyzing an IP address, domain, or URL</p>
          </div>
        ) : (
          <>
            {/* Mobile-friendly stats */}
            <div className="mb-6 text-center">
              <span className="text-sm text-gray-400">
                Showing {history.length} recent scans
              </span>
            </div>

            {/* Responsive table container */}
            <div className="overflow-x-auto">
              <table className="w-full min-w-[600px]">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="text-left py-3 px-2 sm:px-4 text-sm font-semibold text-gray-300">
                      Target
                    </th>
                    <th className="text-left py-3 px-2 sm:px-4 text-sm font-semibold text-gray-300">
                      Type
                    </th>
                    <th className="text-left py-3 px-2 sm:px-4 text-sm font-semibold text-gray-300">
                      Threat Level
                    </th>
                    <th className="text-left py-3 px-2 sm:px-4 text-sm font-semibold text-gray-300">
                      Location
                    </th>
                    <th className="text-left py-3 px-2 sm:px-4 text-sm font-semibold text-gray-300">
                      Date
                    </th>
                    <th className="text-left py-3 px-2 sm:px-4 text-sm font-semibold text-gray-300">
                      Speed
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((scan, index) => (
                    <tr 
                      key={scan.scan_id || index} 
                      className="border-b border-gray-800 hover:bg-white/5 transition-colors"
                    >
                      <td className="py-3 px-2 sm:px-4">
                        <div className="font-mono text-cyber-blue text-sm">
                          {scan.input && scan.input.length > 20 
                            ? `${scan.input.substring(0, 20)}...` 
                            : scan.input || 'N/A'}
                        </div>
                      </td>
                      <td className="py-3 px-2 sm:px-4">
                        <span className="text-xs bg-gray-700 text-gray-300 px-2 py-1 rounded-full">
                          {scan.input_type?.toUpperCase() || 'UNKNOWN'}
                        </span>
                      </td>
                      <td className="py-3 px-2 sm:px-4">
                        {getThreatBadge(scan.threat_score || 0, scan.threat_level || 'UNKNOWN')}
                      </td>
                      <td className="py-3 px-2 sm:px-4">
                        <div className="text-sm text-gray-300">
                          {scan.location && scan.location.city !== 'Unknown' 
                            ? `${scan.location.city}, ${scan.location.country}` 
                            : 'Unknown'}
                        </div>
                      </td>
                      <td className="py-3 px-2 sm:px-4">
                        <div className="text-sm text-gray-400">
                          {formatDate(scan.timestamp)}
                        </div>
                      </td>
                      <td className="py-3 px-2 sm:px-4">
                        <div className="text-xs text-green-400">
                          {scan.processing_time || 'N/A'}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Performance summary */}
            <div className="mt-6 grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-3 text-center">
                <div className="text-green-400 font-semibold text-sm">⚡ Speed Optimized</div>
                <div className="text-xs text-gray-400 mt-1">75-80% faster analysis</div>
              </div>
              <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-3 text-center">
                <div className="text-blue-400 font-semibold text-sm">🔄 Parallel Processing</div>
                <div className="text-xs text-gray-400 mt-1">Simultaneous API calls</div>
              </div>
              <div className="bg-purple-500/10 border border-purple-500/30 rounded-lg p-3 text-center">
                <div className="text-purple-400 font-semibold text-sm">💾 Smart Caching</div>
                <div className="text-xs text-gray-400 mt-1">95% faster cached results</div>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
