import React, { useState } from 'react';
import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

export default function AIInsights({ history }) {
  const [huntingQuery, setHuntingQuery] = useState('');
  const [huntingResults, setHuntingResults] = useState(null);
  const [selectedIP, setSelectedIP] = useState('');
  const [aiInsights, setAIInsights] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleThreatHunting = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      const response = await axios.post(`${API_BASE}/api/threat-hunting`, {
        query: huntingQuery
      });
      setHuntingResults(response.data);
    } catch (error) {
      console.error('Threat hunting failed:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleGetInsights = async (ip) => {
    setLoading(true);
    
    try {
      const response = await axios.post(`${API_BASE}/api/ai-insights`, { ip });
      setAIInsights(response.data);
      setSelectedIP(ip);
    } catch (error) {
      console.error('AI insights failed:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h2 className="text-3xl font-bold mb-8 text-center">
        <span className="bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
          🤖 Advanced AI Insights
        </span>
      </h2>

      <div className="space-y-8">
        {/* Threat Hunting */}
        <div className="bg-gradient-to-r from-purple-900/30 to-blue-900/30 border border-purple-500/50 rounded-xl p-6">
          <h3 className="text-xl font-semibold text-purple-300 mb-4">🎯 AI-Powered Threat Hunting</h3>
          
          <form onSubmit={handleThreatHunting} className="mb-6">
            <div className="flex gap-4">
              <input
                type="text"
                value={huntingQuery}
                onChange={(e) => setHuntingQuery(e.target.value)}
                placeholder="Enter hunting query (e.g., suspicious network activity, malware, etc.)"
                className="flex-1 bg-white/10 border border-white/20 text-white rounded-lg px-4 py-3"
              />
              <button
                type="submit"
                disabled={loading}
                className="bg-gradient-to-r from-purple-500 to-pink-500 text-white px-6 py-3 rounded-lg font-semibold"
              >
                {loading ? '🔄 Hunting...' : '🎯 Hunt Threats'}
              </button>
            </div>
          </form>

          {huntingResults && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-black/20 p-4 rounded-lg">
                  <div className="text-2xl font-bold text-green-400">{huntingResults.matches_found}</div>
                  <div className="text-sm text-gray-300">Matches Found</div>
                </div>
                <div className="bg-black/20 p-4 rounded-lg">
                  <div className="text-2xl font-bold text-blue-400">{(huntingResults.confidence_score * 100).toFixed(1)}%</div>
                  <div className="text-sm text-gray-300">Confidence</div>
                </div>
                <div className="bg-black/20 p-4 rounded-lg">
                  <div className="text-2xl font-bold text-purple-400">{huntingResults.attack_techniques?.length || 0}</div>
                  <div className="text-sm text-gray-300">MITRE Techniques</div>
                </div>
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div>
                  <h4 className="font-semibold text-white mb-2">🎯 Hunting Results:</h4>
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {huntingResults.hunting_results?.map((result, index) => (
                      <div key={index} className="bg-black/20 p-3 rounded border border-gray-600/30">
                        <div className="flex justify-between items-center">
                          <span className="font-mono text-cyan-400">{result.indicator}</span>
                          <span className="text-sm text-red-300">{result.risk_score}/100</span>
                        </div>
                        <div className="text-sm text-gray-400 mt-1">{result.context?.join(', ')}</div>
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <h4 className="font-semibold text-white mb-2">⚔️ Attack Techniques:</h4>
                  <div className="space-y-1">
                    {huntingResults.attack_techniques?.map((technique, index) => (
                      <div key={index} className="text-sm text-yellow-300 bg-yellow-500/10 px-2 py-1 rounded">
                        {technique}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Recent Scans for AI Analysis */}
        <div className="bg-gray-800/30 rounded-xl border border-gray-600/30 p-6">
          <h3 className="text-xl font-semibold text-white mb-4">📊 Recent Scans - Click for AI Insights</h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {history.slice(0, 9).map((scan, index) => (
              <div
                key={index}
                onClick={() => handleGetInsights(scan.input)}
                className="bg-gray-700/30 p-4 rounded-lg cursor-pointer hover:bg-gray-600/30 transition-colors border border-gray-600/30"
              >
                <div className="flex justify-between items-center">
                  <span className="font-mono text-cyan-400">{scan.input}</span>
                  <span className={`text-sm px-2 py-1 rounded ${
                    scan.ai_analysis?.threat_score >= 70 ? 'bg-red-500/20 text-red-300' :
                    scan.ai_analysis?.threat_score >= 30 ? 'bg-yellow-500/20 text-yellow-300' :
                    'bg-green-500/20 text-green-300'
                  }`}>
                    {scan.ai_analysis?.threat_score || 0}/100
                  </span>
                </div>
                <div className="text-sm text-gray-400 mt-1">
                  {new Date(scan.timestamp * 1000).toLocaleString()}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* AI Insights Results */}
        {aiInsights && (
          <div className="bg-gradient-to-r from-blue-900/30 to-cyan-900/30 border border-blue-500/50 rounded-xl p-6">
            <h3 className="text-xl font-semibold text-blue-300 mb-4">
              🧠 Deep AI Analysis for {selectedIP}
            </h3>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div>
                <h4 className="font-semibold text-white mb-3">🎯 Threat Assessment:</h4>
                <div className="space-y-2">
                  <div className="bg-black/20 p-3 rounded">
                    <div className="text-sm text-gray-400">Threat Level:</div>
                    <div className="text-lg font-bold text-white">{aiInsights.threat_assessment?.threat_level}</div>
                  </div>
                  <div className="bg-black/20 p-3 rounded">
                    <div className="text-sm text-gray-400">Risk Factors:</div>
                    <ul className="text-sm text-red-300">
                      {aiInsights.threat_assessment?.risk_factors?.map((factor, index) => (
                        <li key={index}>• {factor}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>

              <div>
                <h4 className="font-semibold text-white mb-3">🔬 Behavioral Analysis:</h4>
                <div className="space-y-2">
                  <div className="bg-black/20 p-3 rounded">
                    <div className="text-sm text-gray-400">Activity Pattern:</div>
                    <div className="text-sm text-white">{aiInsights.behavioral_analysis?.activity_pattern}</div>
                  </div>
                  <div className="bg-black/20 p-3 rounded">
                    <div className="text-sm text-gray-400">Geographic Anomaly:</div>
                    <div className="text-sm text-white">{aiInsights.behavioral_analysis?.geographic_anomaly}</div>
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-6">
              <h4 className="font-semibold text-white mb-3">🛡️ Mitigation Roadmap:</h4>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-red-500/10 p-4 rounded border border-red-500/30">
                  <div className="font-semibold text-red-300 mb-2">🚨 Immediate</div>
                  <ul className="text-sm text-gray-300 space-y-1">
                    {aiInsights.mitigation_roadmap?.immediate?.map((action, index) => (
                      <li key={index}>• {action}</li>
                    ))}
                  </ul>
                </div>
                <div className="bg-yellow-500/10 p-4 rounded border border-yellow-500/30">
                  <div className="font-semibold text-yellow-300 mb-2">⏱️ Short-term</div>
                  <ul className="text-sm text-gray-300 space-y-1">
                    {aiInsights.mitigation_roadmap?.short_term?.map((action, index) => (
                      <li key={index}>• {action}</li>
                    ))}
                  </ul>
                </div>
                <div className="bg-green-500/10 p-4 rounded border border-green-500/30">
                  <div className="font-semibold text-green-300 mb-2">📅 Long-term</div>
                  <ul className="text-sm text-gray-300 space-y-1">
                    {aiInsights.mitigation_roadmap?.long_term?.map((action, index) => (
                      <li key={index}>• {action}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
