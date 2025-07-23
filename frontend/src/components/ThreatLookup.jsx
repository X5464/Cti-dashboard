import React, { useState } from 'react';
import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

export default function ThreatLookup({ onNewScan, compact = false }) {
  const [input, setInput] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleLookup = async (e) => {
    e.preventDefault();
    
    if (!input.trim()) {
      setError('Please enter an IP address');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await axios.post(`${API_BASE}/api/advanced-lookup`, {
        input: input.trim()
      });
      
      setResult(response.data);
      if (onNewScan) onNewScan();
    } catch (error) {
      setError('Analysis failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const getThreatColor = (score) => {
    if (score >= 70) return 'text-red-400 bg-red-500/20 border-red-500/50';
    if (score >= 30) return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/50';
    return 'text-green-400 bg-green-500/20 border-green-500/50';
  };

  const getThreatIcon = (score) => {
    if (score >= 70) return '🚨';
    if (score >= 30) return '⚠️';
    return '✅';
  };

  if (compact) {
    return (
      <div>
        <form onSubmit={handleLookup} className="space-y-4">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Enter IP address..."
            className="w-full bg-white/10 border border-white/20 text-white rounded-lg px-4 py-3"
          />
          <button
            type="submit"
            disabled={loading}
            className="w-full bg-gradient-to-r from-cyan-500 to-purple-500 text-white py-3 rounded-lg"
          >
            {loading ? 'Analyzing...' : '🤖 AI Scan'}
          </button>
        </form>
        
        {result && (
          <div className="mt-4 p-4 bg-gray-800/50 rounded-lg">
            <div className="flex items-center justify-between">
              <span className="font-mono text-cyan-400">{result.input}</span>
              <span className={`px-3 py-1 rounded-full text-sm ${getThreatColor(result.ai_analysis.threat_score)}`}>
                {getThreatIcon(result.ai_analysis.threat_score)} {result.ai_analysis.threat_score}/100
              </span>
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div>
      <h2 className="text-3xl font-bold mb-8 text-center">
        <span className="bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
          🤖 AI-Powered Threat Analysis
        </span>
      </h2>

      <form onSubmit={handleLookup} className="mb-8">
        <div className="flex flex-col sm:flex-row gap-4">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Enter IP address for AI analysis..."
            className="flex-1 bg-white/10 border border-white/20 text-white rounded-xl px-6 py-4 text-lg"
          />
          <button
            type="submit"
            disabled={loading}
            className="bg-gradient-to-r from-cyan-500 to-purple-500 text-white px-8 py-4 rounded-xl font-semibold text-lg"
          >
            {loading ? '🔄 AI Analyzing...' : '🤖 Deep AI Scan'}
          </button>
        </div>
      </form>

      {error && (
        <div className="bg-red-500/20 border border-red-500/50 text-red-200 px-6 py-4 rounded-xl mb-6">
          ❌ {error}
        </div>
      )}

      {result && (
        <div className="space-y-6">
          {/* AI Threat Assessment */}
          <div className={`p-8 rounded-xl border-2 ${getThreatColor(result.ai_analysis.threat_score)}`}>
            <div className="text-center mb-6">
              <div className="text-6xl mb-2">{getThreatIcon(result.ai_analysis.threat_score)}</div>
              <div className="text-3xl font-bold text-white">{result.ai_analysis.threat_score}/100</div>
              <div className="text-xl">{result.ai_analysis.insights.threat_level} THREAT</div>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="text-center">
                <div className="text-2xl font-bold text-white">{result.metadata.confidence}%</div>
                <div className="text-sm">AI Confidence</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-white">{result.metadata.sources_used}</div>
                <div className="text-sm">Data Sources</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-white">{result.ai_analysis.prediction.attack_probability.toFixed(1)}</div>
                <div className="text-sm">Attack Probability</div>
              </div>
            </div>
          </div>

          {/* Intelligence Sources */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-gray-800/30 p-6 rounded-xl border border-gray-600/30">
              <h4 className="text-lg font-semibold text-blue-300 mb-4">🌍 Geolocation Intelligence</h4>
              {result.intelligence.geolocation && (
                <div className="space-y-2 text-sm">
                  <div><span className="text-gray-400">Country:</span> <span className="text-white">{result.intelligence.geolocation.country}</span></div>
                  <div><span className="text-gray-400">Region:</span> <span className="text-white">{result.intelligence.geolocation.region}</span></div>
                  <div><span className="text-gray-400">ISP:</span> <span className="text-white">{result.intelligence.geolocation.isp}</span></div>
                  <div><span className="text-gray-400">Organization:</span> <span className="text-white">{result.intelligence.geolocation.org}</span></div>
                </div>
              )}
            </div>

            <div className="bg-gray-800/30 p-6 rounded-xl border border-gray-600/30">
              <h4 className="text-lg font-semibold text-purple-300 mb-4">🔍 Shodan Intelligence</h4>
              {result.intelligence.shodan && (
                <div className="space-y-2 text-sm">
                  <div><span className="text-gray-400">Open Ports:</span> <span className="text-white">{result.intelligence.shodan.ports?.length || 0}</span></div>
                  <div><span className="text-gray-400">Vulnerabilities:</span> <span className="text-white">{result.intelligence.shodan.vulns?.length || 0}</span></div>
                  <div><span className="text-gray-400">Tags:</span> <span className="text-white">{result.intelligence.shodan.tags?.join(', ') || 'None'}</span></div>
                </div>
              )}
            </div>
          </div>

          {/* AI Insights */}
          <div className="bg-gradient-to-r from-purple-900/30 to-blue-900/30 border border-purple-500/50 rounded-xl p-6">
            <h4 className="text-xl font-semibold text-purple-300 mb-4">🤖 AI Insights & Recommendations</h4>
            
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div>
                <h5 className="font-semibold text-white mb-2">Risk Factors:</h5>
                <ul className="space-y-1 text-sm">
                  {result.ai_analysis.insights.risk_factors.map((factor, index) => (
                    <li key={index} className="text-red-300">• {factor}</li>
                  ))}
                </ul>
              </div>
              
              <div>
                <h5 className="font-semibold text-white mb-2">Recommendations:</h5>
                <ul className="space-y-1 text-sm">
                  {result.ai_analysis.insights.recommendations.map((rec, index) => (
                    <li key={index} className="text-green-300">• {rec}</li>
                  ))}
                </ul>
              </div>
            </div>

            <div className="mt-6">
              <h5 className="font-semibold text-white mb-2">Threat Prediction (Next 24h):</h5>
              <div className="flex items-center space-x-4">
                <div className="text-2xl font-bold text-yellow-400">{result.ai_analysis.prediction.next_24h}%</div>
                <div className="text-sm text-gray-300">Risk increase probability</div>
                <div className={`px-3 py-1 rounded-full text-sm ${
                  result.ai_analysis.prediction.trend === 'increasing' 
                    ? 'bg-red-500/20 text-red-300' 
                    : 'bg-green-500/20 text-green-300'
                }`}>
                  {result.ai_analysis.prediction.trend}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
