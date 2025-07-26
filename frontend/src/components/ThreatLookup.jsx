import React, { useState } from 'react';
import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

export default function ThreatLookup({ onNewScan, compact = false }) {
  const [input, setInput] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false); // ← This was the incomplete line
  const [error, setError] = useState('');

  const detectInputType = (input) => {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (ipRegex.test(input.trim())) return 'IP Address';
    if (input.startsWith('http') || input.startsWith('www.')) return 'URL/Website';
    if (input.includes('.') && !input.includes('/')) return 'Domain';
    return 'Unknown';
  };

  const handleLpreventDefault();
    
    const trimmedInput = input.trim();
    if (!trimmedInput) {
      setError('Please enter an IP address, domain, or URL');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await axios.post(`${API_BASE}/api/lookup`, {
        input: trimmedInput
      }, { timeout: 60000 });
      
      if (response.data && response.data.status !== 'error') {
        setResult(response.data);
        if (onNewScan) onNewScan();
      } else {
        setError(response.data?.error || 'Analysis failed');
      }
    } catch (error) {
      if (error.code === 'ECONNABORTED') {
        setError('Analysis timed out. Please try again.');
      } else if (error.response) {
        setError(error.response.data?.error || `Server error: ${error.response.status}`);
      } else {
        setError('Cannot connect to server. Please check your connection.');
      }
    } finally {
      setLoading(false);
    }
  };

  const getThreatDisplay = (assessment) => {
    const score = assessment?.score || 0;
    
    if (score >= 70) return { 
      level: 'HIGH RISK', 
      color: 'text-red-400', 
      bg: 'bg-red-500/20 border-red-500/50', 
      icon: '🚨',
      shadow: 'shadow-threat'
    };
    if (score >= 40) return { 
      level: 'MEDIUM RISK', 
      color: 'text-yellow-400', 
      bg: 'bg-yellow-500/20 border-yellow-500/50', 
      icon: '⚠️',
      shadow: 'shadow-lg'
    };
    return { 
      level: 'LOW RISK', 
      color: 'text-green-400', 
      bg: 'bg-green-500/20 border-green-500/50', 
      icon: '✅',
      shadow: 'shadow-safe'
    };
  };

  // Safe helper function to process location data
  const safeProcessLocationData = (locationData) => {
    if (!locationData || typeof locationData !== 'object') {
      return {
        country: 'Unknown',
        city: 'Unknown', 
        region: 'Unknown',
        isp: 'Unknown',
        organization: 'Unknown'
      };
    }
    
    return {
      country: locationData.country || 'Unknown',
      city: locationData.city || 'Unknown',
      region: locationData.region || 'Unknown', 
      isp: locationData.isp || 'Unknown',
      organization: locationData.organization || 'Unknown',
      latitude: locationData.latitude || 0,
      longitude: locationData.longitude || 0,
      timezone: locationData.timezone || 'Unknown'
    };
  };

  if (compact) {
    return (
      <div>
        <form onSubmit={handleLookup} className="space-y-4">
          <div className="relative">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Enter IP, domain, or URL..."
              className="w-full bg-white/5 border border-white/20 text-white rounded-xl px-4 py-3 text-lg backdrop-blur-sm focus:ring-2 focus:ring-cyber-blue focus:border-transparent transition-all duration-300"
              disabled={loading}
            />
            {input && (
              <span className="absolute right-4 top-1/2 transform -translate-y-1/2 text-sm bg-surface/50 text-gray-300 px-3 py-1 rounded-full">
                {detectInputType(input)}
              </span>
            )}
          </div>
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="w-full bg-gradient-to-r from-cyber-blue to-cyber-purple text-white py-3 rounded-xl font-semibold text-lg hover:shadow-cyber disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300"
          >
            {loading ? (
              <div className="flex items-center justify-center space-x-3">
                <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-white"></div>
                <span>Analyzing...</span>
              </div>
            ) : (
              '🔍 Professional Analysis'
            )}
          </button>
        </form>
        
        {error && (
          <div className="mt-4 bg-red-500/20 border border-red-500/50 text-red-200 px-4 py-3 rounded-xl">
            <div className="flex items-center space-x-2">
              <span className="text-xl">❌</span>
              <span>{error}</span>
            </div>
          </div>
        )}

        {result && (
          <div className="mt-4 p-4 bg-surface/30 rounded-xl border border-border/30">
            <div className="flex items-center justify-between mb-2">
              <span className="font-mono text-cyber-blue text-sm">
                {result.input.length > 30 ? `${result.input.substring(0, 30)}...` : result.input}
              </span>
              <span className={`px-3 py-1 rounded-full text-sm ${getThreatDisplay(result.threat_analysis).bg} ${getThreatDisplay(result.threat_analysis).color}`}>
                {getThreatDisplay(result.threat_analysis).icon} {result.threat_analysis?.score || 0}/100
              </span>
            </div>
            {result.intelligence_sources?.geolocation && (
              <div className="text-xs text-gray-400">
                📍 {safeProcessLocationData(result.intelligence_sources.geolocation).city}, {safeProcessLocationData(result.intelligence_sources.geolocation).country}
              </div>
            )}
          </div>
        )}
      </div>
    );
  }

  return (
    <div>
      <h2 className="text-4xl font-bold mb-8 text-center font-inter">
        <span className="bg-gradient-to-r from-cyber-blue via-cyber-purple to-cyber-green bg-clip-text text-transparent">
          🛡️ Professional CTI Analysis Platform
        </span>
      </h2>

      {/* API Status Indicators */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
        <div className="bg-gradient-to-r from-red-500/10 to-pink-500/10 p-4 rounded-xl border border-red-500/30">
          <div className="flex items-center space-x-3">
            <span className="text-2xl">🛡️</span>
            <div>
              <div className="font-semibold text-red-300">VirusTotal</div>
              <div className="text-gray-400 text-sm">Malware detection</div>
            </div>
          </div>
        </div>
        <div className="bg-gradient-to-r from-orange-500/10 to-red-500/10 p-4 rounded-xl border border-orange-500/30">
          <div className="flex items-center space-x-3">
            <span className="text-2xl">🚨</span>
            <div>
              <div className="font-semibold text-orange-300">AbuseIPDB</div>
              <div className="text-gray-400 text-sm">Abuse reports</div>
            </div>
          </div>
        </div>
        <div className="bg-gradient-to-r from-blue-500/10 to-cyan-500/10 p-4 rounded-xl border border-blue-500/30">
          <div className="flex items-center space-x-3">
            <span className="text-2xl">🌍</span>
            <div>
              <div className="font-semibold text-blue-300">Geolocation</div>
              <div className="text-gray-400 text-sm">Location intelligence</div>
            </div>
          </div>
        </div>
        <div className="bg-gradient-to-r from-purple-500/10 to-violet-500/10 p-4 rounded-xl border border-purple-500/30">
          <div className="flex items-center space-x-3">
            <span className="text-2xl">🔍</span>
            <div>
              <div className="font-semibold text-purple-300">Shodan</div>
              <div className="text-gray-400 text-sm">Infrastructure scan</div>
            </div>
          </div>
        </div>
      </div>

      {/* Scan Input */}
      <form onSubmit={handleLookup} className="mb-8">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="flex-1 relative">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Enter IP address, domain, or URL for comprehensive threat analysis..."
              className="w-full bg-white/5 border border-white/20 text-white rounded-xl px-6 py-4 text-lg backdrop-blur-sm focus:ring-2 focus:ring-cyber-blue focus:border-transparent transition-all duration-300 font-inter"
              disabled={loading}
            />
            {input && (
              <span className="absolute right-4 top-1/2 transform -translate-y-1/2 text-sm bg-surface/50 text-gray-300 px-3 py-1 rounded-full">
                {detectInputType(input)}
              </span>
            )}
          </div>
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="bg-gradient-to-r from-cyber-blue to-cyber-purple text-white px-8 py-4 rounded-xl font-semibold text-lg hover:shadow-cyber disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300"
          >
            {loading ? (
              <div className="flex items-center space-x-3">
                <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-white"></div>
                <span>Deep Analysis...</span>
              </div>
            ) : (
              '🔍 Professional Analysis'
            )}
          </button>
        </div>
      </form>

      {error && (
        <div className="bg-red-500/20 border border-red-500/50 text-red-200 px-6 py-4 rounded-xl mb-6 backdrop-blur-sm">
          <div className="flex items-center space-x-3">
            <span className="text-2xl">❌</span>
            <div>
              <div className="font-semibold">Analysis Error</div>
              <div>{error}</div>
            </div>
          </div>
        </div>
      )}

      {result && (
        <div className={`rounded-xl p-8 border-2 backdrop-blur-sm ${getThreatDisplay(result.threat_analysis).bg} ${getThreatDisplay(result.threat_analysis).shadow}`}>
          {/* Header */}
          <div className="border-b border-white/10 pb-4 mb-6 flex justify-between items-center">
            <span className="font-mono font-semibold text-cyber-blue text-lg">
              {result.input.length > 40 ? `${result.input.substring(0, 40)}...` : result.input}
            </span>
            <span className={`px-4 py-2 rounded-full text-xl font-semibold ${getThreatDisplay(result.threat_analysis).color}`} title={getThreatDisplay(result.threat_analysis).level}>
              {getThreatDisplay(result.threat_analysis).icon} {result.threat_analysis?.score || 0}/100
            </span>
          </div>

          {/* Main Content */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* Threat Summary */}
            <div>
              <h3 className="font-semibold text-xl text-white mb-3">Threat Summary</h3>
              <p className="text-gray-300">{result.threat_analysis?.summary || 'No summary available.'}</p>
            </div>

            {/* Intelligence Sources */}
            <div>
              <h3 className="font-semibold text-xl text-white mb-3">Geolocation</h3>
              <div className="text-gray-300 space-y-1">
                <p>Country: {safeProcessLocationData(result.intelligence_sources?.geolocation).country}</p>
                <p>Region: {safeProcessLocationData(result.intelligence_sources?.geolocation).region}</p>
                <p>City: {safeProcessLocationData(result.intelligence_sources?.geolocation).city}</p>
                <p>ISP: {safeProcessLocationData(result.intelligence_sources?.geolocation).isp}</p>
                <p>Organization: {safeProcessLocationData(result.intelligence_sources?.geolocation).organization}</p>
                <p>Timezone: {safeProcessLocationData(result.intelligence_sources?.geolocation).timezone}</p>
              </div>
            </div>

            {/* Additional Info */}
            <div>
              <h3 className="font-semibold text-xl text-white mb-3">Additional Intel</h3>
              <div className="text-gray-300 space-y-1">
                <p>Detected on: {result.detected_at || 'N/A'}</p>
                <p>Source count: {result.intelligence_sources ? Object.keys(result.intelligence_sources).length : 0}</p>
                <p>Risk Level: {getThreatDisplay(result.threat_analysis).level}</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
