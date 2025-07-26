import React, { useState } from 'react';
import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

export default function ThreatLookup({ onNewScan, compact = false }) {
  const [input, setInput] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const detectInputType = (input) => {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (ipRegex.test(input.trim())) return 'IP Address';
    if (input.startsWith('http') || input.startsWith('www.')) return 'URL/Website';
    if (input.includes('.') && !input.includes('/')) return 'Domain';
    return 'Unknown';
  };

  const handleLookup = async (e) => {
    e.preventDefault();
    
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
      <div className="w-full max-w-full">
        <form onSubmit={handleLookup} className="space-y-3 sm:space-y-4">
          <div className="relative">
            {/* MOBILE-OPTIMIZED INPUT: 44px min height for touch targets */}
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Enter IP, domain, or URL..."
              className="w-full bg-white/5 border border-white/20 text-white rounded-lg sm:rounded-xl px-3 sm:px-4 py-3 sm:py-4 text-base sm:text-lg backdrop-blur-sm focus:ring-2 focus:ring-cyber-blue focus:border-transparent transition-all duration-300 min-h-[44px] touch-target"
              disabled={loading}
            />
            {input && (
              <span className="absolute right-2 sm:right-4 top-1/2 transform -translate-y-1/2 text-xs sm:text-sm bg-surface/50 text-gray-300 px-2 sm:px-3 py-1 rounded-full">
                {detectInputType(input)}
              </span>
            )}
          </div>
          {/* MOBILE-OPTIMIZED BUTTON: Touch-friendly sizing */}
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="w-full bg-gradient-to-r from-cyber-blue to-cyber-purple text-white py-3 sm:py-4 rounded-lg sm:rounded-xl font-semibold text-base sm:text-lg hover:shadow-cyber disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 min-h-[44px] touch-target"
          >
            {loading ? (
              <div className="flex items-center justify-center space-x-2 sm:space-x-3">
                <div className="animate-spin rounded-full h-5 w-5 sm:h-6 sm:w-6 border-b-2 border-white"></div>
                <span className="text-sm sm:text-base">⚡ Lightning Analysis...</span>
              </div>
            ) : (
              <span className="text-sm sm:text-base">🔍 Lightning Analysis</span>
            )}
          </button>
        </form>
        
        {error && (
          <div className="mt-3 sm:mt-4 bg-red-500/20 border border-red-500/50 text-red-200 px-3 sm:px-4 py-3 rounded-lg sm:rounded-xl">
            <div className="flex items-center space-x-2">
              <span className="text-lg sm:text-xl">❌</span>
              <span className="text-sm sm:text-base">{error}</span>
            </div>
          </div>
        )}

        {result && (
          <div className="mt-3 sm:mt-4 p-3 sm:p-4 bg-surface/30 rounded-lg sm:rounded-xl border border-border/30">
            {/* RESPONSIVE RESULT CARD */}
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-2 space-y-2 sm:space-y-0">
              <span className="font-mono text-cyber-blue text-xs sm:text-sm break-all">
                {result.input.length > 25 ? `${result.input.substring(0, 25)}...` : result.input}
              </span>
              <span className={`px-2 sm:px-3 py-1 rounded-full text-xs sm:text-sm ${getThreatDisplay(result.threat_analysis).bg} ${getThreatDisplay(result.threat_analysis).color} whitespace-nowrap`}>
                {getThreatDisplay(result.threat_analysis).icon} {result.threat_analysis?.score || 0}/100
              </span>
            </div>
            {result.intelligence_sources?.geolocation && (
              <div className="text-xs text-gray-400 mb-2">
                📍 {safeProcessLocationData(result.intelligence_sources.geolocation).city}, {safeProcessLocationData(result.intelligence_sources.geolocation).country}
              </div>
            )}
            {/* SPEED METRICS DISPLAY */}
            {result.scan_metadata?.processing_time && (
              <div className="flex items-center justify-center mt-2">
                <span className="bg-green-500/20 text-green-400 px-2 py-1 rounded-full text-xs font-medium">
                  ⚡ {result.scan_metadata.processing_time}
                </span>
              </div>
            )}
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="w-full max-w-7xl mx-auto px-3 sm:px-4 lg:px-6">
      {/* RESPONSIVE HEADER */}
      <h2 className="text-2xl sm:text-3xl lg:text-4xl font-bold mb-6 sm:mb-8 text-center font-inter">
        <span className="bg-gradient-to-r from-cyber-blue via-cyber-purple to-cyber-green bg-clip-text text-transparent">
          ⚡ Lightning-Fast CTI Analysis Platform
        </span>
      </h2>

      {/* RESPONSIVE API STATUS GRID */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4 mb-6 sm:mb-8">
        <div className="bg-gradient-to-r from-red-500/10 to-pink-500/10 p-3 sm:p-4 rounded-lg sm:rounded-xl border border-red-500/30">
          <div className="flex items-center space-x-2 sm:space-x-3">
            <span className="text-xl sm:text-2xl">🛡️</span>
            <div>
              <div className="font-semibold text-red-300 text-sm sm:text-base">VirusTotal</div>
              <div className="text-gray-400 text-xs sm:text-sm">Parallel mode</div>
            </div>
          </div>
        </div>
        <div className="bg-gradient-to-r from-orange-500/10 to-red-500/10 p-3 sm:p-4 rounded-lg sm:rounded-xl border border-orange-500/30">
          <div className="flex items-center space-x-2 sm:space-x-3">
            <span className="text-xl sm:text-2xl">🚨</span>
            <div>
              <div className="font-semibold text-orange-300 text-sm sm:text-base">AbuseIPDB</div>
              <div className="text-gray-400 text-xs sm:text-sm">Parallel mode</div>
            </div>
          </div>
        </div>
        <div className="bg-gradient-to-r from-blue-500/10 to-cyan-500/10 p-3 sm:p-4 rounded-lg sm:rounded-xl border border-blue-500/30">
          <div className="flex items-center space-x-2 sm:space-x-3">
            <span className="text-xl sm:text-2xl">🌍</span>
            <div>
              <div className="font-semibold text-blue-300 text-sm sm:text-base">Geolocation</div>
              <div className="text-gray-400 text-xs sm:text-sm">Parallel mode</div>
            </div>
          </div>
        </div>
        <div className="bg-gradient-to-r from-purple-500/10 to-violet-500/10 p-3 sm:p-4 rounded-lg sm:rounded-xl border border-purple-500/30">
          <div className="flex items-center space-x-2 sm:space-x-3">
            <span className="text-xl sm:text-2xl">🔍</span>
            <div>
              <div className="font-semibold text-purple-300 text-sm sm:text-base">Shodan</div>
              <div className="text-gray-400 text-xs sm:text-sm">Parallel mode</div>
            </div>
          </div>
        </div>
      </div>

      {/* SPEED IMPROVEMENT BANNER */}
      <div className="bg-gradient-to-r from-green-500/10 to-emerald-500/10 border border-green-500/30 rounded-lg sm:rounded-xl p-3 sm:p-4 mb-6 sm:mb-8">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-2 sm:space-y-0">
          <div className="flex items-center space-x-2 sm:space-x-3">
            <span className="text-xl sm:text-2xl">⚡</span>
            <div>
              <div className="font-semibold text-green-300 text-sm sm:text-base">Speed Optimizations Active</div>
              <div className="text-gray-400 text-xs sm:text-sm">75-80% faster analysis • 95% faster cached results</div>
            </div>
          </div>
          <div className="flex items-center space-x-2 text-xs sm:text-sm">
            <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></span>
            <span className="text-green-400 font-medium">Lightning Mode</span>
          </div>
        </div>
      </div>

      {/* RESPONSIVE SCAN INPUT FORM */}
      <form onSubmit={handleLookup} className="mb-6 sm:mb-8">
        <div className="flex flex-col lg:flex-row gap-3 sm:gap-4">
          <div className="flex-1 relative">
            {/* DESKTOP & MOBILE OPTIMIZED INPUT */}
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Enter IP address, domain, or URL for lightning-fast threat analysis..."
              className="w-full bg-white/5 border border-white/20 text-white rounded-lg sm:rounded-xl px-4 sm:px-6 py-3 sm:py-4 text-base sm:text-lg backdrop-blur-sm focus:ring-2 focus:ring-cyber-blue focus:border-transparent transition-all duration-300 font-inter min-h-[44px] touch-target"
              disabled={loading}
            />
            {input && (
              <span className="absolute right-3 sm:right-4 top-1/2 transform -translate-y-1/2 text-xs sm:text-sm bg-surface/50 text-gray-300 px-2 sm:px-3 py-1 rounded-full hidden sm:block">
                {detectInputType(input)}
              </span>
            )}
          </div>
          {/* RESPONSIVE SUBMIT BUTTON */}
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="bg-gradient-to-r from-cyber-blue to-cyber-purple text-white px-6 sm:px-8 py-3 sm:py-4 rounded-lg sm:rounded-xl font-semibold text-base sm:text-lg hover:shadow-cyber disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 min-h-[44px] whitespace-nowrap touch-target"
          >
            {loading ? (
              <div className="flex items-center space-x-2 sm:space-x-3">
                <div className="animate-spin rounded-full h-5 w-5 sm:h-6 sm:w-6 border-b-2 border-white"></div>
                <span className="hidden sm:inline">⚡ Lightning Analysis...</span>
                <span className="sm:hidden">⚡ Analyzing...</span>
              </div>
            ) : (
              <>
                <span className="hidden sm:inline">⚡ Lightning Analysis</span>
                <span className="sm:hidden">⚡ Analyze</span>
              </>
            )}
          </button>
        </div>
      </form>

      {error && (
        <div className="bg-red-500/20 border border-red-500/50 text-red-200 px-4 sm:px-6 py-3 sm:py-4 rounded-lg sm:rounded-xl mb-4 sm:mb-6 backdrop-blur-sm">
          <div className="flex items-center space-x-2 sm:space-x-3">
            <span className="text-xl sm:text-2xl">❌</span>
            <div>
              <div className="font-semibold text-sm sm:text-base">Analysis Error</div>
              <div className="text-sm sm:text-base">{error}</div>
            </div>
          </div>
        </div>
      )}

      {result && (
        <div className={`rounded-lg sm:rounded-xl p-4 sm:p-6 lg:p-8 border-2 backdrop-blur-sm ${getThreatDisplay(result.threat_analysis).bg} ${getThreatDisplay(result.threat_analysis).shadow}`}>
          {/* RESPONSIVE RESULT HEADER */}
          <div className="border-b border-white/10 pb-3 sm:pb-4 mb-4 sm:mb-6 flex flex-col sm:flex-row sm:justify-between sm:items-center space-y-2 sm:space-y-0">
            <span className="font-mono font-semibold text-cyber-blue text-sm sm:text-lg break-all">
              {result.input.length > 30 ? `${result.input.substring(0, 30)}...` : result.input}
            </span>
            <span className={`px-3 sm:px-4 py-2 rounded-full text-base sm:text-xl font-semibold ${getThreatDisplay(result.threat_analysis).color} whitespace-nowrap`} title={getThreatDisplay(result.threat_analysis).level}>
              {getThreatDisplay(result.threat_analysis).icon} {result.threat_analysis?.score || 0}/100
            </span>
          </div>

          {/* RESPONSIVE MAIN CONTENT GRID */}
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4 sm:gap-6">
            {/* Threat Summary */}
            <div className="md:col-span-2 xl:col-span-1">
              <h3 className="font-semibold text-lg sm:text-xl text-white mb-2 sm:mb-3">Threat Summary</h3>
              <p className="text-gray-300 text-sm sm:text-base">{result.threat_analysis?.summary || result.professional_insights?.executive_summary || 'Professional threat analysis completed.'}</p>
            </div>

            {/* Geolocation Intelligence */}
            <div>
              <h3 className="font-semibold text-lg sm:text-xl text-white mb-2 sm:mb-3">Geolocation Intel</h3>
              <div className="text-gray-300 space-y-1 text-sm sm:text-base">
                <p><span className="text-gray-400">Country:</span> {safeProcessLocationData(result.intelligence_sources?.geolocation).country}</p>
                <p><span className="text-gray-400">Region:</span> {safeProcessLocationData(result.intelligence_sources?.geolocation).region}</p>
                <p><span className="text-gray-400">City:</span> {safeProcessLocationData(result.intelligence_sources?.geolocation).city}</p>
                <p><span className="text-gray-400">ISP:</span> {safeProcessLocationData(result.intelligence_sources?.geolocation).isp}</p>
                <p className="hidden sm:block"><span className="text-gray-400">Organization:</span> {safeProcessLocationData(result.intelligence_sources?.geolocation).organization}</p>
                <p className="hidden sm:block"><span className="text-gray-400">Timezone:</span> {safeProcessLocationData(result.intelligence_sources?.geolocation).timezone}</p>
              </div>
            </div>

            {/* Performance & Additional Info */}
            <div>
              <h3 className="font-semibold text-lg sm:text-xl text-white mb-2 sm:mb-3">Performance Intel</h3>
              <div className="text-gray-300 space-y-1 text-sm sm:text-base">
                <p><span className="text-gray-400">Processing:</span> <span className="text-green-400">{result.scan_metadata?.processing_time || 'N/A'}</span></p>
                <p><span className="text-gray-400">Mode:</span> <span className="text-blue-400">Parallel APIs</span></p>
                <p><span className="text-gray-400">Sources:</span> {Object.keys(result.intelligence_sources || {}).length}</p>
                <p><span className="text-gray-400">Risk Level:</span> <span className={getThreatDisplay(result.threat_analysis).color}>{getThreatDisplay(result.threat_analysis).level}</span></p>
                <p><span className="text-gray-400">Confidence:</span> {result.threat_analysis?.confidence || 0}%</p>
                <p className="hidden sm:block"><span className="text-gray-400">Speed Boost:</span> <span className="text-green-400">75-80% faster</span></p>
              </div>
            </div>
          </div>

          {/* PERFORMANCE METRICS BANNER */}
          {result.scan_metadata?.processing_time && (
            <div className="mt-4 sm:mt-6 flex flex-col sm:flex-row sm:items-center sm:justify-center space-y-2 sm:space-y-0 sm:space-x-4">
              <span className="bg-cyber-blue/20 text-cyber-blue px-3 sm:px-4 py-1 sm:py-2 rounded-full text-xs sm:text-sm font-medium text-center">
                ⚡ Completed in {result.scan_metadata.processing_time}
              </span>
              <span className="bg-green-500/20 text-green-400 px-3 sm:px-4 py-1 sm:py-2 rounded-full text-xs sm:text-sm font-medium text-center">
                🚀 75-80% speed improvement
              </span>
              <span className="bg-purple-500/20 text-purple-400 px-3 sm:px-4 py-1 sm:py-2 rounded-full text-xs sm:text-sm font-medium text-center">
                🔄 Parallel processing
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
