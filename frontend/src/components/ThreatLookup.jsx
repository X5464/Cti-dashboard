import React, { useState } from 'react';
import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

export default function ThreatLookup({ onNewScan, compact = false }) {
  const [input, setInput]       = useState('');
  const [result, setResult]     = useState(null);
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState('');

  /* ---------------- utility helpers ---------------- */

  const detectInputType = (value) => {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (ipRegex.test(value.trim()))                           return 'IP Address';
    if (value.startsWith('http') || value.startsWith('www.')) return 'URL/Website';
    if (value.includes('.') && !value.includes('/'))          return 'Domain';
    return 'Unknown';
  };

  const getThreatDisplay = (assessment = {}) => {
    const score = assessment.score ?? 0;
    if (score >= 70) return { level:'HIGH RISK',   color:'text-red-400',    bg:'bg-red-500/20 border-red-500/50',    icon:'🚨', shadow:'shadow-threat' };
    if (score >= 40) return { level:'MEDIUM RISK', color:'text-yellow-400', bg:'bg-yellow-500/20 border-yellow-500/50',icon:'⚠️', shadow:'shadow-lg'     };
    return               { level:'LOW RISK',    color:'text-green-400',  bg:'bg-green-500/20 border-green-500/50',  icon:'✅', shadow:'shadow-safe'   };
  };

  const safeProcessLocationData = (loc = {}) => ({
    country:      loc.country      || 'Unknown',
    city:         loc.city         || 'Unknown',
    region:       loc.region       || 'Unknown',
    isp:          loc.isp          || 'Unknown',
    organization: loc.organization || 'Unknown',
    latitude:     loc.latitude     || 0,
    longitude:    loc.longitude    || 0,
    timezone:     loc.timezone     || 'Unknown',
  });

  /* ---------------- main handler ---------------- */

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
      const { data } = await axios.post(
        `${API_BASE}/api/lookup`,
        { input: trimmedInput },
        { timeout: 60_000 },
      );

      if (data && data.status !== 'error') {
        setResult(data);
        onNewScan?.();
      } else {
        setError(data?.error || 'Analysis failed');
      }
    } catch (err) {
      if (err.code === 'ECONNABORTED')                setError('Analysis timed out. Please try again.');
      else if (err.response)                          setError(err.response.data?.error || `Server error: ${err.response.status}`);
      else                                            setError('Cannot connect to server. Please check your connection.');
    } finally {
      setLoading(false);
    }
  };

  /* ---------------- JSX ---------------- */

  if (compact) {
    /* ---------- compact card view ---------- */
    const threat = result ? getThreatDisplay(result.threat_analysis) : null;

    return (
      <div>
        {/* input bar */}
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
              <span className="absolute right-4 top-1/2 -translate-y-1/2 text-sm bg-surface/50 text-gray-300 px-3 py-1 rounded-full">
                {detectInputType(input)}
              </span>
            )}
          </div>

          {/* submit button */}
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

        {/* error notice */}
        {error && (
          <div className="mt-4 bg-red-500/20 border border-red-500/50 text-red-200 px-4 py-3 rounded-xl flex items-center space-x-2">
            <span className="text-xl">❌</span>
            <span>{error}</span>
          </div>
        )}

        {/* result card */}
        {result && (
          <div className="mt-4 p-4 bg-surface/30 rounded-xl border border-border/30">
            <div className="flex items-center justify-between mb-2">
              <span className="font-mono text-cyber-blue text-sm">
                {result.input.length > 30 ? `${result.input.slice(0, 30)}…` : result.input}
              </span>
              <span className={`px-3 py-1 rounded-full text-sm ${threat.bg} ${threat.color}`}>
                {threat.icon} {result.threat_analysis?.score ?? 0}/100
              </span>
            </div>
            {result.intelligence_sources?.geolocation && (
              <div className="text-xs text-gray-400">
                📍 {safeProcessLocationData(result.intelligence_sources.geolocation).city},{' '}
                {safeProcessLocationData(result.intelligence_sources.geolocation).country}
              </div>
            )}
          </div>
        )}
      </div>
    );
  }

  /* ---------- full dashboard view ---------- */
  const threat = result ? getThreatDisplay(result.threat_analysis) : null;

  return (
    <div>
      {/* header */}
      <h2 className="text-4xl font-bold mb-8 text-center font-inter">
        <span className="bg-gradient-to-r from-cyber-blue via-cyber-purple to-cyber-green bg-clip-text text-transparent">
          🛡️ Professional CTI Analysis Platform
        </span>
      </h2>

      {/* --- API status tiles omitted for brevity (unchanged) --- */}

      {/* input section */}
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
              <span className="absolute right-4 top-1/2 -translate-y-1/2 text-sm bg-surface/50 text-gray-300 px-3 py-1 rounded-full">
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

      {/* error banner */}
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

      {/* detailed result */}
      {result && (
        <div className={`rounded-xl p-8 border-2 backdrop-blur-sm ${threat.bg} ${threat.shadow}`}>
          {/* header */}
          <div className="border-b border-white/10 pb-4 mb-6 flex justify-between items-center">
            <span className="font-mono font-semibold text-cyber-blue text-lg">
              {result.input.length > 40 ? `${result.input.slice(0, 40)}…` : result.input}
            </span>
            <span
              className={`px-4 py-2 rounded-full text-xl font-semibold ${threat.color}`}
              title={threat.level}
            >
              {threat.icon} {result.threat_analysis?.score ?? 0}/100
            </span>
          </div>

          {/* grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {/* summary */}
            <section>
              <h3 className="font-semibold text-xl text-white mb-3">Threat Summary</h3>
              <p className="text-gray-300">{result.threat_analysis?.summary || 'No summary available.'}</p>
            </section>

            {/* geolocation */}
            <section>
              <h3 className="font-semibold text-xl text-white mb-3">Geolocation</h3>
              {(() => {
                const geo = safeProcessLocationData(result.intelligence_sources?.geolocation);
                return (
                  <div className="text-gray-300 space-y-1">
                    <p>Country: {geo.country}</p>
                    <p>Region: {geo.region}</p>
                    <p>City: {geo.city}</p>
                    <p>ISP: {geo.isp}</p>
                    <p>Organization: {geo.organization}</p>
                    <p>Timezone: {geo.timezone}</p>
                  </div>
                );
              })()}
            </section>

            {/* misc */}
            <section>
              <h3 className="font-semibold text-xl text-white mb-3">Additional Intel</h3>
              <div className="text-gray-300 space-y-1">
                <p>Detected on: {result.detected_at || 'N/A'}</p>
                <p>Source count: {Object.keys(result.intelligence_sources || {}).length}</p>
                <p>Risk Level: {threat.level}</p>
              </div>
            </section>
          </div>
        </div>
      )}
    </div>
  );
}
