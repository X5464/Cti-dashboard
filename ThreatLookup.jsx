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
            {result.intelligence_sources?.geolocation?.country && (
              <div className="text-xs text-gray-400">
                📍 {result.intelligence_sources.geolocation.city}, {result.intelligence_sources.geolocation.country}
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
          <div className="border-b border-white/10 pb-6 mb-8">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-2xl font-semibold text-white flex items-center space-x-3">
                <span>{getThreatDisplay(result.threat_analysis).icon}</span>
                <span>Professional Threat Assessment</span>
              </h3>
              <div className="text-sm text-gray-300 bg-surface/50 px-3 py-1 rounded-full">
                ID: {result.scan_id}
              </div>
            </div>
            
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="bg-surface/30 p-6 rounded-xl border border-border/30">
                <div className="text-sm text-gray-300 mb-3">Target Analysis</div>
                <div className="font-mono text-sm bg-surface/50 p-3 rounded-lg border border-border/30">
                  <span className="text-cyber-blue">{result.input}</span>
                </div>
                <div className="text-xs text-gray-400 mt-3">
                  Type: <span className="text-cyber-blue font-medium">{result.input_type?.toUpperCase()}</span>
                  {result.target_ip !== result.input && (
                    <div className="mt-1">
                      Resolved IP: <span className="text-cyber-green font-mono">{result.target_ip}</span>
                    </div>
                  )}
                </div>
              </div>
              
              <div className="bg-surface/30 p-6 rounded-xl border border-border/30">
                <div className="text-sm text-gray-300 mb-3">Threat Assessment</div>
                <div className="flex items-center space-x-4">
                  <span className="text-4xl">{getThreatDisplay(result.threat_analysis).icon}</span>
                  <div>
                    <div className="text-3xl font-bold text-white">{result.threat_analysis?.score || 0}/100</div>
                    <div className={`text-sm font-medium ${getThreatDisplay(result.threat_analysis).color}`}>
                      {getThreatDisplay(result.threat_analysis).level}
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="bg-surface/30 p-6 rounded-xl border border-border/30">
                <div className="text-sm text-gray-300 mb-3">Analysis Quality</div>
                <div className="space-y-2 text-sm">
                  <div><span className="text-gray-400">Confidence:</span> <span className="text-white">{result.threat_analysis?.confidence || 0}%</span></div>
                  <div><span className="text-gray-400">Data Sources:</span> <span className="text-white">{result.scan_metadata?.data_sources || 0}</span></div>
                  <div><span className="text-gray-400">Processing:</span> <span className="text-green-400">{result.scan_metadata?.processing_time}</span></div>
                </div>
              </div>
            </div>
          </div>

          {/* Executive Summary */}
          <div className="bg-gradient-to-r from-purple-900/30 to-blue-900/30 border border-purple-500/50 rounded-xl p-6 mb-8">
            <h4 className="text-xl font-semibold text-purple-300 mb-4">📋 Executive Summary</h4>
            <p className="text-gray-200 leading-relaxed">{result.professional_insights?.executive_summary}</p>
          </div>

          {/* Intelligence Sources */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
            {/* VirusTotal */}
            {result.intelligence_sources?.virustotal && !result.intelligence_sources.virustotal.error && (
              <div className="bg-gradient-to-r from-red-500/10 to-pink-500/10 border border-red-500/30 rounded-xl p-6">
                <h4 className="text-lg font-semibold text-red-300 mb-4 flex items-center space-x-2">
                  <span>🛡️</span>
                  <span>VirusTotal Analysis</span>
                </h4>
                <div className="space-y-3 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Detection Rate:</span>
                    <span className={`font-bold ${result.intelligence_sources.virustotal.malicious_count > 0 ? 'text-red-400' : 'text-green-400'}`}>
                      {result.intelligence_sources.virustotal.malicious_count}/{result.intelligence_sources.virustotal.total_engines}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Reputation:</span>
                    <span className="text-white">{result.intelligence_sources.virustotal.reputation || 'Unknown'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Suspicious:</span>
                    <span className="text-yellow-400">{result.intelligence_sources.virustotal.suspicious_count}</span>
                  </div>
                  {result.intelligence_sources.virustotal.tags?.length > 0 && (
                    <div>
                      <span className="text-gray-400">Tags:</span>
                      <div className="mt-1 space-x-1">
                        {result.intelligence_sources.virustotal.tags.slice(0, 3).map((tag, index) => (
                          <span key={index} className="inline-block px-2 py-1 bg-red-500/20 text-red-300 rounded text-xs">
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* AbuseIPDB */}
            {result.intelligence_sources?.abuseipdb && !result.intelligence_sources.abuseipdb.error && (
              <div className="bg-gradient-to-r from-orange-500/10 to-red-500/10 border border-orange-500/30 rounded-xl p-6">
                <h4 className="text-lg font-semibold text-orange-300 mb-4 flex items-center space-x-2">
                  <span>🚨</span>
                  <span>AbuseIPDB Analysis</span>
                </h4>
                <div className="space-y-3 text-sm">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Abuse Confidence:</span>
                    <span className={`font-bold ${result.intelligence_sources.abuseipdb.abuse_confidence > 25 ? 'text-red-400' : 'text-green-400'}`}>
                      {result.intelligence_sources.abuseipdb.abuse_confidence}%
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Total Reports:</span>
                    <span className="text-white">{result.intelligence_sources.abuseipdb.total_reports}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Distinct Users:</span>
                    <span className="text-white">{result.intelligence_sources.abuseipdb.num_distinct_users}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Usage Type:</span>
                    <span className="text-white">{result.intelligence_sources.abuseipdb.usage_type}</span>
                  </div>
                  {result.intelligence_sources.abuseipdb.is_whitelisted && (
                    <div className="flex justify-between">
                      <span className="text-gray-400">Status:</span>
                      <span className="text-green-400">✅ Whitelisted</span>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Geolocation */}
            {result.intelligence_sources?.geolocation && !result.intelligence_sources.geolocation.error && (
              <div className="bg-gradient-to-r from-blue-500/10 to-cyan-500/10 border border-blue-500/30 rounded-xl p-6">
                <h4 className="text-lg font-semibold text-blue-300 mb-4 flex items-center space-x-2">
                  <span>🌍</span>
                  <span>Geographic Intelligence</span>
                </h4>
                <div className="space-y-3 text-sm">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <span className="text-gray-400">Country:</span>
                      <div className="text-white font-semibold">{result.intelligence_sources.geolocation.country}</div>
                    </div>
                    <div>
                      <span className="text-gray-400">City:</span>
                      <div className="text-white font-semibold">{result.intelligence_sources.geolocation.city}</div>
                    </div>
                  </div>
                  <div>
                    <span className="text-gray-400">ISP:</span>
                    <div className="text-white">{result.intelligence_sources.geolocation.isp}</div>
                  </div>
                  <div>
                    <span className="text-gray-400">Organization:</span>
                    <div className="text-white">{result.intelligence_sources.geolocation.organization}</div>
                  </div>
                  <div>
                    <span className="text-gray-400">Coordinates:</span>
                    <div className="text-cyber-blue font-mono text-xs">
                      {result.intelligence_sources.geolocation.latitude}, {result.intelligence_sources.geolocation.longitude}
                    </div>
                  </div>
                  {(result.intelligence_sources.geolocation.is_hosting || result.intelligence_sources.geolocation.is_proxy) && (
                    <div className="mt-3 space-y-1">
                      {result.intelligence_sources.geolocation.is_hosting && (
                        <span className="inline-block px-2 py-1 bg-yellow-500/20 text-yellow-300 rounded text-xs">
                          🏗️ Hosting Service
                        </span>
                      )}
                      {result.intelligence_sources.geolocation.is_proxy && (
                        <span className="inline-block px-2 py-1 bg-red-500/20 text-red-300 rounded text-xs ml-2">
                          🔒 Proxy/VPN
                        </span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Shodan */}
            {result.intelligence_sources?.shodan && !result.intelligence_sources.shodan.error && (
              <div className="bg-gradient-to-r from-purple-500/10 to-violet-500/10 border border-purple-500/30 rounded-xl p-6">
                <h4 className="text-lg font-semibold text-purple-300 mb-4 flex items-center space-x-2">
                  <span>🔍</span>
                  <span>Infrastructure Analysis</span>
                </h4>
                <div className="space-y-3 text-sm">
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <span className="text-gray-400">Open Ports:</span>
                      <div className="text-white font-bold">{result.intelligence_sources.shodan.open_ports?.length || 0}</div>
                    </div>
                    <div>
                      <span className="text-gray-400">Vulnerabilities:</span>
                      <div className="text-white font-bold">{result.intelligence_sources.shodan.vulnerabilities?.length || 0}</div>
                    </div>
                  </div>
                  
                  {result.intelligence_sources.shodan.open_ports?.length > 0 && (
                    <div>
                      <span className="text-gray-400">Detected Ports:</span>
                      <div className="text-cyber-blue font-mono text-xs mt-1">
                        {result.intelligence_sources.shodan.open_ports.slice(0, 10).join(', ')}
                        {result.intelligence_sources.shodan.open_ports.length > 10 && '...'}
                      </div>
                    </div>
                  )}
                  
                  {result.intelligence_sources.shodan.service_tags?.length > 0 && (
                    <div>
                      <span className="text-gray-400">Service Tags:</span>
                      <div className="mt-1 space-x-1">
                        {result.intelligence_sources.shodan.service_tags.slice(0, 5).map((tag, index) => (
                          <span key={index} className="inline-block px-2 py-1 bg-surface/50 text-gray-300 rounded text-xs">
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Risk Factors & Recommendations */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
            <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-6">
              <h4 className="text-lg font-semibold text-red-300 mb-4">⚠️ Identified Risk Factors</h4>
              <ul className="space-y-2 text-sm">
                {result.threat_analysis?.risk_factors?.map((factor, index) => (
                  <li key={index} className="text-red-200 flex items-start space-x-2">
                    <span className="text-red-400 mt-1">•</span>
                    <span>{factor}</span>
                  </li>
                )) || <li className="text-gray-400">No significant risk factors detected</li>}
              </ul>
            </div>
            
            <div className="bg-green-500/10 border border-green-500/30 rounded-xl p-6">
              <h4 className="text-lg font-semibold text-green-300 mb-4">✅ Security Recommendations</h4>
              <ul className="space-y-2 text-sm">
                {result.professional_insights?.security_recommendations?.map((rec, index) => (
                  <li key={index} className="text-green-200 flex items-start space-x-2">
                    <span className="text-green-400 mt-1">•</span>
                    <span>{rec}</span>
                  </li>
                )) || <li className="text-gray-400">Standard monitoring procedures sufficient</li>}
              </ul>
            </div>
          </div>

          {/* Business Impact */}
          <div className="bg-gradient-to-r from-orange-900/30 to-red-900/30 border border-orange-500/50 rounded-xl p-6">
            <h4 className="text-xl font-semibold text-orange-300 mb-4">💼 Business Impact Assessment</h4>
            <p className="text-gray-200 leading-relaxed">{result.professional_insights?.business_impact}</p>
          </div>
        </div>
      )}
    </div>
  );
}
