import React, { useState } from 'react';
import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

function ThreatLookup({ onNewScan }) {
  const [input, setInput] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState('overview');

  const detectInputType = (input) => {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (ipRegex.test(input.trim())) return 'IP Address';
    if (input.startsWith('http') || input.startsWith('www.')) return 'URL/Website';
    return 'Domain';
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
    setActiveTab('overview');

    try {
      const response = await axios.post(`${API_BASE}/api/lookup`, 
        { input: trimmedInput },
        { timeout: 45000 }
      );
      
      if (response.data && response.data.status !== 'error') {
        setResult(response.data);
        if (onNewScan) onNewScan();
      } else {
        setError(response.data?.error || 'Comprehensive analysis failed');
      }
    } catch (error) {
      if (error.code === 'ECONNABORTED') {
        setError('Analysis timed out. This is a comprehensive scan - please try again.');
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
    const score = assessment?.overall_score || 0;
    
    if (score >= 70) return { 
      level: 'HIGH RISK', 
      color: 'text-red-400', 
      bg: 'bg-red-500/20 border-red-500/50', 
      icon: '🚨'
    };
    if (score >= 30) return { 
      level: 'MEDIUM RISK', 
      color: 'text-yellow-400', 
      bg: 'bg-yellow-500/20 border-yellow-500/50', 
      icon: '⚠️'
    };
    return { 
      level: 'LOW RISK', 
      color: 'text-green-400', 
      bg: 'bg-green-500/20 border-green-500/50', 
      icon: '✅'
    };
  };

  const formatDate = (timestamp) => {
    if (!timestamp) return 'Not available';
    return new Date(timestamp * 1000).toLocaleString();
  };

  const renderVirusTotalAnalysis = (vt_data) => {
    if (!vt_data || vt_data.error) {
      return (
        <div className="bg-red-500/20 border border-red-500/50 p-6 rounded-xl">
          <h4 className="text-lg font-semibold text-red-300 mb-2">❌ VirusTotal Analysis</h4>
          <p className="text-red-200">{vt_data?.error || 'No data available'}</p>
        </div>
      );
    }

    const basicInfo = vt_data.basic_info || {};
    const securityAnalysis = vt_data.security_analysis || {};
    const detectionEngines = vt_data.detection_engines || {};
    const stats = securityAnalysis.last_analysis_stats || {};

    return (
      <div className="space-y-6">
        {/* Basic Information */}
        <div className="bg-blue-500/10 border border-blue-500/30 p-6 rounded-xl">
          <h4 className="text-lg font-semibold text-blue-300 mb-4 flex items-center">
            <span className="mr-2">🛡️</span>
            VirusTotal Analysis - Basic Information
          </h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            {result.input_type === 'ip' && (
              <>
                <div><span className="text-gray-400">IP Address:</span> <span className="text-white font-mono">{basicInfo.ip_address}</span></div>
                <div><span className="text-gray-400">Country:</span> <span className="text-white">{basicInfo.country}</span></div>
                <div><span className="text-gray-400">Network:</span> <span className="text-white font-mono">{basicInfo.network}</span></div>
                <div><span className="text-gray-400">ASN:</span> <span className="text-white">{basicInfo.asn}</span></div>
                <div><span className="text-gray-400">AS Owner:</span> <span className="text-white">{basicInfo.as_owner}</span></div>
                <div><span className="text-gray-400">Registry:</span> <span className="text-white">{basicInfo.regional_internet_registry}</span></div>
              </>
            )}
            {result.input_type === 'domain' && (
              <>
                <div><span className="text-gray-400">Domain:</span> <span className="text-white font-mono">{basicInfo.domain}</span></div>
                <div><span className="text-gray-400">Creation Date:</span> <span className="text-white">{formatDate(basicInfo.creation_date)}</span></div>
                <div><span className="text-gray-400">Last Update:</span> <span className="text-white">{formatDate(basicInfo.last_update_date)}</span></div>
                <div><span className="text-gray-400">Registrar:</span> <span className="text-white">{basicInfo.registrar}</span></div>
                <div><span className="text-gray-400">Reputation:</span> <span className="text-white">{basicInfo.reputation}</span></div>
              </>
            )}
          </div>
        </div>

        {/* Security Analysis Summary */}
        <div className="bg-purple-500/10 border border-purple-500/30 p-6 rounded-xl">
          <h4 className="text-lg font-semibold text-purple-300 mb-4 flex items-center">
            <span className="mr-2">📊</span>
            Security Analysis Summary
          </h4>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="bg-green-500/20 p-4 rounded-lg text-center">
              <div className="text-2xl font-bold text-green-300">{stats.harmless || 0}</div>
              <div className="text-xs text-green-200">Clean</div>
            </div>
            <div className="bg-yellow-500/20 p-4 rounded-lg text-center">
              <div className="text-2xl font-bold text-yellow-300">{stats.suspicious || 0}</div>
              <div className="text-xs text-yellow-200">Suspicious</div>
            </div>
            <div className="bg-red-500/20 p-4 rounded-lg text-center">
              <div className="text-2xl font-bold text-red-300">{stats.malicious || 0}</div>
              <div className="text-xs text-red-200">Malicious</div>
            </div>
            <div className="bg-gray-500/20 p-4 rounded-lg text-center">
              <div className="text-2xl font-bold text-gray-300">{stats.undetected || 0}</div>
              <div className="text-xs text-gray-200">Undetected</div>
            </div>
          </div>
          <div className="mt-4 text-sm text-gray-300">
            <div><span className="text-gray-400">Last Analysis:</span> {formatDate(securityAnalysis.last_analysis_date)}</div>
            <div><span className="text-gray-400">Total Engines:</span> {Object.keys(detectionEngines).length}</div>
          </div>
        </div>

        {/* Individual Engine Results */}
        {Object.keys(detectionEngines).length > 0 && (
          <div className="bg-gray-800/30 border border-gray-600/30 p-6 rounded-xl">
            <h4 className="text-lg font-semibold text-cyan-300 mb-4 flex items-center">
              <span className="mr-2">🔍</span>
              Individual Security Engine Results ({Object.keys(detectionEngines).length} engines)
            </h4>
            <div className="max-h-96 overflow-y-auto">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {Object.entries(detectionEngines).map(([engine, result]) => (
                  <div key={engine} className={`p-3 rounded-lg border ${
                    result.category === 'malicious' ? 'bg-red-500/10 border-red-500/30' :
                    result.category === 'suspicious' ? 'bg-yellow-500/10 border-yellow-500/30' :
                    result.category === 'harmless' ? 'bg-green-500/10 border-green-500/30' :
                    'bg-gray-500/10 border-gray-500/30'
                  }`}>
                    <div className="text-sm font-medium text-white">{engine}</div>
                    <div className={`text-xs ${
                      result.category === 'malicious' ? 'text-red-300' :
                      result.category === 'suspicious' ? 'text-yellow-300' :
                      result.category === 'harmless' ? 'text-green-300' :
                      'text-gray-300'
                    }`}>
                      {result.result || 'Clean'}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Categories */}
        {vt_data.categories && vt_data.categories.length > 0 && (
          <div className="bg-indigo-500/10 border border-indigo-500/30 p-6 rounded-xl">
            <h4 className="text-lg font-semibold text-indigo-300 mb-4 flex items-center">
              <span className="mr-2">🏷️</span>
              Categories
            </h4>
            <div className="flex flex-wrap gap-2">
              {vt_data.categories.map((category, index) => (
                <span key={index} className="bg-indigo-500/20 text-indigo-200 px-3 py-1 rounded-full text-sm">
                  {category}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  };

  const renderAbuseIPDBAnalysis = (abuse_data) => {
    if (!abuse_data || abuse_data.error) {
      return (
        <div className="bg-gray-500/20 border border-gray-500/50 p-6 rounded-xl">
          <h4 className="text-lg font-semibold text-gray-300 mb-2">ℹ️ AbuseIPDB Analysis</h4>
          <p className="text-gray-200">{abuse_data?.error || 'Not applicable for this input type'}</p>
        </div>
      );
    }

    const basicInfo = abuse_data.basic_info || {};
    const abuseAnalysis = abuse_data.abuse_analysis || {};
    const recentReports = abuse_data.recent_reports || [];

    return (
      <div className="space-y-6">
        {/* Basic Information */}
        <div className="bg-purple-500/10 border border-purple-500/30 p-6 rounded-xl">
          <h4 className="text-lg font-semibold text-purple-300 mb-4 flex items-center">
            <span className="mr-2">🛡️</span>
            AbuseIPDB Analysis - IP Information
          </h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            <div><span className="text-gray-400">IP Address:</span> <span className="text-white font-mono">{basicInfo.ip_address}</span></div>
            <div><span className="text-gray-400">Country:</span> <span className="text-white">{basicInfo.country_name} ({basicInfo.country_code})</span></div>
            <div><span className="text-gray-400">ISP:</span> <span className="text-white">{basicInfo.isp}</span></div>
            <div><span className="text-gray-400">Domain:</span> <span className="text-white">{basicInfo.domain}</span></div>
            <div><span className="text-gray-400">Usage Type:</span> <span className="text-white">{basicInfo.usage_type}</span></div>
            <div><span className="text-gray-400">IP Version:</span> <span className="text-white">IPv{basicInfo.ip_version}</span></div>
            <div><span className="text-gray-400">Is Public:</span> <span className={basicInfo.is_public ? 'text-green-300' : 'text-red-300'}>{basicInfo.is_public ? 'Yes' : 'No'}</span></div>
            <div><span className="text-gray-400">Whitelisted:</span> <span className={basicInfo.is_whitelisted ? 'text-green-300' : 'text-gray-300'}>{basicInfo.is_whitelisted ? 'Yes' : 'No'}</span></div>
          </div>
        </div>

        {/* Abuse Analysis */}
        <div className="bg-red-500/10 border border-red-500/30 p-6 rounded-xl">
          <h4 className="text-lg font-semibold text-red-300 mb-4 flex items-center">
            <span className="mr-2">🚨</span>
            Abuse Analysis
          </h4>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-red-500/20 p-4 rounded-lg text-center">
              <div className="text-2xl font-bold text-red-300">{abuseAnalysis.abuse_confidence_percentage}%</div>
              <div className="text-xs text-red-200">Confidence</div>
            </div>
            <div className="bg-orange-500/20 p-4 rounded-lg text-center">
              <div className="text-2xl font-bold text-orange-300">{abuseAnalysis.total_reports}</div>
              <div className="text-xs text-orange-200">Total Reports</div>
            </div>
            <div className="bg-yellow-500/20 p-4 rounded-lg text-center">
              <div className="text-2xl font-bold text-yellow-300">{abuseAnalysis.num_distinct_users}</div>
              <div className="text-xs text-yellow-200">Distinct Users</div>
            </div>
            <div className="bg-blue-500/20 p-4 rounded-lg text-center">
              <div className="text-sm font-medium text-blue-200">Last Report</div>
              <div className="text-xs text-blue-300">{abuseAnalysis.last_reported_at === 'Never' ? 'Never' : new Date(abuseAnalysis.last_reported_at).toLocaleDateString()}</div>
            </div>
          </div>
        </div>

        {/* Recent Reports */}
        {recentReports.length > 0 && (
          <div className="bg-gray-800/30 border border-gray-600/30 p-6 rounded-xl">
            <h4 className="text-lg font-semibold text-cyan-300 mb-4 flex items-center">
              <span className="mr-2">📋</span>
              Recent Abuse Reports ({recentReports.length} reports)
            </h4>
            <div className="max-h-64 overflow-y-auto space-y-3">
              {recentReports.slice(0, 10).map((report, index) => (
                <div key={index} className="bg-gray-700/30 p-3 rounded-lg border border-gray-600/30">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium text-white">Report #{index + 1}</span>
                    <span className="text-xs text-gray-400">{new Date(report.reportedAt).toLocaleString()}</span>
                  </div>
                  <div className="text-sm text-gray-300">
                    <div><span className="text-gray-400">Country:</span> {report.reporterCountryName}</div>
                    <div><span className="text-gray-400">Categories:</span> {report.categories.join(', ') || 'None specified'}</div>
                    {report.comment && (
                      <div className="mt-2"><span className="text-gray-400">Comment:</span> {report.comment.substring(0, 100)}{report.comment.length > 100 ? '...' : ''}</div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  };

  const renderOverview = () => {
    if (!result) return null;

    const threat = getThreatDisplay(result.threat_assessment);
    
    return (
      <div className="space-y-6">
        {/* Threat Assessment */}
        <div className={`p-8 rounded-xl border-2 ${threat.bg}`}>
          <div className="text-center mb-6">
            <div className="text-6xl mb-2">{threat.icon}</div>
            <div className="text-3xl font-bold text-white">{result.threat_assessment?.overall_score || 0}/100</div>
            <div className={`text-xl font-medium ${threat.color}`}>{threat.level}</div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="text-center">
              <div className="text-2xl font-bold text-white">{result.threat_assessment?.engines_total || 0}</div>
              <div className="text-sm text-gray-300">Security Engines</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-red-400">{result.threat_assessment?.malicious_count || 0}</div>
              <div className="text-sm text-gray-300">Malicious Detections</div>
            </div>
            <div className="text-center">
              <div className="text-2xl font-bold text-green-400">{result.threat_assessment?.clean_count || 0}</div>
              <div className="text-sm text-gray-300">Clean Detections</div>
            </div>
          </div>
        </div>

        {/* Scan Information */}
        <div className="bg-gray-800/30 border border-gray-600/30 p-6 rounded-xl">
          <h4 className="text-lg font-semibold text-white mb-4">📋 Scan Information</h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            <div><span className="text-gray-400">Scan ID:</span> <span className="text-cyan-400 font-mono">{result.scan_id}</span></div>
            <div><span className="text-gray-400">Input Type:</span> <span className="text-white">{result.input_type?.toUpperCase()}</span></div>
            <div><span className="text-gray-400">Scan Time:</span> <span className="text-white">{formatDate(result.timestamp)}</span></div>
            <div><span className="text-gray-400">Duration:</span> <span className="text-white">{result.scan_metadata?.scan_duration}</span></div>
            <div className="md:col-span-2">
              <span className="text-gray-400">APIs Used:</span> 
              <span className="text-white ml-2">{result.scan_metadata?.apis_used?.join(', ')}</span>
            </div>
            <div className="md:col-span-2">
              <span className="text-gray-400">Data Sources:</span> 
              <span className="text-white ml-2">{result.scan_metadata?.data_sources?.join(', ')}</span>
            </div>
          </div>
        </div>

        {/* Target Information */}
        <div className="bg-gray-800/30 border border-gray-600/30 p-6 rounded-xl">
          <h4 className="text-lg font-semibold text-white mb-4">🎯 Target Information</h4>
          <div className="bg-gray-700/50 p-4 rounded-lg border">
            <div className="font-mono text-cyan-400 break-all text-lg">{result.input}</div>
            <div className="text-sm text-gray-400 mt-2">
              Detected as: <span className="text-white">{result.input_type} Address</span>
            </div>
          </div>
        </div>
      </div>
    );
  };

  return (
    <div>
      <h2 className="text-3xl font-bold mb-8 text-center">
        <span className="bg-gradient-to-r from-cyan-400 to-purple-400 bg-clip-text text-transparent">
          🔍 Comprehensive Threat Analysis
        </span>
      </h2>

      {/* Scan Input */}
      <form onSubmit={handleLookup} className="mb-8">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="flex-1 relative">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Enter IP, domain, or URL for comprehensive analysis..."
              className="w-full bg-white/5 border border-white/20 text-white rounded-xl px-6 py-4 text-lg backdrop-blur-sm focus:ring-2 focus:ring-cyan-400 focus:border-transparent transition-all duration-300"
              disabled={loading}
            />
            {input && (
              <span className="absolute right-4 top-1/2 transform -translate-y-1/2 text-sm bg-gray-700/50 text-gray-300 px-3 py-1 rounded-full">
                {detectInputType(input)}
              </span>
            )}
          </div>
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="bg-gradient-to-r from-cyan-500 to-purple-500 text-white px-8 py-4 rounded-xl font-semibold text-lg hover:from-cyan-600 hover:to-purple-600 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 shadow-lg hover:shadow-xl"
          >
            {loading ? (
              <div className="flex items-center space-x-3">
                <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-white"></div>
                <span>Analyzing...</span>
              </div>
            ) : (
              '🔍 Deep Scan'
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
        <div className="bg-white/5 backdrop-blur-lg rounded-2xl border border-white/10 overflow-hidden">
          {/* Navigation Tabs */}
          <div className="border-b border-white/10">
            <nav className="flex space-x-0">
              {['overview', 'virustotal', 'abuseipdb'].map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className={`px-8 py-4 font-semibold text-lg capitalize transition-all duration-300 ${
                    activeTab === tab
                      ? 'bg-gradient-to-r from-cyan-500 to-purple-500 text-white'
                      : 'text-gray-300 hover:text-white hover:bg-white/5'
                  }`}
                >
                  {tab === 'virustotal' ? 'VirusTotal' : 
                   tab === 'abuseipdb' ? 'AbuseIPDB' : 
                   'Overview'}
                </button>
              ))}
            </nav>
          </div>

          {/* Tab Content */}
          <div className="p-8">
            {activeTab === 'overview' && renderOverview()}
            {activeTab === 'virustotal' && renderVirusTotalAnalysis(result.analysis_results?.virustotal)}
            {activeTab === 'abuseipdb' && renderAbuseIPDBAnalysis(result.analysis_results?.abuseipdb)}
          </div>
        </div>
      )}
    </div>
  );
}

export default ThreatLookup;
