import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

export default function GeographicIntel({ history }) {
  const [geoData, setGeoData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchGeographicData();
  }, []);

  const fetchGeographicData = async () => {
    try {
      const response = await axios.get(`${API_BASE}/api/geo-intelligence`);
      setGeoData(response.data);
    } catch (error) {
      console.error('Error fetching geographic data:', error);
    } finally {
      setLoading(false);
    }
  };

  // Process history data for geographic analysis
  const processHistoryData = () => {
    if (!history || history.length === 0) return {};

    const countryCounts = {};
    const cityCounts = {};
    const threatByCountry = {};

    history.forEach(scan => {
      const location = scan.location || {};
      const country = location.country || 'Unknown';
      const city = location.city || 'Unknown';
      const threatScore = scan.threat_score || 0;

      // Count by country
      countryCounts[country] = (countryCounts[country] || 0) + 1;
      
      // Count by city
      if (city !== 'Unknown') {
        cityCounts[city] = (cityCounts[city] || 0) + 1;
      }

      // Average threat by country
      if (!threatByCountry[country]) {
        threatByCountry[country] = { total: 0, count: 0, avg: 0 };
      }
      threatByCountry[country].total += threatScore;
      threatByCountry[country].count += 1;
      threatByCountry[country].avg = threatByCountry[country].total / threatByCountry[country].count;
    });

    return { countryCounts, cityCounts, threatByCountry };
  };

  const { countryCounts, cityCounts, threatByCountry } = processHistoryData();
  const sortedCountries = Object.entries(countryCounts).sort((a, b) => b[1] - a[1]);
  const sortedCities = Object.entries(cityCounts).sort((a, b) => b[1] - a[1]);

  const getCountryRiskLevel = (country) => {
    const avgThreat = threatByCountry[country]?.avg || 0;
    if (avgThreat >= 70) return { level: 'HIGH', color: 'text-red-400', bg: 'bg-red-500/20' };
    if (avgThreat >= 40) return { level: 'MEDIUM', color: 'text-yellow-400', bg: 'bg-yellow-500/20' };
    return { level: 'LOW', color: 'text-green-400', bg: 'bg-green-500/20' };
  };

  if (loading) {
    return (
      <div className="text-center py-12">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyber-blue mx-auto"></div>
        <p className="text-gray-300 mt-4">Loading geographic intelligence...</p>
      </div>
    );
  }

  return (
    <div>
      <h2 className="text-3xl font-bold mb-8 text-center">
        <span className="bg-gradient-to-r from-cyber-blue to-cyber-green bg-clip-text text-transparent">
          🌍 Geographic Threat Intelligence
        </span>
      </h2>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="bg-gradient-to-r from-blue-500/20 to-cyan-500/20 border border-blue-500/30 p-6 rounded-xl">
          <div className="text-center">
            <div className="text-3xl font-bold text-blue-400">{Object.keys(countryCounts).length}</div>
            <div className="text-blue-200">Countries Detected</div>
            <div className="text-xs text-gray-400 mt-1">Unique locations scanned</div>
          </div>
        </div>
        
        <div className="bg-gradient-to-r from-purple-500/20 to-violet-500/20 border border-purple-500/30 p-6 rounded-xl">
          <div className="text-center">
            <div className="text-3xl font-bold text-purple-400">{Object.keys(cityCounts).length}</div>
            <div className="text-purple-200">Cities Identified</div>
            <div className="text-xs text-gray-400 mt-1">Urban areas analyzed</div>
          </div>
        </div>
        
        <div className="bg-gradient-to-r from-green-500/20 to-emerald-500/20 border border-green-500/30 p-6 rounded-xl">
          <div className="text-center">
            <div className="text-3xl font-bold text-green-400">{history?.length || 0}</div>
            <div className="text-green-200">Total Scans</div>
            <div className="text-xs text-gray-400 mt-1">Geographic analyses performed</div>
          </div>
        </div>
      </div>

      {/* Country Analysis */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <div className="bg-surface/20 p-6 rounded-xl border border-border/20">
          <h3 className="text-xl font-semibold text-white mb-6">🗺️ Country Distribution</h3>
          <div className="space-y-3 max-h-64 overflow-y-auto">
            {sortedCountries.slice(0, 10).map(([country, count]) => {
              const riskInfo = getCountryRiskLevel(country);
              return (
                <div key={country} className="flex items-center justify-between p-3 bg-surface/30 rounded-lg">
                  <div className="flex items-center space-x-3">
                    <span className="text-lg">🌍</span>
                    <div>
                      <div className="font-semibold text-white">{country}</div>
                      <div className="text-xs text-gray-400">{count} detection{count !== 1 ? 's' : ''}</div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className={`px-2 py-1 rounded text-xs font-semibold ${riskInfo.bg} ${riskInfo.color}`}>
                      {riskInfo.level}
                    </div>
                    <div className="text-xs text-gray-400 mt-1">
                      Avg: {Math.round(threatByCountry[country]?.avg || 0)}/100
                    </div>
                  </div>
                </div>
              );
            })}
            {sortedCountries.length === 0 && (
              <div className="text-center text-gray-400 py-8">
                <div className="text-4xl mb-4">🌍</div>
                <div>No geographic data available yet</div>
                <div className="text-sm mt-2">Start scanning IPs to see location intelligence</div>
              </div>
            )}
          </div>
        </div>

        <div className="bg-surface/20 p-6 rounded-xl border border-border/20">
          <h3 className="text-xl font-semibold text-white mb-6">🏙️ City Hotspots</h3>
          <div className="space-y-3 max-h-64 overflow-y-auto">
            {sortedCities.slice(0, 10).map(([city, count]) => (
              <div key={city} className="flex items-center justify-between p-3 bg-surface/30 rounded-lg">
                <div className="flex items-center space-x-3">
                  <span className="text-lg">🏙️</span>
                  <div>
                    <div className="font-semibold text-white">{city}</div>
                    <div className="text-xs text-gray-400">{count} detection{count !== 1 ? 's' : ''}</div>
                  </div>
                </div>
              </div>
            ))}
            {sortedCities.length === 0 && (
              <div className="text-center text-gray-400 py-8">
                <div className="text-4xl mb-4">🏙️</div>
                <div>No city data available</div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* High-Risk Regions Alert */}
      {Object.entries(threatByCountry).some(([, data]) => data.avg >= 70) && (
        <div className="mt-8 bg-gradient-to-r from-red-900/30 to-orange-900/30 border border-red-500/50 rounded-xl p-6">
          <h3 className="text-xl font-semibold text-red-300 mb-4">🚨 High-Risk Regions Alert</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {Object.entries(threatByCountry)
              .filter(([, data]) => data.avg >= 70)
              .map(([country, data]) => (
                <div key={country} className="bg-red-500/20 p-4 rounded-lg border border-red-500/30">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="font-semibold text-red-300">{country}</div>
                      <div className="text-xs text-gray-400">{data.count} threats detected</div>
                    </div>
                    <div className="text-right">
                      <div className="text-lg font-bold text-red-400">{Math.round(data.avg)}/100</div>
                      <div className="text-xs text-red-300">Avg Risk</div>
                    </div>
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* Geographic Intelligence Summary */}
      <div className="mt-8 bg-gradient-to-r from-purple-900/30 to-blue-900/30 border border-purple-500/50 rounded-xl p-6">
        <h3 className="text-xl font-semibold text-purple-300 mb-4">📊 Intelligence Summary</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div>
            <h4 className="font-semibold text-white mb-3">🌍 Global Coverage</h4>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-400">Geographic Diversity:</span>
                <span className="text-cyber-blue">{Object.keys(countryCounts).length} countries</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Urban Coverage:</span>
                <span className="text-cyber-green">{Object.keys(cityCounts).length} cities</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Data Quality:</span>
                <span className="text-cyber-purple">Real-time scanning</span>
              </div>
            </div>
          </div>
          
          <div>
            <h4 className="font-semibold text-white mb-3">🎯 Risk Assessment</h4>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-400">High-Risk Regions:</span>
                <span className="text-red-400">
                  {Object.entries(threatByCountry).filter(([, data]) => data.avg >= 70).length}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Medium-Risk Regions:</span>
                <span className="text-yellow-400">
                  {Object.entries(threatByCountry).filter(([, data]) => data.avg >= 40 && data.avg < 70).length}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Low-Risk Regions:</span>
                <span className="text-green-400">
                  {Object.entries(threatByCountry).filter(([, data]) => data.avg < 40).length}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
