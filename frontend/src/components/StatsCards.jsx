import React from 'react';

export default function StatsCards({ stats }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      <div className="bg-gray-800 p-4 rounded">Total Scans: {stats.total_scans}</div>
      <div className="bg-gray-800 p-4 rounded">Last 24h: {stats.recent_scans}</div>
      <div className="bg-gray-800 p-4 rounded">High: {stats.threat_distribution.high}</div>
      <div className="bg-gray-800 p-4 rounded">Low: {stats.threat_distribution.low}</div>
    </div>
  );
}
