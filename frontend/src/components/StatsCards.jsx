import React from 'react';

function StatsCards({ stats }) {
  // Provide default values to prevent undefined errors
  const safeStats = {
    total_scans: 0,
    recent_scans: 0,
    threat_distribution: { high: 0, medium: 0, low: 0 },
    ...stats
  };

  const threatDist = {
    high: 0,
    medium: 0,
    low: 0,
    ...safeStats.threat_distribution
  };

  const statsData = [
    {
      title: 'Total Scans',
      value: safeStats.total_scans || 0,
      icon: '📊',
      color: 'blue'
    },
    {
      title: 'Last 24h',
      value: safeStats.recent_scans || 0,
      icon: '🕒',
      color: 'green'
    },
    {
      title: 'High Threats',
      value: threatDist.high || 0,
      icon: '🚨',
      color: 'red'
    },
    {
      title: 'Clean IPs',
      value: threatDist.low || 0,
      icon: '✅',
      color: 'purple'
    }
  ];

  const getColorClasses = (color) => {
    const colorMap = {
      blue: 'bg-blue-500/20 text-blue-400',
      green: 'bg-green-500/20 text-green-400',
      red: 'bg-red-500/20 text-red-400',
      purple: 'bg-purple-500/20 text-purple-400'
    };
    return colorMap[color] || colorMap.blue;
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      {statsData.map((stat, index) => (
        <div key={index} className="card">
          <div className="flex items-center">
            <div className={`p-3 rounded-full ${getColorClasses(stat.color)}`}>
              <span className="text-xl">{stat.icon}</span>
            </div>
            <div className="ml-4">
              <p className="text-sm font-medium text-gray-400">{stat.title}</p>
              <p className="text-2xl font-semibold text-white">
                {typeof stat.value === 'number' ? stat.value.toLocaleString() : '0'}
              </p>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

export default StatsCards;
