import React from 'react';

export default function StatsCards({ stats }) {
  const safeStats = {
    total_scans: 0,
    recent_scans: 0,
    threat_distribution: { high: 0, medium: 0, low: 0 },
    ai_metrics: { accuracy: '0%', processing_speed: '0s', ml_confidence: '0%' },
    ...stats
  };

  const statsData = [
    {
      title: 'Total AI Scans',
      value: safeStats.total_scans,
      icon: '🤖',
      color: 'from-blue-400 to-cyan-400',
      bgColor: 'bg-blue-500/10 border-blue-500/30',
      subtitle: 'ML-powered analysis'
    },
    {
      title: 'Last 24 Hours',
      value: safeStats.recent_scans,
      icon: '⚡',
      color: 'from-green-400 to-emerald-400',
      bgColor: 'bg-green-500/10 border-green-500/30',
      subtitle: 'Real-time monitoring'
    },
    {
      title: 'High Threats',
      value: safeStats.threat_distribution.high,
      icon: '🚨',
      color: 'from-red-400 to-pink-400',
      bgColor: 'bg-red-500/10 border-red-500/30',
      subtitle: 'Critical alerts'
    },
    {
      title: 'AI Accuracy',
      value: safeStats.ai_metrics.accuracy,
      icon: '🎯',
      color: 'from-purple-400 to-violet-400',
      bgColor: 'bg-purple-500/10 border-purple-500/30',
      subtitle: 'Machine learning'
    }
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      {statsData.map((stat, index) => (
        <div key={index} className={`${stat.bgColor} backdrop-blur-lg rounded-2xl p-6 border transition-all duration-300 hover:scale-105 hover:shadow-xl`}>
          <div className="flex items-center justify-between mb-4">
            <div className={`w-12 h-12 rounded-full bg-gradient-to-r ${stat.color} flex items-center justify-center text-white font-bold text-xl shadow-lg`}>
              <span>{stat.icon}</span>
            </div>
            <div className="text-right">
              <p className="text-2xl font-bold text-white">
                {typeof stat.value === 'number' ? stat.value.toLocaleString() : stat.value}
              </p>
              <p className="text-xs text-gray-400">{stat.title}</p>
            </div>
          </div>
          
          <div className="flex items-center justify-between">
            <p className="text-sm text-gray-300">{stat.subtitle}</p>
            <div className={`w-full bg-gray-700/50 rounded-full h-2 ml-3`}>
              <div 
                className={`bg-gradient-to-r ${stat.color} h-2 rounded-full transition-all duration-1000`}
                style={{ 
                  width: `${Math.min(
                    typeof stat.value === 'number' 
                      ? (stat.value / Math.max(safeStats.total_scans, 1)) * 100 
                      : 85, 
                    100
                  )}%` 
                }}
              ></div>
            </div>
          </div>

          {/* AI Performance Indicator */}
          <div className="mt-4 text-xs">
            <div className="flex items-center space-x-2">
              <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
              <span className="text-gray-400">
                {stat.title.includes('AI') ? 'ML Model Active' : 'Real-time Data'}
              </span>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
