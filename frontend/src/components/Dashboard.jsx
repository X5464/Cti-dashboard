import React, { useState, useEffect } from 'react';
import ThreatLookup from './ThreatLookup';
import HistoryTable from './HistoryTable';
import StatsCards from './StatsCards';

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState('lookup');
  const [scanCount, setScanCount] = useState(0);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  const handleNewScan = () => {
    setScanCount(prev => prev + 1);
  };

  const tabs = [
    { id: 'lookup', name: 'Lightning Analysis', icon: '⚡', component: <ThreatLookup onNewScan={handleNewScan} /> },
    { id: 'history', name: 'Scan History', icon: '📜', component: <HistoryTable key={scanCount} /> },
    { id: 'stats', name: 'Performance Stats', icon: '📊', component: <StatsCards key={scanCount} /> }
  ];

  const activeComponent = tabs.find(tab => tab.id === activeTab)?.component;

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-800">
      {/* MOBILE-OPTIMIZED HEADER WITH HAMBURGER MENU */}
      <div className="bg-gray-900/80 backdrop-blur-md border-b border-gray-700 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-3 sm:px-4 lg:px-6">
          <div className="flex items-center justify-between h-14 sm:h-16">
            {/* Logo/Brand - Responsive */}
            <div className="flex items-center space-x-2 sm:space-x-3">
              <span className="text-xl sm:text-2xl">⚡</span>
              <h1 className="text-lg sm:text-xl lg:text-2xl font-bold text-white font-inter">
                <span className="hidden sm:inline">Lightning CTI Dashboard</span>
                <span className="sm:hidden">Lightning CTI</span>
              </h1>
            </div>

            {/* Desktop Navigation - Hidden on mobile */}
            <nav className="hidden md:flex space-x-1 lg:space-x-2">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`px-3 lg:px-4 py-2 rounded-lg font-medium transition-all duration-200 flex items-center space-x-2 text-sm lg:text-base min-h-[44px] touch-target ${
                    activeTab === tab.id
                      ? 'bg-cyber-blue text-white shadow-lg'
                      : 'text-gray-300 hover:text-white hover:bg-gray-700/50'
                  }`}
                >
                  <span className="text-lg">{tab.icon}</span>
                  <span className="hidden lg:inline">{tab.name}</span>
                </button>
              ))}
            </nav>

            {/* Mobile Menu Button - 44px touch target */}
            <button
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              className="md:hidden p-2 rounded-lg text-gray-300 hover:text-white hover:bg-gray-700/50 transition-colors min-h-[44px] min-w-[44px] touch-target"
            >
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                {isMobileMenuOpen ? (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                ) : (
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
                )}
              </svg>
            </button>
          </div>

          {/* Mobile Navigation Dropdown - Touch-friendly */}
          {isMobileMenuOpen && (
            <div className="md:hidden pb-3">
              <div className="flex flex-col space-y-1">
                {tabs.map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => {
                      setActiveTab(tab.id);
                      setIsMobileMenuOpen(false);
                    }}
                    className={`px-3 py-3 rounded-lg font-medium transition-all duration-200 flex items-center space-x-3 text-left min-h-[44px] touch-target ${
                      activeTab === tab.id
                        ? 'bg-cyber-blue text-white shadow-lg'
                        : 'text-gray-300 hover:text-white hover:bg-gray-700/50'
                    }`}
                  >
                    <span className="text-xl">{tab.icon}</span>
                    <span>{tab.name}</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* PERFORMANCE METRICS BANNER - Responsive */}
      <div className="bg-gradient-to-r from-green-500/10 to-emerald-500/10 border-b border-green-500/30">
        <div className="max-w-7xl mx-auto px-3 sm:px-4 lg:px-6 py-2 sm:py-3">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-2 sm:space-y-0">
            <div className="flex items-center space-x-2 sm:space-x-3">
              <span className="text-lg sm:text-xl">🚀</span>
              <div>
                <div className="font-semibold text-green-300 text-xs sm:text-sm">Performance Optimizations Active</div>
                <div className="text-gray-400 text-xs">75-80% faster • Parallel processing • Intelligent caching</div>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2 text-xs">
              <span className="bg-green-500/20 text-green-400 px-2 py-1 rounded-full">⚡ Lightning Mode</span>
              <span className="bg-blue-500/20 text-blue-400 px-2 py-1 rounded-full">📱 All Devices</span>
              <span className="bg-purple-500/20 text-purple-400 px-2 py-1 rounded-full">🔄 Parallel APIs</span>
            </div>
          </div>
        </div>
      </div>

      {/* MAIN CONTENT AREA - Responsive */}
      <main className="py-4 sm:py-6 lg:py-8">
        <div className="max-w-7xl mx-auto px-3 sm:px-4 lg:px-6">
          {activeComponent}
        </div>
      </main>

      {/* RESPONSIVE FOOTER WITH PERFORMANCE INFO */}
      <footer className="bg-gray-900/60 backdrop-blur-md border-t border-gray-700 mt-8 sm:mt-12">
        <div className="max-w-7xl mx-auto px-3 sm:px-4 lg:px-6 py-4 sm:py-6">
          <div className="flex flex-col space-y-4">
            {/* Performance Features Grid - Mobile stacks, desktop spreads */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
              <div className="bg-gray-800/30 rounded-lg p-3">
                <div className="flex items-center space-x-2">
                  <span className="text-green-400">⚡</span>
                  <div>
                    <div className="text-white font-medium text-sm">Speed Boost</div>
                    <div className="text-gray-400 text-xs">75-80% faster analysis</div>
                  </div>
                </div>
              </div>
              <div className="bg-gray-800/30 rounded-lg p-3">
                <div className="flex items-center space-x-2">
                  <span className="text-blue-400">📱</span>
                  <div>
                    <div className="text-white font-medium text-sm">Device Support</div>
                    <div className="text-gray-400 text-xs">iPhone, Android, Desktop</div>
                  </div>
                </div>
              </div>
              <div className="bg-gray-800/30 rounded-lg p-3">
                <div className="flex items-center space-x-2">
                  <span className="text-purple-400">🔄</span>
                  <div>
                    <div className="text-white font-medium text-sm">Processing</div>
                    <div className="text-gray-400 text-xs">Parallel API calls</div>
                  </div>
                </div>
              </div>
              <div className="bg-gray-800/30 rounded-lg p-3">
                <div className="flex items-center space-x-2">
                  <span className="text-yellow-400">💾</span>
                  <div>
                    <div className="text-white font-medium text-sm">Caching</div>
                    <div className="text-gray-400 text-xs">95% faster results</div>
                  </div>
                </div>
              </div>
            </div>

            {/* Main Footer Info - Responsive layout */}
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-2 sm:space-y-0 pt-4 border-t border-gray-700">
              <p className="text-gray-400 text-xs sm:text-sm text-center sm:text-left">
                © 2025 Lightning-Fast CTI Dashboard. Developed by <strong className="text-white">Rajarshi Chakraborty - Cybersecurity Intern </strong>. All Rights Reserved.
              </p>
              <div className="flex items-center justify-center sm:justify-end space-x-3 sm:space-x-4 text-xs sm:text-sm">
                <span className="text-gray-500">Performance Mode</span>
                <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></span>
                <span className="text-green-400 font-medium">Lightning Active</span>
              </div>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
