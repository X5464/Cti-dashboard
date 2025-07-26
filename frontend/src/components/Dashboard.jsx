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
      {/* PROFESSIONAL HEADER WITH SUBTLE TAB NAVIGATION */}
      <div className="bg-gray-900/80 backdrop-blur-md border-b border-gray-700 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-3 sm:px-4 lg:px-6">
          <div className="flex items-center justify-between h-16 sm:h-20">
            {/* Logo/Brand - Professional */}
            <div className="flex items-center space-x-3 sm:space-x-4">
              <div className="w-10 h-10 sm:w-12 sm:h-12 bg-gradient-to-r from-cyber-blue to-cyber-purple rounded-xl flex items-center justify-center">
                <span className="text-xl sm:text-2xl">⚡</span>
              </div>
              <div>
                <h1 className="text-xl sm:text-2xl lg:text-3xl font-bold text-white font-inter tracking-tight">
                  <span className="hidden sm:inline">Lightning CTI</span>
                  <span className="sm:hidden">CTI</span>
                </h1>
                <p className="text-xs sm:text-sm text-gray-400 hidden sm:block">
                  Professional Threat Intelligence
                </p>
              </div>
            </div>

            {/* Desktop Navigation - Subtle Tab Style */}
            <nav className="hidden md:flex items-center bg-gray-800/50 rounded-xl p-1 backdrop-blur-sm border border-gray-700/50">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`relative px-4 lg:px-6 py-2.5 rounded-lg font-medium transition-all duration-300 flex items-center space-x-2 text-sm lg:text-base min-h-[44px] touch-target ${
                    activeTab === tab.id
                      ? 'bg-gradient-to-r from-cyber-blue/20 to-cyber-purple/20 text-white shadow-lg border border-cyber-blue/30'
                      : 'text-gray-400 hover:text-white hover:bg-gray-700/30'
                  }`}
                >
                  <span className="text-base lg:text-lg">{tab.icon}</span>
                  <span className="hidden lg:inline font-medium">{tab.name}</span>
                  <span className="lg:hidden font-medium">{tab.name.split(' ')[0]}</span>
                  
                  {/* Active indicator */}
                  {activeTab === tab.id && (
                    <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-cyber-blue to-cyber-purple rounded-full"></div>
                  )}
                </button>
              ))}
            </nav>

            {/* Mobile Menu Button */}
            <button
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              className="md:hidden p-2.5 rounded-xl text-gray-300 hover:text-white hover:bg-gray-700/50 transition-colors min-h-[44px] min-w-[44px] touch-target border border-gray-700/50"
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

          {/* Mobile Navigation Dropdown - Professional */}
          {isMobileMenuOpen && (
            <div className="md:hidden pb-4 border-t border-gray-700/50 mt-4 pt-4">
              <div className="space-y-2">
                {tabs.map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => {
                      setActiveTab(tab.id);
                      setIsMobileMenuOpen(false);
                    }}
                    className={`w-full px-4 py-3 rounded-xl font-medium transition-all duration-200 flex items-center space-x-3 text-left min-h-[44px] touch-target ${
                      activeTab === tab.id
                        ? 'bg-gradient-to-r from-cyber-blue/20 to-cyber-purple/20 text-white border border-cyber-blue/30'
                        : 'text-gray-300 hover:text-white hover:bg-gray-700/30 border border-transparent'
                    }`}
                  >
                    <span className="text-xl">{tab.icon}</span>
                    <span className="font-medium">{tab.name}</span>
                    {activeTab === tab.id && (
                      <div className="ml-auto w-2 h-2 bg-cyber-blue rounded-full"></div>
                    )}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Subtle Performance Indicator */}
      <div className="bg-gradient-to-r from-gray-800/30 to-gray-700/30 border-b border-gray-700/30">
        <div className="max-w-7xl mx-auto px-3 sm:px-4 lg:px-6 py-2">
          <div className="flex items-center justify-center space-x-6 text-xs sm:text-sm">
            <div className="flex items-center space-x-2 text-green-400">
              <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
              <span className="font-medium">Lightning Mode Active</span>
            </div>
            <div className="hidden sm:flex items-center space-x-2 text-gray-400">
              <span>•</span>
              <span>75-80% faster analysis</span>
            </div>
            <div className="hidden md:flex items-center space-x-2 text-gray-400">
              <span>•</span>
              <span>Parallel processing</span>
            </div>
          </div>
        </div>
      </div>

      {/* MAIN CONTENT AREA */}
      <main className="py-6 sm:py-8 lg:py-12">
        <div className="max-w-7xl mx-auto px-3 sm:px-4 lg:px-6">
          {activeComponent}
        </div>
      </main>

      {/* PROFESSIONAL FOOTER */}
      <footer className="bg-gradient-to-r from-gray-900/95 to-gray-800/95 backdrop-blur-md border-t border-gray-700/50 mt-12 sm:mt-16">
        <div className="max-w-7xl mx-auto px-3 sm:px-4 lg:px-6">
          {/* Main Footer Content */}
          <div className="py-8 sm:py-12">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8 lg:gap-12">
              {/* Company/Product Info */}
              <div className="md:col-span-1">
                <div className="flex items-center space-x-3 mb-4">
                  <div className="w-10 h-10 bg-gradient-to-r from-cyber-blue to-cyber-purple rounded-xl flex items-center justify-center">
                    <span className="text-xl">⚡</span>
                  </div>
                  <div>
                    <h3 className="text-lg font-bold text-white">Lightning CTI</h3>
                    <p className="text-sm text-gray-400">Threat Intelligence Platform</p>
                  </div>
                </div>
                <p className="text-gray-400 text-sm leading-relaxed mb-4">
                  Professional cyber threat intelligence analysis with lightning-fast performance 
                  and comprehensive multi-source intelligence gathering.
                </p>
                <div className="flex items-center space-x-4 text-xs text-gray-500">
                  <span className="flex items-center space-x-1">
                    <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                    <span>System Online</span>
                  </span>
                  <span>•</span>
                  <span>99.9% Uptime</span>
                </div>
              </div>

              {/* Key Features */}
              <div className="md:col-span-1">
                <h4 className="text-white font-semibold mb-4">Platform Features</h4>
                <ul className="space-y-2 text-sm text-gray-400">
                  <li className="flex items-center space-x-2">
                    <span className="text-green-400">✓</span>
                    <span>Multi-source threat intelligence</span>
                  </li>
                  <li className="flex items-center space-x-2">
                    <span className="text-green-400">✓</span>
                    <span>Lightning-fast parallel processing</span>
                  </li>
                  <li className="flex items-center space-x-2">
                    <span className="text-green-400">✓</span>
                    <span>Real-time geolocation analysis</span>
                  </li>
                  <li className="flex items-center space-x-2">
                    <span className="text-green-400">✓</span>
                    <span>Professional reporting & insights</span>
                  </li>
                  <li className="flex items-center space-x-2">
                    <span className="text-green-400">✓</span>
                    <span>Cross-device compatibility</span>
                  </li>
                </ul>
              </div>

              {/* Technical Specs */}
              <div className="md:col-span-1">
                <h4 className="text-white font-semibold mb-4">Technical Specifications</h4>
                <div className="space-y-3 text-sm">
                  <div className="flex justify-between items-center">
                    <span className="text-gray-400">Analysis Speed:</span>
                    <span className="text-green-400 font-medium">3-8 seconds</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-400">Performance Boost:</span>
                    <span className="text-green-400 font-medium">75-80% faster</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-400">Data Sources:</span>
                    <span className="text-blue-400 font-medium">4 APIs</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-400">Processing Mode:</span>
                    <span className="text-purple-400 font-medium">Parallel</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-gray-400">Cache Performance:</span>
                    <span className="text-yellow-400 font-medium">95% faster</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Bottom Footer Bar */}
          <div className="border-t border-gray-700/50 py-6">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-3 sm:space-y-0">
              {/* Copyright */}
              <div className="flex flex-col sm:flex-row sm:items-center space-y-1 sm:space-y-0 sm:space-x-4">
                <p className="text-gray-400 text-sm">
                  © 2025 Lightning CTI Dashboard. All rights reserved.
                </p>
                <div className="flex items-center space-x-4 text-xs text-gray-500">
                  <span>Developed by <strong className="text-gray-300">Rajarshi Chakraborty</strong></span>
                  <span className="hidden sm:inline">•</span>
                  <span className="hidden sm:inline">Cybersecurity Intern</span>
                </div>
              </div>

              {/* Status Indicators */}
              <div className="flex items-center space-x-6 text-xs">
                <div className="flex items-center space-x-2">
                  <div className="flex space-x-1">
                    <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
                    <div className="w-2 h-2 bg-blue-400 rounded-full animate-pulse" style={{animationDelay: '0.5s'}}></div>
                    <div className="w-2 h-2 bg-purple-400 rounded-full animate-pulse" style={{animationDelay: '1s'}}></div>
                  </div>
                  <span className="text-gray-400">All Systems Operational</span>
                </div>
                <div className="hidden sm:flex items-center space-x-2 text-gray-500">
                  <span>Version 6.0-Lightning</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
