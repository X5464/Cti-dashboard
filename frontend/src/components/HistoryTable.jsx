import React, { useState } from 'react';

export default function HistoryTable({ history }) {
  const [currentPage, setCurrentPage] = useState(1);
  const [sortField, setSortField] = useState('timestamp');
  const [sortDirection, setSortDirection] = useState('desc');
  const itemsPerPage = 10;
  
  const sortedHistory = [...history].sort((a, b) => {
    let aVal = a[sortField];
    let bVal = b[sortField];
    
    if (sortField === 'timestamp') {
      aVal = new Date(aVal * 1000);
      bVal = new Date(bVal * 1000);
    }
    
    if (sortDirection === 'asc') {
      return aVal > bVal ? 1 : -1;
    } else {
      return aVal < bVal ? 1 : -1;
    }
  });
  
  const indexOfLastItem = currentPage * itemsPerPage;
  const indexOfFirstItem = indexOfLastItem - itemsPerPage;
  const currentItems = sortedHistory.slice(indexOfFirstItem, indexOfLastItem);
  const totalPages = Math.ceil(history.length / itemsPerPage);

  const handleSort = (field) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('desc');
    }
  };

  const getThreatBadge = (score) => {
    if (score >= 70) return <span className="px-3 py-1 text-xs font-semibold bg-red-500/20 text-red-300 rounded-full border border-red-500/50">🚨 HIGH</span>;
    if (score >= 30) return <span className="px-3 py-1 text-xs font-semibold bg-yellow-500/20 text-yellow-300 rounded-full border border-yellow-500/50">⚠️ MEDIUM</span>;
    return <span className="px-3 py-1 text-xs font-semibold bg-green-500/20 text-green-300 rounded-full border border-green-500/50">✅ LOW</span>;
  };

  const getTypeIcon = (type) => {
    switch(type) {
      case 'ip': return '🌐';
      case 'domain': return '🏠';
      case 'url': return '🔗';
      default: return '📊';
    }
  };

  const formatInput = (input) => {
    if (!input) return 'Unknown';
    
    if (input.length > 30) {
      return (
        <div className="group relative">
          <div className="font-mono text-sm text-cyber-blue cursor-help">
            {input.substring(0, 30)}...
          </div>
          <div className="absolute z-50 invisible group-hover:visible bg-gray-900 text-white p-3 rounded-lg shadow-xl border border-gray-600 max-w-sm break-all text-xs top-full mt-2 left-0">
            <div className="font-semibold mb-1 text-cyber-blue">Full Address:</div>
            <div className="break-all">{input}</div>
          </div>
        </div>
      );
    }
    
    return <span className="font-mono text-sm text-cyber-blue">{input}</span>;
  };

  if (history.length === 0) {
    return (
      <div>
        <h2 className="text-3xl font-bold mb-8 text-center">
          <span className="bg-gradient-to-r from-cyber-blue to-cyber-purple bg-clip-text text-transparent">
            📈 Professional Scan History
          </span>
        </h2>
        <div className="text-center text-gray-400 py-16">
          <div className="text-6xl mb-6">🔍</div>
          <div className="text-xl mb-4">No threat analyses yet</div>
          <div className="text-gray-500">Start by analyzing IP addresses, domains, or URLs to build your threat intelligence history.</div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-8">
        <h2 className="text-3xl font-bold text-white">
          <span className="bg-gradient-to-r from-cyber-blue to-cyber-purple bg-clip-text text-transparent">
            📈 Professional Scan History
          </span>
        </h2>
        <div className="text-sm text-gray-400 bg-surface/50 px-4 py-2 rounded-full">
          {history.length} total analysis{history.length !== 1 ? 'es' : ''}
        </div>
      </div>
      
      <div className="bg-surface/20 rounded-xl border border-border/30 overflow-hidden backdrop-blur-sm shadow-2xl">
        <div className="overflow-x-auto">
          <table className="min-w-full">
            <thead className="bg-surface/50 border-b border-border/50">
              <tr>
                <th 
                  className="px-6 py-4 text-left text-xs font-medium text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-surface/30 transition-colors"
                  onClick={() => handleSort('input')}
                >
                  <div className="flex items-center space-x-2">
                    <span>Target Asset</span>
                    {sortField === 'input' && (
                      <span className="text-cyber-blue">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                    )}
                  </div>
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                  Type
                </th>
                <th 
                  className="px-6 py-4 text-left text-xs font-medium text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-surface/30 transition-colors"
                  onClick={() => handleSort('threat_score')}
                >
                  <div className="flex items-center space-x-2">
                    <span>Threat Level</span>
                    {sortField === 'threat_score' && (
                      <span className="text-cyber-blue">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                    )}
                  </div>
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                  Risk Score
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                  Location
                </th>
                <th 
                  className="px-6 py-4 text-left text-xs font-medium text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-surface/30 transition-colors"
                  onClick={() => handleSort('timestamp')}
                >
                  <div className="flex items-center space-x-2">
                    <span>Analysis Time</span>
                    {sortField === 'timestamp' && (
                      <span className="text-cyber-blue">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                    )}
                  </div>
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                  Status
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/30">
              {currentItems.map((item, index) => (
                <tr key={`${item.scan_id || item.input}-${index}`} className="hover:bg-surface/20 transition-colors">
                  <td className="px-6 py-4">
                    <div className="flex items-center space-x-3">
                      <span className="text-lg">{getTypeIcon(item.input_type)}</span>
                      <div>
                        {formatInput(item.input)}
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className="text-xs bg-surface/50 text-gray-300 px-3 py-1 rounded-full border border-border/50">
                      {item.input_type?.toUpperCase() || 'UNKNOWN'}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    {getThreatBadge(item.threat_score || 0)}
                  </td>
                  <td className="px-6 py-4">
                    <div className="text-lg font-bold text-white">{item.threat_score || 0}/100</div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="text-sm text-gray-300 flex items-center space-x-1">
                      <span>📍</span>
                      <span>{item.country || 'Unknown'}</span>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className="text-sm text-gray-300">
                      {item.timestamp ? new Date(item.timestamp * 1000).toLocaleDateString() : 'Unknown'}
                    </div>
                    <div className="text-xs text-gray-400">
                      {item.timestamp ? new Date(item.timestamp * 1000).toLocaleTimeString() : ''}
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <div className={`inline-block px-3 py-1 rounded-full text-xs font-medium ${
                      item.status === 'completed' ? 'bg-green-500/20 text-green-300 border border-green-500/50' :
                      item.status === 'error' ? 'bg-red-500/20 text-red-300 border border-red-500/50' :
                      'bg-yellow-500/20 text-yellow-300 border border-yellow-500/50'
                    }`}>
                      {item.status || 'completed'}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {totalPages > 1 && (
          <div className="bg-surface/30 px-6 py-4 border-t border-border/50">
            <div className="flex items-center justify-between">
              <div className="text-sm text-gray-400">
                Showing {indexOfFirstItem + 1} to {Math.min(indexOfLastItem, history.length)} of {history.length} results
              </div>
              <div className="flex space-x-2">
                <button
                  onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
                  disabled={currentPage === 1}
                  className="px-4 py-2 text-sm bg-surface/50 text-white rounded-lg disabled:opacity-50 hover:bg-surface/70 transition-colors border border-border/50"
                >
                  ← Previous
                </button>
                
                <div className="flex space-x-1">
                  {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                    let pageNum;
                    if (totalPages <= 5) {
                      pageNum = i + 1;
                    } else if (currentPage <= 3) {
                      pageNum = i + 1;
                    } else if (currentPage >= totalPages - 2) {
                      pageNum = totalPages - 4 + i;
                    } else {
                      pageNum = currentPage - 2 + i;
                    }
                    
                    return (
                      <button
                        key={pageNum}
                        onClick={() => setCurrentPage(pageNum)}
                        className={`px-4 py-2 text-sm rounded-lg transition-colors ${
                          currentPage === pageNum
                            ? 'bg-gradient-to-r from-cyber-blue to-cyber-purple text-white font-bold shadow-cyber'
                            : 'bg-surface/50 text-white hover:bg-surface/70 border border-border/50'
                        }`}
                      >
                        {pageNum}
                      </button>
                    );
                  })}
                </div>
                
                <button
                  onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
                  disabled={currentPage === totalPages}
                  className="px-4 py-2 text-sm bg-surface/50 text-white rounded-lg disabled:opacity-50 hover:bg-surface/70 transition-colors border border-border/50"
                >
                  Next →
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
