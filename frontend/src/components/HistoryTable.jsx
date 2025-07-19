import React, { useState } from 'react';

function HistoryTable({ history }) {
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

  const getThreatBadge = (score, level) => {
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

  const formatInput = (input, type) => {
    if (!input) return 'Unknown';
    
    // Show full input with proper formatting
    if (input.length > 40) {
      return (
        <div className="group relative">
          <div className="font-mono text-sm text-cyan-300 cursor-help">
            {input.substring(0, 40)}...
          </div>
          <div className="absolute z-50 invisible group-hover:visible bg-gray-900 text-white p-3 rounded-lg shadow-xl border border-gray-600 max-w-sm break-all text-xs top-full mt-2 left-0">
            <div className="font-semibold mb-1 text-cyan-400">Full Address:</div>
            <div className="break-all">{input}</div>
          </div>
        </div>
      );
    }
    
    return <span className="font-mono text-sm text-cyan-300">{input}</span>;
  };

  if (history.length === 0) {
    return (
      <div>
        <h2 className="text-2xl font-bold mb-6 text-white">📈 Scan History</h2>
        <div className="text-center text-gray-400 py-16">
          <div className="text-6xl mb-6">🔍</div>
          <div className="text-xl mb-4">No scans yet</div>
          <div className="text-gray-500">Start by scanning an IP address, domain, or URL above to see your history here.</div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold text-white">📈 Scan History</h2>
        <div className="text-sm text-gray-400 bg-gray-800/50 px-4 py-2 rounded-full">
          {history.length} total scan{history.length !== 1 ? 's' : ''}
        </div>
      </div>
      
      <div className="bg-gray-800/20 rounded-xl border border-gray-700/50 overflow-hidden backdrop-blur-sm">
        <div className="overflow-x-auto">
          <table className="min-w-full">
            <thead className="bg-gray-800/50 border-b border-gray-700/50">
              <tr>
                <th 
                  className="px-6 py-4 text-left text-xs font-medium text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-700/30 transition-colors"
                  onClick={() => handleSort('input')}
                >
                  <div className="flex items-center space-x-2">
                    <span>Target</span>
                    {sortField === 'input' && (
                      <span className="text-cyan-400">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                    )}
                  </div>
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                  Type
                </th>
                <th 
                  className="px-6 py-4 text-left text-xs font-medium text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-700/30 transition-colors"
                  onClick={() => handleSort('threat_score')}
                >
                  <div className="flex items-center space-x-2">
                    <span>Threat Level</span>
                    {sortField === 'threat_score' && (
                      <span className="text-cyan-400">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                    )}
                  </div>
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                  Score
                </th>
                <th 
                  className="px-6 py-4 text-left text-xs font-medium text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-700/30 transition-colors"
                  onClick={() => handleSort('timestamp')}
                >
                  <div className="flex items-center space-x-2">
                    <span>Scan Time</span>
                    {sortField === 'timestamp' && (
                      <span className="text-cyan-400">{sortDirection === 'asc' ? '↑' : '↓'}</span>
                    )}
                  </div>
                </th>
                <th className="px-6 py-4 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                  Details
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700/50">
              {currentItems.map((item, index) => (
                <tr key={`${item.scan_id || item.input}-${index}`} className="hover:bg-gray-700/20 transition-colors">
                  <td className="px-6 py-4">
                    <div className="flex items-center space-x-3">
                      <span className="text-lg">{getTypeIcon(item.input_type)}</span>
                      <div>
                        {formatInput(item.input, item.input_type)}
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-4">
                    <span className="text-xs bg-gray-700/50 text-gray-300 px-3 py-1 rounded-full border border-gray-600/50">
                      {item.input_type?.toUpperCase() || 'UNKNOWN'}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    {getThreatBadge(item.threat_score || 0, item.threat_level)}
                  </td>
                  <td className="px-6 py-4">
                    <div className="text-sm font-bold text-white">{item.threat_score || 0}/100</div>
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
                    <div className="space-y-1 text-xs">
                      {item.abuseipdb && !item.abuseipdb.error && item.input_type === 'ip' && (
                        <div className="text-gray-300 flex items-center space-x-1">
                          <span>📍</span>
                          <span>{item.abuseipdb.countryCode || 'Unknown'}</span>
                        </div>
                      )}
                      <div className={`inline-block px-2 py-1 rounded text-xs font-medium ${
                        item.status === 'completed' ? 'bg-green-500/20 text-green-300 border border-green-500/50' :
                        item.status === 'error' ? 'bg-red-500/20 text-red-300 border border-red-500/50' :
                        'bg-yellow-500/20 text-yellow-300 border border-yellow-500/50'
                      }`}>
                        {item.status || 'unknown'}
                      </div>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {totalPages > 1 && (
          <div className="bg-gray-800/30 px-6 py-4 border-t border-gray-700/50">
            <div className="flex items-center justify-between">
              <div className="text-sm text-gray-400">
                Showing {indexOfFirstItem + 1} to {Math.min(indexOfLastItem, history.length)} of {history.length} results
              </div>
              <div className="flex space-x-2">
                <button
                  onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
                  disabled={currentPage === 1}
                  className="px-4 py-2 text-sm bg-gray-700/50 text-white rounded-lg disabled:opacity-50 hover:bg-gray-600/50 transition-colors border border-gray-600/50"
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
                            ? 'bg-gradient-to-r from-cyan-500 to-purple-500 text-white font-bold shadow-lg'
                            : 'bg-gray-700/50 text-white hover:bg-gray-600/50 border border-gray-600/50'
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
                  className="px-4 py-2 text-sm bg-gray-700/50 text-white rounded-lg disabled:opacity-50 hover:bg-gray-600/50 transition-colors border border-gray-600/50"
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

export default HistoryTable;
