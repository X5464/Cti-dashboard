import React, { useState } from 'react';

function HistoryTable({ history }) {
  const [currentPage, setCurrentPage] = useState(1);
  const [sortField, setSortField] = useState('timestamp');
  const [sortDirection, setSortDirection] = useState('desc');
  const itemsPerPage = 10;
  
  // Sort history
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
    if (score >= 80) return <span className="px-2 py-1 text-xs font-semibold bg-red-100 text-red-800 rounded-full">🚨 HIGH</span>;
    if (score >= 50) return <span className="px-2 py-1 text-xs font-semibold bg-yellow-100 text-yellow-800 rounded-full">⚠️ MEDIUM</span>;
    return <span className="px-2 py-1 text-xs font-semibold bg-green-100 text-green-800 rounded-full">✅ LOW</span>;
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
    if (input.length > 30) {
      return input.substring(0, 30) + '...';
    }
    return input;
  };

  if (history.length === 0) {
    return (
      <div>
        <h2 className="text-2xl font-bold mb-6">Scan History</h2>
        <div className="text-center text-gray-400 py-12">
          <div className="text-4xl mb-4">📊</div>
          <div className="text-lg mb-2">No scans yet</div>
          <div className="text-sm">Start by analyzing an IP address, domain, or URL above.</div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold">Scan History</h2>
        <div className="text-sm text-gray-400">
          {history.length} total scan{history.length !== 1 ? 's' : ''}
        </div>
      </div>
      
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-600">
          <thead className="bg-gray-700">
            <tr>
              <th 
                className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-600"
                onClick={() => handleSort('input')}
              >
                <div className="flex items-center space-x-1">
                  <span>Target</span>
                  {sortField === 'input' && (
                    <span>{sortDirection === 'asc' ? '↑' : '↓'}</span>
                  )}
                </div>
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                Type
              </th>
              <th 
                className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-600"
                onClick={() => handleSort('threat_score')}
              >
                <div className="flex items-center space-x-1">
                  <span>Threat Level</span>
                  {sortField === 'threat_score' && (
                    <span>{sortDirection === 'asc' ? '↑' : '↓'}</span>
                  )}
                </div>
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                Score
              </th>
              <th 
                className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-600"
                onClick={() => handleSort('timestamp')}
              >
                <div className="flex items-center space-x-1">
                  <span>Scan Time</span>
                  {sortField === 'timestamp' && (
                    <span>{sortDirection === 'asc' ? '↑' : '↓'}</span>
                  )}
                </div>
              </th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-300 uppercase tracking-wider">
                Details
              </th>
            </tr>
          </thead>
          <tbody className="bg-gray-800 divide-y divide-gray-600">
            {currentItems.map((item, index) => (
              <tr key={`${item.input}-${item.timestamp}-${index}`} className="hover:bg-gray-700 transition-colors">
                <td className="px-6 py-4">
                  <div className="flex items-center space-x-2">
                    <span>{getTypeIcon(item.type)}</span>
                    <div className="text-sm font-mono text-cyber-blue" title={item.input}>
                      {formatInput(item.input, item.type)}
                    </div>
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className="text-xs bg-gray-600 text-gray-300 px-2 py-1 rounded">
                    {item.type?.toUpperCase() || 'UNKNOWN'}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  {getThreatBadge(item.threat_score || 0)}
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="text-sm font-semibold">{item.threat_score || 0}/100</div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="text-sm text-gray-300">
                    {item.timestamp ? new Date(item.timestamp * 1000).toLocaleDateString() : 'Unknown'}
                  </div>
                  <div className="text-xs text-gray-400">
                    {item.timestamp ? new Date(item.timestamp * 1000).toLocaleTimeString() : ''}
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="text-xs space-y-1">
                    {item.abuseipdb && !item.abuseipdb.error && item.type === 'ip' && (
                      <div className="text-gray-300">
                        📍 {item.abuseipdb.countryCode || 'Unknown'}
                      </div>
                    )}
                    <div className={`px-2 py-1 rounded text-xs ${
                      item.status === 'completed' ? 'bg-green-900 text-green-300' :
                      item.status === 'error' ? 'bg-red-900 text-red-300' :
                      'bg-yellow-900 text-yellow-300'
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
        <div className="flex items-center justify-between mt-6">
          <div className="text-sm text-gray-400">
            Showing {indexOfFirstItem + 1} to {Math.min(indexOfLastItem, history.length)} of {history.length} results
          </div>
          <div className="flex space-x-2">
            <button
              onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
              disabled={currentPage === 1}
              className="px-3 py-2 text-sm bg-gray-700 text-white rounded disabled:opacity-50 hover:bg-gray-600 transition-colors"
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
                    className={`px-3 py-2 text-sm rounded transition-colors ${
                      currentPage === pageNum
                        ? 'bg-cyber-blue text-dark-bg font-semibold'
                        : 'bg-gray-700 text-white hover:bg-gray-600'
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
              className="px-3 py-2 text-sm bg-gray-700 text-white rounded disabled:opacity-50 hover:bg-gray-600 transition-colors"
            >
              Next →
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default HistoryTable;
