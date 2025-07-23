import React from 'react';

export default function HistoryTable({ history }) {
  return (
    <table className="min-w-full bg-gray-800 rounded">
      <thead>
        <tr>
          <th className="p-2">Input</th>
          <th className="p-2">Type</th>
          <th className="p-2">Score</th>
          <th className="p-2">Time</th>
        </tr>
      </thead>
      <tbody>
        {history.map((h,i)=>(
          <tr key={i} className="border-t border-gray-700">
            <td className="p-2">{h.input}</td>
            <td className="p-2">{h.input_type}</td>
            <td className="p-2">{h.threat_score}</td>
            <td className="p-2">{new Date(h.timestamp*1000).toLocaleString()}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
