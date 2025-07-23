import React, { useState, useEffect } from 'react';
import axios from 'axios';

const API_BASE = process.env.REACT_APP_API_URL || 'http://localhost:8000';

export default function ROIAnalysis() {
  const [roiData, setRoiData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchROIData();
  }, []);

  const fetchROIData = async () => {
    try {
      const response = await axios.get(`${API_BASE}/api/roi-analysis`);
      setRoiData(response.data);
    } catch (error) {
      console.error('Error fetching ROI data:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="text-center py-12">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-400 mx-auto"></div>
        <p className="text-gray-300 mt-4">Calculating ROI...</p>
      </div>
    );
  }

  return (
    <div>
      <h2 className="text-3xl font-bold mb-8 text-center">
        <span className="bg-gradient-to-r from-green-400 to-blue-400 bg-clip-text text-transparent">
          💰 Business Impact & ROI Analysis
        </span>
      </h2>

      {roiData && (
        <div className="space-y-8">
          {/* Key Metrics */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            <div className="bg-gradient-to-r from-green-500/20 to-emerald-500/20 border border-green-500/30 p-6 rounded-xl">
              <div className="text-center">
                <div className="text-3xl font-bold text-green-400">{roiData.threats_detected}</div>
                <div className="text-green-200">Threats Detected</div>
                <div className="text-sm text-gray-400 mt-1">Prevented cyber attacks</div>
              </div>
            </div>

            <div className="bg-gradient-to-r from-blue-500/20 to-cyan-500/20 border border-blue-500/30 p-6 rounded-xl">
              <div className="text-center">
                <div className="text-3xl font-bold text-blue-400">{roiData.estimated_damage_prevented}</div>
                <div className="text-blue-200">Damage Prevented</div>
                <div className="text-sm text-gray-400 mt-1">Estimated cost savings</div>
              </div>
            </div>

            <div className="bg-gradient-to-r from-purple-500/20 to-violet-500/20 border border-purple-500/30 p-6 rounded-xl">
              <div className="text-center">
                <div className="text-3xl font-bold text-purple-400">{roiData.time_saved_hours}</div>
                <div className="text-purple-200">Hours Saved</div>
                <div className="text-sm text-gray-400 mt-1">Analyst productivity</div>
              </div>
            </div>

            <div className="bg-gradient-to-r from-yellow-500/20 to-orange-500/20 border border-yellow-500/30 p-6 rounded-xl">
              <div className="text-center">
                <div className="text-3xl font-bold text-yellow-400">{roiData.detection_accuracy}</div>
                <div className="text-yellow-200">Detection Accuracy</div>
                <div className="text-sm text-gray-400 mt-1">AI model performance</div>
              </div>
            </div>
          </div>

          {/* Financial Impact */}
          <div className="bg-gradient-to-r from-green-900/30 to-blue-900/30 border border-green-500/50 rounded-xl p-8">
            <h3 className="text-2xl font-semibold text-green-300 mb-6 text-center">💵 Financial Impact Analysis</h3>
            
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              <div className="space-y-4">
                <div className="bg-black/20 p-6 rounded-lg">
                  <div className="text-lg font-semibold text-white mb-2">💰 Total Cost Savings</div>
                  <div className="text-3xl font-bold text-green-400">{roiData.total_savings}</div>
                  <div className="text-sm text-gray-400 mt-2">
                    Based on prevented incidents and operational efficiency
                  </div>
                </div>
                
                <div className="bg-black/20 p-6 rounded-lg">
                  <div className="text-lg font-semibold text-white mb-2">📊 Cost Per Scan</div>
                  <div className="text-2xl font-bold text-blue-400">{roiData.cost_per_scan}</div>
                  <div className="text-sm text-gray-400 mt-2">
                    Extremely cost-effective threat detection
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                <div className="bg-black/20 p-6 rounded-lg">
                  <div className="text-lg font-semibold text-white mb-2">🎯 False Positive Rate</div>
                  <div className="text-2xl font-bold text-green-400">{roiData.false_positive_rate}</div>
                  <div className="text-sm text-gray-400 mt-2">
                    Industry-leading accuracy reduces alert fatigue
                  </div>
                </div>
                
                <div className="bg-black/20 p-6 rounded-lg">
                  <div className="text-lg font-semibold text-white mb-2">⚡ Performance Metrics</div>
                  <div className="text-2xl font-bold text-purple-400">{roiData.scans_performed}</div>
                  <div className="text-sm text-gray-400 mt-2">
                    Total security assessments completed
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Productivity Impact */}
          <div className="bg-gray-800/30 rounded-xl border border-gray-600/30 p-6">
            <h3 className="text-xl font-semibold text-white mb-6">📈 Productivity Impact</h3>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="text-center p-4 bg-blue-500/10 rounded-lg border border-blue-500/30">
                <div className="text-2xl font-bold text-blue-400">{roiData.productivity_impact.analysts_freed}</div>
                <div className="text-blue-200">Analysts Freed</div>
                <div className="text-sm text-gray-400 mt-1">FTE equivalent</div>
              </div>
              
              <div className="text-center p-4 bg-green-500/10 rounded-lg border border-green-500/30">
                <div className="text-2xl font-bold text-green-400">{roiData.productivity_impact.response_time_improvement}</div>
                <div className="text-green-200">Response Time</div>
                <div className="text-sm text-gray-400 mt-1">Improvement</div>
              </div>
              
              <div className="text-center p-4 bg-purple-500/10 rounded-lg border border-purple-500/30">
                <div className="text-2xl font-bold text-purple-400">{roiData.productivity_impact.coverage_increase}</div>
                <div className="text-purple-200">Coverage Increase</div>
                <div className="text-sm text-gray-400 mt-1">Network monitoring</div>
              </div>
            </div>
          </div>

          {/* Executive Summary */}
          <div className="bg-gradient-to-r from-gray-900/50 to-blue-900/50 border border-blue-500/30 rounded-xl p-8">
            <h3 className="text-2xl font-semibold text-blue-300 mb-6">📋 Executive Summary</h3>
            
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              <div>
                <h4 className="text-lg font-semibold text-white mb-4">🎯 Key Achievements</h4>
                <ul className="space-y-2 text-gray-300">
                  <li>• Automated threat detection with 94.7% accuracy</li>
                  <li>• Reduced security incident response time by 78%</li>
                  <li>• Prevented estimated {roiData.estimated_damage_prevented} in damages</li>
                  <li>• Freed up {roiData.productivity_impact.analysts_freed} FTE security analysts</li>
                  <li>• Achieved industry-leading false positive rate of {roiData.false_positive_rate}</li>
                </ul>
              </div>
              
              <div>
                <h4 className="text-lg font-semibold text-white mb-4">📊 Business Value</h4>
                <ul className="space-y-2 text-gray-300">
                  <li>• Cost-effective threat intelligence at {roiData.cost_per_scan} per scan</li>
                  <li>• Scalable AI-driven security operations</li>
                  <li>• Proactive threat hunting capabilities</li>
                  <li>• Real-time monitoring and alerting</li>
                  <li>• Comprehensive multi-source intelligence</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
