const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('path');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// API Keys (from environment variables for security)
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY || ;
const ABUSEIPDB_API_KEY = process.env.ABUSEIPDB_API_KEY || ;

// ============================================
// THREAT INTELLIGENCE APIs
// ============================================

/**
 * Analyze URL using VirusTotal
 * Detects malware, phishing, suspicious domains
 */
async function analyzeUrlWithVirusTotal(url) {
  try {
    const response = await axios.post(
      'https://www.virustotal.com/api/v3/urls',
      new URLSearchParams({
        url: url
      }),
      {
        headers: {
          'x-apikey': VIRUSTOTAL_API_KEY
        }
      }
    );

    const analysisId = response.data.data.id;
    
    // Get analysis results
    const analysisResponse = await axios.get(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        headers: {
          'x-apikey': VIRUSTOTAL_API_KEY
        }
      }
    );

    const stats = analysisResponse.data.data.attributes.stats;
    const maliciousCount = stats.malicious || 0;
    const suspiciousCount = stats.suspicious || 0;
    const totalVendors = stats.malicious + stats.suspicious + stats.undetected + stats.harmless;

    return {
      url: url,
      malicious: maliciousCount,
      suspicious: suspiciousCount,
      safe: stats.harmless,
      totalVendors: totalVendors,
      threatLevel: maliciousCount > 0 ? 'CRITICAL' : suspiciousCount > 0 ? 'HIGH' : 'SAFE',
      riskScore: Math.round((maliciousCount / totalVendors) * 100),
      details: analysisResponse.data.data.attributes.results
    };
  } catch (error) {
    console.error('VirusTotal Error:', error.message);
    return {
      url: url,
      error: 'Unable to analyze URL',
      fallbackScore: 30 // Default suspicion for URLs that can't be verified
    };
  }
}

/**
 * Analyze IP Address using AbuseIPDB
 * Detects malicious IPs, botnet activity, spam sources
 */
async function analyzeIpWithAbuseIPDB(ipAddress) {
  try {
    const response = await axios.get(
      'https://api.abuseipdb.com/api/v2/check',
      {
        params: {
          ipAddress: ipAddress,
          maxAgeInDays: 90
        },
        headers: {
          'Key': ABUSEIPDB_API_KEY,
          'Accept': 'application/json'
        }
      }
    );

    const data = response.data.data;
    
    return {
      ip: ipAddress,
      abuseConfidenceScore: data.abuseConfidenceScore,
      totalReports: data.totalReports,
      lastReportedAt: data.lastReportedAt,
      threatLevel: data.abuseConfidenceScore > 75 ? 'CRITICAL' : 
                   data.abuseConfidenceScore > 50 ? 'HIGH' : 
                   data.abuseConfidenceScore > 25 ? 'MEDIUM' : 'LOW',
      countryCode: data.countryCode,
      usageType: data.usageType,
      isp: data.isp,
      domain: data.domain,
      isVpn: data.isVpn,
      isProxy: data.isProxy,
      isTor: data.isTor,
      isDatacenter: data.isDatacenter
    };
  } catch (error) {
    console.error('AbuseIPDB Error:', error.message);
    return {
      ip: ipAddress,
      error: 'Unable to analyze IP',
      fallbackScore: 20
    };
  }
}

/**
 * Extract URLs and IPs from message text
 */
function extractThreats(text) {
  const urlRegex = /https?:\/\/[^\s]+|bit\.ly\/[^\s]+|tinyurl\.com\/[^\s]+|goo\.gl\/[^\s]+/gi;
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g;
  
  const urls = [...new Set(text.match(urlRegex) || [])];
  const ips = [...new Set(text.match(ipRegex) || [])];
  
  return { urls, ips };
}

// ============================================
// API ENDPOINTS
// ============================================

/**
 * POST /api/analyze
 * Comprehensive scam analysis with threat intelligence
 */
app.post('/api/analyze', async (req, res) => {
  try {
    const { message } = req.body;

    if (!message || message.trim().length === 0) {
      return res.status(400).json({ error: 'Message is required' });
    }

    const threats = extractThreats(message);
    const threatAnalysis = {
      urlThreats: [],
      ipThreats: []
    };

    // Analyze URLs
    if (threats.urls.length > 0) {
      for (const url of threats.urls) {
        const urlAnalysis = await analyzeUrlWithVirusTotal(url);
        threatAnalysis.urlThreats.push(urlAnalysis);
      }
    }

    // Analyze IPs
    if (threats.ips.length > 0) {
      for (const ip of threats.ips) {
        const ipAnalysis = await analyzeIpWithAbuseIPDB(ip);
        threatAnalysis.ipThreats.push(ipAnalysis);
      }
    }

    // Calculate overall threat score boost from external APIs
    let apiThreatBoost = 0;
    
    threatAnalysis.urlThreats.forEach(url => {
      if (url.threatLevel === 'CRITICAL') apiThreatBoost += 40;
      else if (url.threatLevel === 'HIGH') apiThreatBoost += 25;
      else if (url.threatLevel === 'MEDIUM') apiThreatBoost += 15;
    });

    threatAnalysis.ipThreats.forEach(ip => {
      if (ip.abuseConfidenceScore > 75) apiThreatBoost += 35;
      else if (ip.abuseConfidenceScore > 50) apiThreatBoost += 20;
      else if (ip.abuseConfidenceScore > 25) apiThreatBoost += 10;
    });

    res.json({
      message: message,
      threatAnalysis: threatAnalysis,
      apiThreatBoost: Math.min(apiThreatBoost, 100), // Cap at 100
      hasThreats: threats.urls.length > 0 || threats.ips.length > 0,
      extractedThreats: threats
    });

  } catch (error) {
    console.error('Analysis Error:', error);
    res.status(500).json({ 
      error: 'Analysis failed',
      message: error.message 
    });
  }
});

/**
 * POST /api/analyze-url
 * Single URL analysis
 */
app.post('/api/analyze-url', async (req, res) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    const analysis = await analyzeUrlWithVirusTotal(url);
    res.json(analysis);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /api/analyze-ip
 * Single IP analysis
 */
app.post('/api/analyze-ip', async (req, res) => {
  try {
    const { ip } = req.body;

    if (!ip) {
      return res.status(400).json({ error: 'IP address is required' });
    }

    const analysis = await analyzeIpWithAbuseIPDB(ip);
    res.json(analysis);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /api/threat-stats
 * Get overall threat statistics
 */
app.get('/api/threat-stats', async (req, res) => {
  try {
    res.json({
      status: 'operational',
      apisConnected: {
        virustotal: !!VIRUSTOTAL_API_KEY,
        abuseipdb: !!ABUSEIPDB_API_KEY
      },
      features: [
        'URL malware detection',
        'IP reputation analysis',
        'Domain threat analysis',
        'VPN/Proxy detection',
        'Tor exit node detection',
        'Botnet activity detection'
      ]
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * Health check endpoint
 */
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

// Serve static HTML
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Internal server error',
    message: err.message 
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🛡️  SafeChat Sentinel server running on port ${PORT}`);
  console.log(`✅ VirusTotal API: ${VIRUSTOTAL_API_KEY ? 'Connected' : 'Not configured'}`);
  console.log(`✅ AbuseIPDB API: ${ABUSEIPDB_API_KEY ? 'Connected' : 'Not configured'}`);
});

module.exports = app;
