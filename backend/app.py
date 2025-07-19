import os
import time
import json
import re
from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import requests
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

# MongoDB connection
try:
    client = MongoClient(os.getenv("MONGO_URI"), serverSelectionTimeoutMS=5000)
    db = client.cti_database
    scans = db.scans
    client.admin.command('ping')
    print("✅ MongoDB connection successful!")
except Exception as e:
    print(f"❌ MongoDB connection failed: {e}")
    db = None
    scans = None

# API Keys
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_HEADERS = {"x-apikey": VT_API_KEY} if VT_API_KEY else {}

def vt_ip_report(ip):
    """Comprehensive VirusTotal IP report with all available data"""
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not configured", "status": "missing_key"}
    
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        response = requests.get(url, headers=VT_HEADERS, timeout=20)
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            
            # Enhanced data structure with all available information
            enhanced_data = {
                "raw_data": data,
                "basic_info": {
                    "ip_address": ip,
                    "country": attributes.get("country", "Unknown"),
                    "continent": attributes.get("continent", "Unknown"),
                    "network": attributes.get("network", "Unknown"),
                    "asn": attributes.get("asn", "Unknown"),
                    "as_owner": attributes.get("as_owner", "Unknown"),
                    "regional_internet_registry": attributes.get("regional_internet_registry", "Unknown")
                },
                "security_analysis": {
                    "last_analysis_date": attributes.get("last_analysis_date", 0),
                    "last_analysis_stats": attributes.get("last_analysis_stats", {}),
                    "reputation": attributes.get("reputation", 0),
                    "total_votes": attributes.get("total_votes", {}),
                    "harmless_votes": attributes.get("total_votes", {}).get("harmless", 0),
                    "malicious_votes": attributes.get("total_votes", {}).get("malicious", 0)
                },
                "detection_engines": {},
                "categories": list(attributes.get("categories", {}).values()) if attributes.get("categories") else [],
                "whois_info": {
                    "whois": attributes.get("whois", "Not available"),
                    "whois_date": attributes.get("whois_date", 0)
                },
                "additional_info": {
                    "jarm": attributes.get("jarm", "Not available"),
                    "tags": attributes.get("tags", [])
                }
            }
            
            # Get individual engine results
            if "last_analysis_results" in attributes:
                enhanced_data["detection_engines"] = attributes["last_analysis_results"]
            
            return enhanced_data
            
        elif response.status_code == 404:
            return {"error": "IP address not found in VirusTotal database", "status": "not_found"}
        elif response.status_code == 403:
            return {"error": "VirusTotal API quota exceeded", "status": "quota_exceeded"}
        else:
            return {"error": f"VirusTotal API error: {response.status_code}", "status": "api_error"}
            
    except requests.exceptions.Timeout:
        return {"error": "VirusTotal request timed out", "status": "timeout"}
    except Exception as e:
        return {"error": f"VirusTotal request failed: {str(e)}", "status": "request_failed"}

def vt_domain_report(domain):
    """Comprehensive VirusTotal Domain report"""
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not configured", "status": "missing_key"}
    
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        response = requests.get(url, headers=VT_HEADERS, timeout=20)
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            
            enhanced_data = {
                "raw_data": data,
                "basic_info": {
                    "domain": domain,
                    "creation_date": attributes.get("creation_date", 0),
                    "last_update_date": attributes.get("last_update_date", 0),
                    "registrar": attributes.get("registrar", "Unknown"),
                    "reputation": attributes.get("reputation", 0)
                },
                "security_analysis": {
                    "last_analysis_date": attributes.get("last_analysis_date", 0),
                    "last_analysis_stats": attributes.get("last_analysis_stats", {}),
                    "total_votes": attributes.get("total_votes", {}),
                    "harmless_votes": attributes.get("total_votes", {}).get("harmless", 0),
                    "malicious_votes": attributes.get("total_votes", {}).get("malicious", 0)
                },
                "detection_engines": {},
                "categories": list(attributes.get("categories", {}).values()) if attributes.get("categories") else [],
                "dns_records": {
                    "last_dns_records": attributes.get("last_dns_records", []),
                    "last_dns_records_date": attributes.get("last_dns_records_date", 0)
                },
                "whois_info": {
                    "whois": attributes.get("whois", "Not available"),
                    "whois_date": attributes.get("whois_date", 0)
                },
                "additional_info": {
                    "jarm": attributes.get("jarm", "Not available"),
                    "tags": attributes.get("tags", []),
                    "favicon": attributes.get("favicon", {})
                }
            }
            
            # Get individual engine results
            if "last_analysis_results" in attributes:
                enhanced_data["detection_engines"] = attributes["last_analysis_results"]
            
            return enhanced_data
            
        elif response.status_code == 404:
            return {"error": "Domain not found in VirusTotal database", "status": "not_found"}
        else:
            return {"error": f"VirusTotal API error: {response.status_code}", "status": "api_error"}
            
    except Exception as e:
        return {"error": f"VirusTotal request failed: {str(e)}", "status": "request_failed"}

def vt_url_report(target_url):
    """Comprehensive VirusTotal URL report"""
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not configured", "status": "missing_key"}
    
    try:
        # Submit URL for analysis
        submit_url = "https://www.virustotal.com/api/v3/urls"
        response = requests.post(submit_url, headers=VT_HEADERS, data={"url": target_url}, timeout=20)
        
        if response.status_code == 200:
            analysis_id = response.json().get("data", {}).get("id")
            if not analysis_id:
                return {"error": "Failed to submit URL for analysis", "status": "submission_failed"}
            
            # Wait for analysis to complete
            time.sleep(5)
            result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            
            max_attempts = 3
            for attempt in range(max_attempts):
                result_response = requests.get(result_url, headers=VT_HEADERS, timeout=20)
                
                if result_response.status_code == 200:
                    data = result_response.json().get("data", {})
                    attributes = data.get("attributes", {})
                    
                    if attributes.get("status") == "completed":
                        enhanced_data = {
                            "raw_data": data,
                            "basic_info": {
                                "url": target_url,
                                "analysis_date": attributes.get("date", 0),
                                "status": attributes.get("status", "unknown")
                            },
                            "security_analysis": {
                                "stats": attributes.get("stats", {}),
                                "results": attributes.get("results", {}),
                                "scans": len(attributes.get("results", {}))
                            },
                            "detection_engines": attributes.get("results", {}),
                            "additional_info": {
                                "analysis_id": analysis_id
                            }
                        }
                        return enhanced_data
                    elif attempt == max_attempts - 1:
                        return {"error": "URL analysis timed out", "status": "timeout"}
                else:
                    break
                    
                time.sleep(2)
        
        return {"error": f"URL analysis failed: {response.status_code}", "status": "analysis_failed"}
        
    except Exception as e:
        return {"error": f"URL scan failed: {str(e)}", "status": "scan_failed"}

def abuseipdb_report(ip):
    """Comprehensive AbuseIPDB report with all available data"""
    if not ABUSEIPDB_API_KEY:
        return {"error": "AbuseIPDB API key not configured", "status": "missing_key"}
    
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90,
            'verbose': True
        }
        headers = {
            'Key': ABUSEIPDB_API_KEY,
            'Accept': 'application/json'
        }
        
        response = requests.get(url, headers=headers, params=params, timeout=20)
        
        if response.status_code == 200:
            data = response.json().get("data", {})
            
            enhanced_data = {
                "raw_data": data,
                "basic_info": {
                    "ip_address": ip,
                    "is_public": data.get("isPublic", False),
                    "ip_version": data.get("ipVersion", 4),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "country_code": data.get("countryCode", "Unknown"),
                    "country_name": data.get("countryName", "Unknown"),
                    "usage_type": data.get("usageType", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "domain": data.get("domain", "Unknown")
                },
                "abuse_analysis": {
                    "abuse_confidence_percentage": data.get("abuseConfidencePercentage", 0),
                    "total_reports": data.get("totalReports", 0),
                    "num_distinct_users": data.get("numDistinctUsers", 0),
                    "last_reported_at": data.get("lastReportedAt", "Never")
                },
                "recent_reports": data.get("reports", []),
                "categories": data.get("categories", [])
            }
            
            return enhanced_data
            
        elif response.status_code == 422:
            return {"error": "Invalid IP address format", "status": "invalid_input"}
        elif response.status_code == 403:
            return {"error": "AbuseIPDB API quota exceeded", "status": "quota_exceeded"}
        else:
            return {"error": f"AbuseIPDB API error: {response.status_code}", "status": "api_error"}
            
    except Exception as e:
        return {"error": f"AbuseIPDB request failed: {str(e)}", "status": "request_failed"}

def detect_input_type(input_str):
    """Detect input type with better validation"""
    input_str = input_str.lower().strip()
    
    # IP address pattern
    ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    if re.match(ip_pattern, input_str):
        return "ip"
    
    # URL patterns
    if any(input_str.startswith(prefix) for prefix in ['http://', 'https://', 'www.']):
        return "url"
    
    # Domain pattern
    domain_pattern = r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,}$'
    if re.match(domain_pattern, input_str):
        return "domain"
    
    return "domain"

def calculate_comprehensive_threat_score(vt_data, abuse_data, input_type):
    """Calculate detailed threat score with breakdown"""
    try:
        score_breakdown = {
            "virustotal_score": 0,
            "abuseipdb_score": 0,
            "final_score": 0,
            "total_engines": 0,
            "malicious_detections": 0,
            "suspicious_detections": 0,
            "clean_detections": 0
        }
        
        # VirusTotal scoring
        if vt_data and not vt_data.get("error"):
            if "security_analysis" in vt_data:
                stats = vt_data["security_analysis"].get("last_analysis_stats", {})
            elif "stats" in vt_data.get("security_analysis", {}):
                stats = vt_data["security_analysis"]["stats"]
            else:
                stats = {}
            
            if stats:
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                
                total = malicious + suspicious + harmless + undetected
                score_breakdown["total_engines"] = total
                score_breakdown["malicious_detections"] = malicious
                score_breakdown["suspicious_detections"] = suspicious
                score_breakdown["clean_detections"] = harmless
                
                if total > 0:
                    vt_score = (malicious * 100 + suspicious * 60) / total
                    score_breakdown["virustotal_score"] = vt_score
        
        # AbuseIPDB scoring
        if input_type == "ip" and abuse_data and not abuse_data.get("error"):
            if "abuse_analysis" in abuse_data:
                confidence = abuse_data["abuse_analysis"].get("abuse_confidence_percentage", 0)
                score_breakdown["abuseipdb_score"] = confidence
        
        # Calculate final score
        final_score = max(score_breakdown["virustotal_score"], score_breakdown["abuseipdb_score"])
        score_breakdown["final_score"] = min(int(final_score), 100)
        
        return score_breakdown
        
    except Exception as e:
        return {
            "virustotal_score": 0,
            "abuseipdb_score": 0,
            "final_score": 0,
            "total_engines": 0,
            "malicious_detections": 0,
            "suspicious_detections": 0,
            "clean_detections": 0,
            "error": str(e)
        }

@app.route("/")
def home():
    return {
        "message": "CTI Dashboard API - Comprehensive Analysis Ready",
        "status": "success",
        "version": "3.0",
        "features": ["VirusTotal Full Analysis", "AbuseIPDB Detailed Reports", "Comprehensive Threat Scoring"],
        "timestamp": time.time()
    }

@app.route("/api/lookup", methods=["POST"])
def comprehensive_lookup():
    """Comprehensive lookup with detailed analysis data"""
    try:
        data = request.get_json()
        if not data or 'input' not in data:
            return jsonify({"error": "Input parameter is required"}), 400
        
        user_input = data.get("input", "").strip()
        if not user_input or len(user_input) > 200:
            return jsonify({"error": "Invalid input length"}), 400
        
        input_type = detect_input_type(user_input)
        
        print(f"🔍 Performing comprehensive scan - {input_type.upper()}: {user_input}")
        
        # Fetch comprehensive data
        vt_data = {"error": "Not applicable for this input type", "status": "skipped"}
        abuse_data = {"error": "Not applicable for this input type", "status": "skipped"}
        
        if input_type == "ip":
            print("📡 Fetching VirusTotal IP analysis...")
            vt_data = vt_ip_report(user_input)
            print("🛡️ Fetching AbuseIPDB analysis...")
            abuse_data = abuseipdb_report(user_input)
        elif input_type == "domain":
            print("📡 Fetching VirusTotal domain analysis...")
            vt_data = vt_domain_report(user_input)
        elif input_type == "url":
            print("📡 Fetching VirusTotal URL analysis...")
            vt_data = vt_url_report(user_input)
        
        # Calculate comprehensive threat score
        threat_analysis = calculate_comprehensive_threat_score(vt_data, abuse_data, input_type)
        
        # Create comprehensive record
        record = {
            "input": user_input,
            "input_type": input_type,
            "timestamp": time.time(),
            "scan_id": f"comprehensive_scan_{int(time.time())}_{abs(hash(user_input)) % 10000}",
            "analysis_results": {
                "virustotal": vt_data,
                "abuseipdb": abuse_data
            },
            "threat_assessment": {
                "overall_score": threat_analysis["final_score"],
                "threat_level": "HIGH" if threat_analysis["final_score"] >= 70 else "MEDIUM" if threat_analysis["final_score"] >= 30 else "LOW",
                "score_breakdown": threat_analysis,
                "engines_total": threat_analysis["total_engines"],
                "malicious_count": threat_analysis["malicious_detections"],
                "clean_count": threat_analysis["clean_detections"]
            },
            "scan_metadata": {
                "scan_type": "comprehensive_analysis",
                "apis_used": ["VirusTotal"] if input_type != "ip" else ["VirusTotal", "AbuseIPDB"],
                "scan_duration": "15-30 seconds",
                "data_sources": get_comprehensive_sources(vt_data, abuse_data, input_type)
            },
            "status": "completed"
        }
        
        # Store in MongoDB
        if scans is not None:
            try:
                # Store with limited data for performance
                storage_record = {
                    "input": record["input"],
                    "input_type": record["input_type"],
                    "timestamp": record["timestamp"],
                    "scan_id": record["scan_id"],
                    "threat_score": record["threat_assessment"]["overall_score"],
                    "threat_level": record["threat_assessment"]["threat_level"],
                    "status": record["status"]
                }
                scans.insert_one(storage_record)
                print(f"✅ Scan stored: {record['scan_id']}")
            except Exception as e:
                print(f"⚠️ MongoDB storage failed: {e}")
        
        # Clean for response
        record.pop('_id', None)
        return jsonify(record)
        
    except Exception as e:
        print(f"❌ Comprehensive lookup failed: {e}")
        return jsonify({"error": f"Comprehensive analysis failed: {str(e)}"}), 500

def get_comprehensive_sources(vt_data, abuse_data, input_type):
    """Get detailed list of data sources"""
    sources = []
    
    if vt_data and not vt_data.get("error"):
        if "detection_engines" in vt_data:
            engine_count = len(vt_data["detection_engines"])
            sources.append(f"VirusTotal ({engine_count} security engines)")
        else:
            sources.append("VirusTotal Security Analysis")
    
    if abuse_data and not abuse_data.get("error") and input_type == "ip":
        if "recent_reports" in abuse_data:
            report_count = len(abuse_data["recent_reports"])
            sources.append(f"AbuseIPDB ({report_count} recent reports)")
        else:
            sources.append("AbuseIPDB Community Intelligence")
    
    return sources if sources else ["No comprehensive data sources available"]

# Keep existing endpoints for compatibility
@app.route("/api/history", methods=["GET"])
def get_history():
    try:
        if scans is None:
            return jsonify({"error": "Database not available"}), 503
        
        limit = min(request.args.get('limit', 50, type=int), 100)
        docs = list(scans.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit))
        
        return jsonify({
            "scans": docs,
            "total": len(docs),
            "status": "success"
        })
    except Exception as e:
        return jsonify({
            "error": f"History fetch failed: {str(e)}",
            "scans": [],
            "total": 0
        }), 500

@app.route("/api/stats", methods=["GET"])
def get_stats():
    try:
        if scans is None:
            return jsonify({"error": "Database not available"}), 503
        
        total_scans = scans.count_documents({})
        recent_scans = scans.count_documents({"timestamp": {"$gt": time.time() - 86400}})
        high_threat = scans.count_documents({"threat_score": {"$gte": 70}})
        medium_threat = scans.count_documents({"threat_score": {"$gte": 30, "$lt": 70}})
        low_threat = scans.count_documents({"threat_score": {"$lt": 30}})
        
        return jsonify({
            "total_scans": total_scans,
            "recent_scans": recent_scans,
            "threat_distribution": {
                "high": high_threat,
                "medium": medium_threat,
                "low": low_threat
            },
            "status": "success"
        })
    except Exception as e:
        return jsonify({
            "error": f"Stats failed: {str(e)}",
            "total_scans": 0,
            "recent_scans": 0,
            "threat_distribution": {"high": 0, "medium": 0, "low": 0}
        }), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"🚀 Comprehensive CTI Dashboard starting on port {port}")
    print(f"📊 Features: Full VirusTotal + AbuseIPDB Analysis")
    app.run(host="0.0.0.0", port=port, debug=False)
