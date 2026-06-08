import os
import json
import time
import queue
import threading
import datetime
from flask import Flask, jsonify, request, Response
from flask_cors import CORS

import database
from classifier import SOCClassifier
from generator import generate_wazuh_log
import llm_advisor

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")

# Default configurations
DEFAULT_CONFIG = {
    "attack_threshold": 0.15,
    "simulation_active": False,
    "simulation_speed": 1.5,
    "groq_api_key": ""
}

config = DEFAULT_CONFIG.copy()
config_lock = threading.Lock()
classifier = None

# SSE Announcers list
announcers = []
announcers_lock = threading.Lock()

def load_config():
    global config
    with config_lock:
        if os.path.exists(CONFIG_PATH):
            try:
                with open(CONFIG_PATH, "r") as f:
                    loaded = json.load(f)
                    config.update(loaded)
            except Exception as e:
                print(f"Error loading config: {e}")
        else:
            save_config_under_lock()

def save_config_under_lock():
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        print(f"Error saving config: {e}")

def update_config(new_config):
    global config
    with config_lock:
        config.update(new_config)
        save_config_under_lock()
        # Update the classifier threshold
        if classifier and "attack_threshold" in new_config:
            classifier.attack_threshold = new_config["attack_threshold"]

# SSE message broadcasting
def announce(data):
    msg_str = json.dumps(data)
    with announcers_lock:
        for q in announcers:
            q.put(msg_str)

def format_sse(data: str, event=None) -> str:
    msg = f"data: {data}\n\n"
    if event is not None:
        msg = f"event: {event}\n{msg}"
    return msg

# Background Simulation Thread
class SimulationWorker(threading.Thread):
    def __init__(self):
        super().__init__()
        self.daemon = True
        self.running = True

    def run(self):
        print("  [OK] Background simulation worker thread started.")
        while self.running:
            # Read speed and active status from config safely
            with config_lock:
                active = config["simulation_active"]
                speed = config["simulation_speed"]
                threshold = config["attack_threshold"]

            if active:
                try:
                    # Generate a new Wazuh log based on dataset distributions
                    log = generate_wazuh_log()
                    
                    # Run XGBoost classification
                    result = classifier.predict(log, custom_threshold=threshold)
                    
                    # Merge classification results into the log structure
                    log.update(result)
                    log["llm_analyzed"] = 0
                    
                    # Save to sqlite DB
                    log_id = database.save_log(log)
                    log["id"] = log_id
                    
                    # Broadcast to SSE clients
                    announce({
                        "event": "new_log",
                        "data": log
                    })
                except Exception as e:
                    print(f"Error in simulator loop: {e}")
            
            time.sleep(speed)

@app.route("/api/stream")
def sse_stream():
    def event_stream():
        q = queue.Queue()
        with announcers_lock:
            announcers.append(q)
        
        # Send initial ping/connection event
        yield format_sse(json.dumps({"event": "connected", "message": "SSE Stream Active"}), event="connected")
        
        try:
            while True:
                # Blocks until a new message is received in this connection's queue
                data = q.get()
                yield format_sse(data, event="message")
        except GeneratorExit:
            with announcers_lock:
                announcers.remove(q)
            print("  - SSE client disconnected.")
            
    return Response(event_stream(), mimetype="text/event-stream")

@app.route("/api/stats", methods=["GET"])
def get_stats():
    try:
        stats = database.get_stats()
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/logs", methods=["GET"])
@app.route("/api/alerts", methods=["GET"])
def get_logs():
    limit = request.args.get("limit", default=50, type=int)
    offset = request.args.get("offset", default=0, type=int)
    prediction = request.args.get("prediction", default=None, type=str)
    min_risk = request.args.get("min_risk", default=0, type=int)
    search_query = request.args.get("search", default=None, type=str)
    
    try:
        logs, total = database.get_logs(
            limit=limit, offset=offset, prediction=prediction,
            min_risk=min_risk, search_query=search_query
        )
        return jsonify({
            "logs": logs,
            "total": total,
            "limit": limit,
            "offset": offset
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/analyze", methods=["POST"])
@app.route("/api/alerts", methods=["POST"])
def analyze_log():
    payload = request.get_json()
    if not payload:
        return jsonify({"error": "Missing raw log payload"}), 400
        
    try:
        with config_lock:
            threshold = config["attack_threshold"]
            
        # Run classification
        analysis = classifier.predict(payload, custom_threshold=threshold)
        
        # Merge results
        analyzed_log = payload.copy()
        analyzed_log.update(analysis)
        analyzed_log["llm_analyzed"] = 0
        if "timestamp" not in analyzed_log:
            analyzed_log["timestamp"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
        log_id = database.save_log(analyzed_log)
        analyzed_log["id"] = log_id
        
        # Broadcast to SSE clients
        announce({
            "event": "new_log",
            "data": analyzed_log
        })
        
        return jsonify(analyzed_log), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/analyze-llm/<int:log_id>", methods=["POST"])
def analyze_llm(log_id):
    try:
        # Find log in database
        logs, _ = database.get_logs(limit=1, offset=0)
        conn = database.get_db_connection()
        row = conn.execute("SELECT * FROM analyzed_logs WHERE id = ?", (log_id,)).fetchone()
        conn.close()
        
        if not row:
            return jsonify({"error": "Log not found"}), 404
            
        log_dict = dict(row)
        
        with config_lock:
            api_key = config["groq_api_key"]
            
        # Call Groq/Gemini API or local fallback
        analysis = llm_advisor.analyser_alerte(log_dict, api_key=api_key)
        
        # Update database with results
        database.update_llm_analysis(log_id, analysis)
        
        # Broadcast the update event to SSE client so dashboard details update dynamically
        log_dict.update({
            "llm_analyzed": 1,
            "llm_summary": analysis["summary"],
            "llm_risk_level": analysis["risk_level"],
            "llm_attack_type": analysis["attack_type"],
            "llm_mitre": analysis["mitre"],
            "llm_recommendations": analysis["recommendations"],
            "llm_iocs": analysis["iocs"]
        })
        announce({
            "event": "update_log",
            "data": log_dict
        })
        
        return jsonify(analysis), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/settings", methods=["GET", "POST"])
def manage_settings():
    if request.method == "GET":
        with config_lock:
            return jsonify(config), 200
    else:
        payload = request.get_json()
        if not payload:
            return jsonify({"error": "Missing config payload"}), 400
            
        # Filter config keys
        new_values = {}
        for k in DEFAULT_CONFIG.keys():
            if k in payload:
                if k == "attack_threshold" or k == "simulation_speed":
                    new_values[k] = float(payload[k])
                elif k == "simulation_active":
                    new_values[k] = bool(payload[k])
                elif k == "groq_api_key":
                    new_values[k] = str(payload[k])
                    
        update_config(new_values)
        
        # Broadcast settings update to trigger immediate visual refresh if needed
        announce({
            "event": "settings_update",
            "data": config
        })
        
        return jsonify(config), 200

@app.route("/api/inject", methods=["POST"])
def inject_log():
    payload = request.get_json() or {}
    forced_class = payload.get("class", None)
    if forced_class not in ["normal", "false_positive", "attack"]:
        forced_class = None
        
    try:
        with config_lock:
            threshold = config["attack_threshold"]
            
        log = generate_wazuh_log(true_class=forced_class)
        result = classifier.predict(log, custom_threshold=threshold)
        log.update(result)
        log["llm_analyzed"] = 0
        
        log_id = database.save_log(log)
        log["id"] = log_id
        
        # Broadcast to SSE clients
        announce({
            "event": "new_log",
            "data": log
        })
        
        return jsonify(log), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/clear", methods=["POST"])
def clear_logs():
    try:
        database.clear_db()
        # Broadcast to SSE client
        announce({
            "event": "clear_logs"
        })
        return jsonify({"message": "Logs database cleared"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/download/custom-soc-ai", methods=["GET"])
def download_integration_script():
    script_content = """#!/usr/bin/env python3
import sys
import json
import urllib.request
import re

# Lecture des parametres passes par Wazuh
alert_file = sys.argv[1]
hook_url = sys.argv[3]

# Charger le fichier JSON temporaire de l'alerte
with open(alert_file) as f:
    alert_data = json.load(f)

# Fonction utilitaire pour categoriser une IP comme interne
def is_internal(ip):
    if not ip:
        return 1
    # Recherche des plages privees IPv4 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.1)
    private_ip_pattern = re.compile(r'^(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[0-1])\.\d+\.\d+|192\.168\.\d+\.\d+|127\.0\.0\.1)$')
    return 1 if bool(private_ip_pattern.match(ip)) else 0

# Extraction et normalisation des attributs
rule = alert_data.get("rule", {})
agent = alert_data.get("agent", {})
data = alert_data.get("data", {})

src_ip = data.get("srcip", data.get("src_ip", ""))
dst_ip = agent.get("ip", data.get("dstip", ""))

# En cas d'IP non disponible dans les donnees de protocole, utiliser des fallbacks
if not src_ip and data.get("srcip"):
    src_ip = data.get("srcip")
if not dst_ip and agent.get("ip"):
    dst_ip = agent.get("ip")

# Convertir les ports en entiers
try:
    src_port = int(data.get("srcport", data.get("src_port", 0)))
except (ValueError, TypeError):
    src_port = 0

try:
    dst_port = int(data.get("dstport", data.get("dst_port", 0)))
except (ValueError, TypeError):
    dst_port = 0

protocol = data.get("protocol", "TCP")

# Formater la charge utile pour l'API Flask de notre SOC-AI
payload = {
    "alert_name": rule.get("description", "Alerte de securite Wazuh"),
    "description": rule.get("description", "Alerte generee par les regles OSSEC"),
    "src_ip": src_ip or "N/A",
    "dst_ip": dst_ip or "N/A",
    "src_port": src_port,
    "dst_port": dst_port,
    "protocol": protocol,
    "freq_per_min": int(rule.get("firedtimes", 1)),
    
    # Attributs reseau requis par le classifieur XGBoost
    "src_is_internal": is_internal(src_ip),
    "dst_is_internal": is_internal(dst_ip),
    "is_internal_to_internal": 1 if (is_internal(src_ip) and is_internal(dst_ip)) else 0,
    "same_subnet": 1 if (src_ip.rsplit('.', 1)[0] == dst_ip.rsplit('.', 1)[0] if (src_ip and dst_ip and '.' in src_ip) else False) else 0,
    
    # Objet brut original pour l'affichage JSON dans l'analyseur
    "raw_log": alert_data
}

# Envoyer la requete HTTP POST a l'API Flask
req = urllib.request.Request(
    hook_url,
    data=json.dumps(payload).encode('utf-8'),
    headers={'Content-Type': 'application/json'}
)

try:
    with urllib.request.urlopen(req) as response:
        response.read()
except Exception as e:
    sys.stderr.write(f"Erreur d'envoi a SOC-AI : {e}\\n")
    sys.exit(1)
"""
    return Response(script_content, mimetype="text/plain")

if __name__ == "__main__":
    database.init_db()
    load_config()
    
    classifier = SOCClassifier()
    # Apply threshold from config
    classifier.attack_threshold = config["attack_threshold"]
    
    # Start the simulation background worker
    worker = SimulationWorker()
    worker.start()
    
    print("  [OK] SOC AI API Backend running on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
