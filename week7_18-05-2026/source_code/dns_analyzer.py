import json
import threading
import time
import os
import math
import re
import tldextract
import subprocess
import sys
import numpy as np
import pickle

from collections import Counter, defaultdict

# ==========================================
# CONFIGURATION & THRESHOLDS
# ==========================================
BLOCK_DURATION = 60
GATEWAY_IP = "192.168.50.1"

# Sliding Window and Quota Framework Constraints
THRESHOLD_UNIQUE_HITS = 3    
THRESHOLD_WINDOW = 20.0      
THRESHOLD_BURST_WINDOW = 30.0 
THRESHOLD_VOLUME_BYTES = 1000  

# Dynamic Risk Matrix Alert Tiers
THRESHOLD_RISK_CRITICAL = 75   # RED Tier
THRESHOLD_RISK_WARNING = 40    # YELLOW Tier

# Evasion Mitigation Parameters
MAX_ABSOLUTE_VOLUME_LIMIT = 1000 
MIN_TEMPORAL_SUSPICION_LEVEL = 20

# Thread-safe primitives for global state synchronization
state_lock = threading.Lock()

# Global Telemetry Memory Pools
blocked_ips = set()
violation_history = defaultdict(list)
volume_history = defaultdict(list)
volume_quota = defaultdict(int) 

# ==========================================
# PART 1: CORE FEATURE EXTRACTION SENSORS
# ==========================================
# Lexical Entropy Analyzer for Subdomain Randomness Detection
def calculate_entropy(domain_string):
    # Calculates the Shannon Entropy of a given domain string to detect randomness.
    if not domain_string:
        return 0.0
    entropy = 0
    length = len(domain_string)
    character_counts = Counter(domain_string)
    for count in character_counts.values():
        p_x = count / length
        entropy += - p_x * math.log2(p_x)
    return round(entropy, 3)

# Maps DNS Resource Record types to empirical security weight factors based on observed attack patterns.
def get_rrtype_weight(rrtype_str):
    # Maps the L7 DNS Resource Record type to an empirical security weight factor.
    rrtype_str = str(rrtype_str).upper()
    if rrtype_str == "PTR": return 3.25
    elif rrtype_str == "TXT": return 3.04
    elif rrtype_str == "ANY": return 2.98
    elif rrtype_str == "AAAA": return 2.55
    elif rrtype_str == "SRV": return 2.05
    elif rrtype_str == "A": return 0.02
    return 1.0  

# Core feature extraction function that combines lexical analysis with protocol context for DNS queries
def extract_features(fqdn, rrtype_str="A"):
    # Extracts a 5-dimensional lexical and protocol feature vector from a DNS packet.
    fqdn = str(fqdn).strip()
    if fqdn.endswith('.'):
        fqdn = fqdn[:-1]

    parsed_domain = tldextract.extract(fqdn)
    subdomain = parsed_domain.subdomain

    if not subdomain:
        return [0, 0.0, 0.0, 0.0, 0.0]

    length = len(subdomain)
    entropy = calculate_entropy(subdomain)

    digit_count = len(re.findall(r'\d', subdomain))
    digit_ratio = round(digit_count / length, 3) if length > 0 else 0.0

    type_weight = get_rrtype_weight(rrtype_str)

    consonant_count = len(re.findall(r'[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]', subdomain))
    consonant_ratio = round(consonant_count / length, 3) if length > 0 else 0.0

    return [length, entropy, digit_ratio, type_weight, consonant_ratio]

# ==========================================
# PART 2: MACHINE LEARNING INITIALIZATION
# ==========================================
# AI Model Loader with error handling for missing dependencies and model integrity checks
def load_ai_model():
    # Loads the serialized Decision Tree classifier binary into memory.
    print("[*] Initializing AI Engine (Hybrid Lexical & Unique Behavioral)...")
    try:
        with open('ai_model_id3.pkl', 'rb') as f:
            model = pickle.load(f)
        print("[+] Model loaded successfully! System is ready for deployment.\n" + "="*50)
        return model
    except FileNotFoundError:
        print("[!] ERROR: Core binary dependency 'ai_model_id3.pkl' missing.")
        sys.exit(1)

# ==========================================
# PART 3: CENTRALISED ACTIVE RESPONDER
# ==========================================
# Release IP function with safe state management and subprocess execution for firewall rule manipulation
def unblock_ip(ip_address):
    # Thread-safe worker function to lift network isolation and flush metrics cache.
    print(f"\n[*] Penalty timeout reached. Restoring access for IP: {ip_address} ...")
    
    # Safe decoupled binary call executing outside shell sub-process contexts
    subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", ip_address, "-j", "DROP"], check=False)
    subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"], check=False)

    with state_lock:
        if ip_address in blocked_ips:
            blocked_ips.remove(ip_address)

        # Purge localized volumetric allocations to avoid re-blocking loops
        keys_to_reset = [key for key in volume_quota.keys() if key[0] == ip_address]
        for key in keys_to_reset:
            volume_quota[key] = 0  

    print(f"[+] Successfully unblocked IP: {ip_address}")
    print("-" * 50)

# Block IP function with safe state management and subprocess execution for firewall rule manipulation
def block_attacker_ip(ip_address):
    # Injects real-time kernel rules via iptables to isolate compromised hosts.
    if ip_address == GATEWAY_IP:
        return

    with state_lock:
        if ip_address in blocked_ips:
            return
        blocked_ips.add(ip_address)

    print(f"\n[!!!] CRITICAL: ACTIVE RESPONSE TRIGGERED [!!!]")
    print(f"[*] Executing iptables to isolate IP: {ip_address} for {BLOCK_DURATION} seconds")

    # Secure architectural execution of Linux netfilter rule manipulation
    subprocess.run(["sudo", "iptables", "-I", "FORWARD", "1", "-s", ip_address, "-j", "DROP"], check=False)
    subprocess.run(["sudo", "iptables", "-I", "INPUT", "1", "-s", ip_address, "-j", "DROP"], check=False)

    print(f"[+] Network isolation complete for IP: {ip_address}")

    # Fire asynchronous non-blocking thread execution for host rehabilitation
    timer = threading.Timer(BLOCK_DURATION, unblock_ip, args=[ip_address])
    timer.start()

# ==========================================
# PART 4: LIVE SECURITY EVENT CORRELATOR
# ==========================================
# Main processing function that implements the multi-phase detection pipeline for each DNS packet
def process_dns_packet(log_data, ai_model):
    # Processes a single extracted DNS telemetry packet frame through the pipeline.
    dns_info = log_data.get("dns", {})
    query_type = dns_info.get("type")

    if query_type not in ["query", "request"]:
        return

    domain_queried = dns_info.get("rrname", "")
    if not domain_queried and "queries" in dns_info and len(dns_info["queries"]) > 0:
        domain_queried = dns_info["queries"][0].get("rrname", "")

    if not domain_queried:
        return

    src_ip = log_data.get("src_ip", "")
    rrtype = "A"
    if "queries" in dns_info and len(dns_info["queries"]) > 0:
        rrtype = dns_info["queries"][0].get("rrtype", "A")

    # Fast-path bail out to avoid computing states for already blocked targets
    with state_lock:
        if src_ip in blocked_ips:
            return

    # Phase 1: Contextual L7 DPI Feature Extraction
    length, entropy, digits, t_weight, cons_ratio = extract_features(domain_queried, rrtype)
    features = np.array([[length, entropy, digits, t_weight, cons_ratio]])
    prediction = ai_model.predict(features)[0]

    # Phase 2: Heuristic Security Override Analysis
    is_heuristic_malware = False
    if (prediction == 0) and ((entropy >= 4.2 and length >= 30) or (length >= 60)):
        is_heuristic_malware = True
        print("\n[!] ML Bypassed. Heuristic Override Activated!")

    # Phase 3: Update Telemetry Sliding Windows safely
    parsed_tld = tldextract.extract(domain_queried)
    root_domain = f"{parsed_tld.domain}.{parsed_tld.suffix}" if parsed_tld.suffix else parsed_tld.domain
    timestamp_now = time.time()

    with state_lock:
        volume_quota[(src_ip, root_domain)] += length
        volume_history[src_ip].append((timestamp_now, root_domain, parsed_tld.subdomain))
        volume_history[src_ip] = [frame for frame in volume_history[src_ip] if timestamp_now - frame[0] <= THRESHOLD_BURST_WINDOW]

        if prediction == 1 or is_heuristic_malware:
            violation_history[src_ip].append((timestamp_now, domain_queried))
        violation_history[src_ip] = [frame for frame in violation_history[src_ip] if timestamp_now - frame[0] <= THRESHOLD_WINDOW]

        current_volume = volume_quota[(src_ip, root_domain)]
        unique_subdomains = set(frame[2] for frame in volume_history[src_ip] if frame[1] == root_domain)

    # Phase 4: Dynamic Risk Matrix Multi-Indicator Aggregation
    lexical_score = (20 if prediction == 1 else 0) + (10 if is_heuristic_malware else 0)
    temporal_score = min(len(unique_subdomains) * 4, 35)
    volumetric_score = min(int((current_volume / THRESHOLD_VOLUME_BYTES) * 35), 35)
    total_risk_score = lexical_score + temporal_score + volumetric_score

    # Phase 5: Correlative Anti-Evasion Assessment Gating
    is_low_and_slow_breach = (current_volume >= MAX_ABSOLUTE_VOLUME_LIMIT) and (temporal_score >= MIN_TEMPORAL_SUSPICION_LEVEL)
    if is_low_and_slow_breach:
        total_risk_score = 99
        print("\n[!] ANTI-EVASION ESCALATION: Correlative Low & Slow Exfiltration Identified!")

    # Phase 6: Enforcement Tier Routing Execution
    if total_risk_score >= THRESHOLD_RISK_CRITICAL:
        print(f"\n🔴 [!!!] CRITICAL RISK ALERT [{total_risk_score}/100] | IP: {src_ip}")
        print(f"   -> Context: Lexical={lexical_score}, Temporal={temporal_score}, Volume={volumetric_score} ({current_volume}B)")
        print(f"   -> Targeted Entity: {domain_queried}")
        
        block_attacker_ip(src_ip)
        
        with state_lock:
            if src_ip in violation_history: 
                del violation_history[src_ip]
            volume_history[src_ip] = [frame for frame in volume_history[src_ip] if frame[1] != root_domain]
            
    elif total_risk_score >= THRESHOLD_RISK_WARNING:
        print(f"\n⚠️  [WARNING] SUSPICIOUS BEHAVIOR [{total_risk_score}/100] | IP: {src_ip}")
        print(f"   -> Context: Lexical={lexical_score}, Temporal={temporal_score}, Volume={volumetric_score} ({current_volume}B)")
        print(f"   -> Domain Target: {domain_queried}")
    else:
        print(f"\n✅ [SAFE] Traffic Cleared [{total_risk_score}/100] | IP: {src_ip} | Domain: {domain_queried}")

    # Update dashboard telemetry after processing each packet
    export_dashboard_telemetry()

# ==========================================
# PART 5: MAIN ENGINE LOG TAILER
# ==========================================
# Dashboard Telemetry Exporter for Streamlit Integration
def export_dashboard_telemetry():
   
    # Exports the current state of blocked IPs and volume quotas to a JSON file for Streamlit dashboard consumption.
    telemetry_file = "dns_telemetry.json"
    
    # Thread-safe snapshot of current state for export to avoid race conditions and ensure data integrity in the dashboard feed
    with state_lock:
        active_blocks = list(blocked_ips)
        serialized_quota = {
            f"{ip} ➔ {domain}": bytes_count 
            for (ip, domain), bytes_count in volume_quota.items() 
            if bytes_count > 0
        }
    
    data_to_dump = {
        "blocked_ips": active_blocks,
        "volume_quota": serialized_quota,
        "last_updated": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    
    try:
        with open(telemetry_file, "w") as f:
            json.dump(data_to_dump, f, indent=4)
    except Exception as e:
        pass

# Main log monitoring loop with graceful shutdown handling
def monitor_suricata_logs(log_path, ai_model):
    """Continuously monitors and streams incoming JSON network logs from Suricata."""
    print(f"[*] Listening to Suricata data stream: {log_path} ...")
    try:
        with open(log_path, 'r') as f:
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                try:
                    log_data = json.loads(line)
                    if log_data.get("event_type") == "dns":
                        process_dns_packet(log_data, ai_model)
                except json.JSONDecodeError:
                    continue
                    
    except KeyboardInterrupt:
        print("\n[!] User terminated the system (Ctrl+C). Initiating Graceful Shutdown...")
        with state_lock:
            if len(blocked_ips) > 0:
                print("[*] Flashing leftover active firewall rule definitions...")
                for ip in list(blocked_ips):
                    subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=False)
                    subprocess.run(["sudo", "iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"], check=False)
        print("[*] Core engine safely offline. Exiting system.")
        sys.exit(0)
    except FileNotFoundError:
        print(f"[!] Error: Specified log target missing at {log_path}")
        sys.exit(1)


if __name__ == "__main__":
    ai_engine_model = load_ai_model()
    suricata_log_file = "/var/log/suricata/eve.json"
    monitor_suricata_logs(suricata_log_file, ai_engine_model)