import random
import datetime
import numpy as np

# Pools of realistic IPs
IPS = {
    "normal_src":  ["192.168.1.50", "10.0.0.15", "10.10.0.5", "192.168.10.5", "192.168.1.20"],
    "normal_dst":  ["10.0.0.1", "192.168.1.1", "192.168.126.139"],
    "fp_src":      ["192.168.10.5", "172.16.0.5", "192.168.1.20", "192.168.1.10", "10.0.0.100"],
    "fp_dst":      ["192.168.1.1", "192.168.126.139", "192.168.126.128"],
    "attack_src":  ["192.168.126.133", "192.168.126.1"],
    "attack_dst":  ["192.168.126.139", "192.168.126.128"],
}

# Alert names by class
ALERT_NAMES = {
    "normal":         ["https", "http", "dns", "ssh", "smtp", "ftp", "http_alt", "icmp"],
    "false_positive": ["Web Scan", "Basic Injection Pattern", "HTTP Login Bruteforce", "ICMP Ping Sweep", "Sensitive File Probe", "Script Injection Path", "Traversal Path Attempt"],
    "attack":         ["Web Scan", "Hydra HTTP Tool", "SSH Scan", "Traversal Path Attempt", "Sensitive File Probe", "SSH Brute Force", "SQL Injection pattern", "Hydra HTTP Tool detected"],
}

# Destination ports
DST_PORTS = {
    "normal":         [443, 80, 53, 22, 25, 21, 8080],
    "false_positive": [80, 22, 443, 0, 8080],
    "attack":         [80, 22],
}

DST_SERVICE_MAP = {
    443: "https", 80: "http", 53: "dns", 22: "ssh", 25: "smtp", 21: "ftp", 8080: "http_alt", 0: "icmp",
}

# Severity
SEVERITY = {
    "normal":         [("INFO", 0)],
    "false_positive": [("LOW", 1), ("HIGH", 3), ("CRITICAL", 4), ("INFO", 0), ("MEDIUM", 2)],
    "attack":         [("HIGH", 3), ("LOW", 1), ("CRITICAL", 4), ("MEDIUM", 2)],
}
SEVERITY_WEIGHTS = {
    "normal":         [1.0],
    "false_positive": [0.346, 0.300, 0.172, 0.138, 0.044],
    "attack":         [0.451, 0.426, 0.119, 0.005],
}

# Time contexts
TIME_CONTEXTS = {
    "normal":         ["business_hours", "night", "after_hours"],
    "false_positive": ["business_hours"],
    "attack":         ["business_hours", "after_hours"],
}
TIME_CONTEXT_WEIGHTS = {
    "normal":         [0.458, 0.377, 0.165],
    "false_positive": [1.0],
    "attack":         [0.751, 0.249],
}

TIME_CTX_ENCODE = {"business_hours": 0, "night": 1, "after_hours": 2}

def generate_wazuh_log(true_class: str = None) -> dict:
    """
    Génère un log Wazuh simulé dont les features respectent les distributions observées.
    """
    if true_class is None:
        true_class = random.choices(
            ["normal", "false_positive", "attack"],
            weights=[0.577, 0.279, 0.144]
        )[0]

    cls = true_class

    # Time Context
    time_ctx_str = random.choices(
        TIME_CONTEXTS[cls],
        weights=TIME_CONTEXT_WEIGHTS[cls]
    )[0]

    # Hour consistent with context
    hour_map = {
        "business_hours": random.randint(9, 17),
        "after_hours":    random.choice(list(range(18, 22)) + list(range(6, 9))),
        "night":          random.randint(0, 5),
    }
    hour = hour_map[time_ctx_str]

    # Ports
    dst_port_weights = {
        "normal":         [0.22, 0.22, 0.15, 0.14, 0.07, 0.08, 0.12],
        "false_positive": [0.66, 0.10, 0.06, 0.08, 0.10],
        "attack":         [0.891, 0.109],
    }
    dst_port = random.choices(
        DST_PORTS[cls],
        weights=dst_port_weights[cls]
    )[0]
    dst_service = DST_SERVICE_MAP.get(dst_port, "unknown")

    if cls == "attack":
        src_port = random.randint(30000, 65194)
    else:
        src_port = random.randint(1025, 64998)

    # Network flags matching model training distribution
    if cls == "normal":
        src_int = 1
        dst_int = 1
        int_to_int = 1
        same_subnet = 1 if random.random() < 0.187 else 0
        protocol = "TCP" if random.random() < 0.934 else "ICMP"
    elif cls == "false_positive":
        src_int = 1 if random.random() < 0.734 else 0
        dst_int = 1
        int_to_int = src_int
        same_subnet = 1 if random.random() < 0.202 else 0
        protocol = "TCP" if random.random() < 0.940 else "ICMP"
    else: # attack
        src_int = 1
        dst_int = 1
        int_to_int = 1
        same_subnet = 1
        protocol = "TCP"

    # Frequency
    if cls == "normal":
        freq = max(1, int(np.random.choice(
            [1, 2, 3, 4, 6, 8, 11, 16, 22, 30, 38],
            p=[0.05, 0.10, 0.13, 0.12, 0.18, 0.13, 0.12, 0.10, 0.04, 0.02, 0.01]
        )))
    elif cls == "false_positive":
        freq = max(1, int(np.random.choice(
            [1, 2, 3, 4, 5, 6, 8, 10, 13, 16],
            p=[0.10, 0.14, 0.13, 0.14, 0.13, 0.12, 0.10, 0.08, 0.04, 0.02]
        )))
    else: # attack
        if random.random() < 0.155:
            freq = random.randint(1, 20)
        else:
            freq = max(21, int(np.random.normal(loc=140, scale=40)))
            freq = min(freq, 230)

    is_high_freq = 1 if freq > 20 else 0

    # Severity
    sev_pair = random.choices(
        SEVERITY[cls],
        weights=SEVERITY_WEIGHTS[cls]
    )[0]
    severity, severity_score = sev_pair

    # IPs
    src_ip = random.choice(IPS[f"{cls[:6] if cls!='false_positive' else 'fp'}_src"])
    dst_ip = random.choice(IPS[f"{cls[:6] if cls!='false_positive' else 'fp'}_dst"])

    # Alert name
    alert_name = random.choice(ALERT_NAMES[cls])

    return {
        "timestamp":    datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "description":  alert_name,
        "true_class":   true_class,
        "alert_name":   alert_name,
        "severity":     severity,
        "severity_score": severity_score,
        "src_ip":       src_ip,
        "dst_ip":       dst_ip,
        "src_port":     src_port,
        "dst_port":     dst_port,
        "dst_service":  dst_service,
        "time_context": time_ctx_str,
        "freq_per_min": freq,
        
        # Internal wazuh features
        "data.protocol":       protocol,
        "data.srcport":        src_port,
        "data.dstport":        dst_port,
        "data.srcip_internal": bool(src_int),
        "data.dstip_internal": bool(dst_int),
        "protocol":            protocol,
        "src_is_internal":     int(src_int),
        "dst_is_internal":     int(dst_int),
        "is_internal_to_internal": int(int_to_int),
        "same_subnet":         int(same_subnet),
        "is_high_freq":        int(is_high_freq),
        "_hour":               hour,
        "_same_subnet":        same_subnet,
        "_int_to_int":         int_to_int,
        "_is_high_freq":       is_high_freq,
        "_time_context_str":   time_ctx_str,
        "_freq":               freq,
    }
