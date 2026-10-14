"""
Traffic simulator — generates realistic KDD-like network traffic records.
"""

import random
import ipaddress

PROTOCOLS = ["tcp", "udp", "icmp"]
SERVICES  = ["http", "ftp", "smtp", "ssh", "dns", "other"]
FLAGS     = ["SF", "S0", "REJ", "RSTO", "SH"]

def _random_public_ip():
    while True:
        ip = ipaddress.IPv4Address(random.randint(0, 2**32 - 1))
        if not ip.is_private and not ip.is_loopback and not ip.is_reserved:
            return str(ip)

def _random_private_ip():
    return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"

def normal_traffic():
    return {
        "src_ip": _random_public_ip(),
        "dst_ip": _random_private_ip(),
        "protocol_type": random.choice(PROTOCOLS),
        "service":       random.choice(SERVICES),
        "flag":          "SF",
        "duration":      round(random.expovariate(0.5), 2),
        "src_bytes":     random.randint(0, 5000),
        "dst_bytes":     random.randint(0, 5000),
        "land": 0, "wrong_fragment": 0, "urgent": 0,
        "hot": random.randint(0, 5),
        "num_failed_logins": 0,
        "logged_in": random.choice([0, 1]),
        "num_compromised": 0, "root_shell": 0, "su_attempted": 0,
        "num_root": 0, "num_file_creations": 0, "num_shells": 0,
        "num_access_files": 0, "num_outbound_cmds": 0,
        "is_host_login": 0, "is_guest_login": 0,
        "count": random.randint(1, 50),
        "srv_count": random.randint(1, 50),
        "serror_rate": 0.0, "srv_serror_rate": 0.0,
        "rerror_rate": 0.0, "srv_rerror_rate": 0.0,
        "same_srv_rate": round(random.uniform(0.8, 1.0), 2),
        "diff_srv_rate": round(random.uniform(0.0, 0.2), 2),
        "srv_diff_host_rate": round(random.uniform(0.0, 0.2), 2),
        "dst_host_count": random.randint(1, 255),
        "dst_host_srv_count": random.randint(1, 255),
        "dst_host_same_srv_rate": round(random.uniform(0.7, 1.0), 2),
        "dst_host_diff_srv_rate": round(random.uniform(0.0, 0.3), 2),
        "dst_host_same_src_port_rate": round(random.uniform(0.0, 1.0), 2),
        "dst_host_srv_diff_host_rate": round(random.uniform(0.0, 0.3), 2),
        "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
        "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0,
    }

def dos_attack():
    r = normal_traffic()
    r.update({
        "protocol_type": random.choice(["tcp", "udp", "icmp"]),
        "service": random.choice(["http", "smtp", "ftp"]),
        "flag": random.choice(["S0", "REJ"]),
        "duration": 0,
        "src_bytes": random.randint(0, 100),
        "dst_bytes": 0,
        "count": random.randint(400, 511),
        "srv_count": random.randint(400, 511),
        "serror_rate": round(random.uniform(0.8, 1.0), 2),
        "srv_serror_rate": round(random.uniform(0.8, 1.0), 2),
        "same_srv_rate": round(random.uniform(0.9, 1.0), 2),
        "diff_srv_rate": 0.0,
    })
    return r

def probe_attack():
    r = normal_traffic()
    r.update({
        "protocol_type": random.choice(["tcp", "icmp"]),
        "service": "other",
        "flag": random.choice(["S0", "REJ", "RSTO"]),
        "src_bytes": random.randint(0, 500),
        "dst_bytes": random.randint(0, 500),
        "diff_srv_rate": round(random.uniform(0.3, 1.0), 2),
        "dst_host_count": random.randint(200, 255),
        "dst_host_diff_srv_rate": round(random.uniform(0.3, 1.0), 2),
    })
    return r

def r2l_attack():
    r = normal_traffic()
    r.update({
        "protocol_type": "tcp",
        "service": random.choice(["ftp", "smtp", "ssh"]),
        "flag": "SF",
        "duration": round(random.expovariate(0.2), 2),
        "src_bytes": random.randint(100, 10000),
        "dst_bytes": random.randint(100, 10000),
        "num_failed_logins": random.randint(1, 5),
        "logged_in": 0,
    })
    return r

def u2r_attack():
    r = normal_traffic()
    r.update({
        "protocol_type": "tcp",
        "service": random.choice(["ssh", "ftp"]),
        "flag": "SF",
        "root_shell": 1,
        "num_root": random.randint(1, 10),
        "su_attempted": random.choice([0, 1]),
        "num_compromised": random.randint(1, 10),
        "num_shells": random.randint(1, 3),
    })
    return r

def generate_traffic_record():
    """90% normal, 10% attack traffic."""
    if random.random() < 0.90:
        return normal_traffic()
    attack_fn = random.choice([dos_attack, probe_attack, r2l_attack, u2r_attack])
    return attack_fn()
