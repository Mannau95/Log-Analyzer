# detectors/scan_detector.py
from collections import defaultdict
from datetime import datetime
class ScanDetector:
    """Détecteur de scans réseau et web"""
    
    def __init__(self, port_threshold=10, path_threshold=20):
        self.port_threshold = port_threshold
        self.path_threshold = path_threshold
        self.scanned_ports = defaultdict(set)
        self.scanned_paths = defaultdict(set)
        
    def detect_port_scan(self, ip, port, protocol):
        """Détecte les scans de ports"""
        key = f"{ip}-{protocol}"
        self.scanned_ports[key].add(port)
        
        if len(self.scanned_ports[key]) >= self.port_threshold:
            return {
                "type": "PORT_SCAN",
                "message": f"Scan de ports {protocol} détecté: {ip} a scanné {len(self.scanned_ports[key])} ports",
                "severity": "medium",
                "timestamp": datetime.now().isoformat()
            }
        return None
    
    def detect_dir_scan(self, ip, path, status_code):
        """Détecte les scans de répertoires web"""
        if status_code == 404:  # Fichier non trouvé
            self.scanned_paths[ip].add(path)
            
            if len(self.scanned_paths[ip]) >= self.path_threshold:
                return {
                    "type": "DIRECTORY_SCAN",
                    "message": f"Scan de répertoires détecté: {ip} a tenté {len(self.scanned_paths[ip])} chemins",
                    "severity": "low",
                    "timestamp": datetime.now().isoformat()
                }
        return None