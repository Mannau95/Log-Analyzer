# parsers/apache_parser.py
import re
from datetime import datetime
from urllib.parse import unquote

class ApacheParser:
    """Parseur pour les logs Apache/Nginx"""
    
    def __init__(self, config=None):
        self.config = config or {}
        
        # Patterns d'attaques web
        self.attack_patterns = {
            "sql_injection": [
                r"union.*select", r"select.*from", r"insert.*into",
                r"update.*set", r"delete.*from", r"drop.*table",
                r"\'or\'1\'=\'1", r"\'or 1=1", r"\'or\'.*\'.*=\'.*\'",
                r"benchmark\(.*,.*\)", r"sleep\(.*\)", r"waitfor delay"
            ],
            "xss": [
                r"<script>", r"javascript:", r"onload=", r"onerror=",
                r"onclick=", r"alert\(", r"document\.cookie",
                r"<iframe", r"<img.*src=.*onerror", r"eval\("
            ],
            "path_traversal": [
                r"\.\./", r"\.\.\\", r"\.\.%2f", r"\.\.%5c",
                r"etc/passwd", r"win\.ini", r"boot\.ini"
            ],
            "lfi_rfi": [
                r"include\(.*\.\.", r"require\(.*\.\.", r"php://filter",
                r"php://input", r"data:text/html", r"expect://"
            ],
            "command_injection": [
                r";\s*(ls|dir|cat|type|rm|del|mkdir)",
                r"\|\s*(ls|dir|cat|type|rm|del|mkdir)",
                r"`.*`", r"\$\(.*\)", r"system\(", r"exec\(",
                r"passthru\(", r"shell_exec\("
            ],
            "bruteforce": [
                r"wp-admin", r"admin\.php", r"login\.php",
                r"administrator", r"admin", r"manager"
            ],
            "scanners": [
                r"nikto", r"nessus", r"acunetix", r"w3af",
                r"sqlmap", r"nmap", r"dirbuster", r"gobuster"
            ]
        }
        
        # Pattern de log Apache commun
        self.log_pattern = r'(\S+) (\S+) (\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\d+)'
        
    def analyze(self, file_path):
        """
        Analyse un fichier de logs Apache
        
        Returns:
            dict: Résultats de l'analyse
        """
        results = {
            "lines_processed": 0,
            "requests_by_ip": {},
            "alerts": []
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    results["lines_processed"] += 1
                    
                    # Parse la ligne de log
                    parsed = self.parse_log_line(line)
                    if not parsed:
                        continue
                    
                    ip, user, timestamp, request, status, size = parsed
                    
                    # Statistiques par IP
                    if ip not in results["requests_by_ip"]:
                        results["requests_by_ip"][ip] = {
                            "count": 0,
                            "methods": set(),
                            "paths": set(),
                            "status_codes": set()
                        }
                    
                    results["requests_by_ip"][ip]["count"] += 1
                    results["requests_by_ip"][ip]["methods"].add(request.split()[0] if request else "UNKNOWN")
                    
                    # Détection d'attaques
                    self.detect_attacks(line, ip, request, results, timestamp)
                    
                    # Détection de scans
                    self.detect_scans(ip, request, results, timestamp)
                    
        except Exception as e:
            print(f"Erreur lors de l'analyse du fichier Apache: {e}")
        
        # Analyse comportementale a posteriori
        self.behavioral_analysis(results)
        
        return results
    
    def parse_log_line(self, line):
        """Parse une ligne de log Apache"""
        match = re.match(self.log_pattern, line)
        if match:
            ip, ident, user, timestamp, request, status, size = match.groups()
            return ip, user, timestamp, request, int(status), int(size)
        return None
    
    def detect_attacks(self, line, ip, request, results, timestamp):
        """Détecte les attaques web dans une requête"""
        if not request:
            return
        
        # Décodage URL pour analyse
        decoded_request = unquote(request.lower())
        
        # Vérifie chaque type d'attaque
        for attack_type, patterns in self.attack_patterns.items():
            for pattern in patterns:
                if re.search(pattern, decoded_request, re.IGNORECASE):
                    alert = self.create_alert(
                        attack_type=attack_type.upper(),
                        ip=ip,
                        request=request[:100],  # Limite à 100 caractères
                        pattern=pattern,
                        timestamp=timestamp
                    )
                    results["alerts"].append(alert)
                    break  # Une alerte par type d'attaque par ligne
    
    def detect_scans(self, ip, request, results, timestamp):
        """Détecte les scans et activités suspectes"""
        if not request:
            return
        
        # Détection de scans de répertoires (trop de 404)
        # Cette détection se fera plutôt dans behavioral_analysis
        
        # Détection de User-Agent de scanners (à implémenter si les logs contiennent User-Agent)
        pass
    
    def create_alert(self, attack_type, ip, request, pattern, timestamp):
        """Crée une alerte structurée"""
        severity_map = {
            "SQL_INJECTION": "high",
            "COMMAND_INJECTION": "high", 
            "PATH_TRAVERSAL": "high",
            "LFI_RFI": "high",
            "XSS": "medium",
            "BRUTEFORCE": "medium",
            "SCANNERS": "low"
        }
        
        messages = {
            "SQL_INJECTION": f"Injection SQL détectée depuis {ip}",
            "XSS": f"Cross-Site Scripting détecté depuis {ip}",
            "PATH_TRAVERSAL": f"Path traversal détecté depuis {ip}",
            "LFI_RFI": f"Inclusion de fichier détectée depuis {ip}",
            "COMMAND_INJECTION": f"Injection de commande détectée depuis {ip}",
            "BRUTEFORCE": f"Tentative de bruteforce admin depuis {ip}",
            "SCANNERS": f"Scanner web détecté depuis {ip}"
        }
        
        return {
            "type": attack_type,
            "message": messages.get(attack_type, f"Attaque {attack_type} détectée"),
            "severity": severity_map.get(attack_type, "medium"),
            "timestamp": self.format_timestamp(timestamp),
            "details": {
                "ip": ip,
                "request": request,
                "pattern": pattern
            }
        }
    
    def behavioral_analysis(self, results):
        """Analyse comportementale des IPs"""
        for ip, data in results["requests_by_ip"].items():
            # Trop de requêtes en peu de temps
            if data["count"] > 100:  # Seuil arbitraire
                alert = {
                    "type": "HTTP_FLOOD",
                    "message": f"Possible flood HTTP depuis {ip} ({data['count']} requêtes)",
                    "severity": "medium",
                    "timestamp": datetime.now().isoformat(),
                    "details": {"ip": ip, "request_count": data["count"]}
                }
                results["alerts"].append(alert)
            
            # Trop d'erreurs 404 (scan de répertoires)
            # Note: Nécessite de tracker les codes de statut
    
    def format_timestamp(self, apache_timestamp):
        """Formate le timestamp Apache en ISO"""
        try:
            # Format: 15/Jan/2024:10:30:22 +0100
            dt = datetime.strptime(apache_timestamp, "%d/%b/%Y:%H:%M:%S %z")
            return dt.isoformat()
        except:
            return datetime.now().isoformat()