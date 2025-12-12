# parsers/ssh_parser.py
import re
from datetime import datetime

class SSHParser:
    """Parseur pour les logs SSH (auth.log, secure)"""
    
    def __init__(self, config=None):
        self.config = config or {}
        self.patterns = {
            "failed_login": r"Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+)",
            "success_login": r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)",
            "invalid_user": r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)",
            "root_login": r"Accepted password for root from (\d+\.\d+\.\d+\.\d+)",
            "connection_closed": r"Connection closed by (\d+\.\d+\.\d+\.\d+)",
            "bruteforce": r"error: maximum authentication attempts exceeded"
        }
        
    def analyze(self, file_path):
        """
        Analyse un fichier de logs SSH
        
        Returns:
            dict: Résultats de l'analyse
        """
        results = {
            "lines_processed": 0,
            "failed_logins": [],
            "successful_logins": [],
            "alerts": []
        }
        
        failed_attempts = {}
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    results["lines_processed"] += 1
                    
                    # Détection des tentatives échouées
                    match = re.search(self.patterns["failed_login"], line)
                    if match:
                        username, ip = match.groups()
                        key = f"{ip}:{username}"
                        failed_attempts[key] = failed_attempts.get(key, 0) + 1
                        
                        # Vérifie le seuil pour bruteforce
                        if failed_attempts[key] >= self.config.get('failed_login_threshold', 5):
                            alert = {
                                "type": "SSH_Bruteforce",
                                "message": f"Bruteforce SSH détecté: {ip} a {failed_attempts[key]} tentatives échouées pour {username}",
                                "severity": "high",
                                "timestamp": self.extract_timestamp(line)
                            }
                            results["alerts"].append(alert)
                    
                    # Détection des connexions root
                    match = re.search(self.patterns["root_login"], line)
                    if match:
                        ip = match.group(1)
                        if self.config.get('root_login_alert', True):
                            alert = {
                                "type": "SSH_Root_Login",
                                "message": f"Connexion root SSH depuis {ip}",
                                "severity": "medium",
                                "timestamp": self.extract_timestamp(line)
                            }
                            results["alerts"].append(alert)
                    
                    # Détection des utilisateurs invalides
                    match = re.search(self.patterns["invalid_user"], line)
                    if match:
                        username, ip = match.groups()
                        alert = {
                            "type": "SSH_Invalid_User",
                            "message": f"Tentative avec utilisateur invalide: {username} depuis {ip}",
                            "severity": "low",
                            "timestamp": self.extract_timestamp(line)
                        }
                        results["alerts"].append(alert)
        
        except Exception as e:
            print(f"Erreur lors de l'analyse du fichier SSH: {e}")
        
        return results
    
    def extract_timestamp(self, log_line):
        """Extrait le timestamp d'une ligne de log SSH"""
        # Format typique: "Jan 15 10:30:22"
        match = re.search(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', log_line)
        if match:
            try:
                # Ajoute l'année courante
                timestamp_str = match.group(1) + " " + str(datetime.now().year)
                return datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y").isoformat()
            except:
                pass
        return datetime.now().isoformat()