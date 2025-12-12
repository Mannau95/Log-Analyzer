# detectors/bruteforce_detector.py
from collections import defaultdict
from datetime import datetime, timedelta

class BruteforceDetector:
    """Détecteur de tentatives de bruteforce"""
    
    def __init__(self, threshold=5, time_window=300):
        """
        Args:
            threshold: Nombre de tentatives pour déclencher une alerte
            time_window: Fenêtre temporelle en secondes (5 minutes par défaut)
        """
        self.threshold = threshold
        self.time_window = time_window
        self.attempts = defaultdict(list)  # ip: [timestamps]
        
    def check_ssh(self, ip, timestamp):
        """Vérifie les tentatives SSH"""
        self.clean_old_attempts(ip)
        self.attempts[ip].append(timestamp)
        
        if len(self.attempts[ip]) >= self.threshold:
            return {
                "type": "SSH_BRUTEFORCE",
                "message": f"Bruteforce SSH détecté: {ip} a {len(self.attempts[ip])} tentatives",
                "severity": "high",
                "timestamp": datetime.now().isoformat()
            }
        return None
    
    def check_web(self, ip, path, timestamp):
        """Vérifie les tentatives sur les pages de login web"""
        if "login" in path.lower() or "admin" in path.lower():
            self.clean_old_attempts(ip)
            self.attempts[ip].append(timestamp)
            
            if len(self.attempts[ip]) >= self.threshold:
                return {
                    "type": "WEB_BRUTEFORCE",
                    "message": f"Bruteforce web détecté: {ip} sur {path}",
                    "severity": "medium",
                    "timestamp": datetime.now().isoformat()
                }
        return None
    
    def clean_old_attempts(self, ip):
        """Nettoie les tentatives trop anciennes"""
        now = datetime.now()
        cutoff = now - timedelta(seconds=self.time_window)
        
        self.attempts[ip] = [
            ts for ts in self.attempts[ip] 
            if datetime.fromisoformat(ts) > cutoff
        ]