#!/usr/bin/env python3
"""
Analyseur de Logs de Sécurité - Projet 2
Auteur: [Ton Nom]
Description: Analyse multi-sources de logs pour détection d'incidents
"""

import argparse
import json
import os
import sys
from datetime import datetime
from colorama import init, Fore, Style

# Initialisation colorama
init(autoreset=True)

class LogAnalyzer:
    def __init__(self, config_file="config.json"):
        """
        Initialise l'analyseur de logs
        
        Args:
            config_file: Fichier de configuration JSON
        """
        self.config = self.load_config(config_file)
        self.alerts = []
        self.stats = {
            "total_lines": 0,
            "alerts_found": 0,
            "files_processed": 0
        }
        
        # Chargement des parseurs
        self.parsers = self.load_parsers()
        
        print(f"{Fore.GREEN}[+] Analyseur de logs initialisé{Style.RESET_ALL}")
        print(f"    Parseurs chargés: {len(self.parsers)}")
    
    def load_config(self, config_file):
        """Charge la configuration depuis un fichier JSON"""
        default_config = {
            "ssh": {
                "enabled": True,
                "failed_login_threshold": 5,
                "root_login_alert": True
            },
            "apache": {
                "enabled": True,
                "sql_injection_patterns": [
                    "union select", "select * from", "' or '1'='1"
                ],
                "xss_patterns": [
                    "<script>", "javascript:", "onload="
                ]
            },
            "output": {
                "alert_file": "security_alerts.log",
                "report_file": "security_report.json",
                "verbose": True
            }
        }
        
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                print(f"{Fore.CYAN}[*] Configuration chargée: {config_file}{Style.RESET_ALL}")
                return config
        except FileNotFoundError:
            print(f"{Fore.YELLOW}[!] Fichier de configuration non trouvé, utilisation des valeurs par défaut{Style.RESET_ALL}")
            return default_config
    
    def load_parsers(self):
        """Charge dynamiquement les parseurs disponibles"""
        parsers = {}
        
        # SSH Parser
        try:
            from parsers.ssh_parser import SSHParser
            parsers['ssh'] = SSHParser()
        except ImportError:
            print(f"{Fore.YELLOW}[!] Parseur SSH non disponible{Style.RESET_ALL}")
        
        # Apache Parser
        try:
            from parsers.apache_parser import ApacheParser
            parsers['apache'] = ApacheParser()
        except ImportError:
            print(f"{Fore.YELLOW}[!] Parseur Apache non disponible{Style.RESET_ALL}")
        
        return parsers
    
    def analyze_file(self, file_path, log_type=None):
        """
        Analyse un fichier de logs
        
        Args:
            file_path: Chemin vers le fichier de logs
            log_type: Type de log (ssh, apache, windows)
        """
        if not os.path.exists(file_path):
            print(f"{Fore.RED}[!] Fichier non trouvé: {file_path}{Style.RESET_ALL}")
            return
        
        # Détection automatique du type si non spécifié
        if not log_type:
            log_type = self.detect_log_type(file_path)
        
        if log_type not in self.parsers:
            print(f"{Fore.RED}[!] Aucun parseur disponible pour le type: {log_type}{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}[*] Analyse du fichier: {file_path}{Style.RESET_ALL}")
        print(f"    Type détecté: {log_type}")
        
        # Analyse avec le parseur approprié
        parser = self.parsers[log_type]
        results = parser.analyze(file_path)
        
        # Traitement des résultats
        self.process_results(results, log_type, file_path)
        
        self.stats["files_processed"] += 1
    
    def detect_log_type(self, file_path):
        """Détecte automatiquement le type de log"""
        filename = os.path.basename(file_path).lower()
        
        if 'auth' in filename or 'secure' in filename or 'ssh' in filename:
            return 'ssh'
        elif 'access' in filename or 'apache' in filename or 'nginx' in filename:
            return 'apache'
        elif 'system' in filename or 'security' in filename or 'application' in filename:
            return 'windows'
        else:
            # Analyse du contenu pour deviner
            with open(file_path, 'r') as f:
                first_line = f.readline()
                if 'sshd' in first_line:
                    return 'ssh'
                elif 'HTTP' in first_line or 'GET' in first_line:
                    return 'apache'
                else:
                    return 'unknown'
    
    def process_results(self, results, log_type, source_file):
        """Traite les résultats d'analyse"""
        for alert in results.get('alerts', []):
            self.record_alert(
                alert_type=alert.get('type', 'Unknown'),
                message=alert.get('message', 'No message'),
                severity=alert.get('severity', 'medium'),
                source=source_file,
                timestamp=alert.get('timestamp', datetime.now().isoformat())
            )
        
        self.stats["total_lines"] += results.get('lines_processed', 0)
        self.stats["alerts_found"] += len(results.get('alerts', []))
    
    def record_alert(self, alert_type, message, severity, source, timestamp):
        """Enregistre une alerte"""
        alert = {
            "timestamp": timestamp,
            "type": alert_type,
            "message": message,
            "severity": severity,
            "source": source
        }
        
        self.alerts.append(alert)
        
        # Affichage en couleur selon la sévérité
        colors = {
            'high': Fore.RED,
            'medium': Fore.YELLOW,
            'low': Fore.CYAN
        }
        
        color = colors.get(severity, Fore.WHITE)
        print(f"{color}[!] ALERTE {severity.upper()}: {alert_type}")
        print(f"     {message}{Style.RESET_ALL}")
        
        # Sauvegarde dans le fichier d'alertes
        self.save_alert_to_file(alert)
    
    def save_alert_to_file(self, alert):
        """Sauvegarde une alerte dans un fichier"""
        alert_file = self.config.get('output', {}).get('alert_file', 'security_alerts.log')
        
        with open(alert_file, 'a') as f:
            f.write(f"[{alert['timestamp']}] {alert['severity'].upper()}: {alert['type']} - {alert['message']}\n")
    
    def generate_report(self):
        """Génère un rapport d'analyse"""
        print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}📊 RAPPORT D'ANALYSE COMPLET{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        
        print(f"\n📈 Statistiques:")
        print(f"  Fichiers analysés: {self.stats['files_processed']}")
        print(f"  Lignes traitées: {self.stats['total_lines']}")
        print(f"  Alertes trouvées: {self.stats['alerts_found']}")
        
        if self.alerts:
            print(f"\n🚨 Alertes par sévérité:")
            severities = {}
            for alert in self.alerts:
                severities[alert['severity']] = severities.get(alert['severity'], 0) + 1
            
            for severity, count in severities.items():
                print(f"  {severity.upper()}: {count}")
            
            print(f"\n🔍 Top 5 des alertes:")
            for i, alert in enumerate(self.alerts[:5]):
                print(f"  {i+1}. [{alert['timestamp'][11:19]}] {alert['type']}: {alert['message'][:80]}...")
        
        # Sauvegarde du rapport JSON
        report_data = {
            "generated_at": datetime.now().isoformat(),
            "statistics": self.stats,
            "alerts": self.alerts[-50:],  # 50 dernières alertes
            "summary": {
                "total_alerts": len(self.alerts),
                "high_severity": len([a for a in self.alerts if a['severity'] == 'high']),
                "files_analyzed": self.stats['files_processed']
            }
        }
        
        report_file = self.config.get('output', {}).get('report_file', 'security_report.json')
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"\n✅ Rapport sauvegardé: {report_file}")

def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(
        description="Analyseur de Logs de Sécurité",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument("file", nargs="+", help="Fichier(s) de logs à analyser")
    parser.add_argument("-t", "--type", help="Type de log (ssh, apache, windows)")
    parser.add_argument("-c", "--config", default="config.json", help="Fichier de configuration")
    
    args = parser.parse_args()
    
    # Crée l'analyseur
    analyzer = LogAnalyzer(config_file=args.config)
    
    # Analyse chaque fichier
    for file_path in args.file:
        analyzer.analyze_file(file_path, args.type)
    
    # Génère le rapport
    analyzer.generate_report()

if __name__ == "__main__":
    main()

def generate_html_report(self):
    """Génère un rapport HTML détaillé"""
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Rapport d'Analyse de Logs - {datetime.now().strftime('%Y-%m-%d %H:%M')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
        .stat-card {{ background: #fff; border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin: 10px 0; }}
        .alert-high {{ border-left: 5px solid #dc3545; background: #f8d7da; }}
        .alert-medium {{ border-left: 5px solid #ffc107; background: #fff3cd; }}
        .alert-low {{ border-left: 5px solid #28a745; background: #d4edda; }}
        .severity-badge {{ padding: 3px 8px; border-radius: 3px; color: white; font-size: 12px; }}
        .severity-high {{ background: #dc3545; }}
        .severity-medium {{ background: #ffc107; }}
        .severity-low {{ background: #28a745; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; }}
        .chart-container {{ margin: 20px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Rapport d'Analyse de Logs</h1>
            <p>Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')}</p>
        </div>
        
        <div class="stat-card">
            <h2>📈 Statistiques Générales</h2>
            <p>Fichiers analysés: <strong>{self.stats['files_processed']}</strong></p>
            <p>Lignes traitées: <strong>{self.stats['total_lines']}</strong></p>
            <p>Alertes trouvées: <strong>{self.stats['alerts_found']}</strong></p>
        </div>
        
        <h2>🚨 Alertes par Sévérité</h2>
        <div class="chart-container">
            <!-- Ici on pourrait ajouter un graphique avec Chart.js -->
            <div style="display: flex; gap: 10px; margin: 20px 0;">
                <div class="severity-badge severity-high">HIGH: {len([a for a in self.alerts if a['severity'] == 'high'])}</div>
                <div class="severity-badge severity-medium">MEDIUM: {len([a for a in self.alerts if a['severity'] == 'medium'])}</div>
                <div class="severity-badge severity-low">LOW: {len([a for a in self.alerts if a['severity'] == 'low'])}</div>
            </div>
        </div>
        
        <h2>🔍 Détail des Alertes</h2>
        <table>
            <tr>
                <th>Timestamp</th>
                <th>Type</th>
                <th>Sévérité</th>
                <th>Message</th>
                <th>Source</th>
            </tr>
"""

    # Ajoute les alertes
    for alert in self.alerts[-20:]:  # 20 dernières alertes
        severity_class = f"severity-{alert['severity']}"
        html_content += f"""
            <tr class="alert-{alert['severity']}">
                <td>{alert['timestamp'][11:19]}</td>
                <td>{alert['type']}</td>
                <td><span class="severity-badge {severity_class}">{alert['severity'].upper()}</span></td>
                <td>{alert['message'][:80]}</td>
                <td>{alert.get('source', 'N/A')}</td>
            </tr>
"""

    html_content += """
        </table>
        
        <h2>🎯 Top 5 des IPs Suspectes</h2>
        <table>
            <tr>
                <th>IP</th>
                <th>Alertes</th>
                <th>Dernière Activité</th>
            </tr>
"""
    
    # Analyse des IPs (simplifiée)
    ip_counter = {}
    for alert in self.alerts:
        # Essaye d'extraire l'IP du message
        import re
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', alert['message'])
        if ip_match:
            ip = ip_match.group()
            ip_counter[ip] = ip_counter.get(ip, 0) + 1
    
    for ip, count in sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:5]:
        html_content += f"""
            <tr>
                <td><code>{ip}</code></td>
                <td>{count}</td>
                <td>N/A</td>
            </tr>
"""

    html_content += """
        </table>
        
        <div class="stat-card" style="background: #e8f4f8;">
            <h2>✅ Recommandations</h2>
            <ul>
                <li>Bloquer les IPs avec plus de 10 alertes HIGH</li>
                <li>Examiner les logs des serveurs ciblés</li>
                <li>Mettre à jour les règles de firewall</li>
                <li>Renforcer l'authentification sur les services exposés</li>
            </ul>
        </div>
        
        <footer style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 14px;">
            <p>Rapport généré par Log-Analyzer v1.0</p>
            <p>Note: Ce rapport est généré automatiquement, une analyse humaine est recommandée.</p>
        </footer>
    </div>
</body>
</html>
"""
    
    report_file = "security_report.html"
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"✅ Rapport HTML généré: {report_file}")