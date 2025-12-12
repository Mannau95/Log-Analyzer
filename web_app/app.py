# web_app/app.py
from flask import Flask, render_template, request, jsonify, send_file
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Ajoute le chemin parent pour importer nos modules
sys.path.append(str(Path(__file__).parent.parent))

from log_analyzer import LogAnalyzer

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

# Crée le dossier uploads s'il n'existe pas
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Variable globale pour stocker l'analyseur
analyzer = None

@app.route('/')
def index():
    """Page d'accueil avec dashboard"""
    return render_template('dashboard.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """Page d'upload de fichiers de logs"""
    if request.method == 'POST':
        if 'logfile' not in request.files:
            return jsonify({'error': 'Aucun fichier sélectionné'}), 400
        
        file = request.files['logfile']
        if file.filename == '':
            return jsonify({'error': 'Nom de fichier vide'}), 400
        
        if file:
            # Sauvegarde le fichier
            filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(filename)
            
            # Analyse le fichier
            log_type = request.form.get('log_type', 'auto')
            global analyzer
            if analyzer is None:
                analyzer = LogAnalyzer()
            
            analyzer.analyze_file(filename, log_type)
            
            return jsonify({
                'success': True,
                'filename': file.filename,
                'alerts': len(analyzer.alerts)
            })
    
    return render_template('upload.html')

@app.route('/api/alerts')
def get_alerts():
    """API pour récupérer les alertes"""
    global analyzer
    if analyzer is None:
        return jsonify({'alerts': [], 'stats': {}})
    
    # Filtrage par sévérité
    severity = request.args.get('severity')
    alerts = analyzer.alerts
    
    if severity:
        alerts = [a for a in alerts if a['severity'] == severity]
    
    # Pagination
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))
    start = (page - 1) * per_page
    end = start + per_page
    
    return jsonify({
        'alerts': alerts[start:end],
        'total': len(alerts),
        'page': page,
        'per_page': per_page,
        'stats': analyzer.stats
    })

@app.route('/api/stats')
def get_stats():
    """API pour les statistiques"""
    global analyzer
    if analyzer is None:
        return jsonify({})
    
    # Statistiques par type d'alerte
    alerts_by_type = {}
    alerts_by_severity = {}
    ips = {}
    
    for alert in analyzer.alerts:
        # Par type
        alerts_by_type[alert['type']] = alerts_by_type.get(alert['type'], 0) + 1
        
        # Par sévérité
        alerts_by_severity[alert['severity']] = alerts_by_severity.get(alert['severity'], 0) + 1
        
        # Extraction IP (simplifiée)
        import re
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', alert.get('message', ''))
        if ip_match:
            ip = ip_match.group()
            ips[ip] = ips.get(ip, 0) + 1
    
    return jsonify({
        'total_alerts': len(analyzer.alerts),
        'files_processed': analyzer.stats.get('files_processed', 0),
        'alerts_by_type': alerts_by_type,
        'alerts_by_severity': alerts_by_severity,
        'top_ips': dict(sorted(ips.items(), key=lambda x: x[1], reverse=True)[:10])
    })

@app.route('/api/report/generate')
def generate_report():
    """Génère un rapport et le retourne"""
    global analyzer
    if analyzer is None:
        return jsonify({'error': 'Aucune analyse effectuée'}), 400
    
    report_type = request.args.get('type', 'json')
    
    if report_type == 'html':
        analyzer.generate_html_report()
        return send_file('../security_report.html', as_attachment=True)
    else:
        analyzer.generate_report()
        return send_file('../security_report.json', as_attachment=True)

@app.route('/dashboard')
def dashboard():
    """Page de dashboard"""
    return render_template('dashboard.html')

@app.route('/alerts')
def alerts_page():
    """Page de liste des alertes"""
    return render_template('alerts.html')

if __name__ == '__main__':
    # Pour production, utiliser: waitress-serve --port=5000 app:app
    app.run(debug=True, host='0.0.0.0', port=5000)