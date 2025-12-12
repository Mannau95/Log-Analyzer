# 🔍 Log Analyzer - Analyseur de Logs de Sécurité

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Flask](https://img.shields.io/badge/Flask-2.3%2B-green)
![License](https://img.shields.io/badge/License-MIT-orange)

Un outil complet pour analyser les logs de sécurité avec interface web intuitive.

## ✨ Fonctionnalités

### 🔍 Analyse Multi-Sources

- **SSH/Auth logs** : Détection de bruteforce, connexions root
- **Apache/Nginx logs** : Détection SQLi, XSS, scans web
- **Windows Event Logs** : Événements de sécurité Windows

### 🌐 Interface Web

- Dashboard avec statistiques en temps réel
- Upload de fichiers via navigateur
- Visualisation interactive des alertes
- Graphiques Chart.js dynamiques
- Export de rapports (HTML, JSON)

### ⚡ Détections Intelligentes

- Patterns configurables (JSON)
- Seuils ajustables
- Corrélation d'événements
- Classement par criticité (High/Medium/Low)

## 🚀 Installation Rapide

```bash
# Clone le projet
git clone https://github.com/Mannau95/Log-Analyzer.git
cd Log-Analyzer

# Installe les dépendances
pip install -r requirements.txt

# Lance l'interface web
cd web_app
python app.py

# Ouvre http://localhost:5000 dans ton navigateur
```
