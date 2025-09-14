# 🔍 LogAnalyzer - Analyseur de Logs Web Avancé


**LogAnalyzer** est un analyseur de logs web haute performance écrit en Go, conçu pour détecter automatiquement les menaces de sécurité dans vos fichiers de logs Apache/Nginx.

## 🌟 Fonctionnalités

### 🛡️ Détection de Sécurité
- **SQL Injection** - Détection avancée des tentatives d'injection
- **XSS (Cross-Site Scripting)** - Identification des attaques de script
- **Directory Traversal** - Détection des tentatives d'accès aux fichiers système
- **Brute Force** - Analyse des patterns d'attaque par force brute
- **DDoS/DoS** - Détection des pics de trafic anormaux
- **Bots malveillants** - Identification des scanners et bots suspects

### 📊 Analyse Statistique
- Statistiques détaillées du trafic web
- Distribution temporelle (analyse horaire)
- Top IPs, pages, User Agents
- Codes de statut HTTP
- Analyse de la bande passante
- Score de santé du serveur

### 💾 Export de Données
- **JSON** - Export complet des statistiques
- **CSV** - Export des menaces détectées
- Rapports formatés en couleurs

## 🚀 Installation

### Prérequis
- Go
- Git

### Compilation
```bash
# Cloner le repository
git clone https://github.com/Jamil18474/LogAnalyzer.git
cd LogAnalyzer

# Installer les dépendances
go mod tidy

# Compiler
go build -o loganalyzer.exe

# Ou compilation optimisée
go build -ldflags="-s -w" -o loganalyzer.exe
```

## 📖 Utilisation

### Commandes de Base
```bash
# Analyse simple
./loganalyzer.exe -file  data/sample.log

# Analyse avec exports
./loganalyzer.exe -file  data/sample.log -json output/analysis.json -csv output/threats.csv

# Mode verbeux
./loganalyzer.exe -file data/sample.log -verbose

# Scan rapide (pour gros fichiers)
./loganalyzer.exe -file data/sample.log -quick

# Sans couleurs (pour scripts)
./loganalyzer.exe -file data/sample.log -no-color
```

### Options Disponibles
```
-file string     Fichier de log à analyser (requis)
-json string     Exporter les résultats en JSON
-csv string      Exporter les menaces en CSV  
-verbose         Mode verbeux avec détails
-quick           Scan rapide
-no-color        Désactiver les couleurs
-version         Afficher la version
-help            Afficher l'aide
```

## 🔍 Types de Menaces Détectées

| Type | Sévérité | Description |
|------|----------|-------------|
| **SQL_INJECTION** | 🔴 HIGH | Tentatives d'injection SQL |
| **DIRECTORY_TRAVERSAL** | 🔴 HIGH | Accès aux fichiers système |
| **DDOS_ATTEMPT** | 🔴 HIGH | Pics de trafic anormaux |
| **XSS** | 🟡 MEDIUM | Scripts malveillants |
| **BRUTE_FORCE** | 🟡 MEDIUM | Attaques par force brute |
| **SUSPICIOUS_BOT** | 🟡 MEDIUM | Bots et scanners |
| **AUTH_FAILURE** | 🟢 LOW | Échecs d'authentification |

## 📊 Exemple de Sortie

```
╔══════════════════════════════════════════════════════════╗
║                    🔍 LogAnalyzer v1.0.0                   ║                                                                                                   
║              Analyseur de Logs Web Avancé                ║                                                                                                     
║                  Par: Jamil18474                         ║                                                                                                     
╚══════════════════════════════════════════════════════════╝                                                                                                     
                                                                                                                                                                 
🚀 Démarrage de l'analyse de: data/sample.log
📖 Lecture du fichier de log... ✅ 31 entrées trouvées
🔍 Analyse en cours... ✅ Analyse terminée                                                                                                                        
                                                                                                                                                                 
=============================
| 📊 ANALYSE DES LOGS WEB |
=============================


▶ 📈 Statistiques Générales
-------------------------------
Total des requêtes: 31
IPs uniques: 22
Taux d'erreur: 35.48%
Bande passante totale: 127.5 KB
Taille moyenne des réponses: 4.1 KB
Période analysée: 2025-09-13 21:00:01 à 2025-09-13 21:02:05 (2m4s)

▶ 🔗 Méthodes HTTP
---------------------
| MÉTHODE | REQUÊTES | POURCENTAGE |
|---------|----------|-------------|
| GET     |       22 | 71.0%       |
| POST    |        9 | 29.0%       |

▶ 🔥 Top 10 IPs
-----------------
| RANG |      IP       | REQUÊTES | POURCENTAGE |
|------|---------------|----------|-------------|
|    1 | 192.168.1.100 |        6 | 19.4%       |
|    2 | 192.168.1.106 |        5 | 16.1%       |
|    3 | 192.168.1.103 |        1 | 3.2%        |
|    4 | 192.168.1.104 |        1 | 3.2%        |
|    5 | 192.168.1.111 |        1 | 3.2%        |
|    6 | 203.0.113.46  |        1 | 3.2%        |
|    7 | 8.8.8.8       |        1 | 3.2%        |
|    8 | 192.168.1.150 |        1 | 3.2%        |
|    9 | 192.168.1.108 |        1 | 3.2%        |
|   10 | 192.168.1.102 |        1 | 3.2%        |

▶ 📄 Top 10 Pages
-------------------
| RANG |              PAGE              | HITS | POURCENTAGE |
|------|--------------------------------|------|-------------|
|    1 | /wp-login.php HTTP/1.1         |    5 | 16.1%       |
|    2 | /phpmyadmin/scripts/setup.php  |    1 | 3.2%        |
|      | HTTP/1.1                       |      |             |
|    3 | /cart/add HTTP/1.1             |    1 | 3.2%        |
|    4 | /sitemap.xml HTTP/1.1          |    1 | 3.2%        |
|    5 | /shell.php HTTP/1.1            |    1 | 3.2%        |
|    6 | /about.html HTTP/1.1           |    1 | 3.2%        |
|    7 | /products HTTP/1.1             |    1 | 3.2%        |
|    8 | /cart HTTP/1.1                 |    1 | 3.2%        |
|    9 | /index.html HTTP/1.1           |    1 | 3.2%        |
|   10 | /users.php                     |    1 | 3.2%        |

▶ 🤖 Top 5 User Agents
------------------------
| RANG |                USER AGENT                 | REQUÊTES |
|------|-------------------------------------------|----------|
|    1 | curl/7.68.0                               |        7 |
|    2 | Mozilla/5.0 (Windows NT 10.0; Win64; x64) |        6 |
|    3 | Mozilla/5.0                               |        3 |
|    4 | Mozilla/5.0 (iPhone; CPU iPhone OS 14_0)  |        2 |
|    5 | curl/7.74.0                               |        1 |

▶ 📊 Codes de Statut
----------------------
| CODE |      DESCRIPTION      | COUNT |     STATUS      |
|------|-----------------------|-------|-----------------|
|  200 | OK                    |    19 | 🟢 Success      |
|  302 | Found                 |     1 | 🟡 Redirect     |
|  401 | Unauthorized          |     5 | 🟠 Client Error |
|  403 | Forbidden             |     1 | 🟠 Client Error |
|  404 | Not Found             |     4 | 🟠 Client Error |
|  500 | Internal Server Error |     1 | 🔴 Server Error |

▶ ⏰ Distribution Horaire
--------------------------
| HEURE | REQUÊTES |      GRAPHIQUE       |
|-------|----------|----------------------|
| 00:00 |        0 |                      |
| 01:00 |        0 |                      |
| 02:00 |        0 |                      |
| 03:00 |        0 |                      |
| 04:00 |        0 |                      |
| 05:00 |        0 |                      |
| 06:00 |        0 |                      |
| 07:00 |        0 |                      |
| 08:00 |        0 |                      |
| 09:00 |        0 |                      |
| 10:00 |        0 |                      |
| 11:00 |        0 |                      |
| 12:00 |        0 |                      |
| 13:00 |        0 |                      |
| 14:00 |        0 |                      |
| 15:00 |        0 |                      |
| 16:00 |        0 |                      |
| 17:00 |        0 |                      |
| 18:00 |        0 |                      |
| 19:00 |        0 |                      |
| 20:00 |        0 |                      |
| 21:00 |       31 | ████████████████████ |
| 22:00 |        0 |                      |
| 23:00 |        0 |                      |

▶ 🚨 ALERTES SÉCURITÉ
-------------------------
|        TYPE         |      IP       | SÉVÉRITÉ  |                   URL                    |   TIME   |                   DESCRIPTION                    |
|---------------------|---------------|-----------|------------------------------------------|----------|--------------------------------------------------|
| SQL_INJECTION       | 192.168.1.107 | 🔴 HIGH   | /phpmyadmin/scripts/setup.php HTTP/1.1   | 21:00:12 | Tentative d'injection SQL détectée dans l'URL    |
| DIRECTORY_TRAVERSAL | 192.168.1.105 | 🔴 HIGH   | /../../../etc/passwd HTTP/1.1            | 21:00:07 | Tentative de traversée de répertoire ou LFI d... |
| SQL_INJECTION       | 192.168.1.104 | 🔴 HIGH   | /users.php?id=1' UNION SELECT * FROM ... | 21:00:05 | Tentative d'injection SQL détectée dans l'URL    |
| SQL_INJECTION       | 192.168.1.103 | 🔴 HIGH   | /search.php?q=<script>alert('xss')</s... | 21:00:04 | Tentative d'injection SQL détectée dans l'URL    |
| DIRECTORY_TRAVERSAL | 192.168.1.102 | 🔴 HIGH   | /admin/config.php HTTP/1.1               | 21:00:03 | Tentative de traversée de répertoire ou LFI d... |
| SUSPICIOUS_BOT      | 203.0.113.46  | 🟡 MEDIUM | /sitemap.xml HTTP/1.1                    | 21:01:03 | Bot/Scanner suspect détecté: Bingbot/2.0         |
| SUSPICIOUS_BOT      | 203.0.113.45  | 🟡 MEDIUM | /robots.txt HTTP/1.1                     | 21:01:02 | Bot/Scanner suspect détecté: Googlebot/2.1       |
| SUSPICIOUS_BOT      | 192.168.1.108 | 🟡 MEDIUM | /wp-content/plugins/wp-file-manager/r... | 21:00:13 | Bot/Scanner suspect détecté: bot                 |
| SUSPICIOUS_BOT      | 192.168.1.107 | 🟡 MEDIUM | /phpmyadmin/scripts/setup.php HTTP/1.1   | 21:00:12 | Bot/Scanner suspect détecté: Mozilla/5.0 (com... |
| SUSPICIOUS_BOT      | 192.168.1.105 | 🟡 MEDIUM | /../../../etc/passwd HTTP/1.1            | 21:00:07 | Bot/Scanner suspect détecté: Nikto/2.1.6         |
| SUSPICIOUS_BOT      | 192.168.1.104 | 🟡 MEDIUM | /users.php?id=1' UNION SELECT * FROM ... | 21:00:05 | Bot/Scanner suspect détecté: sqlmap/1.4.7        |
| XSS                 | 192.168.1.103 | 🟡 MEDIUM | /search.php?q=<script>alert('xss')</s... | 21:00:04 | Tentative de Cross-Site Scripting détectée       |
| AUTH_FAILURE        | 192.168.1.106 | 🟢 LOW    | /wp-login.php HTTP/1.1                   | 21:02:05 | Échec d'authentification sur page sensible       |
| AUTH_FAILURE        | 192.168.1.106 | 🟢 LOW    | /wp-login.php HTTP/1.1                   | 21:02:04 | Échec d'authentification sur page sensible       |
| AUTH_FAILURE        | 192.168.1.106 | 🟢 LOW    | /wp-login.php HTTP/1.1                   | 21:00:11 | Échec d'authentification sur page sensible       |
| AUTH_FAILURE        | 192.168.1.106 | 🟢 LOW    | /wp-login.php HTTP/1.1                   | 21:00:10 | Échec d'authentification sur page sensible       |
| AUTH_FAILURE        | 192.168.1.106 | 🟢 LOW    | /wp-login.php HTTP/1.1                   | 21:00:09 | Échec d'authentification sur page sensible       |

📊 Résumé des Menaces:
  Total: 17 menaces détectées
  🔴 Critiques: 5
  🟡 Moyennes: 7
  🟢 Faibles: 5

  Types détectés:
    - SQL_INJECTION: 3
    - DIRECTORY_TRAVERSAL: 2
    - SUSPICIOUS_BOT: 6
    - XSS: 1
    - AUTH_FAILURE: 5
💾 Export JSON vers: output/analysis.json... ✅ Export JSON terminé
💾 Export CSV vers: output/threats.csv... ✅ Export CSV terminé                                                                                                   
                                                                                                                                                                 
⏱️  Analyse terminée en: 72.8559ms
⚡ Performance: 425 lignes/seconde

╔═══════════════════════════════════════════════════════════╗
║                    📋 RÉSUMÉ EXÉCUTIF                     ║                                                                                                    
╚═══════════════════════════════════════════════════════════╝                                                                                                    
                                                                                                                                                                 
📊 STATISTIQUES PRINCIPALES:
   • Requêtes totales: 31
   • IPs uniques: 22
   • Taux d'erreur: 35.48%
   • Bande passante: 127.5 KB

🛡️  ANALYSE DE SÉCURITÉ:
   • Total des menaces: 17
   • 🔴 Critiques: 5
   • 🟡 Moyennes: 7
   • 🟢 Faibles: 5

💡 RECOMMANDATIONS:
   ⚠️  ACTION IMMÉDIATE REQUISE:
      - Bloquer les IPs malveillantes                                                                                                                            
      - Vérifier l'intégrité de l'application
      - Renforcer la sécurité des inputs
   📋 ACTIONS RECOMMANDÉES:
      - Surveiller les IPs suspectes                                                                                                                             
      - Mettre à jour les règles de filtrage

📈 SCORE DE SANTÉ:
   • Score global: 0/100 (Critique)

💡 Utilisez -verbose pour plus de détails

═══════════════════════════════════════════════════════════
                                                                                                                                                                 
⚠️  Des menaces de sécurité ont été détectées. Consultez les détails ci-dessus.

```

## 🛠️ Architecture du Projet

```
LogAnalyzer/
├── main.go                 # Point d'entrée principal
├── pkg/
│   ├── parser/
│   │   └── logparser.go    # Parsing des logs
│   ├── analyzer/  
│   │   └── analyzer.go     # Analyse et détection
│   └── reporter/
│       └── reporter.go     # Génération de rapports
├── data/
│   └── sample.log         # Fichier d'exemple
├── output/                # Dossier des exports
├── go.mod                 # Dépendances Go
└── README.md
```

