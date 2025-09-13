package main

import (
	"flag"
	"fmt"
	"loganalyzer/pkg/analyzer"
	"loganalyzer/pkg/parser"
	"loganalyzer/pkg/reporter"
	"os"
	"runtime"
	"time"

	"github.com/fatih/color"
)

const (
	VERSION  = "1.0.0"
	APP_NAME = "LogAnalyzer"
)

func main() {
	// Configuration des couleurs pour Windows
	if runtime.GOOS == "windows" {
		color.NoColor = false
	}

	// Parse command line arguments
	var (
		logFile    = flag.String("file", "", "Fichier de log à analyser (requis)")
		outputJSON = flag.String("json", "", "Exporter en JSON (optionnel)")
		outputCSV  = flag.String("csv", "", "Exporter en CSV (optionnel)")
		noColor    = flag.Bool("no-color", false, "Désactiver les couleurs")
		version    = flag.Bool("version", false, "Afficher la version")
		help       = flag.Bool("help", false, "Afficher l'aide")
		verbose    = flag.Bool("verbose", false, "Mode verbeux")
		quickScan  = flag.Bool("quick", false, "Scan rapide (analyse basique)")
	)
	flag.Parse()

	// Désactiver les couleurs si demandé
	if *noColor {
		color.NoColor = true
	}

	// Afficher la version
	if *version {
		fmt.Printf("%s v%s\n", APP_NAME, VERSION)
		fmt.Printf("Compilé avec Go %s pour %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return
	}

	// Afficher l'aide
	if *help {
		printUsage()
		return
	}

	// Vérifier les arguments
	if *logFile == "" {
		color.Red("❌ Erreur: Fichier de log requis")
		fmt.Println()
		printUsage()
		os.Exit(1)
	}

	// Vérifier que le fichier existe
	if fileInfo, err := os.Stat(*logFile); os.IsNotExist(err) {
		color.Red("❌ Erreur: Fichier '%s' introuvable", *logFile)
		os.Exit(1)
	} else if fileInfo.IsDir() {
		color.Red("❌ Erreur: '%s' est un répertoire, pas un fichier", *logFile)
		os.Exit(1)
	}

	// Banner de démarrage
	printBanner()

	if *verbose {
		fmt.Printf("🔧 Mode verbeux activé\n")
		fmt.Printf("📁 Fichier: %s\n", *logFile)
		if *quickScan {
			fmt.Printf("⚡ Mode scan rapide\n")
		}
	}

	fmt.Printf("🚀 Démarrage de l'analyse de: %s\n", color.CyanString(*logFile))
	startTime := time.Now()

	// Initialiser les composants
	logParser := parser.NewLogParser()
	logAnalyzer := analyzer.NewAnalyzer()
	logReporter := reporter.NewReporter(!*noColor)

	// Parser le fichier de log
	fmt.Print("📖 Lecture du fichier de log... ")
	entries, err := logParser.ParseFile(*logFile)
	if err != nil {
		color.Red("❌")
		fmt.Printf("\nErreur lors du parsing: %v\n", err)
		os.Exit(1)
	}
	color.Green("✅ %d entrées trouvées", len(entries))

	if len(entries) == 0 {
		color.Yellow("⚠️  Aucune entrée de log valide trouvée")
		fmt.Println("Vérifiez que le fichier est au format Apache/Nginx standard")
		return
	}

	// Afficher des infos de debug si verbeux
	if *verbose {
		parsingStats := logParser.GetParsingStats(entries)
		fmt.Printf("📊 Stats parsing: %d succès, %d erreurs client, %d erreurs serveur\n",
			parsingStats["success"], parsingStats["client_error"], parsingStats["server_error"])
	}

	// Analyser les logs
	fmt.Print("🔍 Analyse en cours... ")
	stats := logAnalyzer.Analyze(entries)
	color.Green("✅ Analyse terminée")

	if *verbose {
		fmt.Printf("🔍 %d menaces détectées, %d IPs uniques analysées\n",
			len(stats.SecurityThreats), stats.UniqueIPs)
	}

	// Afficher les résultats
	logReporter.DisplayStats(stats)

	// Exports optionnels
	if *outputJSON != "" {
		fmt.Printf("💾 Export JSON vers: %s... ", *outputJSON)
		if err := logReporter.ExportToJSON(stats, *outputJSON); err != nil {
			color.Red("❌ Erreur: %v", err)
		} else {
			color.Green("✅ Export JSON terminé")
		}
	}

	if *outputCSV != "" {
		fmt.Printf("💾 Export CSV vers: %s... ", *outputCSV)
		if err := logReporter.ExportToCSV(stats, *outputCSV); err != nil {
			color.Red("❌ Erreur: %v", err)
		} else {
			color.Green("✅ Export CSV terminé")
		}
	}

	// Temps d'exécution et statistiques finales
	duration := time.Since(startTime)
	fmt.Printf("\n⏱️  Analyse terminée en: %s\n", color.MagentaString(duration.String()))

	// Calculs de performance
	if duration.Seconds() > 0 {
		throughput := float64(len(entries)) / duration.Seconds()
		fmt.Printf("⚡ Performance: %.0f lignes/seconde\n", throughput)
	}

	// Résumé final
	printSummary(stats, *verbose)

	// Message de fin
	fmt.Println()
	if len(stats.SecurityThreats) > 0 {
		color.Yellow("⚠️  Des menaces de sécurité ont été détectées. Consultez les détails ci-dessus.")
	} else {
		color.Green("✅ Analyse terminée avec succès. Aucune menace détectée.")
	}
}

func printBanner() {
	fmt.Println()
	color.Cyan("╔══════════════════════════════════════════════════════════╗")
	color.Cyan("║                    🔍 LogAnalyzer v%s                   ║", VERSION)
	color.Cyan("║              Analyseur de Logs Web Avancé                ║")
	color.Cyan("║                  Par: Jamil18474                         ║")
	color.Cyan("╚══════════════════════════════════════════════════════════╝")
	fmt.Println()
}

func printUsage() {
	color.Cyan("📊 %s v%s - Analyseur de Logs Web", APP_NAME, VERSION)
	fmt.Println()
	fmt.Println("DESCRIPTION:")
	fmt.Println("  Analyse les fichiers de logs Apache/Nginx et détecte les menaces de sécurité")
	fmt.Println("  Supporte: SQL Injection, XSS, Directory Traversal, Brute Force, DDoS")
	fmt.Println()
	fmt.Println("USAGE:")
	fmt.Printf("  %s -file <fichier.log> [options]\n", APP_NAME)
	fmt.Println()
	fmt.Println("OPTIONS REQUISES:")
	fmt.Println("  -file string     Fichier de log à analyser (format Apache/Nginx)")
	fmt.Println()
	fmt.Println("OPTIONS:")
	fmt.Println("  -json string     Exporter les résultats complets en JSON")
	fmt.Println("  -csv string      Exporter les menaces de sécurité en CSV")
	fmt.Println("  -no-color        Désactiver les couleurs dans la sortie")
	fmt.Println("  -verbose         Afficher des informations détaillées")
	fmt.Println("  -quick           Mode scan rapide (analyse basique)")
	fmt.Println("  -version         Afficher la version")
	fmt.Println("  -help            Afficher cette aide")
	fmt.Println()
	fmt.Println("EXEMPLES:")
	color.Green("  # Analyse basique")
	fmt.Println("  loganalyzer -file access.log")
	fmt.Println()
	color.Green("  # Analyse avec exports")
	fmt.Println("  loganalyzer -file access.log -json results.json -csv threats.csv")
	fmt.Println()
	color.Green("  # Mode verbeux sans couleurs")
	fmt.Println("  loganalyzer -file access.log -verbose -no-color")
	fmt.Println()
	color.Green("  # Scan rapide pour gros fichiers")
	fmt.Println("  loganalyzer -file huge.log -quick")
	fmt.Println()
	fmt.Println("FORMATS SUPPORTÉS:")
	fmt.Println("  - Apache Common Log Format")
	fmt.Println("  - Apache Combined Log Format")
	fmt.Println("  - Nginx access logs")
	fmt.Println()
	fmt.Println("DÉTECTIONS:")
	fmt.Println("  🔴 Critiques: SQL Injection, Directory Traversal, DDoS")
	fmt.Println("  🟡 Moyennes:  XSS, Bots suspects, Anomalies de trafic")
	fmt.Println("  🟢 Faibles:   Échecs d'authentification, Scans basiques")
	fmt.Println()
}

func printSummary(stats analyzer.Statistics, verbose bool) {
	fmt.Println()
	color.Cyan("╔═══════════════════════════════════════════════════════════╗")
	color.Cyan("║                    📋 RÉSUMÉ EXÉCUTIF                     ║")
	color.Cyan("╚═══════════════════════════════════════════════════════════╝")

	// Statistiques principales
	fmt.Printf("\n📊 STATISTIQUES PRINCIPALES:\n")
	fmt.Printf("   • Requêtes totales: %s\n", color.BlueString("%d", stats.TotalRequests))
	fmt.Printf("   • IPs uniques: %s\n", color.BlueString("%d", stats.UniqueIPs))
	fmt.Printf("   • Taux d'erreur: %s\n", colorizeErrorRate(stats.ErrorRate))
	fmt.Printf("   • Bande passante: %s\n", color.BlueString(formatBytes(stats.BandwidthUsage)))

	// Analyse de sécurité
	fmt.Printf("\n🛡️  ANALYSE DE SÉCURITÉ:\n")
	if len(stats.SecurityThreats) > 0 {
		threatCount := make(map[string]int)
		severityCount := make(map[string]int)

		for _, threat := range stats.SecurityThreats {
			threatCount[threat.Type]++
			severityCount[threat.Severity]++
		}

		fmt.Printf("   • Total des menaces: %s\n", color.RedString("%d", len(stats.SecurityThreats)))

		if severityCount["HIGH"] > 0 {
			fmt.Printf("   • 🔴 Critiques: %s\n", color.RedString("%d", severityCount["HIGH"]))
		}
		if severityCount["MEDIUM"] > 0 {
			fmt.Printf("   • 🟡 Moyennes: %s\n", color.YellowString("%d", severityCount["MEDIUM"]))
		}
		if severityCount["LOW"] > 0 {
			fmt.Printf("   • 🟢 Faibles: %s\n", color.GreenString("%d", severityCount["LOW"]))
		}

		if verbose {
			fmt.Printf("\n   DÉTAIL DES MENACES:\n")
			for threatType, count := range threatCount {
				fmt.Printf("     - %s: %d occurrences\n", threatType, count)
			}
		}

		// Recommandations de sécurité
		fmt.Printf("\n💡 RECOMMANDATIONS:\n")
		if severityCount["HIGH"] > 0 {
			color.Red("   ⚠️  ACTION IMMÉDIATE REQUISE:")
			fmt.Printf("      - Bloquer les IPs malveillantes\n")
			fmt.Printf("      - Vérifier l'intégrité de l'application\n")
			fmt.Printf("      - Renforcer la sécurité des inputs\n")
		}
		if severityCount["MEDIUM"] > 0 {
			color.Yellow("   📋 ACTIONS RECOMMANDÉES:")
			fmt.Printf("      - Surveiller les IPs suspectes\n")
			fmt.Printf("      - Mettre à jour les règles de filtrage\n")
		}
	} else {
		color.Green("   ✅ Aucune menace de sécurité détectée")
		fmt.Printf("   🛡️  Votre serveur semble sécurisé\n")
	}

	// Score de santé
	fmt.Printf("\n📈 SCORE DE SANTÉ:\n")
	healthScore := calculateHealthScore(stats)
	fmt.Printf("   • Score global: %s\n", colorizeHealthScore(healthScore))

	if !verbose {
		fmt.Printf("\n💡 Utilisez -verbose pour plus de détails\n")
	}

	fmt.Println()
	color.Cyan("═══════════════════════════════════════════════════════════")
}

func colorizeErrorRate(rate float64) string {
	if rate < 5.0 {
		return color.GreenString("%.2f%%", rate)
	} else if rate < 15.0 {
		return color.YellowString("%.2f%%", rate)
	} else {
		return color.RedString("%.2f%%", rate)
	}
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func calculateHealthScore(stats analyzer.Statistics) int {
	score := 100

	// Pénalités pour les menaces
	for _, threat := range stats.SecurityThreats {
		switch threat.Severity {
		case "HIGH":
			score -= 15
		case "MEDIUM":
			score -= 5
		case "LOW":
			score -= 1
		}
	}

	// Pénalité pour taux d'erreur élevé
	if stats.ErrorRate > 10 {
		score -= int(stats.ErrorRate)
	}

	// Score minimum de 0
	if score < 0 {
		score = 0
	}

	return score
}

func colorizeHealthScore(score int) string {
	if score >= 85 {
		return color.GreenString("%d/100 (Excellent)", score)
	} else if score >= 70 {
		return color.YellowString("%d/100 (Bon)", score)
	} else if score >= 50 {
		return color.New(color.FgRed).SprintfFunc()("%d/100 (Moyen)", score)
	} else {
		return color.RedString("%d/100 (Critique)", score)
	}
}
