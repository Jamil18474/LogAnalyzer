package reporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"loganalyzer/pkg/analyzer"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
)

type Reporter struct {
	colorEnabled bool
}

func NewReporter(colorEnabled bool) *Reporter {
	return &Reporter{
		colorEnabled: colorEnabled,
	}
}

func (r *Reporter) DisplayStats(stats analyzer.Statistics) {
	r.printHeader("📊 ANALYSE DES LOGS WEB")

	// Statistiques générales
	r.printSection("📈 Statistiques Générales")
	fmt.Printf("Total des requêtes: %s\n", color.CyanString("%d", stats.TotalRequests))
	fmt.Printf("IPs uniques: %s\n", color.GreenString("%d", stats.UniqueIPs))
	fmt.Printf("Taux d'erreur: %s\n", r.colorizeErrorRate(stats.ErrorRate))
	fmt.Printf("Bande passante totale: %s\n", color.BlueString("%s", r.formatBytes(stats.BandwidthUsage)))
	fmt.Printf("Taille moyenne des réponses: %s\n", color.BlueString("%s", r.formatBytes(int64(stats.AverageResponseSize))))

	if !stats.TimeRange.Start.IsZero() && !stats.TimeRange.End.IsZero() {
		duration := stats.TimeRange.End.Sub(stats.TimeRange.Start)
		fmt.Printf("Période analysée: %s à %s (%s)\n",
			color.MagentaString(stats.TimeRange.Start.Format("2006-01-02 15:04:05")),
			color.MagentaString(stats.TimeRange.End.Format("2006-01-02 15:04:05")),
			color.MagentaString(duration.String()))
	}

	// Distribution des méthodes HTTP
	if len(stats.MethodDistribution) > 0 {
		r.printSection("🔗 Méthodes HTTP")
		r.displayMethodDistribution(stats.MethodDistribution)
	}

	// Top IPs
	r.printSection("🔥 Top 10 IPs")
	r.displayTopItems(stats.TopIPs, 10, "IP", "Requêtes")

	// Top Pages
	r.printSection("📄 Top 10 Pages")
	r.displayTopItems(stats.TopPages, 10, "Page", "Hits")

	// Top User Agents
	r.printSection("🤖 Top 5 User Agents")
	r.displayTopUserAgents(stats.TopUserAgents, 5)

	// Codes de statut
	r.printSection("📊 Codes de Statut")
	r.displayStatusCodes(stats.StatusCodes)

	// Distribution horaire
	if len(stats.HourlyDistribution) > 0 {
		r.printSection("⏰ Distribution Horaire")
		r.displayHourlyDistribution(stats.HourlyDistribution)
	}

	// Menaces de sécurité
	if len(stats.SecurityThreats) > 0 {
		r.printSection("🚨 ALERTES SÉCURITÉ")
		r.displaySecurityThreats(stats.SecurityThreats)
		r.displayThreatSummary(stats.SecurityThreats)
	} else {
		r.printSection("✅ Sécurité")
		fmt.Println(color.GreenString("Aucune menace détectée"))
	}
}

func (r *Reporter) printHeader(title string) {
	fmt.Println()
	border := strings.Repeat("=", len(title)+4)
	fmt.Println(color.MagentaString(border))
	fmt.Println(color.MagentaString("| " + title + " |"))
	fmt.Println(color.MagentaString(border))
	fmt.Println()
}

func (r *Reporter) printSection(title string) {
	fmt.Println()
	fmt.Println(color.YellowString("▶ " + title))
	fmt.Println(color.YellowString(strings.Repeat("-", len(title)+2)))
}

func (r *Reporter) colorizeErrorRate(rate float64) string {
	if rate < 5.0 {
		return color.GreenString("%.2f%%", rate)
	} else if rate < 15.0 {
		return color.YellowString("%.2f%%", rate)
	} else {
		return color.RedString("%.2f%%", rate)
	}
}

func (r *Reporter) formatBytes(bytes int64) string {
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

func (r *Reporter) displayTopItems(items map[string]int, limit int, itemLabel, countLabel string) {
	// Convertir en slice et trier
	type itemCount struct {
		item  string
		count int
	}

	var sorted []itemCount
	for item, count := range items {
		sorted = append(sorted, itemCount{item, count})
	}

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})

	if len(sorted) == 0 {
		fmt.Println("Aucune donnée disponible")
		return
	}

	// Afficher dans un tableau
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Rang", itemLabel, countLabel, "Pourcentage"})
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	table.SetCenterSeparator("|")

	total := 0
	for _, item := range sorted {
		total += item.count
	}

	displayLimit := limit
	if displayLimit > len(sorted) {
		displayLimit = len(sorted)
	}

	for i := 0; i < displayLimit; i++ {
		item := sorted[i]
		percentage := float64(item.count) / float64(total) * 100

		// Tronquer les items trop longs
		displayItem := item.item
		if len(displayItem) > 50 {
			displayItem = displayItem[:47] + "..."
		}

		table.Append([]string{
			fmt.Sprintf("%d", i+1),
			displayItem,
			fmt.Sprintf("%d", item.count),
			fmt.Sprintf("%.1f%%", percentage),
		})
	}

	table.Render()
}

func (r *Reporter) displayTopUserAgents(userAgents map[string]int, limit int) {
	type uaCount struct {
		ua    string
		count int
	}

	var sorted []uaCount
	for ua, count := range userAgents {
		sorted = append(sorted, uaCount{ua, count})
	}

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})

	if len(sorted) == 0 {
		fmt.Println("Aucune donnée disponible")
		return
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Rang", "User Agent", "Requêtes"})
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	table.SetCenterSeparator("|")
	table.SetColWidth(60) // Largeur max pour User Agent

	displayLimit := limit
	if displayLimit > len(sorted) {
		displayLimit = len(sorted)
	}

	for i := 0; i < displayLimit; i++ {
		ua := sorted[i]
		displayUA := ua.ua
		if len(displayUA) > 60 {
			displayUA = displayUA[:57] + "..."
		}

		table.Append([]string{
			fmt.Sprintf("%d", i+1),
			displayUA,
			fmt.Sprintf("%d", ua.count),
		})
	}

	table.Render()
}

func (r *Reporter) displayMethodDistribution(methods map[string]int) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Méthode", "Requêtes", "Pourcentage"})
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	table.SetCenterSeparator("|")

	total := 0
	for _, count := range methods {
		total += count
	}

	// Ordre préféré pour les méthodes HTTP
	methodOrder := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}

	// Afficher d'abord les méthodes courantes
	for _, method := range methodOrder {
		if count, exists := methods[method]; exists {
			percentage := float64(count) / float64(total) * 100
			table.Append([]string{
				method,
				fmt.Sprintf("%d", count),
				fmt.Sprintf("%.1f%%", percentage),
			})
		}
	}

	// Puis les autres méthodes
	for method, count := range methods {
		found := false
		for _, knownMethod := range methodOrder {
			if method == knownMethod {
				found = true
				break
			}
		}
		if !found {
			percentage := float64(count) / float64(total) * 100
			table.Append([]string{
				method,
				fmt.Sprintf("%d", count),
				fmt.Sprintf("%.1f%%", percentage),
			})
		}
	}

	table.Render()
}

func (r *Reporter) displayStatusCodes(statusCodes map[int]int) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Code", "Description", "Count", "Status"})
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	table.SetCenterSeparator("|")

	// Trier par code de statut
	var codes []int
	for code := range statusCodes {
		codes = append(codes, code)
	}
	sort.Ints(codes)

	for _, code := range codes {
		count := statusCodes[code]
		description := r.getStatusDescription(code)
		statusColor := r.getStatusColor(code)

		table.Append([]string{
			strconv.Itoa(code),
			description,
			strconv.Itoa(count),
			statusColor,
		})
	}

	table.Render()
}

func (r *Reporter) displayHourlyDistribution(hourlyDist map[int]int) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Heure", "Requêtes", "Graphique"})
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	table.SetCenterSeparator("|")

	// Trouver le maximum pour le graphique
	maxRequests := 0
	for _, count := range hourlyDist {
		if count > maxRequests {
			maxRequests = count
		}
	}

	for hour := 0; hour < 24; hour++ {
		count := hourlyDist[hour]

		// Créer un graphique simple avec des caractères
		barLength := 0
		if maxRequests > 0 {
			barLength = (count * 20) / maxRequests // Barre sur 20 caractères max
		}

		bar := strings.Repeat("█", barLength)
		if barLength == 0 && count > 0 {
			bar = "▌" // Au moins un caractère si il y a des requêtes
		}

		table.Append([]string{
			fmt.Sprintf("%02d:00", hour),
			fmt.Sprintf("%d", count),
			bar,
		})
	}

	table.Render()
}

func (r *Reporter) getStatusDescription(code int) string {
	descriptions := map[int]string{
		200: "OK",
		201: "Created",
		202: "Accepted",
		204: "No Content",
		301: "Moved Permanently",
		302: "Found",
		304: "Not Modified",
		400: "Bad Request",
		401: "Unauthorized",
		403: "Forbidden",
		404: "Not Found",
		405: "Method Not Allowed",
		406: "Not Acceptable",
		408: "Request Timeout",
		409: "Conflict",
		410: "Gone",
		422: "Unprocessable Entity",
		429: "Too Many Requests",
		500: "Internal Server Error",
		501: "Not Implemented",
		502: "Bad Gateway",
		503: "Service Unavailable",
		504: "Gateway Timeout",
	}

	if desc, exists := descriptions[code]; exists {
		return desc
	}
	return "Unknown"
}

func (r *Reporter) getStatusColor(code int) string {
	if code < 300 {
		return "🟢 Success"
	} else if code < 400 {
		return "🟡 Redirect"
	} else if code < 500 {
		return "🟠 Client Error"
	} else {
		return "🔴 Server Error"
	}
}

func (r *Reporter) displaySecurityThreats(threats []analyzer.SecurityThreat) {
	if len(threats) == 0 {
		return
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Type", "IP", "Sévérité", "URL", "Time", "Description"})
	table.SetBorders(tablewriter.Border{Left: true, Top: false, Right: true, Bottom: false})
	table.SetCenterSeparator("|")
	table.SetColWidth(80)

	// Trier par sévérité puis par timestamp
	sort.Slice(threats, func(i, j int) bool {
		severityOrder := map[string]int{"HIGH": 3, "MEDIUM": 2, "LOW": 1}
		if severityOrder[threats[i].Severity] != severityOrder[threats[j].Severity] {
			return severityOrder[threats[i].Severity] > severityOrder[threats[j].Severity]
		}
		return threats[i].Timestamp.After(threats[j].Timestamp)
	})

	for _, threat := range threats {
		var severityColor string
		switch threat.Severity {
		case "HIGH":
			severityColor = "🔴 HIGH"
		case "MEDIUM":
			severityColor = "🟡 MEDIUM"
		case "LOW":
			severityColor = "🟢 LOW"
		default:
			severityColor = threat.Severity
		}

		url := threat.URL
		if len(url) > 40 {
			url = url[:37] + "..."
		}

		description := threat.Description
		if len(description) > 50 {
			description = description[:47] + "..."
		}

		table.Append([]string{
			threat.Type,
			threat.IP,
			severityColor,
			url,
			threat.Timestamp.Format("15:04:05"),
			description,
		})
	}

	table.Render()
}

func (r *Reporter) displayThreatSummary(threats []analyzer.SecurityThreat) {
	fmt.Println()
	fmt.Println(color.YellowString("📊 Résumé des Menaces:"))

	threatCount := make(map[string]int)
	severityCount := make(map[string]int)

	for _, threat := range threats {
		threatCount[threat.Type]++
		severityCount[threat.Severity]++
	}

	fmt.Printf("  Total: %s menaces détectées\n", color.RedString("%d", len(threats)))

	if severityCount["HIGH"] > 0 {
		fmt.Printf("  🔴 Critiques: %d\n", severityCount["HIGH"])
	}
	if severityCount["MEDIUM"] > 0 {
		fmt.Printf("  🟡 Moyennes: %d\n", severityCount["MEDIUM"])
	}
	if severityCount["LOW"] > 0 {
		fmt.Printf("  🟢 Faibles: %d\n", severityCount["LOW"])
	}

	fmt.Println("\n  Types détectés:")
	for threatType, count := range threatCount {
		fmt.Printf("    - %s: %d\n", threatType, count)
	}
}

// Export functions
func (r *Reporter) ExportToJSON(stats analyzer.Statistics, filename string) error {
	// Créer le dossier de sortie si nécessaire
	if err := os.MkdirAll("output", 0755); err != nil {
		return fmt.Errorf("erreur création dossier output: %v", err)
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("erreur création fichier JSON: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(stats)
}

func (r *Reporter) ExportToCSV(stats analyzer.Statistics, filename string) error {
	// Créer le dossier de sortie si nécessaire
	if err := os.MkdirAll("output", 0755); err != nil {
		return fmt.Errorf("erreur création dossier output: %v", err)
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("erreur création fichier CSV: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Header pour les menaces de sécurité
	writer.Write([]string{"Type", "IP", "URL", "Timestamp", "Severity", "Description"})

	// Exporter les menaces
	for _, threat := range stats.SecurityThreats {
		writer.Write([]string{
			threat.Type,
			threat.IP,
			threat.URL,
			threat.Timestamp.Format("2006-01-02 15:04:05"),
			threat.Severity,
			threat.Description,
		})
	}

	return nil
}
