package analyzer

import (
	"fmt"
	"loganalyzer/pkg/parser"
	"regexp"
	"sort"
	"strings"
	"time"
)

type SecurityThreat struct {
	Type        string
	IP          string
	URL         string
	Timestamp   time.Time
	Severity    string
	Description string
}

type Statistics struct {
	TotalRequests       int
	UniqueIPs           int
	ErrorRate           float64
	TopIPs              map[string]int
	TopPages            map[string]int
	TopUserAgents       map[string]int
	StatusCodes         map[int]int
	MethodDistribution  map[string]int
	SecurityThreats     []SecurityThreat
	BandwidthUsage      int64
	AverageResponseSize float64
	TimeRange           TimeRange
	HourlyDistribution  map[int]int
}

type TimeRange struct {
	Start time.Time
	End   time.Time
}

type Analyzer struct {
	sqlInjectionPattern *regexp.Regexp
	xssPattern          *regexp.Regexp
	bruteForcePattern   *regexp.Regexp
	scannerPattern      *regexp.Regexp
	suspiciousUAPattern *regexp.Regexp
}

func NewAnalyzer() *Analyzer {
	return &Analyzer{
		sqlInjectionPattern: regexp.MustCompile(`(?i)(union|select|insert|update|delete|drop|exec|script|alert|onload|information_schema|concat|char\(|0x[0-9a-f]+|sleep\(|benchmark\()`),
		xssPattern:          regexp.MustCompile(`(?i)(<script|javascript:|onload=|onerror=|alert\(|prompt\(|confirm\(|eval\(|document\.|window\.|<iframe|<object|<embed)`),
		bruteForcePattern:   regexp.MustCompile(`(?i)(wp-login|admin|login|auth|signin|password|pwd)`),
		scannerPattern:      regexp.MustCompile(`(?i)(\.\.\/|\.\.\\|\/etc\/|\/proc\/|\/var\/|\/usr\/|\/bin\/|\/sbin\/|\/root\/|\/home\/|\.htaccess|\.htpasswd|config\.php|phpinfo|web\.config)`),
		suspiciousUAPattern: regexp.MustCompile(`(?i)(bot|crawler|scanner|exploit|hack|injection|nikto|sqlmap|nmap|masscan|zmap|dirb|gobuster|wfuzz|burp|owasp)`),
	}
}

func (a *Analyzer) Analyze(entries []parser.LogEntry) Statistics {
	stats := Statistics{
		TopIPs:             make(map[string]int),
		TopPages:           make(map[string]int),
		TopUserAgents:      make(map[string]int),
		StatusCodes:        make(map[int]int),
		MethodDistribution: make(map[string]int),
		HourlyDistribution: make(map[int]int),
	}

	if len(entries) == 0 {
		return stats
	}

	ipRequestCount := make(map[string][]time.Time)
	uniqueIPs := make(map[string]bool)
	errorCount := 0
	totalSize := int64(0)

	// Initialiser les plages de temps
	stats.TimeRange.Start = entries[0].Timestamp
	stats.TimeRange.End = entries[0].Timestamp

	for _, entry := range entries {
		if !entry.IsValid() {
			continue
		}

		stats.TotalRequests++

		// Mise à jour des plages de temps
		if entry.Timestamp.Before(stats.TimeRange.Start) {
			stats.TimeRange.Start = entry.Timestamp
		}
		if entry.Timestamp.After(stats.TimeRange.End) {
			stats.TimeRange.End = entry.Timestamp
		}

		// IPs uniques
		uniqueIPs[entry.IP] = true
		stats.TopIPs[entry.IP]++

		// Pages populaires
		page := a.normalizePage(entry.URL)
		stats.TopPages[page]++

		// User Agents
		ua := a.normalizeUserAgent(entry.UserAgent)
		stats.TopUserAgents[ua]++

		// Codes de statut
		stats.StatusCodes[entry.Status]++

		// Distribution des méthodes HTTP
		stats.MethodDistribution[entry.Method]++

		// Distribution horaire
		hour := entry.Timestamp.Hour()
		stats.HourlyDistribution[hour]++

		// Taux d'erreur
		if entry.Status >= 400 {
			errorCount++
		}

		// Usage bande passante
		totalSize += entry.Size

		// Détection de menaces
		threats := a.detectThreats(entry)
		stats.SecurityThreats = append(stats.SecurityThreats, threats...)

		// Suivi pour détection brute force
		ipRequestCount[entry.IP] = append(ipRequestCount[entry.IP], entry.Timestamp)
	}

	stats.UniqueIPs = len(uniqueIPs)
	stats.BandwidthUsage = totalSize

	if stats.TotalRequests > 0 {
		stats.ErrorRate = float64(errorCount) / float64(stats.TotalRequests) * 100
		stats.AverageResponseSize = float64(totalSize) / float64(stats.TotalRequests)
	}

	// Détection brute force
	bruteForceThreats := a.detectBruteForce(ipRequestCount)
	stats.SecurityThreats = append(stats.SecurityThreats, bruteForceThreats...)

	// Détection d'anomalies de trafic
	anomalies := a.detectTrafficAnomalies(ipRequestCount)
	stats.SecurityThreats = append(stats.SecurityThreats, anomalies...)

	return stats
}

func (a *Analyzer) detectThreats(entry parser.LogEntry) []SecurityThreat {
	var threats []SecurityThreat

	// SQL Injection
	if a.sqlInjectionPattern.MatchString(entry.URL) {
		threats = append(threats, SecurityThreat{
			Type:        "SQL_INJECTION",
			IP:          entry.IP,
			URL:         entry.URL,
			Timestamp:   entry.Timestamp,
			Severity:    "HIGH",
			Description: "Tentative d'injection SQL détectée dans l'URL",
		})
	}

	// XSS
	if a.xssPattern.MatchString(entry.URL) || a.xssPattern.MatchString(entry.UserAgent) {
		threats = append(threats, SecurityThreat{
			Type:        "XSS",
			IP:          entry.IP,
			URL:         entry.URL,
			Timestamp:   entry.Timestamp,
			Severity:    "MEDIUM",
			Description: "Tentative de Cross-Site Scripting détectée",
		})
	}

	// Directory Traversal / Local File Inclusion
	if a.scannerPattern.MatchString(entry.URL) {
		threats = append(threats, SecurityThreat{
			Type:        "DIRECTORY_TRAVERSAL",
			IP:          entry.IP,
			URL:         entry.URL,
			Timestamp:   entry.Timestamp,
			Severity:    "HIGH",
			Description: "Tentative de traversée de répertoire ou LFI détectée",
		})
	}

	// Scanner / Bot malveillant détecté via User-Agent
	if a.suspiciousUAPattern.MatchString(entry.UserAgent) {
		threats = append(threats, SecurityThreat{
			Type:        "SUSPICIOUS_BOT",
			IP:          entry.IP,
			URL:         entry.URL,
			Timestamp:   entry.Timestamp,
			Severity:    "MEDIUM",
			Description: fmt.Sprintf("Bot/Scanner suspect détecté: %s", a.truncateString(entry.UserAgent, 50)),
		})
	}

	// Pages sensibles
	if a.bruteForcePattern.MatchString(entry.URL) && entry.Status == 401 {
		threats = append(threats, SecurityThreat{
			Type:        "AUTH_FAILURE",
			IP:          entry.IP,
			URL:         entry.URL,
			Timestamp:   entry.Timestamp,
			Severity:    "LOW",
			Description: "Échec d'authentification sur page sensible",
		})
	}

	return threats
}

func (a *Analyzer) detectBruteForce(ipRequests map[string][]time.Time) []SecurityThreat {
	var threats []SecurityThreat

	for ip, timestamps := range ipRequests {
		if len(timestamps) < 10 { // Seuil minimum
			continue
		}

		// Trier les timestamps
		sort.Slice(timestamps, func(i, j int) bool {
			return timestamps[i].Before(timestamps[j])
		})

		// Analyser les fenêtres temporelles
		windowSize := time.Hour
		threshold := 50

		for i := 0; i < len(timestamps); i++ {
			windowEnd := timestamps[i].Add(windowSize)
			requestsInWindow := 0

			for j := i; j < len(timestamps) && timestamps[j].Before(windowEnd); j++ {
				requestsInWindow++
			}

			if requestsInWindow >= threshold {
				threats = append(threats, SecurityThreat{
					Type:        "BRUTE_FORCE",
					IP:          ip,
					URL:         "Multiple",
					Timestamp:   timestamps[i],
					Severity:    "HIGH",
					Description: fmt.Sprintf("Possible attaque brute force: %d requêtes en %v", requestsInWindow, windowSize),
				})
				break // Une détection par IP suffit
			}
		}
	}

	return threats
}

func (a *Analyzer) detectTrafficAnomalies(ipRequests map[string][]time.Time) []SecurityThreat {
	var threats []SecurityThreat

	// Détecter les pics de trafic anormaux (DDoS potentiel)
	for ip, timestamps := range ipRequests {
		if len(timestamps) > 1000 { // Seuil de trafic élevé
			duration := timestamps[len(timestamps)-1].Sub(timestamps[0])
			if duration < 10*time.Minute { // Beaucoup de requêtes en peu de temps
				threats = append(threats, SecurityThreat{
					Type:        "DDOS_ATTEMPT",
					IP:          ip,
					URL:         "Multiple",
					Timestamp:   timestamps[0],
					Severity:    "HIGH",
					Description: fmt.Sprintf("Tentative de DDoS potentielle: %d requêtes en %v", len(timestamps), duration),
				})
			}
		}
	}

	return threats
}

// Fonctions utilitaires
func (a *Analyzer) normalizePage(url string) string {
	// Supprimer les paramètres de requête pour grouper les pages similaires
	if idx := strings.Index(url, "?"); idx != -1 {
		url = url[:idx]
	}

	// Limiter la longueur
	return a.truncateString(url, 100)
}

func (a *Analyzer) normalizeUserAgent(ua string) string {
	// Extraire les informations importantes du User-Agent
	if len(ua) > 100 {
		return ua[:97] + "..."
	}
	return ua
}

func (a *Analyzer) truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// Fonction pour obtenir les top N éléments d'une map
func (a *Analyzer) GetTopItems(items map[string]int, limit int) []struct {
	Item  string
	Count int
} {
	type itemCount struct {
		Item  string
		Count int
	}

	var sorted []itemCount
	for item, count := range items {
		sorted = append(sorted, itemCount{item, count})
	}

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Count > sorted[j].Count
	})

	if limit > len(sorted) {
		limit = len(sorted)
	}

	result := make([]struct {
		Item  string
		Count int
	}, limit)

	for i := 0; i < limit; i++ {
		result[i].Item = sorted[i].Item
		result[i].Count = sorted[i].Count
	}

	return result
}
