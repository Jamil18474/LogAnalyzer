package parser

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type LogEntry struct {
	IP        string
	Timestamp time.Time
	Method    string
	URL       string
	Status    int
	Size      int64
	UserAgent string
	Referer   string
}

type LogParser struct {
	// Pattern pour logs Apache/Nginx format combiné
	logPattern *regexp.Regexp
}

func NewLogParser() *LogParser {
	// Format: IP - - [timestamp] "METHOD /path HTTP/1.1" status size "referer" "user-agent"
	pattern := regexp.MustCompile(`^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) ([^"]*)" (\d+) (\S+) "([^"]*)" "([^"]*)"`)
	return &LogParser{
		logPattern: pattern,
	}
}

func (p *LogParser) ParseFile(filename string) ([]LogEntry, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("erreur ouverture fichier: %v", err)
	}
	defer file.Close()

	var entries []LogEntry
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue // Ignorer les lignes vides
		}

		if entry, err := p.parseLine(line); err == nil {
			entries = append(entries, entry)
		} else {
			// En mode debug, vous pouvez décommenter cette ligne
			// fmt.Printf("Ligne %d ignorée: %s\n", lineNum, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("erreur lecture fichier: %v", err)
	}

	return entries, nil
}

func (p *LogParser) parseLine(line string) (LogEntry, error) {
	matches := p.logPattern.FindStringSubmatch(line)
	if len(matches) != 9 {
		return LogEntry{}, fmt.Errorf("format invalide: attendu 9 champs, trouvé %d", len(matches))
	}

	// Parse timestamp - formats multiples supportés
	timestamp, err := p.parseTimestamp(matches[2])
	if err != nil {
		timestamp = time.Now() // Fallback
	}

	// Parse status
	status, err := strconv.Atoi(matches[5])
	if err != nil {
		return LogEntry{}, fmt.Errorf("status code invalide: %s", matches[5])
	}

	// Parse size
	size := int64(0)
	if matches[6] != "-" {
		if s, err := strconv.ParseInt(matches[6], 10, 64); err == nil {
			size = s
		}
	}

	return LogEntry{
		IP:        matches[1],
		Timestamp: timestamp,
		Method:    matches[3],
		URL:       matches[4],
		Status:    status,
		Size:      size,
		Referer:   matches[7],
		UserAgent: matches[8],
	}, nil
}

func (p *LogParser) parseTimestamp(timeStr string) (time.Time, error) {
	// Format Apache: 13/Sep/2025:21:00:01 +0200
	layouts := []string{
		"02/Jan/2006:15:04:05 -0700",
		"02/Jan/2006:15:04:05",
		"2006-01-02 15:04:05",
		"2006/01/02 15:04:05",
	}

	for _, layout := range layouts {
		if t, err := time.Parse(layout, timeStr); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("format timestamp non reconnu: %s", timeStr)
}

// Fonction utilitaire pour valider les entrées
func (e LogEntry) IsValid() bool {
	return e.IP != "" && e.Method != "" && e.Status > 0
}

// Fonction pour obtenir des statistiques basiques du parsing
func (p *LogParser) GetParsingStats(entries []LogEntry) map[string]int {
	stats := make(map[string]int)

	for _, entry := range entries {
		stats["total"]++
		if entry.Status >= 200 && entry.Status < 300 {
			stats["success"]++
		} else if entry.Status >= 300 && entry.Status < 400 {
			stats["redirect"]++
		} else if entry.Status >= 400 && entry.Status < 500 {
			stats["client_error"]++
		} else if entry.Status >= 500 {
			stats["server_error"]++
		}
	}

	return stats
}
