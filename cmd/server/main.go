package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

type Config struct {
	Server       ServerConfig
	VictoriaLogs VictoriaLogsConfig
	Report       ReportConfig
}

type ServerConfig struct{ Addr string }

type VictoriaLogsConfig struct {
	BaseURL   string
	QueryPath string
	Timeout   string
	Auth      AuthConfig
	Headers   map[string]string
}

type AuthConfig struct {
	Type     string
	Username string
	Password string
	Bearer   string
}

type ReportConfig struct {
	DefaultStart       string
	DefaultEnd         string
	DefaultStep        string
	BaseQuery          string
	HostField          string
	ContainerField     string
	HostFilterTemplate string
	InventoryHosts     []string
	Concurrency        int
	QueryLimit         int
	SampleLogLimit     int
	ExpectedHosts      int
	ExpectedGPUs       int
	ErrorKeywords      []string
	WarnKeywords       []string
	StartupKeywords    []string
	BusyKeywords       []string
}

type App struct {
	cfg    Config
	client *http.Client
	tpl    *template.Template
}

type SummaryRow struct {
	Host             string  `json:"host"`
	ContainerName    string  `json:"container_name"`
	LogEvents        int64   `json:"log_events"`
	ActiveBuckets    int64   `json:"active_buckets"`
	ActiveMinutes    float64 `json:"active_minutes"`
	ActiveHours      float64 `json:"active_hours"`
	DutyCycle        float64 `json:"duty_cycle"`
	FirstSeen        string  `json:"first_seen"`
	LastSeen         string  `json:"last_seen"`
	Sessions         int     `json:"sessions"`
	Errors           int64   `json:"errors"`
	Warnings         int64   `json:"warnings"`
	Startups         int64   `json:"startups"`
	BusyHints        int64   `json:"busy_hints"`
	EventsPerHour    float64 `json:"events_per_hour"`
	UtilizationClass string  `json:"utilization_class"`
	WorkloadClass    string  `json:"workload_class"`
	AnalysisZH       string  `json:"analysis_zh"`
	AnalysisEN       string  `json:"analysis_en"`
	SeverityScore    float64 `json:"severity_score"`
}

type HostRollup struct {
	Host             string  `json:"host"`
	Containers       int     `json:"containers"`
	TotalEvents      int64   `json:"total_events"`
	ActiveHours      float64 `json:"active_hours"`
	AvgDutyCycle     float64 `json:"avg_duty_cycle"`
	ErrorContainers  int     `json:"error_containers"`
	BusyContainers   int     `json:"busy_containers"`
	DominantWorkload string  `json:"dominant_workload"`
}

type Diagnostics struct {
	HostQueries          int      `json:"host_queries"`
	HostsWithData        int      `json:"hosts_with_data"`
	ContainerQueries     int      `json:"container_queries"`
	QueryLimit           int      `json:"query_limit"`
	SummaryQuerySeconds  float64  `json:"summary_query_seconds"`
	TimelineQuerySeconds float64  `json:"timeline_query_seconds"`
	SignalQuerySeconds   float64  `json:"signal_query_seconds"`
	SkippedHosts         []string `json:"skipped_hosts"`
	Note                 string   `json:"note"`
}

type ReportResponse struct {
	From              string       `json:"from"`
	To                string       `json:"to"`
	Step              string       `json:"step"`
	Query             string       `json:"query"`
	TotalHosts        int          `json:"total_hosts"`
	ActiveHosts       int          `json:"active_hosts"`
	TotalContainers   int          `json:"total_containers"`
	ActiveContainers  int          `json:"active_containers"`
	ExpectedHosts     int          `json:"expected_hosts"`
	ExpectedGPUs      int          `json:"expected_gpus"`
	HostCoverageRatio float64      `json:"host_coverage_ratio"`
	AvgDutyCycle      float64      `json:"avg_duty_cycle"`
	TotalEvents       int64        `json:"total_events"`
	TotalActiveHours  float64      `json:"total_active_hours"`
	HotContainers     int          `json:"hot_containers"`
	CapacityPressure  string       `json:"capacity_pressure"`
	ExecSummaryZH     string       `json:"exec_summary_zh"`
	ExecSummaryEN     string       `json:"exec_summary_en"`
	Rows              []SummaryRow `json:"rows"`
	HostRollup        []HostRollup `json:"host_rollup"`
	Diagnostics       Diagnostics  `json:"diagnostics"`
	GeneratedAt       string       `json:"generated_at"`
}

type ContainerLogsResponse struct {
	Host          string   `json:"host"`
	ContainerName string   `json:"container_name"`
	Lines         []string `json:"lines"`
}

type aggLine struct {
	Host, Container string
	Count           int64
	FirstSeen       time.Time
	LastSeen        time.Time
}

type bucketLine struct {
	Host, Container string
	Bucket          time.Time
}

type signalLine struct {
	Host, Container string
	Count           int64
}

type rowBuild struct {
	Row     SummaryRow
	Buckets []time.Time
}

type hostResult struct {
	Host        string
	Summary     []aggLine
	Buckets     []bucketLine
	Errors      []signalLine
	Warns       []signalLine
	Startups    []signalLine
	Busy        []signalLine
	SummarySec  float64
	TimelineSec float64
	SignalSec   float64
	Skipped     bool
	SkipReason  string
}

func main() {
	cfgPath := "/Users/allenflux/GolandProjects/comfyui_usage_report_v2/config.yaml.example"
	if len(os.Args) > 2 && os.Args[1] == "-config" {
		cfgPath = os.Args[2]
	} else if len(os.Args) > 1 && strings.TrimSpace(os.Args[1]) != "" {
		cfgPath = os.Args[1]
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	timeout, _ := time.ParseDuration(cfg.VictoriaLogs.Timeout)
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	b, err := os.ReadFile("./web/index.html")
	if err != nil {
		log.Fatal(err)
	}
	app := &App{
		cfg:    cfg,
		client: &http.Client{Timeout: timeout},
		tpl:    template.Must(template.New("index").Parse(string(b))),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", app.handleIndex)
	mux.HandleFunc("/api/report", app.handleReport)
	mux.HandleFunc("/api/report.csv", app.handleCSV)
	mux.HandleFunc("/api/container_logs", app.handleContainerLogs)
	log.Printf("listen on %s", cfg.Server.Addr)
	log.Fatal(http.ListenAndServe(cfg.Server.Addr, mux))
}

func loadConfig(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	cfg, err := parseSimpleYAML(string(b))
	if err != nil {
		return Config{}, err
	}
	if cfg.Server.Addr == "" {
		cfg.Server.Addr = ":8080"
	}
	if cfg.VictoriaLogs.QueryPath == "" {
		cfg.VictoriaLogs.QueryPath = "/select/logsql/query"
	}
	if cfg.VictoriaLogs.Timeout == "" {
		cfg.VictoriaLogs.Timeout = "120s"
	}
	if cfg.Report.DefaultStep == "" {
		cfg.Report.DefaultStep = "1m"
	}
	if cfg.Report.BaseQuery == "" {
		cfg.Report.BaseQuery = "*"
	}
	if cfg.Report.HostField == "" {
		cfg.Report.HostField = "host"
	}
	if cfg.Report.ContainerField == "" {
		cfg.Report.ContainerField = "container_name"
	}
	if cfg.Report.HostFilterTemplate == "" {
		cfg.Report.HostFilterTemplate = "%s:=%q"
	}
	if cfg.Report.Concurrency <= 0 {
		cfg.Report.Concurrency = 8
	}
	if cfg.Report.QueryLimit <= 0 {
		cfg.Report.QueryLimit = 500
	}
	if cfg.Report.SampleLogLimit <= 0 {
		cfg.Report.SampleLogLimit = 80
	}
	if cfg.VictoriaLogs.Headers == nil {
		cfg.VictoriaLogs.Headers = map[string]string{}
	}
	return cfg, nil
}

func parseSimpleYAML(src string) (Config, error) {
	var cfg Config
	cfg.VictoriaLogs.Headers = map[string]string{}
	lines := strings.Split(src, "\n")
	section, subsection, listName := "", "", ""
	for _, raw := range lines {
		line := raw
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = line[:idx]
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "- ") {
			item := trimQuotes(strings.TrimSpace(strings.TrimPrefix(t, "- ")))
			switch listName {
			case "inventory_hosts":
				cfg.Report.InventoryHosts = append(cfg.Report.InventoryHosts, item)
			case "error_keywords":
				cfg.Report.ErrorKeywords = append(cfg.Report.ErrorKeywords, item)
			case "warn_keywords":
				cfg.Report.WarnKeywords = append(cfg.Report.WarnKeywords, item)
			case "startup_keywords":
				cfg.Report.StartupKeywords = append(cfg.Report.StartupKeywords, item)
			case "busy_keywords":
				cfg.Report.BusyKeywords = append(cfg.Report.BusyKeywords, item)
			}
			continue
		}
		listName = ""
		parts := strings.SplitN(t, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if indent == 0 {
			section = key
			subsection = ""
			continue
		}
		if indent == 2 && val == "" {
			if section == "victorialogs" && (key == "auth" || key == "headers") {
				subsection = key
				continue
			}
			if section == "report" && (key == "inventory_hosts" || strings.HasSuffix(key, "_keywords")) {
				listName = key
				subsection = ""
				continue
			}
		}
		val = trimQuotes(val)
		switch section {
		case "server":
			if key == "addr" {
				cfg.Server.Addr = val
			}
		case "victorialogs":
			if subsection == "auth" && indent >= 4 {
				switch key {
				case "type":
					cfg.VictoriaLogs.Auth.Type = val
				case "username":
					cfg.VictoriaLogs.Auth.Username = val
				case "password":
					cfg.VictoriaLogs.Auth.Password = val
				case "bearer":
					cfg.VictoriaLogs.Auth.Bearer = val
				}
				continue
			}
			if subsection == "headers" && indent >= 4 {
				cfg.VictoriaLogs.Headers[key] = val
				continue
			}
			switch key {
			case "base_url":
				cfg.VictoriaLogs.BaseURL = val
			case "query_path":
				cfg.VictoriaLogs.QueryPath = val
			case "timeout":
				cfg.VictoriaLogs.Timeout = val
			}
		case "report":
			switch key {
			case "default_start":
				cfg.Report.DefaultStart = val
			case "default_end":
				cfg.Report.DefaultEnd = val
			case "default_step":
				cfg.Report.DefaultStep = val
			case "base_query":
				cfg.Report.BaseQuery = val
			case "host_field":
				cfg.Report.HostField = val
			case "container_field":
				cfg.Report.ContainerField = val
			case "host_filter_template":
				cfg.Report.HostFilterTemplate = val
			case "concurrency":
				cfg.Report.Concurrency, _ = strconv.Atoi(val)
			case "query_limit":
				cfg.Report.QueryLimit, _ = strconv.Atoi(val)
			case "sample_log_limit":
				cfg.Report.SampleLogLimit, _ = strconv.Atoi(val)
			case "expected_hosts":
				cfg.Report.ExpectedHosts, _ = strconv.Atoi(val)
			case "expected_gpus":
				cfg.Report.ExpectedGPUs, _ = strconv.Atoi(val)
			}
		}
	}
	return cfg, nil
}

func trimQuotes(s string) string { return strings.Trim(strings.TrimSpace(s), "\"'") }

func canonicalHostName(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return ""
	}
	v = strings.ReplaceAll(v, "_", "-")
	v = strings.ReplaceAll(v, " ", "-")
	return v
}

func compactHostNumbering(v string) string {
	v = canonicalHostName(v)
	re := regexp.MustCompile(`^(.*?)-(\d+)$`)
	m := re.FindStringSubmatch(v)
	if len(m) != 3 {
		return v
	}
	n, err := strconv.Atoi(m[2])
	if err != nil {
		return v
	}
	return fmt.Sprintf("%s-%d", m[1], n)
}

func hostDisplayName(v string) string {
	return strings.ToUpper(canonicalHostName(v))
}

func normalizeFieldValue(field, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.EqualFold(field, "host") {
		return hostDisplayName(value)
	}
	return value
}

func hostQueryVariants(host string) []string {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil
	}
	base := canonicalHostName(host)
	compact := compactHostNumbering(host)
	seen := make(map[string]struct{}, 8)
	out := make([]string, 0, 8)
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	add(base)
	add(compact)
	add(strings.ReplaceAll(base, "-", "_"))
	add(strings.ReplaceAll(compact, "-", "_"))
	add(strings.ToUpper(base))
	add(strings.ToUpper(compact))
	add(strings.ReplaceAll(strings.ToUpper(base), "-", "_"))
	add(strings.ReplaceAll(strings.ToUpper(compact), "-", "_"))
	return out
}

func needsQuotedField(name string) bool {
	for _, r := range name {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '.' || r == '-') {
			return true
		}
	}
	return false
}

func quoteFieldName(name string) string {
	if needsQuotedField(name) {
		return strconv.Quote(name)
	}
	return name
}

func buildHostScopedFilter(base, hostField, hostTpl, host string) string {
	base = strings.TrimSpace(base)
	if base == "" {
		base = "*"
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return base
	}
	variants := hostQueryVariants(host)
	clauses := make([]string, 0, len(variants))
	field := quoteFieldName(hostField)
	for _, v := range variants {
		clauses = append(clauses, fmt.Sprintf("%s:=%q", field, v))
	}
	return fmt.Sprintf("(%s) AND ((%s))", base, strings.Join(clauses, " OR "))
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	data := map[string]any{
		"DefaultFrom":  time.Now().Add(-24 * time.Hour).Format("2006-01-02T15:04"),
		"DefaultTo":    time.Now().Format("2006-01-02T15:04"),
		"DefaultStep":  a.cfg.Report.DefaultStep,
		"DefaultQuery": a.cfg.Report.BaseQuery,
	}
	if err := a.tpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

func (a *App) handleReport(w http.ResponseWriter, r *http.Request) {
	from, err := parseInputTime(r.URL.Query().Get("from"), time.Now().Add(-24*time.Hour))
	if err != nil {
		http.Error(w, "invalid from", 400)
		return
	}
	to, err := parseInputTime(r.URL.Query().Get("to"), time.Now())
	if err != nil {
		http.Error(w, "invalid to", 400)
		return
	}
	if !to.After(from) {
		http.Error(w, "to must be greater than from", 400)
		return
	}
	step := strings.TrimSpace(r.URL.Query().Get("step"))
	if step == "" {
		step = a.cfg.Report.DefaultStep
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		q = a.cfg.Report.BaseQuery
	}
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	log.Printf("[HTTP] /api/report from=%s to=%s step=%s host=%q q=%q", from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339), step, host, q)
	rep, err := a.buildReport(r.Context(), from.UTC(), to.UTC(), step, q, host)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(rep)
}

func (a *App) handleCSV(w http.ResponseWriter, r *http.Request) {
	from, _ := parseInputTime(r.URL.Query().Get("from"), time.Now().Add(-24*time.Hour))
	to, _ := parseInputTime(r.URL.Query().Get("to"), time.Now())
	step := strings.TrimSpace(r.URL.Query().Get("step"))
	if step == "" {
		step = a.cfg.Report.DefaultStep
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		q = a.cfg.Report.BaseQuery
	}
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	log.Printf("[HTTP] /api/report from=%s to=%s step=%s host=%q q=%q", from.UTC().Format(time.RFC3339), to.UTC().Format(time.RFC3339), step, host, q)
	rep, err := a.buildReport(r.Context(), from.UTC(), to.UTC(), step, q, host)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"host", "container_name", "log_events", "active_hours", "duty_cycle", "errors", "warnings", "busy_hints", "sessions", "analysis_zh"})
	for _, row := range rep.Rows {
		_ = cw.Write([]string{
			row.Host, row.ContainerName, strconv.FormatInt(row.LogEvents, 10),
			fmt.Sprintf("%.2f", row.ActiveHours), fmt.Sprintf("%.4f", row.DutyCycle),
			strconv.FormatInt(row.Errors, 10), strconv.FormatInt(row.Warnings, 10),
			strconv.FormatInt(row.BusyHints, 10), strconv.Itoa(row.Sessions), row.AnalysisZH,
		})
	}
	cw.Flush()
}

func (a *App) handleContainerLogs(w http.ResponseWriter, r *http.Request) {
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	containerName := strings.TrimSpace(r.URL.Query().Get("container"))
	if host == "" || containerName == "" {
		http.Error(w, "host and container are required", 400)
		return
	}
	from, _ := parseInputTime(r.URL.Query().Get("from"), time.Now().Add(-24*time.Hour))
	to, _ := parseInputTime(r.URL.Query().Get("to"), time.Now())
	lines, err := a.fetchContainerLogs(r.Context(), from.UTC(), to.UTC(), host, containerName)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(ContainerLogsResponse{
		Host: hostDisplayName(host), ContainerName: containerName, Lines: lines,
	})
}

func (a *App) buildReport(ctx context.Context, from, to time.Time, step, baseQuery, host string) (*ReportResponse, error) {
	baseQuery = strings.TrimSpace(baseQuery)
	if baseQuery == "" {
		baseQuery = "*"
	}
	targetHosts := []string{}
	if strings.TrimSpace(host) != "" {
		targetHosts = append(targetHosts, canonicalHostName(host))
	} else {
		for _, h := range a.cfg.Report.InventoryHosts {
			if strings.TrimSpace(h) != "" {
				targetHosts = append(targetHosts, canonicalHostName(h))
			}
		}
	}
	if len(targetHosts) == 0 {
		return nil, errors.New("inventory_hosts is empty")
	}
	sort.Strings(targetHosts)

	jobs := make(chan string)
	results := make(chan hostResult, len(targetHosts))
	var wg sync.WaitGroup
	workerN := a.cfg.Report.Concurrency
	if workerN <= 0 {
		workerN = 8
	}
	for i := 0; i < workerN; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				results <- a.collectHost(ctx, from, to, step, baseQuery, h)
			}
		}()
	}
	go func() {
		for _, h := range targetHosts {
			jobs <- h
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	summaryRows := []aggLine{}
	bucketRows := []bucketLine{}
	errRows := []signalLine{}
	warnRows := []signalLine{}
	startupRows := []signalLine{}
	busyRows := []signalLine{}
	activeHostSet := map[string]struct{}{}
	var summarySec, timelineSec, signalSec float64

	skippedHosts := make([]string, 0, len(targetHosts))
	for hr := range results {
		summarySec += hr.SummarySec
		timelineSec += hr.TimelineSec
		signalSec += hr.SignalSec

		if hr.Skipped {
			skippedHosts = append(skippedHosts, fmt.Sprintf("%s (%s)", hr.Host, hr.SkipReason))
			continue
		}

		if len(hr.Summary) > 0 {
			activeHostSet[hr.Host] = struct{}{}
		}
		summaryRows = append(summaryRows, hr.Summary...)
		bucketRows = append(bucketRows, hr.Buckets...)
		errRows = append(errRows, hr.Errors...)
		warnRows = append(warnRows, hr.Warns...)
		startupRows = append(startupRows, hr.Startups...)
		busyRows = append(busyRows, hr.Busy...)
	}
	if len(summaryRows) == 0 {
		log.Printf("[REPORT] no host-level summary rows collected; hosts=%d skipped=%d", len(targetHosts), len(skippedHosts))
		return &ReportResponse{
			From:             from.Format(time.RFC3339),
			To:               to.Format(time.RFC3339),
			Step:             step,
			Query:            baseQuery,
			TotalHosts:       len(targetHosts),
			ActiveHosts:      0,
			TotalContainers:  0,
			ActiveContainers: 0,
			ExpectedHosts:    a.cfg.Report.ExpectedHosts,
			ExpectedGPUs:     a.cfg.Report.ExpectedGPUs,
			Rows:             []SummaryRow{},
			HostRollup:       []HostRollup{},
			Diagnostics: Diagnostics{
				HostQueries:          len(targetHosts),
				HostsWithData:        0,
				ContainerQueries:     0,
				QueryLimit:           a.cfg.Report.QueryLimit,
				SummaryQuerySeconds:  round3(summarySec),
				TimelineQuerySeconds: round3(timelineSec),
				SignalQuerySeconds:   round3(signalSec),
				SkippedHosts:         skippedHosts,
				Note:                 "No host produced data. Errors were skipped. The current host filter uses exact-match OR clauses such as host:=\"tw-5090-8\" OR host:=\"tw-5090-08\". This usually means the host field name is wrong, the host values differ from the inventory list, or the selected time range truly has no matching logs.",
			},
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		}, nil
	}

	buildMap := map[string]*rowBuild{}
	windowHours := to.Sub(from).Hours()
	stepDur := parseStep(step)
	for _, s := range summaryRows {
		key := s.Host + "\x00" + s.Container
		buildMap[key] = &rowBuild{Row: SummaryRow{
			Host: s.Host, ContainerName: s.Container, LogEvents: s.Count,
			FirstSeen: formatTime(s.FirstSeen), LastSeen: formatTime(s.LastSeen),
		}}
	}
	for _, b := range bucketRows {
		key := b.Host + "\x00" + b.Container
		rb := buildMap[key]
		if rb == nil {
			rb = &rowBuild{Row: SummaryRow{Host: b.Host, ContainerName: b.Container}}
			buildMap[key] = rb
		}
		rb.Row.ActiveBuckets++
		rb.Buckets = append(rb.Buckets, b.Bucket)
	}
	applySignal(buildMap, errRows, "error")
	applySignal(buildMap, warnRows, "warn")
	applySignal(buildMap, startupRows, "startup")
	applySignal(buildMap, busyRows, "busy")

	rows := make([]SummaryRow, 0, len(buildMap))
	hostRoll := map[string]*HostRollup{}
	var totalEvents int64
	totalActiveHours := 0.0
	totalDuty := 0.0
	hotContainers := 0
	gapThreshold := 2 * stepDur

	for _, rb := range buildMap {
		sort.Slice(rb.Buckets, func(i, j int) bool { return rb.Buckets[i].Before(rb.Buckets[j]) })
		//rb.Row.ActiveMinutes = round2(float64(rb.Row.ActiveBuckets) * stepDur.Minutes())
		//rb.Row.ActiveHours = round2(rb.Row.ActiveMinutes / 60)
		dur := calcActiveDuration(rb.Buckets, gapThreshold)

		rb.Row.ActiveMinutes = round2(dur.Minutes())
		rb.Row.ActiveHours = round2(dur.Hours())
		if windowHours > 0 {
			rb.Row.DutyCycle = round4(rb.Row.ActiveHours / windowHours)
		}
		if rb.Row.ActiveHours > 0 {
			rb.Row.EventsPerHour = round2(float64(rb.Row.LogEvents) / rb.Row.ActiveHours)
		}
		rb.Row.Sessions = estimateSessions(rb.Buckets, gapThreshold)
		rb.Row.UtilizationClass, rb.Row.WorkloadClass, rb.Row.AnalysisZH, rb.Row.AnalysisEN = classify(rb.Row)
		rb.Row.SeverityScore = round2(rb.Row.DutyCycle*50 + float64(rb.Row.BusyHints)*0.5 + float64(rb.Row.Errors)*0.8 + float64(rb.Row.Warnings)*0.15 + float64(rb.Row.Startups)*0.2)
		if rb.Row.DutyCycle >= 0.60 || rb.Row.ActiveHours >= 8 {
			hotContainers++
		}
		totalEvents += rb.Row.LogEvents
		totalActiveHours += rb.Row.ActiveHours
		totalDuty += rb.Row.DutyCycle

		hr := hostRoll[rb.Row.Host]
		if hr == nil {
			hr = &HostRollup{Host: rb.Row.Host}
			hostRoll[rb.Row.Host] = hr
		}
		hr.Containers++
		hr.TotalEvents += rb.Row.LogEvents
		hr.ActiveHours = round2(hr.ActiveHours + rb.Row.ActiveHours)
		hr.AvgDutyCycle += rb.Row.DutyCycle
		if rb.Row.Errors > 0 {
			hr.ErrorContainers++
		}
		if rb.Row.BusyHints > 0 || rb.Row.DutyCycle >= 0.6 {
			hr.BusyContainers++
		}
		rows = append(rows, rb.Row)
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].SeverityScore == rows[j].SeverityScore {
			return rows[i].LogEvents > rows[j].LogEvents
		}
		return rows[i].SeverityScore > rows[j].SeverityScore
	})

	hostRows := make([]HostRollup, 0, len(hostRoll))
	for hostName, hr := range hostRoll {
		hr.AvgDutyCycle = round4(hr.AvgDutyCycle / float64(max(1, hr.Containers)))
		hr.DominantWorkload = dominantWorkload(rows, hostName)
		hostRows = append(hostRows, *hr)
	}
	sort.Slice(hostRows, func(i, j int) bool { return hostRows[i].ActiveHours > hostRows[j].ActiveHours })

	totalHosts := len(targetHosts)
	activeHosts := len(activeHostSet)
	totalContainers := len(buildMap)
	activeContainers := len(rows)
	hostCoverageRatio := 0.0
	if a.cfg.Report.ExpectedHosts > 0 {
		hostCoverageRatio = round4(float64(totalHosts) / float64(a.cfg.Report.ExpectedHosts))
	}
	avgDutyCycle := avgDuty(totalDuty, len(rows))
	pressure := "moderate"
	if hotContainers >= max(12, len(rows)/3) || avgDutyCycle >= 0.55 || activeHosts <= max(3, totalHosts/3) {
		pressure = "high"
	}
	if hotContainers >= max(20, len(rows)/2) || avgDutyCycle >= 0.7 {
		pressure = "critical"
	}

	summaryZH := fmt.Sprintf("本报告基于固定 Host 清单逐台查询 ComfyUI 日志。当前清单共 %d 台 Host，其中 %d 台在所选时间窗内出现运行日志；共识别 %d 个活跃容器、%d 条日志、%.2f 小时活跃时间。按“有日志即在用、无日志即空闲”的口径，当前有效 GPU 承载面偏小，热点容器 %d 个，说明集群难以安全承接更多并发任务。", totalHosts, activeHosts, activeContainers, totalEvents, round2(totalActiveHours), hotContainers)
	summaryEN := fmt.Sprintf("This report queries ComfyUI logs host-by-host from a fixed inventory. The inventory contains %d hosts, of which %d showed runtime logs in the selected window. It detected %d active containers, %d log events, and %.2f active hours. Under the rule of 'logs mean busy, no logs mean idle', the effective GPU serving fleet is still small, with %d hot containers, so the cluster is not in a safe position to absorb much more concurrent workload.", totalHosts, activeHosts, activeContainers, totalEvents, round2(totalActiveHours), hotContainers)

	return &ReportResponse{
		From:              from.Format(time.RFC3339),
		To:                to.Format(time.RFC3339),
		Step:              step,
		Query:             baseQuery,
		TotalHosts:        totalHosts,
		ActiveHosts:       activeHosts,
		TotalContainers:   totalContainers,
		ActiveContainers:  activeContainers,
		ExpectedHosts:     a.cfg.Report.ExpectedHosts,
		ExpectedGPUs:      a.cfg.Report.ExpectedGPUs,
		HostCoverageRatio: hostCoverageRatio,
		AvgDutyCycle:      avgDutyCycle,
		TotalEvents:       totalEvents,
		TotalActiveHours:  round2(totalActiveHours),
		HotContainers:     hotContainers,
		CapacityPressure:  pressure,
		ExecSummaryZH:     summaryZH,
		ExecSummaryEN:     summaryEN,
		Rows:              rows,
		HostRollup:        hostRows,
		Diagnostics: Diagnostics{
			HostQueries:          totalHosts,
			HostsWithData:        activeHosts,
			ContainerQueries:     totalContainers,
			QueryLimit:           a.cfg.Report.QueryLimit,
			SummaryQuerySeconds:  round3(summarySec),
			TimelineQuerySeconds: round3(timelineSec),
			SignalQuerySeconds:   round3(signalSec),
			SkippedHosts:         skippedHosts,
			Note:                 "Errors skipped per host. Host filtering uses exact-match OR clauses such as host:=\"tw-5090-8\" OR host:=\"tw-5090-08\". If all hosts are skipped with no data, verify host_field and the actual host values in raw logs.",
		},
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func (a *App) collectHost(ctx context.Context, from, to time.Time, step, baseQuery, host string) hostResult {
	res := hostResult{Host: hostDisplayName(host)}
	filter := buildHostScopedFilter(baseQuery, a.cfg.Report.HostField, a.cfg.Report.HostFilterTemplate, host)
	summaryQuery := fmt.Sprintf(`%s | stats by (%s, %s) count() as log_events, min(_time) as first_seen, max(_time) as last_seen`, filter, a.cfg.Report.HostField, a.cfg.Report.ContainerField)
	timelineQuery := fmt.Sprintf(`%s | stats by (%s, %s, _time:%s) count() as hits`, filter, a.cfg.Report.HostField, a.cfg.Report.ContainerField, step)
	errQuery := buildSignalQuery(filter, a.cfg.Report.HostField, a.cfg.Report.ContainerField, a.cfg.Report.ErrorKeywords)
	warnQuery := buildSignalQuery(filter, a.cfg.Report.HostField, a.cfg.Report.ContainerField, a.cfg.Report.WarnKeywords)
	startupQuery := buildSignalQuery(filter, a.cfg.Report.HostField, a.cfg.Report.ContainerField, a.cfg.Report.StartupKeywords)
	busyQuery := buildSignalQuery(filter, a.cfg.Report.HostField, a.cfg.Report.ContainerField, a.cfg.Report.BusyKeywords)

	log.Printf("[HOST] start host=%s raw=%q variants=%q filter=%q", res.Host, host, hostQueryVariants(host), filter)

	summaryBody, sec, err := a.query(ctx, summaryQuery, from, to)
	res.SummarySec += sec
	if err != nil {
		res.Skipped = true
		res.SkipReason = fmt.Sprintf("summary query failed: %v", err)
		log.Printf("[HOST] skip host=%s reason=%s", res.Host, res.SkipReason)
		return res
	}
	parsedSummary, err := parseAggLines(summaryBody, a.cfg.Report.HostField, a.cfg.Report.ContainerField)
	if err != nil {
		res.Skipped = true
		res.SkipReason = fmt.Sprintf("parse failed: %v", err)
		log.Printf("[HOST] skip host=%s reason=%s", res.Host, res.SkipReason)
		return res
	}
	if len(parsedSummary) == 0 {
		res.Skipped = true
		res.SkipReason = "no data"
		log.Printf("[HOST] skip host=%s reason=%s", res.Host, res.SkipReason)
		return res
	}
	res.Summary = parsedSummary

	if b, sec, err := a.query(ctx, timelineQuery, from, to); err == nil {
		res.TimelineSec += sec
		if x, err := parseBucketLines(b, a.cfg.Report.HostField, a.cfg.Report.ContainerField); err == nil {
			res.Buckets = x
		}
	}
	if b, sec, err := a.query(ctx, errQuery, from, to); err == nil {
		res.SignalSec += sec
		res.Errors = parseSignalLines(b, a.cfg.Report.HostField, a.cfg.Report.ContainerField)
	}
	if b, sec, err := a.query(ctx, warnQuery, from, to); err == nil {
		res.SignalSec += sec
		res.Warns = parseSignalLines(b, a.cfg.Report.HostField, a.cfg.Report.ContainerField)
	}
	if b, sec, err := a.query(ctx, startupQuery, from, to); err == nil {
		res.SignalSec += sec
		res.Startups = parseSignalLines(b, a.cfg.Report.HostField, a.cfg.Report.ContainerField)
	}
	if b, sec, err := a.query(ctx, busyQuery, from, to); err == nil {
		res.SignalSec += sec
		res.Busy = parseSignalLines(b, a.cfg.Report.HostField, a.cfg.Report.ContainerField)
	}
	return res
}

func (a *App) fetchContainerLogs(ctx context.Context, from, to time.Time, host, container string) ([]string, error) {
	filter := buildHostScopedFilter(a.cfg.Report.BaseQuery, a.cfg.Report.HostField, a.cfg.Report.HostFilterTemplate, host)
	filter = fmt.Sprintf("(%s) AND (%s:=%q)", filter, a.cfg.Report.ContainerField, container)
	b, _, err := a.query(ctx, filter, from, to)
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	out := make([]string, 0, a.cfg.Report.SampleLogLimit)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		out = append(out, line)
		if len(out) >= a.cfg.Report.SampleLogLimit {
			break
		}
	}
	return out, sc.Err()
}

func buildSignalQuery(base, hostField, containerField string, keywords []string) string {
	if len(keywords) == 0 {
		return fmt.Sprintf(`%s AND __no_match__ | stats by (%s, %s) count() as signal_count`, base, hostField, containerField)
	}
	parts := make([]string, 0, len(keywords))
	for _, kw := range keywords {
		kw = strings.TrimSpace(kw)
		if kw == "" {
			continue
		}
		if strings.ContainsAny(kw, ` :"()`) {
			parts = append(parts, strconv.Quote(kw))
		} else {
			parts = append(parts, kw)
		}
	}
	return fmt.Sprintf(`(%s) AND (%s) | stats by (%s, %s) count() as signal_count`, base, strings.Join(parts, " OR "), hostField, containerField)
}

func (a *App) query(ctx context.Context, query string, from, to time.Time) ([]byte, float64, error) {
	endpoint := strings.TrimRight(a.cfg.VictoriaLogs.BaseURL, "/") + a.cfg.VictoriaLogs.QueryPath
	form := url.Values{}
	form.Set("query", query)
	form.Set("start", from.Format(time.RFC3339))
	form.Set("end", to.Format(time.RFC3339))
	form.Set("limit", strconv.Itoa(a.cfg.Report.QueryLimit))
	encoded := form.Encode()
	log.Printf("[QUERY] POST %s?%s", endpoint, encoded)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(encoded))
	if err != nil {
		log.Printf("[QUERY] build failed: %v", err)
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	for k, v := range a.cfg.VictoriaLogs.Headers {
		req.Header.Set(k, v)
	}
	switch strings.ToLower(strings.TrimSpace(a.cfg.VictoriaLogs.Auth.Type)) {
	case "basic":
		req.SetBasicAuth(a.cfg.VictoriaLogs.Auth.Username, a.cfg.VictoriaLogs.Auth.Password)
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+a.cfg.VictoriaLogs.Auth.Bearer)
	}

	started := time.Now()
	resp, err := a.client.Do(req)
	if err != nil {
		log.Printf("[QUERY] request failed: %v", err)
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[QUERY] read failed: %v", err)
		return nil, 0, err
	}
	cost := round3(time.Since(started).Seconds())
	if resp.StatusCode >= 300 {
		log.Printf("[QUERY] bad status=%d cost=%.3fs", resp.StatusCode, cost)
		return nil, 0, fmt.Errorf("status=%d body=%s", resp.StatusCode, string(b))
	}
	log.Printf("[QUERY] ok status=%d cost=%.3fs bytes=%d", resp.StatusCode, cost, len(b))
	return b, cost, nil
}

func parseAggLines(data []byte, hostField, containerField string) ([]aggLine, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	out := []aggLine{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			return nil, err
		}
		out = append(out, aggLine{
			Host:      normalizeFieldValue(hostField, getString(m, hostField)),
			Container: normalizeFieldValue(containerField, getString(m, containerField)),
			Count:     int64(getFloat(m, "log_events")),
			FirstSeen: parseAnyTime(m["first_seen"]),
			LastSeen:  parseAnyTime(m["last_seen"]),
		})
	}
	return out, sc.Err()
}

func parseBucketLines(data []byte, hostField, containerField string) ([]bucketLine, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	out := []bucketLine{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			return nil, err
		}
		out = append(out, bucketLine{
			Host:      normalizeFieldValue(hostField, getString(m, hostField)),
			Container: normalizeFieldValue(containerField, getString(m, containerField)),
			Bucket:    parseAnyTime(firstNonNil(m["bucket_time"], m["_time"])),
		})
	}
	return out, sc.Err()
}

func parseSignalLines(data []byte, hostField, containerField string) []signalLine {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	out := []signalLine{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		out = append(out, signalLine{
			Host:      normalizeFieldValue(hostField, getString(m, hostField)),
			Container: normalizeFieldValue(containerField, getString(m, containerField)),
			Count:     int64(getFloat(m, "signal_count")),
		})
	}
	return out
}

func applySignal(m map[string]*rowBuild, sig []signalLine, kind string) {
	for _, s := range sig {
		key := s.Host + "\x00" + s.Container
		rb := m[key]
		if rb == nil {
			continue
		}
		switch kind {
		case "error":
			rb.Row.Errors += s.Count
		case "warn":
			rb.Row.Warnings += s.Count
		case "startup":
			rb.Row.Startups += s.Count
		case "busy":
			rb.Row.BusyHints += s.Count
		}
	}
}

func classify(r SummaryRow) (string, string, string, string) {
	util := "light"
	if r.DutyCycle >= 0.75 || r.ActiveHours >= 12 {
		util = "very_high"
	} else if r.DutyCycle >= 0.45 || r.ActiveHours >= 6 {
		util = "high"
	} else if r.DutyCycle >= 0.20 || r.ActiveHours >= 2 {
		util = "moderate"
	}
	workload := "sporadic"
	if r.Sessions <= 2 && r.DutyCycle >= 0.5 {
		workload = "steady"
	} else if r.Sessions >= 8 && r.DutyCycle < 0.35 {
		workload = "bursty"
	} else if r.EventsPerHour >= 500 || r.BusyHints > 0 {
		workload = "render_dense"
	}
	zh, en := []string{}, []string{}
	switch workload {
	case "steady":
		zh = append(zh, "日志连续，表现出持续执行特征")
		en = append(en, "Logs are continuous, indicating sustained execution.")
	case "bursty":
		zh = append(zh, "日志呈脉冲式分布，更像批处理或抢占任务")
		en = append(en, "Logs are bursty, more like batch or opportunistic jobs.")
	case "render_dense":
		zh = append(zh, "活跃时间内日志密度高，疑似高吞吐渲染阶段")
		en = append(en, "High event density during active time suggests a render-dense phase.")
	default:
		zh = append(zh, "日志稀疏，利用率偏低或任务间隔较长")
		en = append(en, "Logs are sparse, indicating low utilization or longer idle gaps.")
	}
	if r.Errors > 0 {
		zh = append(zh, fmt.Sprintf("检测到 %d 条错误信号", r.Errors))
		en = append(en, fmt.Sprintf("Detected %d error markers.", r.Errors))
	}
	if r.Warnings > 0 {
		zh = append(zh, fmt.Sprintf("检测到 %d 条告警信号", r.Warnings))
		en = append(en, fmt.Sprintf("Detected %d warning markers.", r.Warnings))
	}
	if r.Startups > 0 {
		zh = append(zh, fmt.Sprintf("出现 %d 次启动型日志，可能有重启或预热", r.Startups))
		en = append(en, fmt.Sprintf("Observed %d startup-like markers, possibly warm-up or restarts.", r.Startups))
	}
	if r.BusyHints > 0 {
		zh = append(zh, "存在忙碌信号，说明有队列压力或并发执行")
		en = append(en, "Busy markers indicate queue pressure or concurrency.")
	}
	zh = append(zh, fmt.Sprintf("综合判断：利用率 %s，负载形态 %s。", util, workload))
	en = append(en, fmt.Sprintf("Overall: utilization is %s and workload shape is %s.", util, strings.ReplaceAll(workload, "_", " ")))
	return util, workload, strings.Join(zh, "；"), strings.Join(en, " ")
}

func dominantWorkload(rows []SummaryRow, host string) string {
	counts := map[string]int{}
	for _, r := range rows {
		if r.Host == host {
			counts[r.WorkloadClass]++
		}
	}
	best, bestN := "", -1
	for k, v := range counts {
		if v > bestN {
			best, bestN = k, v
		}
	}
	return best
}

func parseInputTime(v string, def time.Time) (time.Time, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return def, nil
	}
	if v == "now" {
		return time.Now(), nil
	}
	if strings.HasPrefix(v, "-") {
		d, err := time.ParseDuration(v)
		if err != nil {
			return time.Time{}, err
		}
		return time.Now().Add(d), nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04", "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t, nil
		}
	}
	return time.Time{}, errors.New("invalid time")
}

func parseStep(s string) time.Duration {
	d, _ := time.ParseDuration(strings.TrimSpace(s))
	if d <= 0 {
		d = time.Minute
	}
	return d
}

func estimateSessions(times []time.Time, gap time.Duration) int {
	if len(times) == 0 {
		return 0
	}
	n := 1
	for i := 1; i < len(times); i++ {
		if times[i].Sub(times[i-1]) > gap {
			n++
		}
	}
	return n
}

func firstNonNil(vs ...any) any {
	for _, v := range vs {
		if v != nil {
			return v
		}
	}
	return nil
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		return strings.TrimSpace(fmt.Sprint(v))
	}
	if i := strings.LastIndex(key, "."); i >= 0 {
		if v, ok := m[key[i+1:]]; ok {
			return strings.TrimSpace(fmt.Sprint(v))
		}
	}
	return ""
}

func getFloat(m map[string]any, key string) float64 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case string:
		f, _ := strconv.ParseFloat(t, 64)
		return f
	default:
		return 0
	}
}

func parseAnyTime(v any) time.Time {
	switch t := v.(type) {
	case string:
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05"} {
			if x, err := time.Parse(layout, t); err == nil {
				return x.UTC()
			}
		}
		if n, err := strconv.ParseInt(t, 10, 64); err == nil {
			if len(t) >= 13 {
				return time.UnixMilli(n).UTC()
			}
			return time.Unix(n, 0).UTC()
		}
	case float64:
		if t > 1e12 {
			return time.UnixMilli(int64(t)).UTC()
		}
		return time.Unix(int64(t), 0).UTC()
	}
	return time.Time{}
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}
func avgDuty(totalDuty float64, n int) float64 { return round4(totalDuty / float64(max(1, n))) }
func round2(v float64) float64                 { return math.Round(v*100) / 100 }
func round3(v float64) float64                 { return math.Round(v*1000) / 1000 }
func round4(v float64) float64                 { return math.Round(v*10000) / 10000 }
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func calcActiveDuration(times []time.Time, gap time.Duration) time.Duration {
	if len(times) == 0 {
		return 0
	}

	sort.Slice(times, func(i, j int) bool {
		return times[i].Before(times[j])
	})

	var total time.Duration
	start := times[0]
	prev := times[0]

	for i := 1; i < len(times); i++ {
		if times[i].Sub(prev) > gap {
			total += prev.Sub(start)
			start = times[i]
		}
		prev = times[i]
	}

	total += prev.Sub(start)
	return total
}
