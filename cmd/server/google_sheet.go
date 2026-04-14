package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/api/option"
	"google.golang.org/api/sheets/v4"
)

const (
	googleSheetEnabled              = true
	googleSheetSpreadsheetID        = "1hLXYMaW5xgghAyEMRktNnVhY0lT6EcDshTOzUXjn-IQ"
	googleSheetName                 = "gpu_log"
	googleSheetIncludeGeneratedAt   = true
	googleSheetIncludeWindow        = true
	googleSheetIncludeSummaryFields = true
)

var googleSheetColumns = []string{
	"generated_at",
	"from",
	"to",
	"step",
	"total_hosts",
	"active_hosts",
	"total_containers",
	"active_containers",
	"total_events",
	"total_active_hours",
	"hot_containers",
	"capacity_pressure",
	"host",
	"container_name",
	"log_events",
	"active_buckets",
	"active_minutes",
	"active_hours",
	"duty_cycle",
	"idle_ratio",
	"first_seen",
	"last_seen",
	"sessions",
	"errors",
	"warnings",
	"startups",
	"busy_hints",
	"events_per_hour",
	"utilization_class",
	"workload_class",
	"analysis_zh",
	"analysis_en",
	"severity_score",
}

type googleSheetJobSnapshot struct {
	LastRunAt    string `json:"last_run_at"`
	LastStatus   string `json:"last_status"`
	LastError    string `json:"last_error"`
	RowsAppended int    `json:"rows_appended"`
}

var googleSheetJobState struct {
	sync.Mutex
	Snapshot googleSheetJobSnapshot
}

func googleSheetCredentialsFile() string {
	return strings.TrimSpace(os.Getenv("GOOGLE_SHEETS_CREDENTIALS_FILE"))
}

func (a *App) StartGoogleSheetsHourlyJob(ctx context.Context) {
	if !googleSheetEnabled {
		log.Printf("[GSHEET] scheduler disabled")
		return
	}

	log.Printf("[GSHEET] scheduler enabled spreadsheet=%s sheet=%q", googleSheetSpreadsheetID, googleSheetName)

	go a.RunGoogleSheetsJobOnce(context.Background())

	ticker := time.NewTicker(time.Hour)
	//ticker := time.NewTicker(time.Second * 10)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("[GSHEET] scheduler stopped: %v", ctx.Err())
			return
		case <-ticker.C:
			a.RunGoogleSheetsJobOnce(context.Background())
		}
	}
}

func (a *App) RunGoogleSheetsJobOnce(ctx context.Context) {
	startedAt := time.Now().UTC()

	googleSheetJobState.Lock()
	googleSheetJobState.Snapshot.LastRunAt = startedAt.Format(time.RFC3339)
	googleSheetJobState.Snapshot.LastStatus = "running"
	googleSheetJobState.Snapshot.LastError = ""
	googleSheetJobState.Snapshot.RowsAppended = 0
	googleSheetJobState.Unlock()

	from := startedAt.Add(-1 * time.Hour)
	to := startedAt

	step := "1m"
	if strings.TrimSpace(a.cfg.Report.DefaultStep) != "" {
		step = strings.TrimSpace(a.cfg.Report.DefaultStep)
	}

	q := "*"
	if strings.TrimSpace(a.cfg.Report.BaseQuery) != "" {
		q = strings.TrimSpace(a.cfg.Report.BaseQuery)
	}

	rep, err := a.buildReport(ctx, from, to, step, q, "")
	if err != nil {
		a.setGoogleSheetJobResult("error", err.Error(), 0)
		log.Printf("[GSHEET] build report failed: %v", err)
		return
	}

	rows := a.buildGoogleSheetRows(rep)
	if len(rows) == 0 {
		a.setGoogleSheetJobResult("ok", "", 0)
		log.Printf("[GSHEET] nothing to append")
		return
	}

	rows = a.wrapGoogleSheetRowsWithSection(rep, rows)

	appended, err := a.appendRowsToGoogleSheet(ctx, rows)
	if err != nil {
		a.setGoogleSheetJobResult("error", err.Error(), 0)
		log.Printf("[GSHEET] append failed: %v", err)
		return
	}

	log.Printf("[GSHEET] append ok rows=%d", appended)
	a.setGoogleSheetJobResult("ok", "", appended)
}

func (a *App) GoogleSheetJobSnapshot() googleSheetJobSnapshot {
	googleSheetJobState.Lock()
	defer googleSheetJobState.Unlock()
	return googleSheetJobState.Snapshot
}

func (a *App) setGoogleSheetJobResult(status, errMsg string, rows int) {
	googleSheetJobState.Lock()
	defer googleSheetJobState.Unlock()
	googleSheetJobState.Snapshot.LastStatus = status
	googleSheetJobState.Snapshot.LastError = errMsg
	googleSheetJobState.Snapshot.RowsAppended = rows
}

func (a *App) buildGoogleSheetRows(rep *ReportResponse) [][]any {
	if rep == nil || len(rep.Rows) == 0 {
		return nil
	}

	out := make([][]any, 0, len(rep.Rows))
	sort.Slice(rep.Rows, func(i, j int) bool {
		idleI := 1 - rep.Rows[i].DutyCycle
		idleJ := 1 - rep.Rows[j].DutyCycle
		if idleI == idleJ {
			if rep.Rows[i].Host == rep.Rows[j].Host {
				return rep.Rows[i].ContainerName < rep.Rows[j].ContainerName
			}
			return rep.Rows[i].Host < rep.Rows[j].Host
		}
		return idleI > idleJ
	})
	for _, row := range rep.Rows {
		record := make([]any, 0, 32)

		if googleSheetIncludeGeneratedAt {
			record = append(record, rep.GeneratedAt)
		}
		if googleSheetIncludeWindow {
			record = append(record, rep.From, rep.To, rep.Step)
		}
		if googleSheetIncludeSummaryFields {
			record = append(record,
				rep.TotalHosts,
				rep.ActiveHosts,
				rep.TotalContainers,
				rep.ActiveContainers,
				rep.TotalEvents,
				rep.TotalActiveHours,
				rep.HotContainers,
				rep.CapacityPressure,
			)
		}

		record = append(record,
			row.Host,
			row.ContainerName,
			row.LogEvents,
			row.ActiveBuckets,
			row.ActiveMinutes,
			row.ActiveHours,
			row.DutyCycle,
			1-row.DutyCycle,
			row.FirstSeen,
			row.LastSeen,
			row.Sessions,
			row.Errors,
			row.Warnings,
			row.Startups,
			row.BusyHints,
			row.EventsPerHour,
			row.UtilizationClass,
			row.WorkloadClass,
			row.AnalysisZH,
			row.AnalysisEN,
			row.SeverityScore,
		)

		out = append(out, record)
	}

	return out
}

func (a *App) wrapGoogleSheetRowsWithSection(rep *ReportResponse, dataRows [][]any) [][]any {
	if rep == nil || len(dataRows) == 0 {
		return dataRows
	}

	colCount := len(googleSheetColumns)
	sectionTitle := fmt.Sprintf(
		"batch | window=%s ~ %s | step=%s | rows=%d | collected_at=%s",
		rep.From,
		rep.To,
		rep.Step,
		len(dataRows),
		rep.GeneratedAt,
	)

	titleRow := make([]any, colCount)
	if colCount > 0 {
		titleRow[0] = sectionTitle
	}

	emptyRow := make([]any, colCount)

	out := make([][]any, 0, len(dataRows)+4)
	out = append(out, titleRow)
	out = append(out, a.googleSheetHeaderRow())
	out = append(out, dataRows...)
	out = append(out, emptyRow)
	return out
}

func (a *App) googleSheetHeaderRow() []any {
	headers := make([]any, len(googleSheetColumns))
	for i, col := range googleSheetColumns {
		headers[i] = col
	}
	return headers
}

func padGoogleSheetRow(row []any, size int) []any {
	if len(row) >= size {
		return row
	}
	out := make([]any, size)
	copy(out, row)
	return out
}

func (a *App) appendRowsToGoogleSheet(ctx context.Context, rows [][]any) (int, error) {
	if !googleSheetEnabled {
		return 0, errors.New("google sheets is disabled")
	}
	if strings.TrimSpace(googleSheetSpreadsheetID) == "" {
		return 0, errors.New("google sheets spreadsheet id is empty")
	}
	credentialsFile := googleSheetCredentialsFile()
	if strings.TrimSpace(credentialsFile) == "" {
		return 0, errors.New("google sheets credentials file is empty")
	}
	if strings.TrimSpace(googleSheetName) == "" {
		return 0, errors.New("google sheets sheet name is empty")
	}

	svc, err := sheets.NewService(
		ctx,
		option.WithCredentialsFile(credentialsFile),
		option.WithScopes(sheets.SpreadsheetsScope),
	)
	if err != nil {
		return 0, err
	}

	colCount := len(googleSheetColumns)
	for i := range rows {
		rows[i] = padGoogleSheetRow(rows[i], colCount)
	}
	vr := &sheets.ValueRange{Values: rows}
	rangeName := fmt.Sprintf("%s!A:ZZ", googleSheetName)

	resp, err := svc.Spreadsheets.Values.Append(googleSheetSpreadsheetID, rangeName, vr).
		ValueInputOption("USER_ENTERED").
		InsertDataOption("INSERT_ROWS").
		Context(ctx).
		Do()
	if err != nil {
		return 0, err
	}

	if resp != nil && resp.Updates != nil {
		return int(resp.Updates.UpdatedRows), nil
	}

	return len(rows), nil
}
