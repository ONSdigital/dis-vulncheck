package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/ONSdigital/dis-vulncheck/config"
	"github.com/ONSdigital/dis-vulncheck/output"
	"github.com/ONSdigital/log.go/v2/log"
	"github.com/briandowns/spinner"
)

var (
	ResultTypeAffected    = "affected"
	ResultTypeIgnored     = "ignored"
	ResultTypeNotAffected = "not_affected"
)

type VulnerabilityReport struct {
	Statements    []VulnerabilityStatement `json:"statements"`
	Results       VulnerabilityResults     `json:"results"`
	FailedIgnores []config.IgnoreStatement `json:"failed_ignores"`
	GoToolchain   string                   `json:"toolchain"`
}

type VulnerabilityResults struct {
	Failures    int `json:"failures"`
	Ignored     int `json:"ignored"`
	NotAffected int `json:"not_affected"`
}

type GoVulncheckReport struct {
	Statements []VulnerabilityStatement `json:"statements"`
}

type VulnerabilityMetadata struct {
	ID          string `json:"@id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type VulnerabilityStatement struct {
	Metadata        VulnerabilityMetadata `json:"vulnerability"`
	Status          string                `json:"status"`
	ImpactStatement string                `json:"impact_statement,omitempty"`
}

// NewVulnerabilityReport creates a vulnerability report from a govulncheckreport
// using the configuration to manipulate the report in transit
func NewVulnerabilityReport(ctx context.Context, cfg *config.Config, govulncheckReport GoVulncheckReport) *VulnerabilityReport {
	report := new(VulnerabilityReport)
	report.GoToolchain = cfg.GoToolChain
	report.Statements = govulncheckReport.Statements

	if cfg.UserConfig != nil && cfg.UserConfig.Ignore != nil {
		report.excludeVulnerabilities(ctx, cfg.UserConfig.Ignore)
	}

	report.countAuditFailures(ctx)

	return report
}

// excludeVulnerabilities rewrites the report to ignore the vulnerabilities specified
func (v *VulnerabilityReport) excludeVulnerabilities(ctx context.Context, ignores []config.IgnoreStatement) {
	log.Info(ctx, "excluding vulnerabilties")

	for i := range v.Statements {
		for j := range ignores {
			if ignores[j].ID == v.Statements[i].Metadata.Name {
				log.Info(ctx, "excluded vulnerabilty", log.Data{
					"vulnerabilityID": ignores[j].ID,
				})
				v.Statements[i].Status = "ignored"
				ignores[j].Matched = true
			}
		}
	}

	for i := range ignores {
		if !ignores[i].Matched {
			log.Info(ctx, "vulnerability to ignore was not matched", log.Data{
				"vulnerabilityID": ignores[i].ID,
			})
			v.FailedIgnores = append(v.FailedIgnores, ignores[i])
		}
	}
}

// CountAuditFailures calculates the overall results for the report
func (v *VulnerabilityReport) countAuditFailures(ctx context.Context) {
	for i := range v.Statements {
		switch v.Statements[i].Status {
		case ResultTypeAffected:
			v.Results.Failures++
		case ResultTypeNotAffected:
			v.Results.NotAffected++
		case ResultTypeIgnored:
			v.Results.Ignored++
		default:
			log.Info(ctx, "didn't recognise vulnerability status", log.Data{
				"status": v.Statements[i].Status,
			})
		}
	}
}

// GetTextReport return the report as a text format
func (v *VulnerabilityReport) GetTextReport(ctx context.Context) string {
	var byteBuffer bytes.Buffer

	v.renderReportHeader(&byteBuffer)

	for i := range v.Statements {
		statement := &v.Statements[i]
		renderResult(&byteBuffer, statement, i+1)
	}

	v.renderFailedIgnores(&byteBuffer)

	return byteBuffer.String()
}

// renderReportHeader renders the top level results of the report
func (v *VulnerabilityReport) renderReportHeader(b *bytes.Buffer) {
	b.WriteString("\n")
	b.WriteString("/**************************/\n")
	b.WriteString("/*     DIS-VULNCHECK      */\n")
	b.WriteString("/*  Vulnerability report  */\n")
	b.WriteString("/**************************/\n")
	b.WriteString("\n")
	fmt.Fprintf(b, "Go Toolchain used: %s\n", v.GoToolchain)
	b.WriteString("\n")

	if v.Results.Failures > 0 {
		b.WriteString(output.ErrorSprintf("Audit has failed\n"))
	} else {
		b.WriteString(output.SuccessSprintf("Audit has passed\n"))
	}
	fmt.Fprintf(b,
		"Found %s, %s, %s\n",
		output.ErrorSprintf("%d failures", v.Results.Failures),
		output.WarnSprintf("%d ignored", v.Results.Ignored),
		output.InfoSprintf("%d not affected", v.Results.NotAffected),
	)

	b.WriteString("\n")
}

// renderResult renders each individual vulnerability statement for the command line
func renderResult(b *bytes.Buffer, statement *VulnerabilityStatement, n int) {
	fmt.Fprintf(b, "Vulnerability #%d: %s\n", n, statement.Metadata.Name)
	fmt.Fprintf(b, "%s\n", statement.Metadata.Description)
	fmt.Fprintf(b, "More info: %s\n", statement.Metadata.ID)

	switch statement.Status {
	case ResultTypeAffected:
		b.WriteString(output.ErrorSprintf("Your code is affected by this vulnerability\n"))
	case ResultTypeNotAffected:
		b.WriteString(output.InfoSprintf("Your code does not appear to call this vulnerability\n"))
	case ResultTypeIgnored:
		b.WriteString(output.WarnSprintf("Your configuration has set this vulnerability to be ignored\n"))
	default:
	}
	b.WriteString("\n")
}

func (v *VulnerabilityReport) renderFailedIgnores(b *bytes.Buffer) {
	for i := range v.FailedIgnores {
		b.WriteString(output.WarnSprintf("You are ignoring a vulnerability that this application is not affected by: %s\n", v.FailedIgnores[i].ID))
	}
}

func Generate(ctx context.Context, cfg *config.Config) (*VulnerabilityReport, error) {
	govulncheckReport, err := runGoVulncheckReport(ctx, cfg)
	if err != nil {
		return &VulnerabilityReport{}, err
	}

	vulnerabilityReport := NewVulnerabilityReport(ctx, cfg, govulncheckReport)

	return vulnerabilityReport, nil
}

// TODO: Abstract this behind a cmd interface for better testing.
// TODO: Split out the installation command
func runGoVulncheckReport(ctx context.Context, cfg *config.Config) (GoVulncheckReport, error) {
	installCmd := "go install golang.org/x/vuln/cmd/govulncheck@latest"
	if cfg.GoToolChain != "" {
		installCmd = fmt.Sprintf("GOTOOLCHAIN=%s %s", cfg.GoToolChain, installCmd)
	}

	log.Info(ctx, "installing go vulncheck", log.Data{
		"installCmd": installCmd,
		"toolchain":  cfg.GoToolChain,
	})

	sInstall := spinner.New(spinner.CharSets[36], 100*time.Millisecond)
	sInstall.Prefix = "Installing govulncheck for toolchain..."
	sInstall.Start()

	_, err := execCommand(ctx, installCmd, ".")
	if err != nil {
		log.Error(ctx, "not able to install govulncheck", err)
		return GoVulncheckReport{}, fmt.Errorf("not able to install govulncheck: %v", err)
	}
	sInstall.Stop()

	cmd := "govulncheck"

	if cfg.BuildTags != "" {
		cmd = fmt.Sprintf("%s -tags=%s", cmd, cfg.BuildTags)
	}

	cmd = fmt.Sprintf("%s -format openvex ./...", cmd)

	if cfg.GoToolChain != "" {
		cmd = fmt.Sprintf("GOTOOLCHAIN=%s %s", cfg.GoToolChain, cmd)
	}

	s := spinner.New(spinner.CharSets[36], 100*time.Millisecond)
	s.Prefix = "Analysing code..."
	s.Start()

	cmdOutput, err := execCommand(ctx, cmd, ".")
	if err != nil {
		log.Error(ctx, "not able to run govulncheck", err)
		s.Stop()
		return GoVulncheckReport{}, fmt.Errorf("not able to run govulncheck: %v", err)
	}

	s.Stop()

	var report GoVulncheckReport

	err = json.Unmarshal(cmdOutput, &report)
	if err != nil {
		log.Error(ctx, "unable to unmarshal report", err)
		return GoVulncheckReport{}, fmt.Errorf("unable to unmarshal report: %v", err)
	}

	return report, nil
}

// ExecCommand executes the given command with bash and then returns the result
// as a byte array
func execCommand(ctx context.Context, command, wrkDir string) ([]byte, error) {
	log.Info(ctx, "executing command", log.Data{
		"command": command,
	})

	cmd := exec.Command("bash", "-c", command)

	if wrkDir != "" {
		cmd.Dir = wrkDir
	}

	return cmd.Output()
}
