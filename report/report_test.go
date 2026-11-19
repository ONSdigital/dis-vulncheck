package report

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ONSdigital/dis-vulncheck/config"
	. "github.com/smartystreets/goconvey/convey"
)

const (
	testVulnerabilityName        = "Vulnerability Name"
	testVulnerabilityDescription = "Vulnerability Description"
	testImpactStatement          = "a statement about impact"
)

func TestRunGoVulncheckTimeout(t *testing.T) {
	tests := []struct {
		name       string
		timeout    time.Duration
		install    string
		analysis   string
		wantErr    error
		wantErrMsg string
	}{
		{
			name:     "no analysis timeout",
			analysis: `printf '{"statements":[{"status":"affected"}]}'`,
		},
		{
			name:     "installation takes longer than the analysis timeout",
			timeout:  time.Second,
			install:  "/bin/sleep 1.1",
			analysis: `printf '{"statements":[{"status":"affected"}]}'`,
		},
		{
			name:     "analysis exceeds its timeout",
			timeout:  50 * time.Millisecond,
			analysis: "exec /bin/sleep 5",
			wantErr:  context.DeadlineExceeded,
		},
		{
			name:       "analysis fails with stderr",
			analysis:   "echo scan-failed >&2; exit 1",
			wantErrMsg: "scan-failed",
		},
	}
	for _, tt := range tests {
		Convey("Given "+tt.name, t, func() {
			dir := t.TempDir()
			scripts := map[string]string{
				"go":          tt.install + "\nexit 0",
				"govulncheck": tt.analysis,
			}
			for name, script := range scripts {
				script = "#!/bin/bash\n[ \"$GOTOOLCHAIN\" = \"go1.26.0\" ] || exit 2\n" + script + "\n"
				So(os.WriteFile(filepath.Join(dir, name), []byte(script), 0755), ShouldBeNil)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

			Convey("When the govulncheck report is generated", func() {
				start := time.Now()
				report, err := runGoVulncheckReport(context.Background(), &config.Config{
					GoToolChain: "go1.26.0",
					Timeout:     tt.timeout,
				})
				elapsed := time.Since(start)

				switch {
				case tt.wantErr != nil:
					Convey("Then analysis should stop promptly with a deadline error", func() {
						So(errors.Is(err, tt.wantErr), ShouldBeTrue)
						So(elapsed, ShouldBeLessThan, 2*time.Second)
					})
				case tt.wantErrMsg != "":
					Convey("Then the error should retain stderr", func() {
						So(err, ShouldNotBeNil)
						So(err.Error(), ShouldContainSubstring, tt.wantErrMsg)
					})
				default:
					Convey("Then the analysis report should be returned", func() {
						So(err, ShouldBeNil)
						So(report.Statements, ShouldHaveLength, 1)
						So(report.Statements[0].Status, ShouldEqual, ResultTypeAffected)
					})
				}
			})
		})
	}
}

func TestReportGeneration(t *testing.T) {
	Convey("Given a govulncheck report supplied with several errors", t, func() {
		ctx := context.Background()

		gvreport := GoVulncheckReport{
			Statements: []VulnerabilityStatement{
				{
					Metadata: VulnerabilityMetadata{
						ID:          "1",
						Name:        testVulnerabilityName,
						Description: testVulnerabilityDescription,
					},
					ImpactStatement: testImpactStatement,
					Status:          "affected",
				},
				{
					Metadata: VulnerabilityMetadata{
						ID:          "2",
						Name:        testVulnerabilityName,
						Description: testVulnerabilityDescription,
					},
					ImpactStatement: testImpactStatement,
					Status:          ResultTypeNotAffected,
				},
			},
		}

		dvulnReport := NewVulnerabilityReport(ctx, &config.Config{}, gvreport)

		Convey("Then the failures should be calculated", func() {
			So(dvulnReport.Results.NotAffected, ShouldEqual, 1)
			So(dvulnReport.Results.Failures, ShouldEqual, 1)
		})
	})

	Convey("Given a govulncheck report supplied with several errors and a config that excludes one of them", t, func() {
		ctx := context.Background()

		gvreport := GoVulncheckReport{
			Statements: []VulnerabilityStatement{
				{
					Metadata: VulnerabilityMetadata{
						ID:          "https://pkg.go.dev/vuln/GO-2025-3749",
						Name:        "GO-2025-3749",
						Description: "Usage of ExtKeyUsageAny disables policy validation in crypto/x509",
					},
					ImpactStatement: testImpactStatement,
					Status:          ResultTypeAffected,
				},
				{
					Metadata: VulnerabilityMetadata{
						ID:          "https://pkg.go.dev/vuln/GO-2025-3563",
						Name:        "GO-2025-3563",
						Description: "Request smuggling due to acceptance of invalid chunked data in net/http",
					},
					ImpactStatement: testImpactStatement,
					Status:          ResultTypeNotAffected,
				},
			},
		}
		cfg := &config.Config{
			UserConfig: &config.UserConfig{
				Ignore: []config.IgnoreStatement{
					{
						ID:     "GO-2025-3749",
						Reason: "This is a test and I want to test ignoring it",
						Expiry: time.Now().Add(24 * time.Hour),
					},
				},
			},
		}
		dvulnReport := NewVulnerabilityReport(ctx, cfg, gvreport)

		Convey("Then the failures should be calculated", func() {
			So(dvulnReport.Results.NotAffected, ShouldEqual, 1)
			So(dvulnReport.Results.Ignored, ShouldEqual, 1)
			So(dvulnReport.Statements[0].Status, ShouldEqual, ResultTypeIgnored)
		})
	})

	Convey("Given a govulncheck report supplied with several errors and a config that excludes one", t, func() {
		ctx := context.Background()

		gvreport := GoVulncheckReport{}
		cfg := &config.Config{
			UserConfig: &config.UserConfig{
				Ignore: []config.IgnoreStatement{
					{
						ID:     "GO-2025-3749",
						Reason: "This is a test and I want to test failing to ignore it",
						Expiry: time.Now().Add(24 * time.Hour),
					},
				},
			},
		}
		dvulnReport := NewVulnerabilityReport(ctx, cfg, gvreport)

		Convey("Then the failures should be calculated", func() {
			So(dvulnReport.Results.NotAffected, ShouldEqual, 0)
			So(dvulnReport.Results.Ignored, ShouldEqual, 0)
			So(dvulnReport.Results.Failures, ShouldEqual, 0)

			So(dvulnReport.FailedIgnores, ShouldHaveLength, 1)
		})
	})

	Convey("Given a govulncheck report with an expired ignore", t, func() {
		ctx := context.Background()

		gvreport := GoVulncheckReport{
			Statements: []VulnerabilityStatement{
				{
					Metadata: VulnerabilityMetadata{
						ID:          "https://pkg.go.dev/vuln/GO-2025-3749",
						Name:        "GO-2025-3749",
						Description: "Usage of ExtKeyUsageAny disables policy validation in crypto/x509",
					},
					ImpactStatement: testImpactStatement,
					Status:          ResultTypeAffected,
				},
			},
		}
		cfg := &config.Config{
			UserConfig: &config.UserConfig{
				Ignore: []config.IgnoreStatement{
					{
						ID:     "GO-2025-3749",
						Reason: "This is a test and I want to test expiring it",
						Expiry: time.Now().Add(-24 * time.Hour),
					},
				},
			},
		}
		dvulnReport := NewVulnerabilityReport(ctx, cfg, gvreport)

		Convey("Then the vulnerability should not be ignored", func() {
			So(dvulnReport.Results.Failures, ShouldEqual, 1)
			So(dvulnReport.Results.Ignored, ShouldEqual, 0)
			So(dvulnReport.Statements[0].Status, ShouldEqual, ResultTypeAffected)
			So(dvulnReport.FailedIgnores, ShouldBeEmpty)
		})
	})
}

func TestReportRendering(t *testing.T) {
	Convey("Given a disvulncheck report with all types of results", t, func() {
		ctx := context.Background()

		vcreport := VulnerabilityReport{
			GoToolchain: "go1.24.1",
			Results: VulnerabilityResults{
				Ignored:     1,
				Failures:    1,
				NotAffected: 1,
			},
			Statements: []VulnerabilityStatement{
				{
					Metadata: VulnerabilityMetadata{
						ID:          "https://pkg.go.dev/vuln/GO-2025-0001",
						Name:        "GO-2025-0001",
						Description: "A description of GO-2025-0001",
					},
					Status: ResultTypeAffected,
					Products: []Product{
						{
							ID: "an id",
							Subcomponents: []Components{
								{
									ID: "pkg:golang/stdlib@v1.24.1",
								},
							},
						},
					},
				},
				{
					Metadata: VulnerabilityMetadata{
						ID:          "https://pkg.go.dev/vuln/GO-2025-0002",
						Name:        "GO-2025-0002",
						Description: "A description of GO-2025-0002",
					},
					Status: ResultTypeIgnored,
				},
				{
					Metadata: VulnerabilityMetadata{
						ID:          "https://pkg.go.dev/vuln/GO-2025-0003",
						Name:        "GO-2025-0003",
						Description: "A description of GO-2025-0003",
					},
					Status: ResultTypeNotAffected,
				},
			},
		}
		Convey("When the text report is retrieved", func() {
			reportOutput := vcreport.GetTextReport(ctx)

			Convey("Then the output contains the data expected in the report", func() {
				So(strings.Contains(reportOutput, "go1.24.1"), ShouldBeTrue)
				So(strings.Contains(reportOutput, "Audit has failed"), ShouldBeTrue)
				So(strings.Contains(reportOutput, "1 ignored"), ShouldBeTrue)
				So(strings.Contains(reportOutput, "1 not affected"), ShouldBeTrue)
				So(strings.Contains(reportOutput, "1 failure"), ShouldBeTrue)
				for i := range vcreport.Statements {
					So(strings.Contains(reportOutput, vcreport.Statements[i].Metadata.Description), ShouldBeTrue)
					So(strings.Contains(reportOutput, vcreport.Statements[i].Metadata.ID), ShouldBeTrue)
					So(strings.Contains(reportOutput, vcreport.Statements[i].Metadata.Name), ShouldBeTrue)
					for j := range vcreport.Statements[i].Products {
						for k := range vcreport.Statements[i].Products[j].Subcomponents {
							So(strings.Contains(reportOutput, vcreport.Statements[i].Products[j].Subcomponents[k].ID), ShouldBeTrue)
						}
					}
				}
			})
		})
	})
}
