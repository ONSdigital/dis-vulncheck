package report

import (
	"context"
	"strings"
	"testing"

	"github.com/ONSdigital/dis-vulncheck/config"
	. "github.com/smartystreets/goconvey/convey"
)

func TestReportGeneration(t *testing.T) {
	Convey("Given a govulncheck report supplied with several errors", t, func() {
		ctx := context.Background()

		gvreport := GoVulncheckReport{
			Statements: []VulnerabilityStatement{
				{
					Metadata: VulnerabilityMetadata{
						ID:          "1",
						Name:        "Vulnerability Name",
						Description: "Vulnerability Description",
					},
					ImpactStatement: "a statement about impact",
					Status:          "affected",
				},
				{
					Metadata: VulnerabilityMetadata{
						ID:          "2",
						Name:        "Vulnerability Name",
						Description: "Vulnerability Description",
					},
					ImpactStatement: "a statement about impact",
					Status:          "not_affected",
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
					ImpactStatement: "a statement about impact",
					Status:          "affected",
				},
				{
					Metadata: VulnerabilityMetadata{
						ID:          "https://pkg.go.dev/vuln/GO-2025-3563",
						Name:        "GO-2025-3563",
						Description: "Request smuggling due to acceptance of invalid chunked data in net/http",
					},
					ImpactStatement: "a statement about impact",
					Status:          "not_affected",
				},
			},
		}
		cfg := &config.Config{
			UserConfig: &config.UserConfig{
				Ignore: []config.IgnoreStatement{
					{
						ID:     "GO-2025-3749",
						Reason: "This is a test and I want to test ignoring it",
					},
				},
			},
		}
		dvulnReport := NewVulnerabilityReport(ctx, cfg, gvreport)

		Convey("Then the failures should be calculated", func() {
			So(dvulnReport.Results.NotAffected, ShouldEqual, 1)
			So(dvulnReport.Results.Ignored, ShouldEqual, 1)
			So(dvulnReport.Statements[0].Status, ShouldEqual, "ignored")
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
					Status: "affected",
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
					Status: "ignored",
				},
				{
					Metadata: VulnerabilityMetadata{
						ID:          "https://pkg.go.dev/vuln/GO-2025-0003",
						Name:        "GO-2025-0003",
						Description: "A description of GO-2025-0003",
					},
					Status: "not_affected",
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
