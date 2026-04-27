package config_test

import (
	"context"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/ONSdigital/dis-vulncheck/config"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/spf13/afero"
)

const testConfigFileName = ".dis-vulncheck.yml"

func TestCliArgs(t *testing.T) {
	Convey("Given a command with accepted flags set", t, func() {
		// Save os.Args and restore after test
		origArgs := os.Args
		defer func() { os.Args = origArgs }()

		// Reset flags for test
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

		os.Args = []string{"dis-vulncheck", "--verbose", "--config=./mycustomfilepath", "--build-tags=production"}

		Convey("When the cli arg values are retrieved", func() {
			cliArgs := config.GetCliArgs()
			Convey("Then they should be set to the values passed", func() {
				So(cliArgs.BuildTags, ShouldEqual, "production")
				So(cliArgs.ConfigFilePath, ShouldEqual, "./mycustomfilepath")
				So(cliArgs.Verbose, ShouldBeTrue)
			})
		})
	})

	Convey("Given a command with no flags set", t, func() {
		// Save os.Args and restore after test
		origArgs := os.Args
		defer func() { os.Args = origArgs }()

		// Reset flags for test
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

		os.Args = []string{"dis-vulncheck"}

		Convey("When the cli arg values are retrieved", func() {
			cliArgs := config.GetCliArgs()
			Convey("Then they should be set to their defaults", func() {
				So(cliArgs.Verbose, ShouldBeFalse)
				So(cliArgs.ConfigFilePath, ShouldEqual, "")
			})
		})
	})
}

func TestConfig(t *testing.T) {
	Convey("Given a config file that sets an ignore statement and a go toolchain", t, func() {
		ctx := context.Background()

		// The indentation is off here due to the way that yaml deals with whitespace.
		content := `
---
ignore:
    - id: GO-2025-3563
      reason: This is a reason why it should be ignored
      expiry: 2085-01-15
toolchain: go1.24.1
`
		fs := afero.NewMemMapFs()
		afero.WriteFile(fs, testConfigFileName, []byte(content), 0644)

		Convey("When the config is retrieved", func() {
			cfg, err := config.Get(ctx, &config.CliArgs{
				ConfigFilePath: testConfigFileName,
			}, fs)
			So(err, ShouldBeNil)

			Convey("Then the values should be set as appropriate", func() {
				So(cfg.GoToolChain, ShouldEqual, "go1.24.1")
				So(cfg.UserConfig.Ignore[0], ShouldEqual, config.IgnoreStatement{ID: "GO-2025-3563", Reason: "This is a reason why it should be ignored", Expiry: time.Date(2085, 1, 15, 0, 0, 0, 0, time.UTC)})
			})
		})
	})

	Convey("Given a config file that sets an expiry date", t, func() {
		ctx := context.Background()

		// The indentation is off here due to the way that yaml deals with whitespace.
		content := `
---
ignore:
    - id: GO-2025-3563
      reason: This is a reason why it should be ignored
      expiry: 2026-04-27
`
		fs := afero.NewMemMapFs()
		afero.WriteFile(fs, testConfigFileName, []byte(content), 0644)

		Convey("When the config is retrieved", func() {
			cfg, err := config.Get(ctx, &config.CliArgs{
				ConfigFilePath: testConfigFileName,
			}, fs)
			So(err, ShouldBeNil)

			Convey("Then the expiry date should be parsed", func() {
				expected := time.Date(2026, 4, 27, 0, 0, 0, 0, time.UTC)
				So(cfg.UserConfig.Ignore[0].Expiry, ShouldEqual, expected)
			})
		})
	})

	Convey("Given a config file with an invalid expiry date", t, func() {
		ctx := context.Background()

		// The indentation is off here due to the way that yaml deals with whitespace.
		content := `
---
ignore:
    - id: GO-2025-3563
      reason: This is a reason why it should be ignored
      expiry: 2026-13-40
`
		fs := afero.NewMemMapFs()
		afero.WriteFile(fs, testConfigFileName, []byte(content), 0644)

		Convey("When the config is retrieved", func() {
			_, err := config.Get(ctx, &config.CliArgs{
				ConfigFilePath: testConfigFileName,
			}, fs)

			Convey("Then an error should be returned", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})

	Convey("Given no config file exists", t, func() {
		ctx := context.Background()
		fs := afero.NewMemMapFs()

		Convey("When the config is retrieved", func() {
			cfg, err := config.Get(ctx, &config.CliArgs{}, fs)
			So(err, ShouldBeNil)

			Convey("Then the values should be set as default", func() {
				So(cfg.GoToolChain, ShouldEqual, "")
				So(cfg.UserConfig.Ignore, ShouldBeEmpty)
			})
		})
	})

	Convey("Given a config filename is set but no file exists there", t, func() {
		ctx := context.Background()
		fs := afero.NewMemMapFs()

		configFilename := ".my-config-file.yml"

		Convey("When the config is retrieved", func() {
			_, err := config.Get(ctx, &config.CliArgs{
				ConfigFilePath: configFilename,
			}, fs)

			Convey("Then an error should be returned", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})

	Convey("Given a ci build yml with a go toolchain declaration", t, func() {
		ctx := context.Background()
		fs := afero.NewMemMapFs()

		// The indentation is off here due to the way that yaml deals with whitespace.
		buildFileContent := `
---
image_resource:
  type: docker-image
  source:
    repository: golang
    tag: 1.24.6-bookworm
`

		afero.WriteFile(fs, "./ci/build.yml", []byte(buildFileContent), 0644)

		Convey("When the config is retrieved", func() {
			cfg, err := config.Get(ctx, &config.CliArgs{}, fs)
			So(err, ShouldBeNil)

			Convey("Then the go toolchain should be picked up", func() {
				So(cfg.GoToolChain, ShouldEqual, "go1.24.6")
			})
		})
	})

	Convey("Given an invalid go build yaml", t, func() {
		ctx := context.Background()
		fs := afero.NewMemMapFs()

		// The indentation is off here due to the way that yaml deals with whitespace.
		buildFileContent := `
---
garbage
`

		afero.WriteFile(fs, "./ci/build.yml", []byte(buildFileContent), 0644)

		Convey("When the config is retrieved", func() {
			cfg, err := config.Get(ctx, &config.CliArgs{}, fs)

			Convey("Then no error should be returned", func() {
				So(err, ShouldBeNil)
			})

			Convey("And no toolchain should be set", func() {
				So(cfg.GoToolChain, ShouldBeEmpty)
			})
		})
	})

	Convey("Given a go build yaml with no tag", t, func() {
		ctx := context.Background()
		fs := afero.NewMemMapFs()

		// The indentation is off here due to the way that yaml deals with whitespace.
		buildFileContent := `
---
image_resource:
  type: docker-image
  source:
    repository: golang
    tag: bookworm
`

		afero.WriteFile(fs, "./ci/build.yml", []byte(buildFileContent), 0644)

		Convey("When the config is retrieved", func() {
			cfg, err := config.Get(ctx, &config.CliArgs{}, fs)

			Convey("Then no error should be returned", func() {
				So(err, ShouldBeNil)
			})

			Convey("And no toolchain should be set", func() {
				So(cfg.GoToolChain, ShouldBeEmpty)
			})
		})
	})
}
