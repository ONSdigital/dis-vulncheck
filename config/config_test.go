package config_test

import (
	"context"
	"flag"
	"os"
	"testing"

	"github.com/ONSdigital/dis-vulncheck/config"
	. "github.com/smartystreets/goconvey/convey"
	"github.com/spf13/afero"
)

const (
	// The indentation is off here due to the way that yaml deals with whitespace.
	testBuildFileContent = `
---
image_resource:
  type: docker-image
  source:
    repository: golang
    tag: 1.24.6-bookworm
`
)

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
		configFilename := ".dis-vulncheck.yml"

		// The indentation is off here due to the way that yaml deals with whitespace.
		content := `
---
ignore:
    - id: GO-2025-3563
      reason: This is a reason why it should be ignored
toolchain: go1.24.1
`
		fs := afero.NewMemMapFs()
		afero.WriteFile(fs, configFilename, []byte(content), 0644)

		Convey("When the config is retrieved", func() {
			cfg, err := config.Get(ctx, &config.CliArgs{
				ConfigFilePath: configFilename,
			}, fs)
			So(err, ShouldBeNil)

			Convey("Then the values should be set as appropriate", func() {
				So(cfg.GoToolChain, ShouldEqual, "go1.24.1")
				So(cfg.UserConfig.Ignore[0], ShouldEqual, config.IgnoreStatement{ID: "GO-2025-3563", Reason: "This is a reason why it should be ignored"})
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

		afero.WriteFile(fs, "./ci/build.yml", []byte(testBuildFileContent), 0644)

		Convey("When the config is retrieved", func() {
			cfg, err := config.Get(ctx, &config.CliArgs{}, fs)
			So(err, ShouldBeNil)

			Convey("Then the go toolchain should be picked up", func() {
				So(cfg.GoToolChain, ShouldEqual, "go1.24.6")
			})
		})
	})

	Convey("Given a ci build yaml with a go toolchain declaration", t, func() {
		ctx := context.Background()
		fs := afero.NewMemMapFs()

		afero.WriteFile(fs, "./ci/build.yaml", []byte(testBuildFileContent), 0644)

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
