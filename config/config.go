package config

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"regexp"
	"strings"

	"github.com/ONSdigital/log.go/v2/log"
	"github.com/goccy/go-yaml"
	"github.com/spf13/afero"
)

type CliArgs struct {
	ConfigFilePath string `json:"config,omitempty"`
	Verbose        bool   `json:"verbose,omitempty"`
}

type UserConfig struct {
	Ignore []IgnoreStatement `yaml:"ignore"`
}

type Config struct {
	UserConfig *UserConfig
}

type IgnoreStatement struct {
	ID      string `yaml:"id"`
	Reason  string `yaml:"reason"`
	Matched bool
}

var (
	configFileNames []string = []string{
		".dis-vulncheck.yml",
		".dis-vulncheck.yaml",
		".disvulncheck.yml",
		".disvulncheck.yaml",
	}
	defaultCIBuildFilePath = "./ci/build.yml"
)

func getCIGoBuildVersion(ctx context.Context, filepath string, fs afero.Fs) (string, error) {
	var ciBuild struct {
		Platform string `yaml:"platform"`
		ImRes    struct {
			Source struct {
				Repository string `yaml:"repository"`
				Tag        string `yaml:"tag"`
			} `yaml:"source"`
		} `yaml:"image_resource"`
	}

	buildBytes, err := afero.ReadFile(fs, filepath)
	if err != nil {
		log.Error(ctx, "unable to read ci build file", err)
		return "", err
	}

	err = yaml.Unmarshal(buildBytes, &ciBuild)
	if err != nil {
		log.Error(ctx, "unable to unmarshal ci build file yaml", err)
		return "", err
	}

	if ciBuild.ImRes.Source.Tag != "" {
		version := strings.Split(ciBuild.ImRes.Source.Tag, "-")[0]
		r := regexp.MustCompile(`^\d+.\d+.\d+$`)

		if r.MatchString(version) {
			return fmt.Sprintf("go%s", version), nil
		}
	}

	return "", errors.New("no tag returned")
}

func pickUserConfigFile(ctx context.Context, cliArgs *CliArgs, fs afero.Fs) (string, error) {
	if cliArgs.ConfigFilePath != "" {
		if _, err := fs.Stat(cliArgs.ConfigFilePath); err == nil {
			return cliArgs.ConfigFilePath, nil
		} else {
			log.Error(ctx, "error finding custom config file", err, log.Data{
				"filepath": cliArgs.ConfigFilePath,
			})
			return "", err
		}
	} else {
		for _, filename := range configFileNames {
			if _, err := fs.Stat(filename); err == nil {
				return filename, nil
			}
		}
		log.Info(ctx, "no default config files available")
	}
	// No user config file is acceptable
	return "", nil
}

func getUserConfig(ctx context.Context, cliArgs *CliArgs, fs afero.Fs) (*UserConfig, error) {
	var cfg UserConfig

	configFileName, err := pickUserConfigFile(ctx, cliArgs, fs)
	if err != nil {
		log.Info(ctx, "couldn't get a user config file", log.Data{
			"filename": configFileName,
		})
		return &UserConfig{}, err
	}

	// If no config, just return nothing
	if configFileName == "" {
		return &UserConfig{}, nil
	}

	log.Info(ctx, "getting config from file", log.Data{
		"filename": configFileName,
	})

	configBytes, err := afero.ReadFile(fs, configFileName)
	if err != nil {
		log.Error(ctx, "unable to read config file", err)
		return &UserConfig{}, err
	}

	err = yaml.Unmarshal(configBytes, &cfg)
	if err != nil {
		log.Error(ctx, "unable to unmarshal config file yaml", err)
		return &UserConfig{}, err
	}

	return &cfg, nil
}

// GetCliArgs parses the cli arguments passed.
func GetCliArgs() *CliArgs {
	var cliArgs CliArgs

	flag.StringVar(&cliArgs.ConfigFilePath, "config", "", "config filepath")
	flag.BoolVar(&cliArgs.Verbose, "verbose", false, "run tool in verbose mode or not")
	flag.Parse()

	return &cliArgs
}

// Get will retrieve the userConfig and the Go Toolchain.
func Get(ctx context.Context, cliArgs *CliArgs, fs afero.Fs) (*Config, error) {
	userConfig, err := getUserConfig(ctx, cliArgs, fs)
	if err != nil {
		log.Error(ctx, "unable to load config", err)
		return nil, fmt.Errorf("unable to load config: %v", err)
	}

	cfg := Config{
		userConfig,
	}

	log.Info(ctx, "config", log.Data{
		"config": cfg,
	})

	return &cfg, err
}
