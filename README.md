# dis-vulncheck

dis-vulncheck is a wrapper around [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) to ensure we can exclude vulnerabilities where necesssary whilst awaiting updates to govulncheck.

## Dependencies

dis-vulncheck requires govulncheck to be installed to work as it wraps around it.

```sh
  go install golang.org/x/vuln/cmd/govulncheck@latest
```

## Installation

```sh
  go install github.com/ONSdigital/dis-vulncheck@latest
```

## Configuration

dis-vulncheck looks for a configuration file, currently defaulting to searching through:

- .dis-vulncheck.yml
- .dis-vulncheck.yaml
- .disvulncheck.yml
- .disvulncheck.yaml

This can be overriden by using a [config flag](#flags)

This specification for this file is below:

```yml
---
ignore:
  type: array
  items:
    type: object
    properties:
      id:
        description: "The Go vuln database ID of this vulnerability"
        example: "GO-2025-3563"
        type: string
      reason:
        description: "A reason why this vulnerability has been excluded from auditing"
        example: "This doesn't affect our application"
        type: string
toolchain:
  description: "An optional toolchain directive to override the default"
  example: "go1.25.0"
  type: string
```

## Running

To run dis-vulncheck:

```sh
  dis-vulncheck
```

### Flags

You can use two different flags against dis-vulncheck:

- `--build-tags` will pass this down to the underlying govulncheck scan
- `--config` can supply a string filepath for your config file
- `--verbose` will add full logging output

## What it checks against

By default, dis-vulncheck will inspect the CI build yml (`/ci/build.yml` or `/ci/build.yaml`) to retrieve the version of Go it will be built with.

e.g.

```yml
image_resource:
  type: docker-image
  source:
    repository: golang
    tag: 1.24.6-bookworm
```

In this case it will extract "1.24.6" and set this as the `GOTOOLCHAIN` when running `govulncheck`. This is to ensure consistency between CI and local environments.

If this is not found it will default to the Go version found in the local environment, or can be overriden through the [config file](#configuration).
