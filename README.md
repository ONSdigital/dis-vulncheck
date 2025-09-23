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
```

## Running

To run dis-vulncheck:

```sh
  dis-vulncheck
```

### Flags

You can use two different flags against dis-vulncheck:

- `--verbose` will add full logging output
- `--config` can supply a string filepath for your config file

## What it checks against

By default, dis-vulncheck will get the gotoolchain from the local environment. In future we will look to allow user setting of this.
