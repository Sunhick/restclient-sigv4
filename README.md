# restclient-sigv4

AWS Signature Version 4 (SigV4) signing for [restclient.el](https://github.com/pashky/restclient.el).

Sign requests to AWS services directly from your restclient buffers — no manual signature computation needed.

## Requirements

- Emacs 27.1+ (for `gnutls-hash-mac`)
- [restclient.el](https://github.com/pashky/restclient.el)

## Installation

Add to your Emacs config:

```elisp
(add-to-list 'load-path "/path/to/restclient-sigv4")
(autoload 'restclient-sigv4-mode "restclient-sigv4" nil t)
(add-hook 'restclient-mode-hook #'restclient-sigv4-mode)
```

The package lazy-loads — the signer and credential modules are only loaded on the first request that actually uses `X-Sigv4`.

## Usage

Add an `X-Sigv4` header to your restclient request with `region` and `service` parameters:

```
#
GET https://execute-api.us-east-1.amazonaws.com/prod/items
X-Sigv4: region=us-east-1 service=execute-api
```

With an optional profile:

```
#
POST https://dynamodb.us-west-2.amazonaws.com/
X-Sigv4: region=us-west-2 service=dynamodb profile=production
Content-Type: application/x-amz-json-1.0

{"TableName": "my-table", "Key": {"id": {"S": "123"}}}
```

The `X-Sigv4` header is consumed during signing and replaced with the proper AWS authorization headers (`Authorization`, `x-amz-date`, `x-amz-content-sha256`, and optionally `x-amz-security-token`).

### Directive Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `region`  | Yes*     | AWS region (e.g. `us-east-1`) |
| `service` | Yes      | AWS service name (e.g. `execute-api`, `dynamodb`) |
| `profile` | No       | AWS credentials profile name |

*Region can be omitted if `restclient-sigv4-default-region` is set.

## Minor Mode

`restclient-sigv4-mode` is a minor mode that activates automatically in `restclient-mode` buffers. When active, you'll see ` SigV4` in the mode line.

| Command | Description |
|---------|-------------|
| `M-x restclient-sigv4-mode` | Toggle SigV4 signing on/off |

The mode auto-enables via `restclient-mode-hook`. Requests without an `X-Sigv4` header pass through unchanged regardless of whether the mode is active.

## Credentials

Credentials are resolved in order:

1. **Environment variables**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
2. **Credentials file**: `~/.aws/credentials` (configurable via `restclient-sigv4-credentials-file`)

If a session token is present, the `x-amz-security-token` header is automatically included.

### Profile Selection

Profile selection priority:
1. `profile=NAME` in the directive
2. `AWS_PROFILE` environment variable
3. `"default"`

### Setting Credentials Inline with `:eval`

You can set AWS credentials directly in your restclient buffer using `:eval` blocks. This is useful for temporary credentials (e.g., from `aws sts assume-role` or SSO sessions):

```
# Set credentials via environment variables (evaluated before requests)
:eval (setenv "AWS_ACCESS_KEY_ID" "ASIAYYCLVGDKEXAMPLE")
:eval (setenv "AWS_SECRET_ACCESS_KEY" "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
:eval (setenv "AWS_SESSION_TOKEN" "AQoDYXdzEJr...")

#
GET https://s3.us-east-1.amazonaws.com/
X-Sigv4: region=us-east-1 service=s3
```

The `:eval` blocks run before the request is sent, so the credentials are available when signing occurs. You can also select a profile this way:

```
:eval (setenv "AWS_PROFILE" "production")

#
GET https://s3.us-east-1.amazonaws.com/
X-Sigv4: region=us-east-1 service=s3
```

### Credentials File Format

Standard AWS INI format:

```ini
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

[production]
aws_access_key_id = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
aws_session_token = AQoDYXdzEJr...
```

## Configuration

All customizable variables are under the `restclient-sigv4` customization group (child of `restclient`):

```elisp
;; Set a default region so you can omit it from directives
(setq restclient-sigv4-default-region "us-east-1")

;; Use a non-default credentials file
(setq restclient-sigv4-credentials-file "~/.aws/my-credentials")
```

| Variable | Default | Description |
|----------|---------|-------------|
| `restclient-sigv4-default-region` | `nil` | Default AWS region when directive omits it |
| `restclient-sigv4-credentials-file` | `"~/.aws/credentials"` | Path to AWS credentials file |

## File Structure

```
restclient-sigv4/
├── restclient-sigv4.el              ; Minor mode, hook, directive parser
├── restclient-sigv4-signer.el       ; SigV4 signing algorithm (lazy-loaded)
├── restclient-sigv4-credentials.el  ; Credential resolution (lazy-loaded)
├── restclient-sigv4-pkg.el          ; Package metadata
├── examples.restclient              ; Example requests for various AWS services
├── Makefile                         ; Build and test automation
└── test/
    ├── restclient-sigv4-test.el     ; Unit tests (ERT)
    └── restclient-sigv4-pbt.el      ; Property-based tests (propcheck)
```

## Development

### Running Tests

```bash
# Install dependencies, byte-compile, and run unit tests
make all

# Unit tests only
make test

# Property-based tests (requires propcheck)
make pbt

# Strict byte-compilation (warnings as errors)
make lint
```

### Dependencies

Test dependencies are managed in `.deps/` and installed via `make deps`:
- `restclient` (from MELPA)
- `dash` (from MELPA)
- `propcheck` (cloned from GitHub for property-based tests)

## License

GPL-3.0. See [LICENSE](LICENSE).
