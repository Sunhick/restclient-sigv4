# restclient-sigv4

AWS Signature Version 4 (SigV4) signing for [restclient.el](https://github.com/pashky/restclient.el).

Sign requests to AWS services directly from your restclient buffers.

## Status

Work in progress. Currently implemented:

- Package structure and metadata
- INI file parser for AWS credentials files

## Requirements

- Emacs 27.1+ (for `gnutls-hash-mac`)
- [restclient.el](https://github.com/pashky/restclient.el)

## Planned Usage

Add an `X-Sigv4` header to your restclient request:

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

## Credentials

Credentials are resolved in order:

1. **Environment variables**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
2. **Credentials file**: `~/.aws/credentials` (configurable)

### Credentials File Format

The credentials file uses standard INI format:

```ini
# Comments start with # or ;
; This is also a comment

[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

[production]
aws_access_key_id = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
aws_session_token = AQoDYXdzEJr...
```

Profile selection priority:
1. `profile=NAME` in the directive
2. `AWS_PROFILE` environment variable
3. `"default"`

## File Structure

```
restclient-sigv4/
├── restclient-sigv4.el              ; Integration layer (planned)
├── restclient-sigv4-signer.el       ; SigV4 signing algorithm (planned)
├── restclient-sigv4-credentials.el  ; Credential resolution
├── restclient-sigv4-pkg.el          ; Package metadata
└── test/
    ├── restclient-sigv4-test.el     ; Unit tests
    └── restclient-sigv4-pbt.el      ; Property-based tests (planned)
```

## Running Tests

```bash
emacs -batch -L . -L test -l ert -l test/restclient-sigv4-test.el -f ert-run-tests-batch-and-exit
```

## License

GPL-3.0. See [LICENSE](LICENSE).
