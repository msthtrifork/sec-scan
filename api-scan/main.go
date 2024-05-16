package main

import (
	"context"
	"dagger/sec-scan/internal/dagger"
)

type SecScan struct{}

// scan API endpoints for security vulnerabilities
// send the api specification and a format to the zap-api-scan.py script
func (t *SecScan) ScanApi(
	ctx context.Context,
	openapiSpec *dagger.File,
	// +optional
	// +default="openapi"
	format string,
) (*dagger.File, error) {
	openapiSpec.Sync(ctx)

	fileId, err := openapiSpec.ID(ctx)
	if err != nil {
		return nil, err
	}

	file := dag.LoadFileFromID(fileId)

	filePath := "/zap/wrk/openapi.json"
	outputPath := "/zap/wrk/html_report.html"

	return dag.
		Container().
		From("ghcr.io/zaproxy/zaproxy:stable").
		WithMountedFile(filePath, file).
		WithWorkdir("/zap/wrk/").
		WithExec([]string{
			"zap-api-scan.py",
			"-t", filePath,
			"-f", format,
			"-I",
			"-r", outputPath,
			"-O", "https://youngmoney.test.internal.andmoney.dk",
		}).
		File(outputPath), nil
}
