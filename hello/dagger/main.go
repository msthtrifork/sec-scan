// A generated module for Hello functions
//
// This module has been generated via dagger init and serves as a reference to
// basic module structure as you get started with Dagger.
//
// Two functions have been pre-created. You can modify, delete, or add to them,
// as needed. They demonstrate usage of arguments and return types using simple
// echo and grep commands. The functions can be called from the dagger CLI or
// from one of the SDKs.
//
// The first line in this comment block is a short description line and the
// rest is a long description with more detail on the module's purpose or usage,
// if appropriate. All modules should have a short description.

package main

import (
	"context"
	"fmt"
)

type Hello struct{}

// Returns a container that echoes whatever string argument is provided
func (m *Hello) ContainerEcho(stringArg string) *Container {
	return dag.Container().From("alpine:latest").WithExec([]string{"echo", stringArg})
}

func (m *Hello) ApiScan(
	ctx context.Context,
	openapiSpec *File,
	// +optional
	// +default="openapi"
	format string,
) (*File, error) {
	openapiSpec.Sync(ctx)

	fileId, err := openapiSpec.ID(ctx)
	if err != nil {
		return nil, err
	}

	file := dag.LoadFileFromID(fileId)

	filePath := "/zap/wrk/openapi.json"
	outputPath := "/zap/wrk/html_report.html"

	fmt.Println("Test")

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

// Returns lines that match a pattern in the files of the provided Directory
func (m *Hello) GrepDir(ctx context.Context, directoryArg *Directory, pattern string) (string, error) {
	return dag.Container().
		From("alpine:latest").
		WithMountedDirectory("/mnt", directoryArg).
		WithWorkdir("/mnt").
		WithExec([]string{"grep", "-R", pattern, "."}).
		Stdout(ctx)
}
