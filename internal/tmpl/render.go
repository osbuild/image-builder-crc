package tmpl

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"log/slog"
	"text/template"

	"github.com/osbuild/image-builder-crc/internal/common"
)

//go:embed *.tmpl.*
var templateFS embed.FS

var templates *template.Template

func init() {
	var err error
	templates, err = template.ParseFS(templateFS, "*.tmpl.*")
	if err != nil {
		panic(err)
	}
}

func Render(ctx context.Context, name string, params any) (*string, error) {
	var buf bytes.Buffer
	slog.DebugContext(ctx, "rendering template", "name", name, "params", params)
	err := templates.ExecuteTemplate(&buf, name, params)
	if err != nil {
		return nil, fmt.Errorf("error executing template: %w", err)
	}
	slog.DebugContext(ctx, "template rendered", "output", buf.String(), "template", true)

	return common.ToPtr(buf.String()), nil
}

func RenderAAPServiceUnit(ctx context.Context) (*string, error) {
	return Render(ctx, "aap-first-boot.tmpl.service", "")
}

func RenderAAPRegistrationScript(ctx context.Context, params AAPRegistrationParams) (*string, error) {
	return Render(ctx, "aap-first-boot-script.tmpl.txt", params)
}
