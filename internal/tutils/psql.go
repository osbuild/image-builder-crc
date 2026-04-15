package tutils

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/tern/v2/migrate"

	"github.com/osbuild/image-builder-crc/internal/db"
)

type PSQLContainer struct {
	name string
	id   string
	port int

	pgMu   sync.Mutex
	pgConn *pgx.Conn // lazily opened to "postgres" for admin SQL (e.g. CREATE DATABASE)
}

const (
	image string = "quay.io/osbuild/postgres:13-alpine"
	user  string = "postgres"
)

var fastPgArgs = []string{
	"postgres",
	"-c", "fsync=off",
	"-c", "full_page_writes=off",
	"-c", "synchronous_commit=off",
}

func containerRuntime() (string, error) {
	out, err := exec.Command("which", "podman").Output()
	if err == nil {
		return strings.TrimSpace(string(out)), nil
	}
	out, err = exec.Command("which", "docker").Output()
	if err == nil {
		return strings.TrimSpace(string(out)), nil
	}
	return "", fmt.Errorf("no container runtime found (looked for podman or docker)")
}

func NewPSQLContainer() (*PSQLContainer, error) {
	rt, err := containerRuntime()
	if err != nil {
		return nil, err
	}

	name := fmt.Sprintf("image_builder_test_%d", time.Now().Unix())
	/* #nosec G404 */
	port := 65535 - rand.Intn(32000)
	runArgs := []string{
		rt,
		"run",
		"--mount=type=tmpfs,destination=/var/lib/postgresql/data",
		"--mount=type=tmpfs,destination=/dev/shm",
		"--detach",
		"--rm",
		"--name", name,
		"--env", fmt.Sprintf("POSTGRES_USER=%s", user),
		"--env", "POSTGRES_HOST_AUTH_METHOD=trust",
		"-p", fmt.Sprintf("127.0.0.1:%d:5432", port),
		image,
	}
	runArgs = append(runArgs, fastPgArgs...)
	/* #nosec G204 */
	out, err := exec.Command(runArgs[0], runArgs[1:]...).Output()
	if err != nil {
		fmt.Println(out, err)
		return nil, err
	}

	p := &PSQLContainer{
		name: name,
		id:   strings.TrimSpace(string(out)),
		port: port,
	}

	var lastErr error
	for i := 0; i < 40; i++ {
		_, err := p.execCommand("exec", p.name, "pg_isready")
		if err == nil {
			return p, nil
		}
		lastErr = err
		time.Sleep(250 * time.Millisecond)
	}
	_, _ = p.execCommand("kill", p.name)
	return nil, fmt.Errorf("container not ready after pg_isready attempts: %w", lastErr)
}

func (p *PSQLContainer) execCommand(args ...string) (string, error) {
	rt, err := containerRuntime()
	if err != nil {
		return "", err
	}
	/* #nosec G204 */
	out, err := exec.Command(rt, args...).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("command %s %s error: %w, output: %s", rt, args, err, out)
	}
	return strings.TrimSpace(string(out)), err
}

func (p *PSQLContainer) pgConnString(database string) string {
	host := net.JoinHostPort("127.0.0.1", strconv.Itoa(p.port))
	return fmt.Sprintf("postgres://%s@%s/%s?sslmode=disable", user, host, database)
}

func (p *PSQLContainer) adminPGConn(ctx context.Context) (*pgx.Conn, error) {
	p.pgMu.Lock()
	defer p.pgMu.Unlock()
	if p.pgConn != nil {
		if err := p.pgConn.Ping(ctx); err == nil {
			return p.pgConn, nil
		}
		_ = p.pgConn.Close(ctx)
		p.pgConn = nil
	}
	conn, err := pgx.Connect(ctx, p.pgConnString("postgres"))
	if err != nil {
		return nil, err
	}
	p.pgConn = conn
	return conn, nil
}

func (p *PSQLContainer) closePGConn(ctx context.Context) {
	p.pgMu.Lock()
	defer p.pgMu.Unlock()
	if p.pgConn != nil {
		_ = p.pgConn.Close(ctx)
		p.pgConn = nil
	}
}

func (p *PSQLContainer) execQuery(ctx context.Context, dbase, cmd string) (string, error) {
	targetDB := dbase
	if targetDB == "" {
		targetDB = "postgres"
	}
	if targetDB == "postgres" {
		conn, err := p.adminPGConn(ctx)
		if err != nil {
			return "", err
		}
		tag, err := conn.Exec(ctx, cmd)
		if err != nil {
			return "", err
		}
		return tag.String(), nil
	}
	conn, err := pgx.Connect(ctx, p.pgConnString(targetDB))
	if err != nil {
		return "", err
	}
	defer conn.Close(ctx)
	tag, err := conn.Exec(ctx, cmd)
	if err != nil {
		return "", err
	}
	return tag.String(), nil
}

func (p *PSQLContainer) Stop() error {
	p.closePGConn(context.Background())

	_, err := p.execCommand("kill", p.name)
	return err
}

type TernMigrateOptions struct {
	MigrationsDir string
	Hostname      string
	DBName        string
	DBPort        string
	DBUser        string
	DBPassword    string
	SSLMode       string
}

// ternVersionTable matches the default in the tern CLI (see tern LoadConfig).
const ternVersionTable = "public.schema_version"

func pgURLForTern(opt TernMigrateOptions) string {
	sslmode := opt.SSLMode
	if sslmode == "" {
		sslmode = "disable"
	}
	u := &url.URL{
		Scheme: "postgres",
		Host:   net.JoinHostPort(opt.Hostname, opt.DBPort),
		Path:   "/" + opt.DBName,
	}
	if opt.DBPassword != "" {
		u.User = url.UserPassword(opt.DBUser, opt.DBPassword)
	} else {
		u.User = url.User(opt.DBUser)
	}
	q := url.Values{}
	q.Set("sslmode", sslmode)
	u.RawQuery = q.Encode()
	return u.String()
}

// callTernMigrate runs the same migration logic as `tern migrate` (destination "last")
// by using the tern [migrate] package directly instead of shelling out to the tern binary.
func callTernMigrate(ctx context.Context, opt TernMigrateOptions) error {
	migDir, err := filepath.Abs(opt.MigrationsDir)
	if err != nil {
		return fmt.Errorf("tern migrations path: %w", err)
	}

	conn, err := pgx.Connect(ctx, pgURLForTern(opt))
	if err != nil {
		return fmt.Errorf("tern connect: %w", err)
	}
	defer conn.Close(ctx)

	migrator, err := migrate.NewMigrator(ctx, conn, ternVersionTable)
	if err != nil {
		return fmt.Errorf("tern new migrator: %w", err)
	}
	migrator.Data = map[string]interface{}{}

	if err := migrator.LoadMigrations(os.DirFS(migDir)); err != nil {
		return fmt.Errorf("tern load migrations: %w", err)
	}
	if len(migrator.Migrations) == 0 {
		return fmt.Errorf("tern: no migrations found in %s", migDir)
	}
	if err := migrator.Migrate(ctx); err != nil {
		return fmt.Errorf("tern migrate: %w", err)
	}
	return nil
}

func (p *PSQLContainer) NewDB(ctx context.Context) (db.DB, error) {
	dbName := fmt.Sprintf("test%s", strings.Replace(uuid.New().String(), "-", "", -1))
	_, err := p.execQuery(ctx, "", fmt.Sprintf("CREATE DATABASE %s TEMPLATE template0", dbName))
	if err != nil {
		return nil, err
	}

	if err := callTernMigrate(
		ctx,
		TernMigrateOptions{
			MigrationsDir: "../db/migrations-tern/",
			Hostname:      "localhost",
			DBName:        dbName,
			DBPort:        fmt.Sprintf("%d", p.port),
			DBUser:        user,
		},
	); err != nil {
		return nil, err
	}
	return db.InitDBConnectionPool(ctx, fmt.Sprintf("postgres://postgres@localhost:%d/%s", p.port, dbName))
}
