package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	sqlDeleteComposes = `
                DELETE FROM composes
                WHERE created_at < $1`
	sqlExpiredComposesCount = `
                SELECT COUNT(*) FROM composes
                WHERE created_at < $1`
	sqlVacuumAnalyze = `
                VACUUM ANALYZE`
	sqlVacuumStats = `
                SELECT relname, pg_size_pretty(pg_total_relation_size(relid)),
                    n_tup_ins, n_tup_upd, n_tup_del, n_live_tup, n_dead_tup,
                    vacuum_count, autovacuum_count, analyze_count, autoanalyze_count,
                    last_vacuum, last_autovacuum, last_analyze, last_autoanalyze
                 FROM pg_stat_user_tables`
)

type maintenanceDB struct {
	Conn *pgx.Conn
}

func newDB(ctx context.Context, dbURL string) (maintenanceDB, error) {
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		return maintenanceDB{}, err
	}

	return maintenanceDB{
		conn,
	}, nil
}

func (d *maintenanceDB) Close() error {
	return d.Conn.Close(context.Background())
}

func (d *maintenanceDB) DeleteComposes(ctx context.Context, emailRetentionDate time.Time) (int64, error) {
	tag, err := d.Conn.Exec(ctx, sqlDeleteComposes, emailRetentionDate)
	if err != nil {
		return tag.RowsAffected(), fmt.Errorf("error deleting composes: %v", err)
	}
	return tag.RowsAffected(), nil
}

func (d *maintenanceDB) ExpiredComposesCount(ctx context.Context, emailRetentionDate time.Time) (int64, error) {
	var count int64
	err := d.Conn.QueryRow(ctx, sqlExpiredComposesCount, emailRetentionDate).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (d *maintenanceDB) VacuumAnalyze(ctx context.Context) error {
	_, err := d.Conn.Exec(ctx, sqlVacuumAnalyze)
	if err != nil {
		return fmt.Errorf("error running VACUUM ANALYZE: %v", err)
	}
	return nil
}

func (d *maintenanceDB) LogVacuumStats(ctx context.Context) (int64, error) {
	rows, err := d.Conn.Query(ctx, sqlVacuumStats)
	if err != nil {
		return int64(0), fmt.Errorf("error querying vacuum stats: %v", err)
	}
	defer rows.Close()

	deleted := int64(0)

	for rows.Next() {
		select {
		case <-ctx.Done():
			err = ctx.Err()
			slog.ErrorContext(ctx, "context cancelled LogVacuumStats", "err", err)
			return int64(0), err
		default:
			var relName, relSize string
			var ins, upd, del, live, dead, vc, avc, ac, aac int64
			var lvc, lavc, lan, laan *time.Time

			err = rows.Scan(&relName, &relSize, &ins, &upd, &del, &live, &dead,
				&vc, &avc, &ac, &aac,
				&lvc, &lavc, &lan, &laan)
			if err != nil {
				return int64(0), err
			}

			attrs := []any{
				slog.String("table_name", relName),
				slog.String("table_size", relSize),
				slog.Int64("tuples_inserted", ins),
				slog.Int64("tuples_updated", upd),
				slog.Int64("tuples_deleted", del),
				slog.Int64("tuples_live", live),
				slog.Int64("tuples_dead", dead),
				slog.Int64("vacuum_count", vc),
				slog.Int64("autovacuum_count", avc),
				slog.Int64("analyze_count", ac),
				slog.Int64("autoanalyze_count", aac),
			}
			if lvc != nil {
				attrs = append(attrs, slog.Time("last_vacuum", *lvc))
			}
			if lavc != nil {
				attrs = append(attrs, slog.Time("last_autovacuum", *lavc))
			}
			if lan != nil {
				attrs = append(attrs, slog.Time("last_analyze", *lan))
			}
			if laan != nil {
				attrs = append(attrs, slog.Time("last_autoanalyze", *laan))
			}
			slog.With(attrs...).InfoContext(ctx, "vacuum and analyze stats for table")
		}
	}
	if rows.Err() != nil {
		return int64(0), rows.Err()
	}
	return deleted, nil

}

func DBCleanup(ctx context.Context, dbURL string, dryRun bool, ComposesRetentionMonths int) error {
	db, err := newDB(ctx, dbURL)
	if err != nil {
		return err
	}

	_, err = db.LogVacuumStats(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "error running vacuum stats", "err", err)
	}

	var rows int64

	emailRetentionDate := time.Now().AddDate(0, ComposesRetentionMonths*-1, 0)

	for {
		select {
		case <-ctx.Done():
			err = ctx.Err()
			slog.ErrorContext(ctx, "context cancelled DBCleanup", "err", err)
			return err
		default:
			// continue execution outside of select
			// so `break` works as expected
		}
		if dryRun {
			rows, err = db.ExpiredComposesCount(ctx, emailRetentionDate)
			if err != nil {
				slog.WarnContext(ctx, "error querying expired composes", "err", err)
			}
			slog.InfoContext(ctx, "dryrun", "expired_composes_count", rows)
			break
		}

		rows, err = db.DeleteComposes(ctx, emailRetentionDate)
		if err != nil {
			slog.ErrorContext(ctx, "error deleting composes", "err", err, "rows_affected", rows)
			return err
		}

		err = db.VacuumAnalyze(ctx)
		if err != nil {
			slog.ErrorContext(ctx, "error running vacuum analyze", "err", err)
			return err
		}

		if rows == 0 {
			break
		}

		slog.InfoContext(ctx, "deleted results", "deleted_composes", rows)
	}

	_, err = db.LogVacuumStats(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "error running vacuum stats", "err", err)
	}

	return nil
}
