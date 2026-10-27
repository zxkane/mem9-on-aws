package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pgvector/pgvector-go"
	"github.com/qiffang/mnemos/server/internal/domain"
	"github.com/qiffang/mnemos/server/internal/testutil"
)

// This file is copied into a disposable, patched upstream checkout by the local
// experiment runner. It is never included in the service image.
func TestNamespaceVectorCapacityMatrix(t *testing.T) {
	if os.Getenv("MEM9_VECTOR_CAPACITY_MATRIX") != "1" {
		t.Skip("explicit local capacity experiment required")
	}
	u, err := url.Parse(os.Getenv("MNEMO_TEST_POSTGRES_DSN"))
	if err != nil || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") || u.Path != "/mem9_namespace_test" {
		t.Fatal("capacity experiment requires its loopback-only disposable database")
	}
	rows := []int{25000, 30000, 50000}
	if value := os.Getenv("MEM9_VECTOR_MATRIX_ROWS"); value != "" {
		rows = nil
		for _, part := range strings.Split(value, ",") {
			n, err := strconv.Atoi(part)
			if err != nil || (n != 25000 && n != 30000 && n != 50000) {
				t.Fatal("unsupported fixture size")
			}
			rows = append(rows, n)
		}
	}
	for _, size := range rows {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			db := ingestTestDB(t)
			seedVectorCapacityFixture(t, db, size)
			var sourceDatabase string
			if err := db.QueryRow("SELECT current_database()").Scan(&sourceDatabase); err != nil {
				t.Fatal(err)
			}
			// Every comparison starts with an independent pristine clone.
			db.Close()
			fixtureURL := *u
			fixtureURL.Path = "/" + sourceDatabase
			for _, mode := range []string{"auto", "force_custom_plan", "force_generic_plan"} {
				for _, concurrency := range []int{1, 5, 10} {
					for _, writes := range []bool{false, true} {
						t.Run(fmt.Sprintf("%s/c%d/writes_%t", mode, concurrency, writes), func(t *testing.T) {
							caseDB := testutil.OpenIsolatedPostgres(t, fixtureURL.String())
							runVectorCapacityCase(t, caseDB, size, mode, concurrency, writes)
						})
					}
				}
			}
		})
	}
}

func seedVectorCapacityFixture(t *testing.T, db *sql.DB, size int) {
	t.Helper()
	for _, fixture := range []struct{ prefix, namespace, principal string }{
		{"97000000-0000-4000-8000-", testutil.TestNamespaceID, testutil.TestPrincipalID},
		{"98000000-0000-4000-8000-", testutil.TestOtherNamespaceID, testutil.TestOtherPrincipalID},
	} {
		_, err := db.Exec(`INSERT INTO memories
 (id,content,embedding,memory_type,app_id,state,version,namespace_id,created_by_principal_id,updated_by_principal_id)
 SELECT $1||lpad(i::text,12,'0'),repeat('synthetic capacity fixture ',120),
 (ARRAY[1::real,0.1::real+i::real/$4::real] || ARRAY(SELECT (sin((i*1024+j)::double precision)/1000)::real FROM generate_series(1,1022)j))::vector,
 'pinned','vector-capacity-fixture','active',1,$2,$3,$3 FROM generate_series(1,$4)i`,
			fixture.prefix, fixture.namespace, fixture.principal, size)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec("VACUUM ANALYZE memories"); err != nil {
		t.Fatal(err)
	}
}

func runVectorCapacityCase(t *testing.T, admin *sql.DB, size int, mode string, concurrency int, writes bool) {
	t.Helper()
	var database string
	if err := admin.QueryRow("SELECT current_database()").Scan(&database); err != nil {
		t.Fatal(err)
	}
	config, err := pgx.ParseConfig(os.Getenv("MNEMO_TEST_POSTGRES_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	config.Database = database
	config.RuntimeParams["plan_cache_mode"] = mode
	pools := make([]*sql.DB, concurrency)
	repos := make([]*MemoryRepo, concurrency)
	for i := range pools {
		pools[i] = stdlib.OpenDB(*config.Copy())
		defer pools[i].Close()
		pools[i].SetMaxOpenConns(1)
		pools[i].SetMaxIdleConns(1)
		repos[i] = NewMemoryRepo(pools[i], false, "", testutil.TestNamespaceScope())
		repos[i].exactVectorMaxRows = size // experiment only; production guard is unchanged
		repos[i].exactVectorTimeout = 2 * time.Second
	}
	vector := make([]float32, 1024)
	vector[0] = 1
	const topK = 50
	filter := domain.MemoryFilter{MinScore: -1}
	reference, err := admin.Query(`SELECT id FROM memories WHERE namespace_id=$1 AND state='active' AND embedding IS NOT NULL ORDER BY embedding <=> $2 LIMIT $3`,
		testutil.TestNamespaceID, pgvector.NewVector(vector), topK)
	if err != nil {
		t.Fatal(err)
	}
	var expected []string
	for reference.Next() {
		var id string
		if err := reference.Scan(&id); err != nil {
			t.Fatal(err)
		}
		expected = append(expected, id)
	}
	if err := reference.Err(); err != nil {
		t.Fatal(err)
	}
	reference.Close()
	if len(expected) != topK {
		t.Fatal("incomplete exact reference")
	}
	validate := func(actual []domain.Memory) error {
		if len(actual) != len(expected) {
			return fmt.Errorf("incomplete result: %d", len(actual))
		}
		for i := range actual {
			if actual[i].ID != expected[i] || !strings.HasPrefix(actual[i].ID, "97000000-") {
				return fmt.Errorf("incorrect or foreign result at rank %d", i)
			}
		}
		return nil
	}
	firstStart := time.Now()
	first, firstErr := repos[0].VectorSearch(context.Background(), vector, filter, topK)
	firstMs := float64(time.Since(firstStart).Microseconds()) / 1000
	if firstErr == nil {
		firstErr = validate(first)
	}
	if firstErr != nil && !errors.Is(firstErr, domain.ErrNamespaceVectorTimeout) {
		t.Fatal(firstErr)
	}
	// Warm each physical connection independently, including the five custom
	// plans PostgreSQL considers before selecting a generic prepared plan.
	type warmObservation struct {
		err                       error
		attempted, completed      int
		genericPlans, customPlans int64
	}
	warmResults := make(chan warmObservation, concurrency)
	for i, repo := range repos {
		go func(repo *MemoryRepo, pool *sql.DB) {
			observed := warmObservation{}
			for call := 0; call < 6; call++ {
				observed.attempted++
				actual, err := repo.VectorSearch(context.Background(), vector, filter, topK)
				if err == nil {
					err = validate(actual)
				}
				if err != nil {
					observed.err = err
					break
				}
				observed.completed++
			}
			if err := pool.QueryRow(`SELECT coalesce(sum(generic_plans),0),coalesce(sum(custom_plans),0)
 FROM pg_prepared_statements WHERE statement ~ '^[[:space:]]*WITH namespace_distances'`).Scan(&observed.genericPlans, &observed.customPlans); err != nil {
				observed.err = err
			}
			warmResults <- observed
		}(repo, pools[i])
	}
	warmTimeouts, warmAttempts, warmCompleted := 0, 0, 0
	var warmGeneric, warmCustom int64
	for range repos {
		observed := <-warmResults
		warmAttempts += observed.attempted
		warmCompleted += observed.completed
		warmGeneric += observed.genericPlans
		warmCustom += observed.customPlans
		if errors.Is(observed.err, domain.ErrNamespaceVectorTimeout) {
			warmTimeouts++
		} else if observed.err != nil {
			t.Fatal(observed.err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var writeWG sync.WaitGroup
	defer func() { cancel(); writeWG.Wait() }()
	var writeCount, writeErrors atomic.Int64
	writeReady := make(chan struct{})
	if writes {
		writeWG.Add(1)
		go func() {
			defer writeWG.Done()
			ticker := time.NewTicker(50 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					// Replace distant vectors with new dense values. These rows stay
					// below the exact top-K, keeping the read oracle stable.
					count := writeCount.Load()
					_, err := admin.ExecContext(ctx, `UPDATE memories SET embedding=(
 ARRAY[1::real,2::real+($3::int%7)::real/10] ||
 ARRAY(SELECT (sin(($3::int*1024+j)::double precision)/1000)::real FROM generate_series(1,1022)j)
 )::vector WHERE namespace_id=$1 AND id=$2`,
						testutil.TestNamespaceID, fmt.Sprintf("97000000-0000-4000-8000-%012d", int64(size)-999+count%1000), count)
					if err != nil {
						if ctx.Err() == nil {
							writeErrors.Add(1)
						}
					} else {
						if writeCount.Add(1) == 1 {
							close(writeReady)
						}
					}
				}
			}
		}()
		select {
		case <-writeReady:
		case <-ctx.Done():
			t.Fatal("background writer did not start")
		}
	}
	writeBaseline := writeCount.Load()
	measurementStart := time.Now()
	const samples = 30
	jobs := make(chan int, samples)
	for i := 0; i < samples; i++ {
		jobs <- i
	}
	close(jobs)
	type observation struct {
		milliseconds float64
		err          error
	}
	results := make(chan observation, samples)
	var readers sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		readers.Add(1)
		go func(repo *MemoryRepo) {
			defer readers.Done()
			for range jobs {
				start := time.Now()
				actual, err := repo.VectorSearch(ctx, vector, filter, topK)
				if err == nil {
					err = validate(actual)
				}
				results <- observation{float64(time.Since(start).Microseconds()) / 1000, err}
			}
		}(repos[i])
	}
	readers.Wait()
	measurementMs := float64(time.Since(measurementStart).Microseconds()) / 1000
	overlapWrites := writeCount.Load() - writeBaseline
	cancel()
	writeWG.Wait()
	close(results)
	latencies := []float64{}
	timeouts, failures := 0, 0
	for result := range results {
		if errors.Is(result.err, domain.ErrNamespaceVectorTimeout) {
			timeouts++
		} else if result.err != nil {
			failures++
			t.Error(result.err)
		} else {
			latencies = append(latencies, result.milliseconds)
		}
	}
	sort.Float64s(latencies)
	quantile := func(percent int) any {
		if len(latencies) == 0 {
			return nil
		}
		return latencies[(len(latencies)*percent+99)/100-1]
	}
	var genericPlans, customPlans int64
	for _, pool := range pools {
		var generic, custom int64
		if err := pool.QueryRow(`SELECT coalesce(sum(generic_plans),0),coalesce(sum(custom_plans),0)
 FROM pg_prepared_statements WHERE statement ~ '^[[:space:]]*WITH namespace_distances'`).Scan(&generic, &custom); err != nil {
			t.Fatal(err)
		}
		genericPlans += generic
		customPlans += custom
	}
	var postgresVersion, vectorVersion string
	if err := admin.QueryRow("SELECT current_setting('server_version'),extversion FROM pg_extension WHERE extname='vector'").Scan(&postgresVersion, &vectorVersion); err != nil {
		t.Fatal(err)
	}
	report := map[string]any{"event": "vector_capacity_sample", "rowsPerNamespace": size, "dimensions": 1024,
		"planMode": mode, "concurrency": concurrency, "backgroundWrites": writes, "topK": topK, "attempts": samples,
		"successes": len(latencies), "timeouts": timeouts, "failures": failures, "successfulP50Ms": quantile(50),
		"successfulP95Ms": quantile(95), "successfulP99Ms": quantile(99), "firstConnectionMs": firstMs,
		"firstConnectionTimeout": firstErr != nil, "cacheEvicted": false, "writesCompleted": writeCount.Load(), "writeErrors": writeErrors.Load(),
		"writesDuringReads": overlapWrites, "measurementMs": measurementMs, "configuredWarmupRequestsPerConnection": 6, "warmupConnectionsTimedOut": warmTimeouts,
		"warmupAttempts": warmAttempts, "warmupCompleted": warmCompleted, "warmupComplete": warmCompleted == concurrency*6,
		"preMeasurementGenericPlans": warmGeneric, "preMeasurementCustomPlans": warmCustom,
		"genericPlans": genericPlans, "customPlans": customPlans, "postgresVersion": postgresVersion, "pgvectorVersion": vectorVersion,
		"environment": os.Getenv("MEM9_VECTOR_MATRIX_ENVIRONMENT"), "configuredCpuLimit": os.Getenv("MEM9_VECTOR_MATRIX_CPUS"),
		"configuredMemoryLimit": os.Getenv("MEM9_VECTOR_MATRIX_MEMORY")}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(encoded))
	if writeErrors.Load() > 0 {
		t.Fatal("background writes failed")
	}
	if writes && overlapWrites < 1 {
		t.Fatal("no background writes overlapped the measurement")
	}
	if warmTimeouts == 0 && warmGeneric+warmCustom < int64(concurrency*6) {
		t.Fatal("prepared-plan warmup was not observed")
	}
}
