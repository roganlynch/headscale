# PR11: Integration Testing - Logtail Database Foundation

**Status:** Planning  
**Related PR:** PR1 - Database Foundation  
**Purpose:** Define integration test components for Logtail database schema

---

## 📋 Overview

This document lists the components that need to be included in integration testing for the Logtail database foundation (PR1). These tests will validate that the database schema works correctly in a full Headscale environment.

---

## 🧪 Integration Test Components

### 1. Database Migration Integration

**Component:** Migration execution in full database context  
**Test Scope:**
- Migration runs successfully during Headscale startup
- All Logtail tables created alongside existing Headscale tables
- Foreign key relationships work with real node data
- Migration is idempotent (can be re-run safely)
- Schema validation after migration completes

**Test Files:**
- `hscontrol/db/suite_test.go` - Add Logtail schema validation
- New: `integration/logtail_schema_test.go`

**Key Validations:**
```go
// Verify tables exist in full DB context
- node_logs table present
- log_instances table present  
- logtail_private_id_associations table present
- logtail_ip_observations table present
- logtail_first_seen table present
- logtail_rate_limits table present

// Verify indexes created
- All 19 indexes present and functional

// Verify foreign key behavior
- Association CASCADE DELETE with real nodes
- IP observations CASCADE DELETE with associations
```

---

### 2. Foreign Key Cascade with Real Nodes

**Component:** Node deletion cascades to Logtail associations  
**Test Scope:**
- Create real node through Headscale registration flow
- Create Logtail association for that node
- Delete node via Headscale API
- Verify association and IP observations are deleted

**Test Files:**
- `integration/logtail_foreign_keys_test.go`

**Test Scenario:**
```go
1. Register node with Headscale (TestNodeRegistrationWithLogtailAssociation)
2. Create logtail_private_id_associations entry for node
3. Create logtail_ip_observations entries
4. Delete node via gRPC DeleteNode API
5. Verify CASCADE DELETE removed associations
6. Verify CASCADE DELETE removed IP observations
```

---

### 3. Multi-Database Compatibility

**Component:** Schema works with both SQLite and PostgreSQL  
**Test Scope:**
- Run migration on SQLite database
- Run migration on PostgreSQL database
- Verify identical schema structure
- Test foreign key enforcement on both
- Test DATETIME handling on both

**Test Files:**
- `integration/logtail_postgres_test.go`
- `integration/logtail_sqlite_test.go`

**Database-Specific Validations:**
```
SQLite:
- NUMERIC type for booleans works correctly
- TEXT type for JSON works correctly
- DATETIME functions work correctly
- Foreign key constraints enabled (PRAGMA foreign_keys = ON)

PostgreSQL:
- BOOLEAN type works correctly
- JSONB/JSON type works correctly
- TIMESTAMP type works correctly
- Foreign key constraints work natively
```

---

### 4. Index Performance Validation

**Component:** Indexes improve query performance as expected  
**Test Scope:**
- Insert large dataset (1000+ log entries)
- Verify query plans use indexes
- Measure query performance with/without indexes
- Validate composite index usage

**Test Files:**
- `integration/logtail_performance_test.go`

**Performance Benchmarks:**
```go
// Query patterns that should use indexes:
1. Find logs by (collection, private_id) - idx_logs_collection_private
2. Find logs by public_id - idx_logs_public
3. Find logs by timestamp range - idx_logs_timestamp
4. Find logs by tier and timestamp - idx_logs_tier_timestamp
5. Find recent IPs by (private_id, last_seen) - idx_logtail_ip_obs_window

// Verify using EXPLAIN QUERY PLAN (SQLite) or EXPLAIN (PostgreSQL)
```

---

### 5. Constraint Enforcement

**Component:** Database constraints prevent invalid data  
**Test Scope:**
- Attempt to insert duplicate private_id in log_instances
- Attempt to insert duplicate public_id in log_instances
- Attempt to violate (collection, private_id) unique constraint
- Attempt to insert NULL in required fields
- Verify appropriate error messages

**Test Files:**
- `integration/logtail_constraints_test.go`

**Constraint Tests:**
```go
// UNIQUE constraints
- log_instances.private_id (column unique)
- log_instances.public_id (column unique)  
- log_instances(collection, private_id) (composite unique)
- logtail_private_id_associations.private_id (primary key)
- logtail_first_seen.private_id (primary key)
- logtail_rate_limits.private_id (primary key)

// NOT NULL constraints
- All required fields reject NULL values
- Default values applied when not specified

// FOREIGN KEY constraints
- Reject invalid node_id in associations
- Reject invalid private_id in IP observations
```

---

### 6. Schema Compatibility with Existing Migrations

**Component:** Logtail schema doesn't conflict with existing tables  
**Test Scope:**
- Run all migrations including Logtail migration
- Verify no table name conflicts
- Verify no index name conflicts
- Verify no constraint name conflicts
- Test full migration rollback (if supported)

**Test Files:**
- `integration/logtail_migration_compatibility_test.go`

**Compatibility Checks:**
```
No conflicts with existing tables:
- nodes, users, routes, preauth_keys, api_keys, etc.

No conflicts with existing indexes:
- All Logtail indexes use 'logtail_' or 'idx_logs_' prefix

Foreign keys reference existing tables correctly:
- logtail_private_id_associations.node_id -> nodes.id
```

---

### 7. Default Value Behavior

**Component:** Default values applied correctly in production  
**Test Scope:**
- Insert log without specifying persisted (should default to false)
- Insert log without specifying log_tier (should default to 'grace_period')
- Insert log without specifying created_at (should use CURRENT_TIMESTAMP)
- Verify defaults across SQLite and PostgreSQL

**Test Files:**
- `integration/logtail_defaults_test.go`

---

### 8. Concurrent Access Patterns

**Component:** Schema handles concurrent writes correctly  
**Test Scope:**
- Multiple goroutines inserting logs simultaneously
- Multiple goroutines updating associations simultaneously
- Verify no deadlocks
- Verify data consistency
- Test transaction isolation

**Test Files:**
- `integration/logtail_concurrency_test.go`

---

### 9. Data Type Compatibility

**Component:** Data types work correctly across databases  
**Test Scope:**
- DATETIME/TIMESTAMP handling and timezone behavior
- JSON/TEXT storage and retrieval
- INTEGER vs BIGINT for IDs
- BOOLEAN vs NUMERIC for flags
- TEXT field character set and encoding

**Test Files:**
- `integration/logtail_datatypes_test.go`

---

## 🎯 Test Coverage Goals

### Required Coverage
- ✅ All tables created successfully
- ✅ All indexes created successfully
- ✅ Foreign key constraints enforced
- ✅ Cascade deletes work correctly
- ✅ Unique constraints enforced
- ✅ Default values applied
- ✅ Migration idempotent
- ✅ PostgreSQL compatibility
- ✅ SQLite compatibility

### Desired Coverage
- ⚠️ Query performance validation
- ⚠️ Concurrent access patterns
- ⚠️ Large dataset behavior
- ⚠️ Index usage verification
- ⚠️ Transaction isolation

---

## 📊 Test Execution Strategy

### Phase 1: Schema Validation (Immediate)
Run with PR1 changes:
```bash
# Unit tests (already passing)
go test ./hscontrol/db/logtail_migration_test.go

# Integration tests - schema only
go test ./integration/logtail_schema_test.go
go test ./integration/logtail_constraints_test.go
go test ./integration/logtail_defaults_test.go
```

### Phase 2: Foreign Key Integration (After PR2)
Run after configuration and types are added:
```bash
go test ./integration/logtail_foreign_keys_test.go
go test ./integration/logtail_postgres_test.go
go test ./integration/logtail_sqlite_test.go
```

### Phase 3: Performance Validation (After PR3+)
Run after service implementation:
```bash
go test ./integration/logtail_performance_test.go -bench=.
go test ./integration/logtail_concurrency_test.go -race
```

---

## 🔧 Test Infrastructure Requirements

### Docker Test Environment
- PostgreSQL container for Postgres tests
- SQLite in-memory for SQLite tests
- Real Headscale instance for foreign key tests

### Test Data Fixtures
- Sample node records
- Sample log entries (various tiers)
- Sample IP observations
- Sample associations

### Test Helpers
```go
// Helper functions needed:
- createTestNode(t *testing.T) *Node
- createTestAssociation(t *testing.T, nodeID uint64) string
- createTestLogs(t *testing.T, privateID string, count int)
- verifyTableExists(t *testing.T, tableName string)
- verifyIndexExists(t *testing.T, indexName, tableName string)
- verifyForeignKeyWorks(t *testing.T, parentTable, childTable string)
```

---

## 🚨 Critical Test Scenarios

### Must Pass Before Merge
1. **Migration executes without errors** on both SQLite and PostgreSQL
2. **All tables and indexes created** as specified in schema
3. **Foreign key CASCADE DELETE** removes associations when node deleted
4. **Unique constraints** prevent duplicate private_id and public_id
5. **Default values** applied correctly (persisted=false, log_tier='grace_period')
6. **Migration is idempotent** - can be run multiple times safely

### Should Pass Before Release
7. Index performance improvements measurable
8. Concurrent access doesn't cause deadlocks
9. Large dataset insertion performs acceptably
10. Data types compatible across both databases

---

## 📝 Documentation Updates

Integration tests should verify:
- Schema matches documentation in PR1-database-foundation.md
- Table relationships match architecture diagram
- Index purposes align with query patterns

---

## 🎓 Test Lessons Learned

### From PR1 Implementation
- **Foreign keys must reference existing tables** - Tests must create nodes table first
- **Index names must be unique** - Use 'logtail_' prefix to avoid conflicts
- **Boolean handling varies** - SQLite uses NUMERIC, PostgreSQL uses BOOLEAN
- **CASCADE DELETE testing** - Requires PRAGMA foreign_keys = ON for SQLite
- **Migration idempotency** - Use IF NOT EXISTS in all CREATE statements

---

## ✅ Acceptance Criteria for Integration Tests

**PR1 integration tests are complete when:**

- [ ] All 9 test components implemented
- [ ] Tests run in CI/CD pipeline
- [ ] Tests pass on both SQLite and PostgreSQL
- [ ] Tests cover all critical scenarios
- [ ] Test documentation updated
- [ ] Test helpers and fixtures created
- [ ] Performance benchmarks established
- [ ] Concurrency tests validate thread safety

---

## 📞 Next Steps

1. **Immediate (PR1):** Implement Phase 1 tests (schema validation)
2. **PR2-3:** Implement Phase 2 tests (foreign key integration)
3. **PR4+:** Implement Phase 3 tests (performance validation)
4. **Continuous:** Update tests as schema evolves in subsequent PRs

---

**Note:** This document will be updated as integration tests are implemented and new requirements discovered during testing.
