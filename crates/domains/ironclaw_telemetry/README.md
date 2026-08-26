# ironclaw_telemetry

The tenant-scoped BI telemetry domain. It will own bounded observation
aggregation, hourly durable record grammar, the non-blocking recorder worker,
and tenant-scoped export reads.

This shell deliberately contains no observation behavior, queue, migration, or
SQL. The domain is the one ADR-governed persistence exception for telemetry:
future private libSQL and PostgreSQL adapters use the existing composition-owned
admission handles and never create a database, pool, URL, or backend-selection
plane. Driver types remain private to those adapters.

The domain depends downward on `ironclaw_telemetry_contracts` and the admitted
`ironclaw_libsql_runtime`; the future PostgreSQL/libSQL adapter dependencies are
declared now so their driver cone is mechanically chartered before behavior
lands. It does not depend on `ironclaw_filesystem`, product, composition, or any
producer.

See [ADR 0005](../../../docs/internal/adr/0005-telemetry-keeps-dedicated-sql-tables.md)
for the exception rationale and limits.
