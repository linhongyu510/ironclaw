# ironclaw_telemetry_contracts

The neutral tenant-telemetry membrane. This contracts-layer crate will own
bounded, provider-neutral observations and the synchronous recorder port used
by canonical producers and the domain-owned buffered implementation.

The shell is intentionally dormant in the persistence-boundary change. It has
one workspace dependency, `ironclaw_host_api`, for the canonical typed tenant
and user identities. It contains no storage, execution, queue, driver, product,
or transport behavior. Observation grammar and the recorder port arrive in the
next telemetry behavior slice.

See [ADR 0005](../../../docs/internal/adr/0005-telemetry-keeps-dedicated-sql-tables.md)
and the target-architecture contracts family specification for the persistence
exception's boundary.
