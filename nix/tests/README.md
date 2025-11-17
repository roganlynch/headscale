# Headscale Nix Tests

This directory contains NixOS integration tests for Headscale.

## Available Tests

### headscale.nix
Tests the standard Headscale deployment with default SQLite database backend.

### turso.nix
Tests Headscale with Turso database backend in local mode.

**What it tests:**
- Turso database file creation at `/var/lib/headscale/db.turso`
- Valid SQLite format verification
- All required tables creation (api_keys, migrations, nodes, policies, pre_auth_keys, users)
- WAL mode configuration
- User creation and database persistence
- Node registration in Turso database
- Peer-to-peer connectivity via Tailscale
- DNS resolution
- Database integrity checks

## Running Tests

### Run all tests
```bash
nix flake check
```

### Run specific test
```bash
# Run standard Headscale test
nix build .#checks.x86_64-linux.headscale

# Run Turso database test
nix build .#checks.x86_64-linux.turso
```

### Interactive test debugging
```bash
# For standard test
nix build .#checks.x86_64-linux.headscale.driverInteractive
./result/bin/nixos-test-driver

# For Turso test
nix build .#checks.x86_64-linux.turso.driverInteractive
./result/bin/nixos-test-driver
```

## Test Architecture

Each test creates a complete NixOS virtual machine environment with:
- **headscale** node: Runs the Headscale control server with nginx TLS termination
- **peer1** and **peer2** nodes: Run Tailscale clients that connect to the control server

The tests verify:
1. Service startup and availability
2. User and pre-auth key creation
3. Node registration and connectivity
4. DNS resolution
5. Database operations and integrity

## Turso-Specific Testing

The Turso test validates:
- **Local Mode**: Tests Turso database configured in local-only mode (no cloud sync)
- **Database Creation**: Verifies the Turso database file is created with correct SQLite format
- **Schema Validation**: Confirms all Headscale tables are created
- **Data Persistence**: Ensures users and nodes are properly stored in Turso database
- **Functional Validation**: Full end-to-end connectivity test with Turso backend

### Configuration Used

```nix
database = {
  type = "turso";
  turso = {
    mode = "local";
    path = "/var/lib/headscale/db.turso";
    write_ahead_log = true;
    wal_autocheckpoint = 1000;
  };
};
```

## Adding New Tests

To add a new test:

1. Create a new `.nix` file in this directory
2. Follow the structure of existing tests
3. Add the test to `flake.nix` in the `checks` section:
```nix
checks = {
  headscale = pkgs.nixosTest (import ./nix/tests/headscale.nix);
  turso = pkgs.nixosTest (import ./nix/tests/turso.nix);
  your-test = pkgs.nixosTest (import ./nix/tests/your-test.nix);
};
```

## Test Requirements

- Tests must be deterministic and reproducible
- Tests should clean up after themselves
- Tests should include meaningful assertions with clear error messages
- Tests should follow the existing pattern for consistency

## Troubleshooting

### Test fails with timeout
Increase wait times in the test script or check service logs.

### Database not created
Verify the database configuration in the test node's settings.

### Connection issues between peers
Check firewall rules and DERP server configuration.

## Further Reading

- [NixOS Testing Documentation](https://nixos.org/manual/nixos/stable/index.html#sec-nixos-tests)
- [Headscale Documentation](https://headscale.net/)
- [Turso Documentation](https://docs.turso.tech/)
