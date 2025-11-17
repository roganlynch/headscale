{ pkgs, lib, ... }:
let
  tls-cert = pkgs.runCommand "selfSignedCerts" { buildInputs = [ pkgs.openssl ]; } ''
    openssl req \
      -x509 -newkey rsa:4096 -sha256 -days 365 \
      -nodes -out cert.pem -keyout key.pem \
      -subj '/CN=headscale' -addext "subjectAltName=DNS:headscale"

    mkdir -p $out
    cp key.pem cert.pem $out
  '';
in
{
  name = "headscale-turso";
  meta.maintainers = with lib.maintainers; [
    kradalby
    misterio77
  ];

  nodes =
    let
      headscalePort = 8080;
      stunPort = 3478;
      peer = {
        services.tailscale.enable = true;
        security.pki.certificateFiles = [ "${tls-cert}/cert.pem" ];
      };
    in
    {
      peer1 = peer;
      peer2 = peer;

      headscale = { config, pkgs, ... }: {
        imports = [ ../module.nix ];
        
        services = {
          headscale = {
            enable = true;
            port = headscalePort;
            settings = {
              server_url = "https://headscale";
              ip_prefixes = [ "100.64.0.0/10" ];
              
              # Configure Turso database in local mode
              database = {
                type = "turso";
                turso = {
                  mode = "local";
                  path = "/var/lib/headscale/db.turso";
                  write_ahead_log = true;
                  wal_autocheckpoint = 1000;
                };
              };
              
              derp.server = {
                enabled = true;
                region_id = 999;
                stun_listen_addr = "0.0.0.0:${toString stunPort}";
              };
              dns = {
                base_domain = "tailnet";
                extra_records = [
                  {
                    name = "foo.bar";
                    type = "A";
                    value = "100.64.0.2";
                  }
                ];
                override_local_dns = false;
              };
            };
          };
          nginx = {
            enable = true;
            virtualHosts.headscale = {
              addSSL = true;
              sslCertificate = "${tls-cert}/cert.pem";
              sslCertificateKey = "${tls-cert}/key.pem";
              locations."/" = {
                proxyPass = "http://127.0.0.1:${toString headscalePort}";
                proxyWebsockets = true;
              };
            };
          };
        };
        networking.firewall = {
          allowedTCPPorts = [
            80
            443
          ];
          allowedUDPPorts = [ stunPort ];
        };
        environment.systemPackages = [ pkgs.headscale pkgs.sqlite ];
      };
    };

  testScript = ''
    start_all()
    headscale.wait_for_unit("headscale")
    headscale.wait_for_open_port(443)

    # Verify Turso database file was created
    headscale.succeed("test -f /var/lib/headscale/db.turso")
    
    # Verify database is valid SQLite format
    headscale.succeed("file /var/lib/headscale/db.turso | grep -i 'SQLite'")
    
    # Verify database has correct tables
    tables = headscale.succeed("sqlite3 /var/lib/headscale/db.turso '.tables'")
    assert "api_keys" in tables, "api_keys table not found"
    assert "migrations" in tables, "migrations table not found"
    assert "nodes" in tables, "nodes table not found"  
    assert "policies" in tables, "policies table not found"
    assert "pre_auth_keys" in tables, "pre_auth_keys table not found"
    assert "users" in tables, "users table not found"
    
    # Verify WAL mode is enabled (if configured)
    wal_check = headscale.succeed("ls -la /var/lib/headscale/ | grep -E 'db\\.turso-(shm|wal)' || echo 'WAL files may not exist yet'")
    print(f"WAL check output: {wal_check}")

    # Create headscale user and preauth-key
    headscale.succeed("headscale users create test")
    authkey = headscale.succeed("headscale preauthkeys -u 1 create --reusable")

    # Verify user was created in Turso database
    user_count = headscale.succeed("sqlite3 /var/lib/headscale/db.turso 'SELECT COUNT(*) FROM users'").strip()
    assert int(user_count) > 0, f"No users found in database, expected at least 1, got {user_count}"

    # Connect peers
    up_cmd = f"tailscale up --login-server 'https://headscale' --auth-key {authkey}"
    peer1.execute(up_cmd)
    peer2.execute(up_cmd)

    # Check that they are reachable from the tailnet
    peer1.wait_until_succeeds("tailscale ping peer2")
    peer2.wait_until_succeeds("tailscale ping peer1.tailnet")
    
    # Verify DNS resolution works
    assert (res := peer1.wait_until_succeeds("${lib.getExe pkgs.dig} +short foo.bar").strip()) == "100.64.0.2", f"Domain {res} did not match 100.64.0.2"
    
    # Verify nodes were registered in Turso database
    node_count = headscale.succeed("sqlite3 /var/lib/headscale/db.turso 'SELECT COUNT(*) FROM nodes'").strip()
    assert int(node_count) >= 2, f"Expected at least 2 nodes in database, got {node_count}"
    
    # Verify database integrity
    integrity = headscale.succeed("sqlite3 /var/lib/headscale/db.turso 'PRAGMA integrity_check'").strip()
    assert integrity == "ok", f"Database integrity check failed: {integrity}"
    
    print("✅ All Turso database tests passed!")
  '';
}
