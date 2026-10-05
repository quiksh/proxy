//! Regression test: a config with an `[[auth]]` block but no `[[upstreams]]`
//! must build its auth registry. Nothing else has installed the process
//! crypto provider at that point, so the JWKS client must install it before
//! building its rustls config instead of panicking.
//!
//! This lives in its own test binary on purpose: integration test files run
//! as separate processes, so no other test can have installed the provider
//! first and hidden the bug.

use quik::auth::SharedAuthRegistry;
use quik::config::Config;

#[test]
fn auth_registry_builds_without_any_upstream() {
    let cfg: Config = toml::from_str(
        r#"
        [listener]
        bind = "127.0.0.1:0"

        [listener.tls]
        self_signed = true

        [admin]
        bind = "127.0.0.1:0"

        [[auth]]
        name     = "corp"
        jwks_url = "https://auth.corp.example.test/.well-known/jwks.json"
        "#,
    )
    .unwrap();

    SharedAuthRegistry::from_config(&cfg).unwrap();
}
