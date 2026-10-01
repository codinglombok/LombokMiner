// LombokMiner — End-to-End Integration Test
//
// Simulates the complete pool mining lifecycle:
//   1. Load config
//   2. Initialize hardware (CPU miner)
//   3. Set up metrics registry
//   4. Connect to pool (simulated)
//   5. Receive work (simulated block template)
//   6. Mine with multiple threads
//   7. Submit share
//   8. Verify metrics + alerts
//   9. Failover test
//  10. Validate wallet address from config

#[cfg(test)]
mod integration {
    use lombokminer_core::block::{BlockHeader, CoinbaseBuilder, merkle_root};
    use lombokminer_core::hash;
    use lombokminer_core::mining::{
        Target, MineResult, difficulty_from_nbits, format_hashrate,
    };
    use lombokminer_hal::{CpuMiner, CpuConfig, MiningDevice};
    use lombokminer_monitor::metrics::MetricsRegistry;
    use lombokminer_monitor::alerts::{AlertEngine, AlertLevel};
    use lombokminer_monitor::prometheus;
    use lombokminer_net::pool::{PoolConfig, PoolManager, PoolProtocol, ConnectionState};
    use lombokminer_net::rpc::gbt::{BlockTemplate, TemplateTransaction};
    use lombokminer_security::{
        validate_address, AddressType, Network,
        aead_encrypt, aead_decrypt,
        MitmDetector, ConnectionFingerprint, HijackDetector,
        ConfigVault,
    };
    use lombokminer_config::{self, Config};

    use std::sync::atomic::Ordering;
    use std::time::Instant;

    /// Full solo mining lifecycle.
    #[test]
    fn test_solo_mining_lifecycle() {
        // 1. Load config
        let config = lombokminer_config::parse_config(r#"
            [general]
            mode = "solo"
            [wallet]
            address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
            [hardware.cpu]
            threads = 2
        "#).unwrap();
        assert_eq!(config.general.mode, "solo");

        // 2. Validate wallet
        let wallet = validate_address(&config.wallet.address).unwrap();
        assert_eq!(wallet.address_type, AddressType::P2wpkh);
        assert_eq!(wallet.network, Network::Mainnet);

        // 3. Initialize CPU miner
        let miner = CpuMiner::new(CpuConfig {
            threads: config.hardware.cpu.threads,
            core_affinity: false,
        });

        // 4. Simulate getblocktemplate response
        let template_bits = 0x207fffff_u32; // easy difficulty for test
        let template = BlockTemplate {
            version: 0x20000000,
            prev_block_hash: "0000000000000000000000000000000000000000000000000000000000000001".into(),
            transactions: vec![],
            coinbaseaux: serde_json::json!({}),
            coinbase_value: 312_500_000,
            target: "7fffff0000000000000000000000000000000000000000000000000000000000".into(),
            min_time: 1700000000,
            mutable: vec!["time".into(), "transactions".into()],
            nonce_range: "00000000ffffffff".into(),
            sigop_limit: 80000,
            size_limit: 4000000,
            weight_limit: 4000000,
            cur_time: 1700000100,
            bits: format!("{:08x}", template_bits),
            height: 800000,
            witness_commitment: None,
            longpoll_id: None,
        };

        assert_eq!(template.nbits(), template_bits);
        assert_eq!(template.height, 800000);

        // 5. Build coinbase + merkle root
        let output_script = vec![0x51]; // OP_TRUE for testing
        let coinbase_builder = CoinbaseBuilder::new_solo(
            template.height as u32,
            template.coinbase_value,
            output_script,
        );
        let extranonce2 = [0u8; 4];
        let coinbase_txid = coinbase_builder.build_txid(&extranonce2);

        let tx_hashes = template.tx_hashes();
        let mut all_hashes = vec![coinbase_txid];
        all_hashes.extend(tx_hashes);
        let merkle = merkle_root(&all_hashes);

        // 6. Build block header
        let header = BlockHeader {
            version: template.version as i32,
            prev_block: template.prev_block_bytes(),
            merkle_root: merkle,
            timestamp: template.cur_time as u32,
            bits: template.nbits(),
            nonce: 0,
        };

        // 7. Set up metrics
        let metrics = MetricsRegistry::new();
        let dev_idx = metrics.register_device("cpu0");

        // 8. Mine!
        let target = Target::from_nbits(template.nbits());
        let start = Instant::now();
        let result = miner.submit_work(&header, &target, 0, 1_000_000).unwrap();
        let elapsed = start.elapsed();

        // 9. Verify result
        match &result.result {
            MineResult::Found { nonce, hash } => {
                assert!(target.check_hash(hash), "found hash must meet target");

                // Verify the hash independently
                let mut verify_header = header;
                verify_header.nonce = *nonce;
                let verify_hash = verify_header.hash();
                assert_eq!(hash, &verify_hash, "hash must match independent computation");

                println!(
                    "Solo mining: found nonce {} in {:.2}ms ({}) — hash {}",
                    nonce,
                    elapsed.as_secs_f64() * 1000.0,
                    format_hashrate(result.hashrate),
                    hex::encode(verify_header.hash_display()),
                );
            }
            MineResult::Exhausted => {
                panic!("should find nonce with easy target");
            }
        }

        // 10. Update metrics
        {
            let devices = metrics.devices.read().unwrap();
            devices[dev_idx].set_hashrate(result.hashrate);
            devices[dev_idx].add_hashes(result.hashes);
        }

        let snap = metrics.snapshot();
        assert!(snap.total_hashrate > 0.0);
        assert!(snap.devices[0].hashes_total > 0);

        // 11. Export Prometheus metrics
        let prom = prometheus::render(&snap);
        assert!(prom.contains("lombokminer_hashrate_hps"));
        assert!(prom.contains("lombokminer_device_hashrate_hps"));
    }

    /// Full pool mining lifecycle simulation.
    #[test]
    fn test_pool_mining_lifecycle() {
        // 1. Set up pool manager
        let pools = vec![
            PoolConfig::from_url("sv2://primary.pool:3336", "worker1", "x"),
            PoolConfig::from_url("stratum+tcp://backup.pool:3333", "worker1", "x"),
        ];
        let mut mgr = PoolManager::new(pools);
        assert_eq!(mgr.active().config.protocol, PoolProtocol::StratumV2);

        // 2. Simulate connection
        mgr.active_mut().mark_connected();
        assert_eq!(mgr.active().state, ConnectionState::Connected);
        assert!(mgr.active().uptime().is_some());

        // 3. Initialize miner
        let miner = CpuMiner::new(CpuConfig { threads: 2, core_affinity: false });

        // 4. Receive mining job (simulated)
        let header = BlockHeader {
            version: 0x20000000,
            prev_block: [0xAA; 32],
            merkle_root: [0xBB; 32],
            timestamp: 1700000100,
            bits: 0x207fffff,
            nonce: 0,
        };
        let target = Target::from_nbits(0x207fffff);

        // 5. Mine
        let result = miner.submit_work(&header, &target, 0, 500_000).unwrap();

        // 6. Submit share
        match &result.result {
            MineResult::Found { .. } => {
                mgr.active_mut().record_accepted();
                mgr.active_mut().record_accepted();
                mgr.active_mut().record_accepted();
                mgr.active_mut().record_rejected();
            }
            _ => panic!("should find"),
        }

        assert_eq!(mgr.active().shares.accepted, 3);
        assert_eq!(mgr.active().shares.rejected, 1);
        assert!(mgr.active().shares.accept_rate() > 0.7);

        // 7. Failover test
        mgr.active_mut().mark_disconnected();
        assert_eq!(mgr.active().state, ConnectionState::Reconnecting);

        assert!(mgr.failover());
        assert_eq!(mgr.active().config.protocol, PoolProtocol::StratumV1);

        // 8. Failback
        mgr.pools[0].state = ConnectionState::Disconnected; // primary recoverable
        assert!(mgr.should_failback());
        mgr.failback();
        assert_eq!(mgr.active().config.url, "sv2://primary.pool:3336");

        // 9. Summary
        let summary = mgr.summary();
        assert_eq!(summary.len(), 2);
        assert!(summary[0].is_active);
    }

    /// Security: MITM + hijack detection + encryption lifecycle.
    #[test]
    fn test_security_lifecycle() {
        // MITM detection
        let mut mitm = MitmDetector::new();

        let fp1 = ConnectionFingerprint {
            pool_url: "sv2://pool:3336".into(),
            resolved_ip: "1.2.3.4".into(),
            cert_hash: None,
            noise_pubkey: Some([0xAA; 32]),
            timestamp: Instant::now(),
            latency_us: 20000,
        };
        assert!(mitm.check_connection(fp1).is_empty());

        // Same IP, same key — no alert
        let fp2 = ConnectionFingerprint {
            pool_url: "sv2://pool:3336".into(),
            resolved_ip: "1.2.3.4".into(),
            cert_hash: None,
            noise_pubkey: Some([0xAA; 32]),
            timestamp: Instant::now(),
            latency_us: 22000,
        };
        assert!(mitm.check_connection(fp2).is_empty());

        // Key changed — alert!
        let fp3 = ConnectionFingerprint {
            pool_url: "sv2://pool:3336".into(),
            resolved_ip: "1.2.3.4".into(),
            cert_hash: None,
            noise_pubkey: Some([0xBB; 32]),
            timestamp: Instant::now(),
            latency_us: 22000,
        };
        let alerts = mitm.check_connection(fp3);
        assert!(!alerts.is_empty(), "should detect key change");

        // Hijack detection
        let mut hijack = HijackDetector::new();
        for _ in 0..60 {
            hijack.record_share(true, false, 1.0);
        }
        // Baseline established — no alerts for normal operation

        // Config vault roundtrip
        let secret = r#"{"pool_pass":"secret123","wallet":"bc1q..."}"#;
        let vault = ConfigVault::seal("strong_passphrase", secret);
        let decrypted = vault.unseal("strong_passphrase").unwrap();
        assert_eq!(decrypted, secret);
        assert!(vault.unseal("wrong").is_err());

        // AEAD roundtrip
        let key = [0x42; 32];
        let nonce = [0x01; 12];
        let (ct, tag) = aead_encrypt(&key, &nonce, b"pool_header", b"share_data");
        let pt = aead_decrypt(&key, &nonce, b"pool_header", &ct, &tag).unwrap();
        assert_eq!(pt, b"share_data");

        // Tampered → rejected
        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 0xFF;
        assert!(aead_decrypt(&key, &nonce, b"pool_header", &bad_ct, &tag).is_err());
    }

    /// Multi-threaded mining consistency.
    #[test]
    fn test_multithread_mining_consistency() {
        let target = Target::from_nbits(0x207fffff);
        let header = BlockHeader {
            version: 0x20000000,
            prev_block: [0x33; 32],
            merkle_root: [0x44; 32],
            timestamp: 1700000000,
            bits: 0x207fffff,
            nonce: 0,
        };

        // Mine with 1, 2, and 4 threads — all should find valid hashes
        for threads in [1, 2, 4] {
            let miner = CpuMiner::new(CpuConfig { threads, core_affinity: false });
            let result = miner.submit_work(&header, &target, 0, 200_000).unwrap();

            match result.result {
                MineResult::Found { hash, nonce } => {
                    assert!(target.check_hash(&hash), "threads={threads}: hash must meet target");
                    println!("threads={threads}: nonce={nonce}, hashrate={}", format_hashrate(result.hashrate));
                }
                MineResult::Exhausted => panic!("threads={threads}: should find with easy target"),
            }
        }
    }

    /// Alert engine integration with metrics.
    #[test]
    fn test_alert_integration() {
        let metrics = MetricsRegistry::new();
        let dev = metrics.register_device("gpu0");

        // Set hot temperature
        {
            let devices = metrics.devices.read().unwrap();
            devices[dev].set_temperature(92.0);
            devices[dev].set_hashrate(188e12);
        }

        let snap = metrics.snapshot();

        let mut engine = AlertEngine::with_defaults();
        let alerts = engine.evaluate(&snap);

        // Should fire temp_warning AND temp_critical
        assert!(alerts.iter().any(|a| a.rule_name == "temp_warning"));
        assert!(alerts.iter().any(|a| a.rule_name == "temp_critical"));
        assert!(engine.count_by_level(AlertLevel::Critical) > 0);
    }

    /// Midstate optimization consistency across threads.
    #[test]
    fn test_midstate_cross_thread() {
        let header = BlockHeader {
            version: 0x20000000,
            prev_block: [0x55; 32],
            merkle_root: [0x66; 32],
            timestamp: 1700000000,
            bits: 0x207fffff,
            nonce: 12345,
        };

        // Full hash
        let full_hash = header.hash();

        // Midstate + from_midstate
        let (first_64, last_16) = header.split_for_midstate();
        let midstate = hash::sha256_midstate(&first_64);
        let mid_hash = hash::sha256_from_midstate(&midstate, &last_16);

        assert_eq!(full_hash, mid_hash);

        // Verify across 100 nonces in parallel
        std::thread::scope(|s| {
            for nonce in 0u32..100 {
                s.spawn(move || {
                    let mut h = header;
                    h.nonce = nonce;

                    let full = h.hash();
                    let (_, last) = h.split_for_midstate();
                    let mid = hash::sha256_from_midstate(&midstate, &last);
                    assert_eq!(full, mid, "mismatch at nonce {nonce}");
                });
            }
        });
    }

    /// Config loading + validation pipeline.
    #[test]
    fn test_config_pipeline() {
        let toml = lombokminer_config::generate_default_toml();
        let config = lombokminer_config::parse_config(&toml).unwrap();

        assert_eq!(config.general.mode, "pool");
        assert!(config.hardware.cpu.enabled);
        assert!(!config.hardware.gpu.enabled);
        assert!(!config.hardware.asic.enabled);
        assert!(config.dashboard.enabled);
        assert_eq!(config.alerts.temp_warning, 80.0);
        assert_eq!(config.alerts.temp_critical, 90.0);

        // Serialize to JSON and back
        let json = serde_json::to_string(&config).unwrap();
        let _: Config = serde_json::from_str(&json).unwrap();
    }
}
