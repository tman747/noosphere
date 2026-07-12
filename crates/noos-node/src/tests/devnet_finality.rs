//! Focused coverage for the live-devnet fixture finality driver.

use noos_braid::EPOCH_LENGTH;

use super::util::*;

#[test]
fn devnet_finality_tick_advances_two_epoch_ladder_only_when_enabled() {
    let enabled_dir = test_dir("devnet-finality-enabled");
    let mut enabled_cfg = node_config();
    enabled_cfg.devnet_fixture_finality = true;
    let mut enabled = boot_node(&enabled_dir, enabled_cfg);

    for _ in 0..2 * EPOCH_LENGTH {
        produce_next(&mut enabled);
    }

    assert!(enabled.devnet_finality_tick().expect("justify epoch 1"));
    assert_eq!(enabled.justified().epoch, 1);
    assert_eq!(enabled.finalized().epoch, 0);

    assert!(enabled.devnet_finality_tick().expect("justify epoch 2"));
    assert_eq!(enabled.justified().epoch, 2);
    assert_eq!(enabled.finalized().epoch, 1);
    assert!(!enabled
        .devnet_finality_tick()
        .expect("epoch 3 boundary is not available"));

    let disabled_dir = test_dir("devnet-finality-disabled");
    let mut disabled = boot_node(&disabled_dir, node_config());
    for _ in 0..2 * EPOCH_LENGTH {
        produce_next(&mut disabled);
    }
    let justified_before = disabled.justified();
    let finalized_before = disabled.finalized();

    assert!(!disabled
        .devnet_finality_tick()
        .expect("disabled fixture finality is inert"));
    assert_eq!(disabled.justified(), justified_before);
    assert_eq!(disabled.finalized(), finalized_before);
}

#[test]
fn restart_reembeds_certificate_queued_after_epoch_boundary() {
    let dir = test_dir("devnet-finality-restart-pending");
    let mut cfg = node_config();
    cfg.devnet_fixture_finality = true;
    let mut producer = boot_node(&dir, cfg.clone());
    for _ in 0..EPOCH_LENGTH {
        produce_next(&mut producer);
    }
    assert!(producer
        .devnet_finality_tick()
        .expect("queue epoch-1 certificate"));
    assert_eq!(producer.justified().epoch, 1);
    drop(producer);

    let mut restarted = boot_node(&dir, cfg);
    assert_eq!(restarted.justified().epoch, 1);
    let next = produce_full(&mut restarted);
    assert_eq!(
        next.body.finality_certificates.as_slice().len(),
        1,
        "first post-restart body re-embeds the durable pending certificate"
    );
    assert_eq!(
        next.body.finality_certificates.as_slice()[0].target.epoch,
        1
    );
}
