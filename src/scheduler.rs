//! Periodic scan scheduler. A background task wakes on a fixed tick, finds the
//! schedules that are due and enabled, runs each scan (which still passes the
//! authorisation gate), and reschedules it. Keeping the cadence here — rather
//! than in a cron — means every run is auditable through the same path.

use std::time::Duration;

use anyhow::Result;
use chrono::Utc;
use tokio::task::JoinHandle;

use crate::scan;
use crate::store::Store;

/// Spawn the scheduler loop. `tick` is how often due schedules are checked.
pub fn spawn(store: Store, tick: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(tick);
        loop {
            ticker.tick().await;
            if let Err(e) = tick_once(&store).await {
                eprintln!("netdefense scheduler: tick error: {e}");
            }
        }
    })
}

/// Run every schedule that is due now. Each scan is rescheduled to `now +
/// interval` regardless of its outcome, so a transient failure does not stop
/// future runs.
pub async fn tick_once(store: &Store) -> Result<()> {
    let now = Utc::now();
    for sched in store.list_due_schedules(now)? {
        match scan::run_scan(store, sched.asset_id, sched.kind, false).await {
            Ok(outcome) => {
                if outcome.alert.is_some() {
                    eprintln!(
                        "netdefense scheduler: alert raised for asset {}",
                        sched.asset_id
                    );
                }
            }
            Err(e) => eprintln!(
                "netdefense scheduler: scan of {} failed: {e}",
                sched.asset_id
            ),
        }
        let next = now + chrono::Duration::seconds(sched.interval_secs.max(1));
        store.update_schedule_next_run(sched.id, next)?;
    }
    Ok(())
}
