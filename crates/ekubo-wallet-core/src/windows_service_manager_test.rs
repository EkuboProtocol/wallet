use super::*;

#[derive(Default)]
struct RecordingReporter {
    reports: Vec<(Phase, bool)>,
    fail: bool,
}
impl Reporter for RecordingReporter {
    fn report(&mut self, phase: Phase, failed: bool) -> Result<()> {
        self.reports.push((phase, failed));
        anyhow::ensure!(!self.fail, "test SCM report failure");
        Ok(())
    }
}

fn control() -> (Control<RecordingReporter>, watch::Receiver<bool>) {
    let (stop, stopping) = watch::channel(false);
    (Control::new(RecordingReporter::default(), stop), stopping)
}

#[test]
fn normal_lifecycle_reports_each_transition_once() {
    let (mut control, stop) = control();
    control.initialize().unwrap();
    control.running().unwrap();
    control.running().unwrap();
    assert!(!*stop.borrow());
    control.request_stop().unwrap();
    assert!(*stop.borrow());
    control.request_stop().unwrap();
    control.finish(false).unwrap();
    control.finish(false).unwrap();
    assert_eq!(
        control.reporter.reports,
        vec![
            (Phase::Starting, false),
            (Phase::Running, false),
            (Phase::Stopping, false),
            (Phase::Stopped, false),
        ]
    );
}

#[test]
fn stop_during_startup_cannot_be_overwritten_by_running() {
    let (mut control, stop) = control();
    control.initialize().unwrap();
    control.request_stop().unwrap();
    control.running().unwrap();
    assert!(*stop.borrow());
    assert_eq!(control.phase, Phase::Stopping);
    assert_eq!(
        control.reporter.reports,
        vec![(Phase::Starting, false), (Phase::Stopping, false)]
    );
}

#[test]
fn stop_delivered_during_handler_registration_is_preserved() {
    let (mut control, stop) = control();
    control.stop.send_replace(true);
    control.initialize().unwrap();
    control.running().unwrap();
    assert!(*stop.borrow());
    assert_eq!(control.reporter.reports, vec![(Phase::Stopping, false)]);
}

#[test]
fn reporting_failure_still_signals_host_shutdown() {
    let (mut control, stop) = control();
    control.initialize().unwrap();
    control.reporter.fail = true;
    assert!(control.request_stop().is_err());
    assert!(*stop.borrow());
    control.running().unwrap();
    assert_eq!(control.phase, Phase::Stopping);
}

#[test]
fn stopped_handle_is_never_reused_even_if_final_report_failed() {
    let (mut control, stop) = control();
    control.initialize().unwrap();
    control.reporter.fail = true;
    assert!(control.finish(true).is_err());
    assert!(*stop.borrow());
    control.reporter.fail = false;
    control.finish(true).unwrap();
    control.request_stop().unwrap();
    assert!(control.running().is_err());
    assert!(control.initialize().is_err());
    assert_eq!(
        control.reporter.reports,
        vec![(Phase::Starting, false), (Phase::Stopped, true)]
    );
}
