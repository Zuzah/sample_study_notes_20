# sample_study_notes_20
KYC/AML Studies

# Security & Compliance Q&A — FenX Downstream Reporting Platform

Status key: ✅ Confirmed · ⚠️ Gap found (fixable by us) · 🔲 Outside this repo's ownership

## OAuth Client Secret — storage & lifecycle (Q2–3)
- Stored as a Kubernetes Secret, synced from Vault via External Secrets Operator (5-min refresh cycle). App reads the env var only — never talks to Vault directly.
- Rotation, expiration, and revocation are managed entirely by Vault/devops. No app-side detection or alerting on a rotated/revoked secret.
- 🔲 **Owner:** Devops / Secrets management team.

## OAuth Scope (Q4)
- Current scope is broad (`fenx.all`) — not narrowed to report-retrieval functions only.
- ⚠️ Known, already-flagged gap: the service account sees **more** Fenergo entities than an individual user's login (confirmed via a real row-count discrepancy investigation). Raised to the team lead — answer still pending on whether this is intentional.
- **Status:** Open question, not yet answered.

## Report Authorization / Presigned URL (Q5)
- URL scope/expiry is controlled entirely by Fenergo. We store only the **expiry timestamp** — the URL itself is never persisted, by design.
- ⚠️ **Gap confirmed:** on a download *failure* specifically, the presigned URL is currently written into both the error log file and the database error field. Not yet remediated.

## KYC Service Trigger / Caller Authentication (Q6)
- No scheduler exists in this app today — it runs as a one-shot CLI job (K8s Job), triggered externally. Airflow DAGs exist only as unexecuted drafts.
- The app has no inbound endpoint and therefore no caller-authentication mechanism today.
- 🔲 **Owner:** Whoever owns the real scheduling/trigger layer — not this workstream.

## PVC Encryption & Access (Q7)
- Not documented anywhere — the TDD's own Infrastructure/Security Design sections are still blank template text, not just missing from our side.
- 🔲 **Owner:** Infra / Rancher platform team.

## Retention & Deletion (Q8)
- ⚠️ **Gap confirmed:** no retention or cleanup logic exists anywhere in the app. Delivered files, Archive/Failed PVC folders, and DB rows accumulate indefinitely.
- SFTP archive-folder retention is controlled by the receiving landing zone, not by us.

## No Customer Data / Tokens in Logs, Dynatrace, SQL Server (Q9)
- ✅ Largely holds — DB only ever stores file paths, status, counts, and error text; never raw report data, SQL, or the OAuth token/secret.
- ⚠️ **Exception:** same presigned-URL leak as Q5 applies here.
- Dynatrace is not integrated into the app directly (confirmed: TDD's Dynatrace section describes a web server component this batch job doesn't have).

## SAST / SCA / CNAPP / Image Signing / Vuln Reports (Q10)
- 🔲 None of this exists or is visible in this repo. Build/scan pipeline is owned by devops in a separate CD repo we have no visibility into.
- Cannot confirm a clean vulnerability scan or provide App Security reports — this needs to come from Devops/AppSec directly.

## GBM Data Exchange / BF3N Integration (Q11)
- 🔲 No such integration exists in this platform. Out of scope — needs routing to whoever owns BF3N.

## APM Code (Q12)
- 🔲 Not tracked anywhere in this repo. Platform/Rancher registration detail, outside our scope.

---

## Summary for leadership
- **2 real gaps on our side, fixable:** presigned-URL leaking into logs/DB on failure (Q5/Q9); no file/DB retention policy (Q8).
- **5 items need answers from other teams**, not us: KYC trigger/auth (Q6), PVC encryption/access (Q7), security scanning/signing (Q10), BF3N integration (Q11), APM code (Q12).
- **1 open governance question already escalated:** service-account scope breadth (Q4), awaiting team lead response.


app/services/sftp_connection_service.py


```python
known_hosts_override = os.environ.get(prefix + "KNOWN_HOSTS_PATH")
```

tests/services/test_reporting_orchestrator.py
```python
import dataclasses
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.core.config import settings
from app.core.logging import log
from app.models.execution import ExecutionStatus
from app.services import execution_service
from app.services.delivery_service import (
    DeliveryConfigError,
    DeliveryError,
    DeliveryResult,
)
from app.services.download_service import DownloadResult
from app.services.fenergo_service import StatusResult, SubmitResult
from app.services.report_definition_service import (
    ReportDefinition,
    ReportDefinitionService,
)
from app.services.reporting_orchestrator import (
    OrchestrationError,
    ReportingOrchestrator,
    UtilityOperationResult,
)

CHINA_GTT_CSV = (
    "Fenergo ID,Client Name,LEI,Global Risk Rating,Scheduled Review Date,"
    "China Risk Rating,China Risk Rating (Override),China Next Review Date,"
    "China Next Review Date (Override),China Comments,Country of Incorporation,"
    "Product Category,Product Type,Booking Entity,Arranging Entity,Product ID\n"
    "1,Acme Corp,LEI123,High,2026-01-01,Medium,,2026-06-01,,,China,FamilyA,"
    "TypeA,EntityA,EntityB,PROD-1\n"
)


class FakeFenergoService:
    def __init__(
        self, status="Completed", presigned_url="https://example.test/report.csv"
    ):
        self.status = status
        self.presigned_url = presigned_url
        self.submit_calls = []

    async def submit(self, source, description):
        self.submit_calls.append((source, description))
        return SubmitResult(report_id="FEN-123")

    async def check_status(self, report_id):
        return StatusResult(status=self.status, presigned_url=self.presigned_url)


class FakeDownloadService:
    def __init__(self, csv_content=CHINA_GTT_CSV):
        self._csv_content = csv_content
        self.download_calls = []

    async def download(self, presigned_url, destination_filename):
        self.download_calls.append((presigned_url, destination_filename))
        path = settings.download_path / destination_filename
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self._csv_content)
        return DownloadResult(local_path=path, size_bytes=len(self._csv_content))


class FailingDownloadService:
    async def download(self, presigned_url, destination_filename):
        raise RuntimeError("simulated download failure")


class FakeDeliveryService:
    def __init__(self, fail: bool = False):
        self.deliver_calls = []
        self._fail = fail

    def deliver(
        self, local_path, remote_directory, remote_filename=None, connection=None
    ):
        self.deliver_calls.append((local_path, remote_directory, connection))
        if self._fail:
            raise DeliveryError("simulated delivery failure")
        return DeliveryResult(
            remote_path=f"{remote_directory}/{local_path.name}",
            size_bytes=local_path.stat().st_size,
            delivered_at=datetime.now(timezone.utc),
        )


@pytest.fixture(autouse=True)
def _isolated_download_folder(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "DOWNLOAD_FOLDER", str(tmp_path / "downloads"))
    monkeypatch.setattr(settings, "SFTP_SUCCESS_DIRECTORY", "success")
    monkeypatch.setattr(settings, "AUDIT_ROOT", None)
    # ChinaGTTReport declares sftp_connection="ClientCentralData" - required env vars
    # for SFTPConnectionService.get() to resolve without raising.
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_HOST", "test-host")
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_USERNAME", "test-user")
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_PRIVATE_KEY_PATH", "/test/key")
    monkeypatch.setenv(
        "SFTP_CLIENTCENTRALDATA_REMOTE_FOLDER", "./ClientCentralDataTest"
    )
    monkeypatch.delenv("SFTP_CLIENTCENTRALDATA_MARKER_REMOTE_FOLDER", raising=False)


def _seed_full_run_execution(report_name="ChinaGTTReport", downloaded_file_path=None):
    """Seeds a real FULL_RUN execution the way submit->download would leave it -
    the shape every linked utility-flow test needs to attach to."""
    execution = execution_service.create_execution(report_name)
    execution_service.mark_submitted(execution.execution_id, "FEN-123")
    if downloaded_file_path is not None:
        execution_service.mark_downloaded(
            execution.execution_id, str(downloaded_file_path)
        )
    return execution


async def test_run_report_full_success_sequences_all_steps_and_completes(db):
    fenergo = FakeFenergoService()
    download = FakeDownloadService()
    delivery = FakeDeliveryService()
    orchestrator = ReportingOrchestrator(
        fenergo_service=fenergo, download_service=download, delivery_service=delivery
    )

    execution = await orchestrator.run_report("ChinaGTTReport")

    assert execution.status == ExecutionStatus.SFTP_COMPLETED.value
    assert execution.fenergo_report_id == "FEN-123"
    assert execution.output_file_path is not None

    output_path = Path(execution.output_file_path)
    assert output_path.exists()
    content = output_path.read_text()
    assert "Fenergo ID" in content
    assert "TypeA" in content

    marker_path = output_path.with_suffix(output_path.suffix + ".mrk")
    assert marker_path.exists()

    assert (
        marker_path.read_text().strip()
        == hashlib.sha256(output_path.read_bytes()).hexdigest()
    )

    assert len(delivery.deliver_calls) == 2
    delivered_paths = {call[0] for call in delivery.deliver_calls}
    assert delivered_paths == {output_path, marker_path}
    # ChinaGTTReport declares sftp_connection="ClientCentralData" - delivery goes to
    # that connection's own remote_folder, not the legacy global SFTP_SUCCESS_DIRECTORY.
    assert all(call[1] == "./ClientCentralDataTest" for call in delivery.deliver_calls)
    assert all(
        call[2] is not None and call[2].host == "test-host"
        for call in delivery.deliver_calls
    )


async def test_run_report_uses_fircosoft_manifest_and_output_filename_template_when_configured(
    db, monkeypatch
):
    """A report whose registry entry opts into marker_type="fircosoft_manifest"
    gets a structured JSON manifest instead of a SHA256 checksum, and its output
    filename follows output_filename_template instead of the usual
    {report_name}_{date}.csv convention - the EDLReport shape, exercised here
    against ChinaGTTReport's already-real template/SQL for test isolation."""
    manifest_definition = dataclasses.replace(
        ReportDefinitionService.get("ChinaGTTReport"),
        marker_type="fircosoft_manifest",
        output_filename_template="Fircosoft_Fcore_EDL_Data_{date}.csv",
        manifest_source_appl={"providingParty": "gbm", "appAcronym": "b8fb"},
        manifest_source_file_static={
            "ingestMetadata": "Fircosoft_EDL_Metadata_V8.xml",
            "recordCount": "",
            "fileExtension": "csv",
            "dataFileURI": "",
        },
    )
    monkeypatch.setitem(
        ReportDefinitionService._registry, "ChinaGTTReport", manifest_definition
    )

    orchestrator = ReportingOrchestrator(
        fenergo_service=FakeFenergoService(),
        download_service=FakeDownloadService(),
        delivery_service=FakeDeliveryService(),
    )

    execution = await orchestrator.run_report("ChinaGTTReport")

    output_path = Path(execution.output_file_path)
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    assert output_path.name == f"Fircosoft_Fcore_EDL_Data_{today}.csv"

    marker_path = output_path.with_suffix(output_path.suffix + ".mrk")
    assert marker_path.exists()
    manifest = json.loads(marker_path.read_text())
    assert manifest["specVersion"] == "2.0"
    assert manifest["sourceAppl"]["appAcronym"] == "b8fb"
    assert manifest["sourceFiles"][0]["dataFileURI"] == output_path.name
    assert (
        manifest["sourceFiles"][0]["recordCount"] == "1"
    )  # CHINA_GTT_CSV has 1 data row


async def test_run_report_delivers_marker_to_its_own_remote_folder_when_configured(
    db, monkeypatch
):
    """A connection's marker_remote_folder (net new - see SFTP_EDL) lets the
    marker artifact land in a different remote folder than the primary output.
    Exercised here against ChinaGTTReport's ClientCentralData connection for
    isolation, since EDLReport's own real SQL/wiring isn't this test's concern."""
    monkeypatch.setenv(
        "SFTP_CLIENTCENTRALDATA_MARKER_REMOTE_FOLDER",
        "./ClientCentralDataTest/marker",
    )
    delivery = FakeDeliveryService()
    orchestrator = ReportingOrchestrator(
        fenergo_service=FakeFenergoService(),
        download_service=FakeDownloadService(),
        delivery_service=delivery,
    )

    await orchestrator.run_report("ChinaGTTReport")

    assert len(delivery.deliver_calls) == 2
    directories = {call[1] for call in delivery.deliver_calls}
    assert directories == {
        "./ClientCentralDataTest",
        "./ClientCentralDataTest/marker",
    }


async def test_run_report_untracked_never_touches_execution_service(monkeypatch):
    """track=False (2026-09-16, Airflow smoke-testing): the real pipeline runs
    end-to-end - submit, poll, download, transform, marker, deliver - but not
    one execution_service call happens. Every function on the module is
    patched to raise if called at all, so any accidental DB touch fails this
    test loudly rather than silently succeeding against leftover DB state."""

    def _fail(*args, **kwargs):
        raise AssertionError("execution_service must not be called when track=False")

    for name in (
        "create_execution",
        "get_in_progress_execution",
        "mark_submitted",
        "mark_url_received",
        "mark_downloaded",
        "mark_transformed",
        "mark_completed",
        "mark_failed",
        "record_file_processing",
        "get_execution",
    ):
        monkeypatch.setattr(execution_service, name, _fail)

    fenergo = FakeFenergoService()
    download = FakeDownloadService()
    delivery = FakeDeliveryService()
    orchestrator = ReportingOrchestrator(
        fenergo_service=fenergo, download_service=download, delivery_service=delivery
    )

    execution = await orchestrator.run_report("ChinaGTTReport", track=False)

    assert execution.status == ExecutionStatus.SFTP_COMPLETED.value
    assert execution.fenergo_report_id == "FEN-123"
    assert execution.execution_id is not None
    assert Path(execution.output_file_path).exists()
    marker_path = Path(execution.output_file_path).with_suffix(".csv.mrk")
    assert marker_path.exists()
    assert len(delivery.deliver_calls) == 2


async def test_run_report_untracked_logs_completion(monkeypatch):
    orchestrator = ReportingOrchestrator(
        fenergo_service=FakeFenergoService(),
        download_service=FakeDownloadService(),
        delivery_service=FakeDeliveryService(),
    )

    logged_messages = []
    sink_id = log.add(
        lambda message: logged_messages.append(message.record["message"]),
        level="INFO",
    )
    try:
        await orchestrator.run_report("ChinaGTTReport", track=False)
    finally:
        log.remove(sink_id)

    assert any(
        "run_report completed untracked" in msg and "ChinaGTTReport" in msg
        for msg in logged_messages
    )


async def test_run_report_untracked_failure_reraises_without_touching_db(monkeypatch):
    def _fail(*args, **kwargs):
        raise AssertionError("execution_service must not be called when track=False")

    for name in (
        "create_execution",
        "get_in_progress_execution",
        "mark_submitted",
        "mark_failed",
    ):
        monkeypatch.setattr(execution_service, name, _fail)

    orchestrator = ReportingOrchestrator(
        fenergo_service=FakeFenergoService(),
        download_service=FailingDownloadService(),
        delivery_service=FakeDeliveryService(),
    )

    with pytest.raises(RuntimeError, match="simulated download failure"):
        await orchestrator.run_report("ChinaGTTReport", track=False)


async def test_run_report_output_lands_under_reports_archive_path_locally(db):
    """No AUDIT_ROOT set: settings.download_path/<archive_path>/, no Archive/Failed
    split - matches the user's own description of local behavior."""
    orchestrator = ReportingOrchestrator(
        fenergo_service=FakeFenergoService(),
        download_service=FakeDownloadService(),
        delivery_service=FakeDeliveryService(),
    )

    execution = await orchestrator.run_report("ChinaGTTReport")

    output_path = Path(execution.output_file_path)
    assert output_path.parent == settings.download_path / "GTT" / "China"


async def test_run_report_output_lands_under_audit_root_archive_when_set(
    db, monkeypatch, tmp_path
):
    audit_root = tmp_path / "Audit"
    monkeypatch.setattr(settings, "AUDIT_ROOT", str(audit_root))
    orchestrator = ReportingOrchestrator(
        fenergo_service=FakeFenergoService(),
        download_service=FakeDownloadService(),
        delivery_service=FakeDeliveryService(),
    )

    execution = await orchestrator.run_report("ChinaGTTReport")

    output_path = Path(execution.output_file_path)
    assert output_path.parent == audit_root / "Archive" / "GTT" / "China"


async def test_run_report_moves_output_to_failed_when_delivery_fails_and_audit_root_set(
    db, monkeypatch, tmp_path
):
    audit_root = tmp_path / "Audit"
    monkeypatch.setattr(settings, "AUDIT_ROOT", str(audit_root))
    orchestrator = ReportingOrchestrator(
        fenergo_service=FakeFenergoService(),
        download_service=FakeDownloadService(),
        delivery_service=FakeDeliveryService(fail=True),
    )

    with pytest.raises(DeliveryError):
        await orchestrator.run_report("ChinaGTTReport")

    archive_dir = audit_root / "Archive" / "GTT" / "China"
    failed_dir = audit_root / "Failed" / "GTT" / "China"
    assert list(archive_dir.glob("*.csv")) == []
    failed_files = list(failed_dir.glob("*.csv"))
    assert len(failed_files) == 1
    assert "Fenergo ID" in failed_files[0].read_text()


async def test_run_report_leaves_output_in_place_when_delivery_fails_and_no_audit_root(
    db,
):
    """Locally (no AUDIT_ROOT), Archive/Failed are the same directory - moving is a
    harmless no-op, not an error."""
    orchestrator = ReportingOrchestrator(
        fenergo_service=FakeFenergoService(),
        download_service=FakeDownloadService(),
        delivery_service=FakeDeliveryService(fail=True),
    )

    with pytest.raises(DeliveryError):
        await orchestrator.run_report("ChinaGTTReport")

    output_dir = settings.download_path / "GTT" / "China"
    files = list(output_dir.glob("*.csv"))
    assert len(files) == 1
    assert "Fenergo ID" in files[0].read_text()


async def test_run_report_full_success_records_seven_file_processing_rows_one_per_artifact(
    db,
):
    orchestrator = ReportingOrchestrator(
        fenergo_service=FakeFenergoService(),
        download_service=FakeDownloadService(),
        delivery_service=FakeDeliveryService(),
    )

    execution = await orchestrator.run_report("ChinaGTTReport")

    records = execution_service.list_file_processing(execution.execution_id)
    steps = [r.processing_step for r in records]
    assert steps == [
        "SUBMIT",
        "POLL",
        "DOWNLOAD",
        "TRANSFORM",
        "MARKER",
        "DELIVER",
        "DELIVER",
    ]
    assert all(r.status == "COMPLETED" for r in records)

    marker_record = records[4]
    output_path = Path(execution.output_file_path)
    marker_path = output_path.with_suffix(output_path.suffix + ".mrk")
    assert marker_record.checksum_value == marker_path.read_text().strip()

    deliver_file_names = {
        r.file_name for r in records if r.processing_step == "DELIVER"
    }
    assert deliver_file_names == {output_path.name, marker_path.name}


async def test_run_report_skips_marker_records_five_file_processing_rows(
    db, monkeypatch
):
    definition = ReportDefinitionService.get("ChinaGTTReport")
    monkeypatch.setitem(
        ReportDefinitionService._registry,
        "ChinaGTTReport",
        dataclasses.replace(definition, generate_marker=False),
    )
    orchestrator = ReportingOrchestrator(
        fenergo_service=FakeFenergoService(),
        download_service=FakeDownloadService(),
        delivery_service=FakeDeliveryService(),
    )

    execution = await orchestrator.run_report("ChinaGTTReport")

    records = execution_service.list_file_processing(execution.execution_id)
    assert [r.processing_step for r in records] == [
        "SUBMIT",
        "POLL",
        "DOWNLOAD",
        "TRANSFORM",
        "DELIVER",
    ]
    assert all(r.status == "COMPLETED" for r in records)


async def test_run_report_marks_failed_when_polling_reports_failed(db):
    fenergo = FakeFenergoService(status="Failed")
    orchestrator = ReportingOrchestrator(
        fenergo_service=fenergo,
        download_service=FakeDownloadService(),
        delivery_service=FakeDeliveryService(),
    )

    with pytest.raises(OrchestrationError):
        await orchestrator.run_report("ChinaGTTReport")

    executions = [e for e in _all_executions() if e.report_name == "ChinaGTTReport"]
    execution = executions[-1]
    assert execution.status == ExecutionStatus.FAILED.value
    assert execution.failure_stage == "POLL"


async def test_run_report_marks_failed_when_download_raises(db):
    orchestrator = ReportingOrchestrator(
        fenergo_service=FakeFenergoService(),
        download_service=FailingDownloadService(),
        delivery_service=FakeDeliveryService(),
    )

    with pytest.raises(RuntimeError):
        await orchestrator.run_report("ChinaGTTReport")

    execution = _all_executions()[-1]
    assert execution.status == ExecutionStatus.FAILED.value
    assert execution.failure_stage == "DOWNLOAD"
    assert "simulated download failure" in execution.error_message

    records = execution_service.list_file_processing(execution.execution_id)
    assert [r.processing_step for r in records] == ["SUBMIT", "POLL", "DOWNLOAD"]
    assert records[-1].status == "FAILED"


async def test_run_report_marks_failed_when_marker_generation_raises(db):
    class FailingMarkerService:
        @staticmethod
        def create_marker_for_file(path):
            raise OSError("simulated marker generation failure")

    delivery = FakeDeliveryService()
    orchestrator = ReportingOrchestrator(
        fenergo_service=FakeFenergoService(),
        download_service=FakeDownloadService(),
        delivery_service=delivery,
        marker_service=FailingMarkerService,
    )

    with pytest.raises(OSError):
        await orchestrator.run_report("ChinaGTTReport")

    assert delivery.deliver_calls == []
    execution = _all_executions()[-1]
    assert execution.status == ExecutionStatus.FAILED.value
    assert execution.failure_stage == "MARKER"

    records = execution_service.list_file_processing(execution.execution_id)
    assert [r.processing_step for r in records] == [
        "SUBMIT",
        "POLL",
        "DOWNLOAD",
        "TRANSFORM",
        "MARKER",
    ]
    assert records[-1].status == "FAILED"
    assert "simulated marker generation failure" in records[-1].error_message


async def test_run_report_raises_delivery_config_error_when_success_directory_unset(
    db, monkeypatch
):
    # ChinaGTTReport now delivers via sftp_connection="ClientCentralData" (see
    # SFTPConnectionService), not the legacy global SFTP_SUCCESS_DIRECTORY - the
    # connection's own required env var is what needs to be missing to reproduce
    # this config error for this report now.
    monkeypatch.delenv("SFTP_CLIENTCENTRALDATA_HOST", raising=False)
    delivery = FakeDeliveryService()
    orchestrator = ReportingOrchestrator(
        fenergo_service=FakeFenergoService(),
        download_service=FakeDownloadService(),
        delivery_service=delivery,
    )

    with pytest.raises(DeliveryConfigError):
        await orchestrator.run_report("ChinaGTTReport")

    assert delivery.deliver_calls == []
    execution = _all_executions()[-1]
    assert execution.status == ExecutionStatus.FAILED.value
    assert execution.failure_stage == "DELIVER"

    records = execution_service.list_file_processing(execution.execution_id)
    assert [r.processing_step for r in records] == [
        "SUBMIT",
        "POLL",
        "DOWNLOAD",
        "TRANSFORM",
        "MARKER",
        "DELIVER",
    ]
    assert [r.status for r in records] == [
        "COMPLETED",
        "COMPLETED",
        "COMPLETED",
        "COMPLETED",
        "COMPLETED",
        "FAILED",
    ]


async def test_run_report_explicit_true_override_forces_marker_over_false_default(
    db, monkeypatch
):
    definition = ReportDefinitionService.get("ChinaGTTReport")
    monkeypatch.setitem(
        ReportDefinitionService._registry,
        "ChinaGTTReport",
        dataclasses.replace(definition, generate_marker=False),
    )
    delivery = FakeDeliveryService()
    orchestrator = ReportingOrchestrator(
        fenergo_service=FakeFenergoService(),
        download_service=FakeDownloadService(),
        delivery_service=delivery,
    )

    execution = await orchestrator.run_report("ChinaGTTReport", generate_marker=True)

    output_path = Path(execution.output_file_path)
    marker_path = output_path.with_suffix(output_path.suffix + ".mrk")
    assert marker_path.exists()
    assert len(delivery.deliver_calls) == 2


async def test_run_report_explicit_false_override_suppresses_marker_over_true_default(
    db,
):
    delivery = FakeDeliveryService()
    orchestrator = ReportingOrchestrator(
        fenergo_service=FakeFenergoService(),
        download_service=FakeDownloadService(),
        delivery_service=delivery,
    )

    execution = await orchestrator.run_report("ChinaGTTReport", generate_marker=False)

    output_path = Path(execution.output_file_path)
    marker_path = output_path.with_suffix(output_path.suffix + ".mrk")
    assert not marker_path.exists()
    assert len(delivery.deliver_calls) == 1


async def test_run_report_no_sftp_no_output_path_skips_delivery_stays_transformed(db):
    delivery = FakeDeliveryService()
    orchestrator = ReportingOrchestrator(
        fenergo_service=FakeFenergoService(),
        download_service=FakeDownloadService(),
        delivery_service=delivery,
    )

    execution = await orchestrator.run_report("ChinaGTTReport", sftp=False)

    assert execution.status == ExecutionStatus.TRANSFORMED.value
    assert delivery.deliver_calls == []
    records = execution_service.list_file_processing(execution.execution_id)
    assert [r.processing_step for r in records] == [
        "SUBMIT",
        "POLL",
        "DOWNLOAD",
        "TRANSFORM",
        "MARKER",
    ]


async def test_run_report_output_path_copies_locally_and_completes(db, tmp_path):
    destination = tmp_path / "local_drop"
    orchestrator = ReportingOrchestrator(
        fenergo_service=FakeFenergoService(),
        download_service=FakeDownloadService(),
        delivery_service=FakeDeliveryService(),
    )

    execution = await orchestrator.run_report(
        "ChinaGTTReport", local_destination=destination
    )

    assert execution.status == ExecutionStatus.SFTP_COMPLETED.value
    output_path = Path(execution.output_file_path)
    marker_path = output_path.with_suffix(output_path.suffix + ".mrk")
    assert (destination / output_path.name).exists()
    assert (destination / marker_path.name).exists()
    assert (destination / output_path.name).read_bytes() == output_path.read_bytes()

    records = execution_service.list_file_processing(execution.execution_id)
    deliver_records = [r for r in records if r.processing_step == "DELIVER"]
    assert len(deliver_records) == 2
    assert {r.output_file_path for r in deliver_records} == {
        str(destination / output_path.name),
        str(destination / marker_path.name),
    }


async def test_run_report_sftp_true_and_output_path_together_raises(db, tmp_path):
    orchestrator = ReportingOrchestrator(
        fenergo_service=FakeFenergoService(),
        download_service=FakeDownloadService(),
        delivery_service=FakeDeliveryService(),
    )

    with pytest.raises(ValueError):
        await orchestrator.run_report(
            "ChinaGTTReport", sftp=True, local_destination=tmp_path / "out"
        )


async def test_submit_report_success_creates_and_marks_submitted(db):
    orchestrator = ReportingOrchestrator(fenergo_service=FakeFenergoService())

    execution = await orchestrator.submit_report("ChinaGTTReport")

    assert execution.status == ExecutionStatus.REQUEST_SUBMITTED.value
    assert execution.report_name == "ChinaGTTReport"
    assert execution.fenergo_report_id == "FEN-123"

    records = execution_service.list_file_processing(execution.execution_id)
    assert len(records) == 1
    assert records[0].processing_step == "SUBMIT"
    assert records[0].status == "COMPLETED"


async def test_submit_report_resumes_in_progress_execution_instead_of_resubmitting(db):
    fenergo = FakeFenergoService()
    orchestrator = ReportingOrchestrator(fenergo_service=fenergo)
    first = await orchestrator.submit_report("ChinaGTTReport")

    second = await orchestrator.submit_report("ChinaGTTReport")

    assert second.execution_id == first.execution_id
    assert len(fenergo.submit_calls) == 1


async def test_submit_report_submits_fresh_when_prior_execution_is_terminal(db):
    fenergo = FakeFenergoService()
    orchestrator = ReportingOrchestrator(fenergo_service=fenergo)
    first = await orchestrator.submit_report("ChinaGTTReport")
    execution_service.mark_completed(first.execution_id, "/tmp/out.csv")

    second = await orchestrator.submit_report("ChinaGTTReport")

    assert second.execution_id != first.execution_id
    assert len(fenergo.submit_calls) == 2


async def test_submit_report_marks_failed_when_fenergo_raises(db):
    class FailingFenergoService:
        async def submit(self, source, description):
            raise RuntimeError("simulated submit failure")

    orchestrator = ReportingOrchestrator(fenergo_service=FailingFenergoService())

    with pytest.raises(RuntimeError):
        await orchestrator.submit_report("ChinaGTTReport")

    execution = _all_executions()[-1]
    assert execution.status == ExecutionStatus.FAILED.value
    assert execution.failure_stage == "SUBMIT"

    records = execution_service.list_file_processing(execution.execution_id)
    assert len(records) == 1
    assert records[0].processing_step == "SUBMIT"
    assert records[0].status == "FAILED"


async def test_poll_execution_success_returns_presigned_url_and_marks_url_received(db):
    created = execution_service.create_execution("ChinaGTTReport")
    execution_service.mark_submitted(created.execution_id, "FEN-123")
    orchestrator = ReportingOrchestrator(fenergo_service=FakeFenergoService())

    poll_result = await orchestrator.poll_execution(created.execution_id)

    assert poll_result.status == "Completed"
    assert poll_result.presigned_url == "https://example.test/report.csv"
    updated = execution_service.get_execution(created.execution_id)
    assert updated.status == ExecutionStatus.REPORT_READY.value

    records = execution_service.list_file_processing(created.execution_id)
    assert len(records) == 1
    assert records[0].processing_step == "POLL"
    assert records[0].status == "COMPLETED"


async def test_poll_execution_marks_failed_when_status_is_failed(db):
    created = execution_service.create_execution("ChinaGTTReport")
    execution_service.mark_submitted(created.execution_id, "FEN-123")
    orchestrator = ReportingOrchestrator(
        fenergo_service=FakeFenergoService(status="Failed")
    )

    with pytest.raises(OrchestrationError):
        await orchestrator.poll_execution(created.execution_id)

    updated = execution_service.get_execution(created.execution_id)
    assert updated.status == ExecutionStatus.FAILED.value
    assert updated.failure_stage == "POLL"

    records = execution_service.list_file_processing(created.execution_id)
    assert len(records) == 1
    assert records[0].processing_step == "POLL"
    assert records[0].status == "FAILED"


async def test_poll_execution_raises_lookuperror_directly_for_unknown_execution_id(db):
    orchestrator = ReportingOrchestrator(fenergo_service=FakeFenergoService())

    with pytest.raises(LookupError):
        await orchestrator.poll_execution("does-not-exist")


async def test_poll_execution_once_true_completes_immediately_without_looping(db):
    created = execution_service.create_execution("ChinaGTTReport")
    execution_service.mark_submitted(created.execution_id, "FEN-123")
    orchestrator = ReportingOrchestrator(fenergo_service=FakeFenergoService())

    poll_result = await orchestrator.poll_execution(created.execution_id, once=True)

    assert poll_result.status == "Completed"
    assert poll_result.presigned_url == "https://example.test/report.csv"
    updated = execution_service.get_execution(created.execution_id)
    assert updated.status == ExecutionStatus.REPORT_READY.value
    assert updated.poll_attempts == 1

    records = execution_service.list_file_processing(created.execution_id)
    assert len(records) == 1
    assert records[0].processing_step == "POLL"


async def test_poll_execution_once_true_marks_failed_when_status_is_failed(db):
    created = execution_service.create_execution("ChinaGTTReport")
    execution_service.mark_submitted(created.execution_id, "FEN-123")
    orchestrator = ReportingOrchestrator(
        fenergo_service=FakeFenergoService(status="Failed")
    )

    with pytest.raises(OrchestrationError):
        await orchestrator.poll_execution(created.execution_id, once=True)

    updated = execution_service.get_execution(created.execution_id)
    assert updated.status == ExecutionStatus.FAILED.value
    assert updated.failure_stage == "POLL"

    records = execution_service.list_file_processing(created.execution_id)
    assert len(records) == 1
    assert records[0].status == "FAILED"


async def test_poll_execution_once_true_returns_pending_without_raising_or_marking_failed(
    db,
):
    created = execution_service.create_execution("ChinaGTTReport")
    execution_service.mark_submitted(created.execution_id, "FEN-123")
    orchestrator = ReportingOrchestrator(
        fenergo_service=FakeFenergoService(status="Pending")
    )

    poll_result = await orchestrator.poll_execution(created.execution_id, once=True)

    assert poll_result.status == "Pending"
    updated = execution_service.get_execution(created.execution_id)
    # increment_poll_attempt() sets status=POLLING as a side effect - correct,
    # not FAILED, which is the actual thing being asserted here.
    assert updated.status == ExecutionStatus.POLLING.value
    assert updated.failure_stage is None
    assert updated.poll_attempts == 1

    # "still pending" writes no file_processing row at all - not an event worth
    # recording, same treatment as "not a failure".
    assert execution_service.list_file_processing(created.execution_id) == []


async def test_poll_execution_once_true_increments_poll_attempts_across_calls(db):
    created = execution_service.create_execution("ChinaGTTReport")
    execution_service.mark_submitted(created.execution_id, "FEN-123")
    orchestrator = ReportingOrchestrator(
        fenergo_service=FakeFenergoService(status="Pending")
    )

    await orchestrator.poll_execution(created.execution_id, once=True)
    await orchestrator.poll_execution(created.execution_id, once=True)

    updated = execution_service.get_execution(created.execution_id)
    assert updated.poll_attempts == 2


async def test_poll_execution_marks_failed_when_no_fenergo_report_id(db):
    created = execution_service.create_execution("ChinaGTTReport")
    orchestrator = ReportingOrchestrator(fenergo_service=FakeFenergoService())

    with pytest.raises(ValueError):
        await orchestrator.poll_execution(created.execution_id)

    updated = execution_service.get_execution(created.execution_id)
    assert updated.status == ExecutionStatus.FAILED.value
    assert updated.failure_stage == "POLL"


def test_poll_execution_no_fenergo_report_id_does_not_record_file_processing(db):
    import asyncio

    created = execution_service.create_execution("ChinaGTTReport")
    orchestrator = ReportingOrchestrator(fenergo_service=FakeFenergoService())

    with pytest.raises(ValueError):
        asyncio.run(orchestrator.poll_execution(created.execution_id))

    assert execution_service.list_file_processing(created.execution_id) == []


async def test_download_execution_success(db):
    created = execution_service.create_execution("ChinaGTTReport")
    execution_service.mark_submitted(created.execution_id, "FEN-123")
    download = FakeDownloadService()
    orchestrator = ReportingOrchestrator(download_service=download)

    execution = await orchestrator.download_execution(
        created.execution_id, "https://example.test/report.csv"
    )

    assert execution.status == ExecutionStatus.DOWNLOADED.value
    assert execution.downloaded_file_path is not None
    assert download.download_calls == [
        ("https://example.test/report.csv", "FEN-123.csv")
    ]

    records = execution_service.list_file_processing(created.execution_id)
    assert len(records) == 1
    assert records[0].processing_step == "DOWNLOAD"
    assert records[0].status == "COMPLETED"


async def test_download_execution_marks_failed_when_download_raises(db):
    created = execution_service.create_execution("ChinaGTTReport")
    execution_service.mark_submitted(created.execution_id, "FEN-123")
    orchestrator = ReportingOrchestrator(download_service=FailingDownloadService())

    with pytest.raises(RuntimeError):
        await orchestrator.download_execution(created.execution_id, "https://x/y.csv")

    updated = execution_service.get_execution(created.execution_id)
    assert updated.status == ExecutionStatus.FAILED.value
    assert updated.failure_stage == "DOWNLOAD"

    records = execution_service.list_file_processing(created.execution_id)
    assert len(records) == 1
    assert records[0].status == "FAILED"


async def test_download_execution_no_fenergo_report_id_does_not_record_file_processing(
    db,
):
    created = execution_service.create_execution("ChinaGTTReport")
    orchestrator = ReportingOrchestrator(download_service=FakeDownloadService())

    with pytest.raises(ValueError):
        await orchestrator.download_execution(created.execution_id, "https://x/y.csv")

    assert execution_service.list_file_processing(created.execution_id) == []


async def test_transform_execution_success(db, tmp_path):
    input_path = tmp_path / "existing.csv"
    input_path.write_text(CHINA_GTT_CSV)
    created = execution_service.create_execution("ChinaGTTReport")
    execution_service.mark_downloaded(created.execution_id, str(input_path))
    orchestrator = ReportingOrchestrator()

    execution = await orchestrator.transform_execution(created.execution_id)

    assert execution.status == ExecutionStatus.TRANSFORMED.value
    output_path = Path(execution.output_file_path)
    assert output_path.exists()
    assert "Fenergo ID" in output_path.read_text()

    records = execution_service.list_file_processing(created.execution_id)
    assert len(records) == 1
    assert records[0].processing_step == "TRANSFORM"
    assert records[0].status == "COMPLETED"
    assert records[0].output_file_path == str(output_path)


async def test_transform_execution_marks_failed_when_no_downloaded_file_path(db):
    created = execution_service.create_execution("ChinaGTTReport")
    orchestrator = ReportingOrchestrator()

    with pytest.raises(ValueError):
        await orchestrator.transform_execution(created.execution_id)

    updated = execution_service.get_execution(created.execution_id)
    assert updated.status == ExecutionStatus.FAILED.value
    assert updated.failure_stage == "TRANSFORM"

    records = execution_service.list_file_processing(created.execution_id)
    assert len(records) == 1
    assert records[0].status == "FAILED"


# --- Utility flows: deliver_file (Flow: raw SFTP delivery, no report) ---


def test_deliver_file_unlinked_returns_untracked_result_and_writes_no_db_rows(
    db, tmp_path
):
    source_file = tmp_path / "arbitrary.csv"
    source_file.write_text("a,b\n1,2\n")
    delivery = FakeDeliveryService()
    orchestrator = ReportingOrchestrator(delivery_service=delivery)

    result = orchestrator.deliver_file(source_file)

    assert isinstance(result, UtilityOperationResult)
    assert result.execution_id is None
    assert result.output_path == "success/arbitrary.csv"
    assert len(delivery.deliver_calls) == 1
    assert _all_executions() == []


def test_deliver_file_linked_writes_deliver_file_processing_row(db, tmp_path):
    execution = _seed_full_run_execution()
    source_file = tmp_path / "arbitrary.csv"
    source_file.write_text("a,b\n1,2\n")
    delivery = FakeDeliveryService()
    orchestrator = ReportingOrchestrator(delivery_service=delivery)

    result = orchestrator.deliver_file(source_file, execution_id=execution.execution_id)

    assert result.execution_id == execution.execution_id
    assert result.output_path == "success/arbitrary.csv"
    records = execution_service.list_file_processing(execution.execution_id)
    assert len(records) == 1
    assert records[0].processing_step == "DELIVER"
    assert records[0].status == "COMPLETED"
    assert records[0].file_name == "arbitrary.csv"
    # The linked execution's own report_execution row is untouched.
    unchanged = execution_service.get_execution(execution.execution_id)
    assert unchanged.status == ExecutionStatus.REQUEST_SUBMITTED.value


def test_deliver_file_to_error_target(db, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "SFTP_ERROR_DIRECTORY", "error")
    source_file = tmp_path / "arbitrary.csv"
    source_file.write_text("a,b\n1,2\n")
    delivery = FakeDeliveryService()
    orchestrator = ReportingOrchestrator(delivery_service=delivery)

    orchestrator.deliver_file(source_file, target="error")

    assert delivery.deliver_calls[0][1] == "error"


def test_deliver_file_linked_marks_failed_file_processing_on_error(
    db, tmp_path, monkeypatch
):
    execution = _seed_full_run_execution()
    monkeypatch.setattr(settings, "SFTP_ERROR_DIRECTORY", None)
    source_file = tmp_path / "arbitrary.csv"
    source_file.write_text("a,b\n1,2\n")
    orchestrator = ReportingOrchestrator(delivery_service=FakeDeliveryService())

    with pytest.raises(DeliveryConfigError):
        orchestrator.deliver_file(
            source_file, target="error", execution_id=execution.execution_id
        )

    records = execution_service.list_file_processing(execution.execution_id)
    assert len(records) == 1
    assert records[0].processing_step == "DELIVER"
    assert records[0].status == "FAILED"


def test_deliver_file_unlinked_writes_no_db_rows_on_error(db, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "SFTP_ERROR_DIRECTORY", None)
    source_file = tmp_path / "arbitrary.csv"
    source_file.write_text("a,b\n1,2\n")
    orchestrator = ReportingOrchestrator(delivery_service=FakeDeliveryService())

    with pytest.raises(DeliveryConfigError):
        orchestrator.deliver_file(source_file, target="error")

    assert _all_executions() == []


def test_deliver_file_raises_for_unknown_target(db, tmp_path):
    source_file = tmp_path / "arbitrary.csv"
    source_file.write_text("a,b\n1,2\n")
    orchestrator = ReportingOrchestrator(delivery_service=FakeDeliveryService())

    with pytest.raises(ValueError):
        orchestrator.deliver_file(source_file, target="nonsense")


def test_deliver_file_raises_lookuperror_for_unknown_execution_id(db, tmp_path):
    source_file = tmp_path / "arbitrary.csv"
    source_file.write_text("a,b\n1,2\n")
    orchestrator = ReportingOrchestrator(delivery_service=FakeDeliveryService())

    with pytest.raises(LookupError):
        orchestrator.deliver_file(source_file, execution_id="does-not-exist")


# --- Utility flows: generate_marker_for_file (Flow 3) ---


def test_generate_marker_for_file_unlinked_returns_untracked_result_and_writes_no_db_rows(
    db, tmp_path
):
    source_file = tmp_path / "arbitrary.csv"
    source_file.write_text("some,content\n1,2\n")
    delivery = FakeDeliveryService()
    orchestrator = ReportingOrchestrator(delivery_service=delivery)

    result = orchestrator.generate_marker_for_file(source_file)

    assert isinstance(result, UtilityOperationResult)
    assert result.execution_id is None
    marker_path = source_file.with_suffix(source_file.suffix + ".mrk")
    assert result.output_path == str(marker_path)
    assert (
        marker_path.read_text().strip()
        == hashlib.sha256(source_file.read_bytes()).hexdigest()
    )
    assert len(delivery.deliver_calls) == 1
    assert _all_executions() == []


def test_generate_marker_for_file_linked_writes_marker_and_deliver_file_processing_rows(
    db, tmp_path
):
    execution = _seed_full_run_execution()
    source_file = tmp_path / "arbitrary.csv"
    source_file.write_text("some,content\n1,2\n")
    delivery = FakeDeliveryService()
    orchestrator = ReportingOrchestrator(delivery_service=delivery)

    result = orchestrator.generate_marker_for_file(
        source_file, execution_id=execution.execution_id
    )

    assert result.execution_id == execution.execution_id
    records = execution_service.list_file_processing(execution.execution_id)
    assert [r.processing_step for r in records] == ["MARKER", "DELIVER"]
    assert all(r.status == "COMPLETED" for r in records)
    marker_path = source_file.with_suffix(source_file.suffix + ".mrk")
    assert records[0].checksum_value == marker_path.read_text().strip()


def test_generate_marker_for_file_no_sftp_no_output_path_skips_delivery(db, tmp_path):
    execution = _seed_full_run_execution()
    source_file = tmp_path / "arbitrary.csv"
    source_file.write_text("some,content\n1,2\n")
    delivery = FakeDeliveryService()
    orchestrator = ReportingOrchestrator(delivery_service=delivery)

    result = orchestrator.generate_marker_for_file(
        source_file, execution_id=execution.execution_id, sftp=False
    )

    assert delivery.deliver_calls == []
    records = execution_service.list_file_processing(execution.execution_id)
    assert [r.processing_step for r in records] == ["MARKER"]
    marker_path = source_file.with_suffix(source_file.suffix + ".mrk")
    assert result.output_path == str(marker_path)


def test_generate_marker_for_file_output_path_copies_locally(db, tmp_path):
    execution = _seed_full_run_execution()
    destination = tmp_path / "local_drop"
    source_file = tmp_path / "arbitrary.csv"
    source_file.write_text("some,content\n1,2\n")
    delivery = FakeDeliveryService()
    orchestrator = ReportingOrchestrator(delivery_service=delivery)

    orchestrator.generate_marker_for_file(
        source_file, execution_id=execution.execution_id, local_destination=destination
    )

    assert delivery.deliver_calls == []
    marker_path = source_file.with_suffix(source_file.suffix + ".mrk")
    assert (destination / marker_path.name).exists()
    records = execution_service.list_file_processing(execution.execution_id)
    deliver_record = next(r for r in records if r.processing_step == "DELIVER")
    assert deliver_record.output_file_path == str(destination / marker_path.name)


def test_generate_marker_for_file_sftp_true_and_output_path_together_raises(
    db, tmp_path
):
    source_file = tmp_path / "arbitrary.csv"
    source_file.write_text("some,content\n1,2\n")
    orchestrator = ReportingOrchestrator(delivery_service=FakeDeliveryService())

    with pytest.raises(ValueError):
        orchestrator.generate_marker_for_file(
            source_file, sftp=True, local_destination=tmp_path / "out"
        )


def test_generate_marker_for_file_linked_writes_failed_file_processing_row_on_error(
    db, tmp_path, monkeypatch
):
    execution = _seed_full_run_execution()
    monkeypatch.setattr(settings, "SFTP_SUCCESS_DIRECTORY", None)
    source_file = tmp_path / "arbitrary.csv"
    source_file.write_text("some,content\n1,2\n")
    orchestrator = ReportingOrchestrator(delivery_service=FakeDeliveryService())

    with pytest.raises(DeliveryConfigError):
        orchestrator.generate_marker_for_file(
            source_file, execution_id=execution.execution_id
        )

    records = execution_service.list_file_processing(execution.execution_id)
    assert [r.processing_step for r in records] == ["MARKER", "DELIVER"]
    assert [r.status for r in records] == ["COMPLETED", "FAILED"]


def test_generate_marker_for_file_unlinked_writes_no_db_rows_on_error(
    db, tmp_path, monkeypatch
):
    monkeypatch.setattr(settings, "SFTP_SUCCESS_DIRECTORY", None)
    source_file = tmp_path / "arbitrary.csv"
    source_file.write_text("some,content\n1,2\n")
    orchestrator = ReportingOrchestrator(delivery_service=FakeDeliveryService())

    with pytest.raises(DeliveryConfigError):
        orchestrator.generate_marker_for_file(source_file)

    assert _all_executions() == []


def test_generate_marker_for_file_raises_lookuperror_for_unknown_execution_id(
    db, tmp_path
):
    source_file = tmp_path / "arbitrary.csv"
    source_file.write_text("some,content\n1,2\n")
    orchestrator = ReportingOrchestrator(delivery_service=FakeDeliveryService())

    with pytest.raises(LookupError):
        orchestrator.generate_marker_for_file(
            source_file, execution_id="does-not-exist"
        )


# --- Utility flows: transform_existing_csv (Flow 2) ---


async def test_transform_existing_csv_unlinked_returns_untracked_result_and_writes_no_db_rows(
    db, tmp_path
):
    input_path = tmp_path / "existing.csv"
    input_path.write_text(CHINA_GTT_CSV)
    delivery = FakeDeliveryService()
    orchestrator = ReportingOrchestrator(delivery_service=delivery)

    result = await orchestrator.transform_existing_csv("ChinaGTTReport", input_path)

    assert isinstance(result, UtilityOperationResult)
    assert result.execution_id is None
    output_path = Path(result.output_path)
    assert output_path.exists()
    assert "Fenergo ID" in output_path.read_text()
    marker_path = output_path.with_suffix(output_path.suffix + ".mrk")
    assert marker_path.exists()
    assert len(delivery.deliver_calls) == 2
    assert _all_executions() == []


async def test_transform_existing_csv_unlinked_respects_generate_marker_override_false(
    db, tmp_path
):
    input_path = tmp_path / "existing.csv"
    input_path.write_text(CHINA_GTT_CSV)
    delivery = FakeDeliveryService()
    orchestrator = ReportingOrchestrator(delivery_service=delivery)

    result = await orchestrator.transform_existing_csv(
        "ChinaGTTReport", input_path, generate_marker=False
    )

    output_path = Path(result.output_path)
    marker_path = output_path.with_suffix(output_path.suffix + ".mrk")
    assert not marker_path.exists()
    assert len(delivery.deliver_calls) == 1


async def test_transform_existing_csv_unlinked_marker_file_missing_input_raises(
    db, tmp_path
):
    orchestrator = ReportingOrchestrator(delivery_service=FakeDeliveryService())

    with pytest.raises(FileNotFoundError):
        await orchestrator.transform_existing_csv(
            "ChinaGTTReport", tmp_path / "does-not-exist.csv"
        )

    assert _all_executions() == []


async def test_transform_existing_csv_linked_writes_file_processing_rows(db, tmp_path):
    execution = _seed_full_run_execution(report_name="ChinaGTTReport")
    input_path = tmp_path / "existing.csv"
    input_path.write_text(CHINA_GTT_CSV)
    delivery = FakeDeliveryService()
    orchestrator = ReportingOrchestrator(delivery_service=delivery)

    result = await orchestrator.transform_existing_csv(
        "ChinaGTTReport", input_path, execution_id=execution.execution_id
    )

    assert result.execution_id == execution.execution_id
    records = execution_service.list_file_processing(execution.execution_id)
    assert [r.processing_step for r in records] == [
        "TRANSFORM",
        "MARKER",
        "DELIVER",
        "DELIVER",
    ]
    assert all(r.status == "COMPLETED" for r in records)
    # The linked execution's own report_execution row is untouched - re-processing
    # is a file-level event, not a change to the original run's outcome.
    unchanged = execution_service.get_execution(execution.execution_id)
    assert unchanged.status == ExecutionStatus.REQUEST_SUBMITTED.value
    assert unchanged.output_file_path is None


async def test_transform_existing_csv_no_sftp_no_output_path_skips_delivery(
    db, tmp_path
):
    execution = _seed_full_run_execution(report_name="ChinaGTTReport")
    input_path = tmp_path / "existing.csv"
    input_path.write_text(CHINA_GTT_CSV)
    delivery = FakeDeliveryService()
    orchestrator = ReportingOrchestrator(delivery_service=delivery)

    await orchestrator.transform_existing_csv(
        "ChinaGTTReport", input_path, execution_id=execution.execution_id, sftp=False
    )

    assert delivery.deliver_calls == []
    records = execution_service.list_file_processing(execution.execution_id)
    assert [r.processing_step for r in records] == ["TRANSFORM", "MARKER"]


async def test_transform_existing_csv_output_path_copies_locally(db, tmp_path):
    execution = _seed_full_run_execution(report_name="ChinaGTTReport")
    destination = tmp_path / "local_drop"
    input_path = tmp_path / "existing.csv"
    input_path.write_text(CHINA_GTT_CSV)
    delivery = FakeDeliveryService()
    orchestrator = ReportingOrchestrator(delivery_service=delivery)

    result = await orchestrator.transform_existing_csv(
        "ChinaGTTReport",
        input_path,
        execution_id=execution.execution_id,
        local_destination=destination,
    )

    assert delivery.deliver_calls == []
    output_path = Path(result.output_path)
    marker_path = output_path.with_suffix(output_path.suffix + ".mrk")
    assert (destination / output_path.name).exists()
    assert (destination / marker_path.name).exists()
    records = execution_service.list_file_processing(execution.execution_id)
    deliver_records = [r for r in records if r.processing_step == "DELIVER"]
    assert len(deliver_records) == 2


async def test_transform_existing_csv_sftp_true_and_output_path_together_raises(
    db, tmp_path
):
    input_path = tmp_path / "existing.csv"
    input_path.write_text(CHINA_GTT_CSV)
    orchestrator = ReportingOrchestrator(delivery_service=FakeDeliveryService())

    with pytest.raises(ValueError):
        await orchestrator.transform_existing_csv(
            "ChinaGTTReport", input_path, sftp=True, local_destination=tmp_path / "out"
        )


async def test_transform_existing_csv_linked_raises_on_report_name_mismatch(
    db, tmp_path
):
    execution = _seed_full_run_execution(report_name="CANDERReport")
    input_path = tmp_path / "existing.csv"
    input_path.write_text(CHINA_GTT_CSV)
    orchestrator = ReportingOrchestrator(delivery_service=FakeDeliveryService())

    with pytest.raises(ValueError):
        await orchestrator.transform_existing_csv(
            "ChinaGTTReport", input_path, execution_id=execution.execution_id
        )

    assert execution_service.list_file_processing(execution.execution_id) == []


async def test_transform_existing_csv_linked_writes_failed_file_processing_row_on_error(
    db, tmp_path
):
    execution = _seed_full_run_execution(report_name="ChinaGTTReport")
    orchestrator = ReportingOrchestrator(delivery_service=FakeDeliveryService())

    with pytest.raises(FileNotFoundError):
        await orchestrator.transform_existing_csv(
            "ChinaGTTReport",
            tmp_path / "does-not-exist.csv",
            execution_id=execution.execution_id,
        )

    records = execution_service.list_file_processing(execution.execution_id)
    assert len(records) == 1
    assert records[0].processing_step == "TRANSFORM"
    assert records[0].status == "FAILED"


async def test_transform_existing_csv_raises_lookuperror_for_unknown_execution_id(
    db, tmp_path
):
    input_path = tmp_path / "existing.csv"
    input_path.write_text(CHINA_GTT_CSV)
    orchestrator = ReportingOrchestrator(delivery_service=FakeDeliveryService())

    with pytest.raises(LookupError):
        await orchestrator.transform_existing_csv(
            "ChinaGTTReport", input_path, execution_id="does-not-exist"
        )


def test_timestamp_is_date_only_no_time_component():
    """2026-09-01: output/marker filenames switched to a date-only YYYYMMDD stamp,
    matching the finalized reports' naming standard - see docs/decisions.md."""
    value = ReportingOrchestrator._timestamp()
    assert len(value) == 8
    assert value.isdigit()
    assert datetime.strptime(value, "%Y%m%d")


async def test_output_filename_uses_date_only_timestamp(db):
    orchestrator = ReportingOrchestrator(
        fenergo_service=FakeFenergoService(),
        download_service=FakeDownloadService(),
        delivery_service=FakeDeliveryService(),
    )

    execution = await orchestrator.run_report("ChinaGTTReport")

    output_path = Path(execution.output_file_path)
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    assert output_path.name == f"ChinaGTTReport_{today}.csv"


def _all_executions():
    return execution_service.list_executions()

```

tests/services/test_sftp_connection_service.py:

skip for now, do pytest
```python
import pytest

from app.services.delivery_service import DeliveryConfigError
from app.services.sftp_connection_service import (
    SFTPConnectionSettings,
    SFTPConnectionService,
)


def _fake_key_path(tmp_path, name="key"):
    """tmp_path-based, not a string literal - avoids tripping GitGuardian."""
    return str(tmp_path / name)


def test_get_raises_for_unknown_connection_name():
    with pytest.raises(KeyError):
        SFTPConnectionService.get("DoesNotExist")


def test_get_resolves_real_connection_from_prefixed_env_vars(monkeypatch, tmp_path):
    key_path = _fake_key_path(tmp_path)
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_HOST", "lvappi01908.cloud.bns")
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_USERNAME", "sftpuser")
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_PRIVATE_KEY_PATH", key_path)
    monkeypatch.setenv(
        "SFTP_CLIENTCENTRALDATA_REMOTE_FOLDER", "./ClientCentralDataFenergo"
    )

    result = SFTPConnectionService.get("ClientCentralData")

    assert result.host == "lvappi01908.cloud.bns"
    assert result.port == 22
    assert result.username == "sftpuser"
    assert result.private_key_path == key_path
    assert result.remote_folder == "./ClientCentralDataFenergo"
    assert result.marker_remote_folder is None


def test_get_uses_default_port_when_unset(monkeypatch, tmp_path):
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_HOST", "host")
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_USERNAME", "user")
    monkeypatch.setenv(
        "SFTP_CLIENTCENTRALDATA_PRIVATE_KEY_PATH", _fake_key_path(tmp_path)
    )
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_REMOTE_FOLDER", "./folder")
    monkeypatch.delenv("SFTP_CLIENTCENTRALDATA_PORT", raising=False)

    assert SFTPConnectionService.get("ClientCentralData").port == 22


def test_get_respects_explicit_port_override(monkeypatch, tmp_path):
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_HOST", "host")
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_USERNAME", "user")
    monkeypatch.setenv(
        "SFTP_CLIENTCENTRALDATA_PRIVATE_KEY_PATH", _fake_key_path(tmp_path)
    )
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_REMOTE_FOLDER", "./folder")
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_PORT", "2222")

    assert SFTPConnectionService.get("ClientCentralData").port == 2222


def test_get_falls_back_to_global_known_hosts_path_when_unset(monkeypatch, tmp_path):
    from app.core.config import settings

    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_HOST", "host")
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_USERNAME", "user")
    monkeypatch.setenv(
        "SFTP_CLIENTCENTRALDATA_PRIVATE_KEY_PATH", _fake_key_path(tmp_path)
    )
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_REMOTE_FOLDER", "./folder")
    monkeypatch.delenv("SFTP_CLIENTCENTRALDATA_KNOWN_HOSTS_PATH", raising=False)

    result = SFTPConnectionService.get("ClientCentralData")

    assert result.known_hosts_path == settings.known_hosts_path


def test_get_respects_explicit_known_hosts_path_override(monkeypatch, tmp_path):
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_HOST", "host")
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_USERNAME", "user")
    monkeypatch.setenv(
        "SFTP_CLIENTCENTRALDATA_PRIVATE_KEY_PATH", _fake_key_path(tmp_path)
    )
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_REMOTE_FOLDER", "./folder")
    custom_path = str(tmp_path / "custom_known_hosts")
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_KNOWN_HOSTS_PATH", custom_path)

    result = SFTPConnectionService.get("ClientCentralData")

    assert str(result.known_hosts_path) == custom_path


def test_get_resolves_reg_central_connection_from_prefixed_env_vars(
    monkeypatch, tmp_path
):
    key_path = _fake_key_path(tmp_path, "reg_central_key")
    monkeypatch.setenv("SFTP_REGCENTRAL_HOST", "lvappi03337.cloud.bns")
    monkeypatch.setenv("SFTP_REGCENTRAL_USERNAME", "fenergo2rcp")
    monkeypatch.setenv("SFTP_REGCENTRAL_PRIVATE_KEY_PATH", key_path)
    monkeypatch.setenv(
        "SFTP_REGCENTRAL_REMOTE_FOLDER", "/opt/bns/rcp/feed/refdata/fenergo"
    )

    result = SFTPConnectionService.get("RegCentral")

    assert result.host == "lvappi03337.cloud.bns"
    assert result.port == 22
    assert result.username == "fenergo2rcp"
    assert result.private_key_path == key_path
    assert result.remote_folder == "/opt/bns/rcp/feed/refdata/fenergo"


@pytest.mark.parametrize(
    "missing_var",
    [
        "SFTP_CLIENTCENTRALDATA_HOST",
        "SFTP_CLIENTCENTRALDATA_USERNAME",
        "SFTP_CLIENTCENTRALDATA_PRIVATE_KEY_PATH",
        "SFTP_CLIENTCENTRALDATA_REMOTE_FOLDER",
    ],
)
def test_get_raises_delivery_config_error_when_a_required_field_is_missing(
    monkeypatch, tmp_path, missing_var
):
    required = {
        "SFTP_CLIENTCENTRALDATA_HOST": "host",
        "SFTP_CLIENTCENTRALDATA_USERNAME": "user",
        "SFTP_CLIENTCENTRALDATA_PRIVATE_KEY_PATH": _fake_key_path(tmp_path),
        "SFTP_CLIENTCENTRALDATA_REMOTE_FOLDER": "./folder",
    }
    for name, value in required.items():
        if name == missing_var:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)

    with pytest.raises(DeliveryConfigError):
        SFTPConnectionService.get("ClientCentralData")


def test_get_resolves_edl_connection_including_marker_remote_folder(
    monkeypatch, tmp_path
):
    """EDL is the one connection with a distinct remote folder for its marker
    (Fircosoft manifest) - .../b8fb/ for the data file, .../b8fb/marker/ for the
    manifest. See docs/decisions.md for why .../b8fb/metadata/ is deliberately
    left unwired (not yet confirmed what it's for)."""
    monkeypatch.setenv(
        "SFTP_EDL_HOST", "sdusvrbi814.scglobaluat.aduat.scotiacapital.com"
    )
    monkeypatch.setenv("SFTP_EDL_USERNAME", "edlu_b8fb_sftpid")
    monkeypatch.setenv(
        "SFTP_EDL_PRIVATE_KEY_PATH", _fake_key_path(tmp_path, "edl_key")
    )
    monkeypatch.setenv("SFTP_EDL_REMOTE_FOLDER", "../../../landing1/gbm/b8fb/")
    monkeypatch.setenv(
        "SFTP_EDL_MARKER_REMOTE_FOLDER", "../../../landing1/gbm/b8fb/marker/"
    )

    result = SFTPConnectionService.get("EDL")

    assert result.host == "sdusvrbi814.scglobaluat.aduat.scotiacapital.com"
    assert result.username == "edlu_b8fb_sftpid"
    assert result.remote_folder == "../../../landing1/gbm/b8fb/"
    assert result.marker_remote_folder == "../../../landing1/gbm/b8fb/marker/"


def test_marker_remote_folder_defaults_to_none_when_unset(monkeypatch, tmp_path):
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_HOST", "host")
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_USERNAME", "user")
    monkeypatch.setenv(
        "SFTP_CLIENTCENTRALDATA_PRIVATE_KEY_PATH", _fake_key_path(tmp_path)
    )
    monkeypatch.setenv("SFTP_CLIENTCENTRALDATA_REMOTE_FOLDER", "./folder")
    monkeypatch.delenv("SFTP_CLIENTCENTRALDATA_MARKER_REMOTE_FOLDER", raising=False)

    assert SFTPConnectionService.get("ClientCentralData").marker_remote_folder is None


@pytest.mark.parametrize("connection_name", ["EDL", "TENXCCD", "CCD", "DUCO", "TMX"])
def test_new_connections_are_registered(connection_name, monkeypatch):
    """Registered (no KeyError) even with no real secrets yet - TBD per
    docs/decisions.md, pending another team. DeliveryConfigError (missing HOST,
    the first required field) proves the name is in the registry without needing
    any real/fake secret value."""
    for field in (
        "HOST",
        "USERNAME",
        "PRIVATE_KEY_PATH",
        "REMOTE_FOLDER",
        "PORT",
        "KNOWN_HOSTS_PATH",
        "MARKER_REMOTE_FOLDER",
    ):
        monkeypatch.delenv(f"SFTP_{connection_name}_{field}", raising=False)

    with pytest.raises(DeliveryConfigError):
        SFTPConnectionService.get(connection_name)


def test_duco_uses_non_default_port(monkeypatch, tmp_path):
    """SFTP_DUCO is the one new connection on a non-standard port (2222)."""
    monkeypatch.setenv("SFTP_DUCO_HOST", "pymthwy-transfer-uat.bns")
    monkeypatch.setenv("SFTP_DUCO_USERNAME", "FENERGODUCO")
    monkeypatch.setenv(
        "SFTP_DUCO_PRIVATE_KEY_PATH", _fake_key_path(tmp_path, "duco_key")
    )
    monkeypatch.setenv("SFTP_DUCO_REMOTE_FOLDER", ".")
    monkeypatch.setenv("SFTP_DUCO_PORT", "2222")

    assert SFTPConnectionService.get("DUCO").port == 2222


@pytest.mark.parametrize("connection_name", ["DUCO", "TMX"])
def test_duco_and_tmx_use_dot_for_root_directory(
    connection_name, monkeypatch, tmp_path
):
    """Both were specified as delivering to the account's "root directory" -
    represented as "." (relative to the SFTP session's own start directory),
    confirmed with the user rather than guessed - see docs/decisions.md."""
    monkeypatch.setenv(f"SFTP_{connection_name}_HOST", "host")
    monkeypatch.setenv(f"SFTP_{connection_name}_USERNAME", "user")
    monkeypatch.setenv(
        f"SFTP_{connection_name}_PRIVATE_KEY_PATH", _fake_key_path(tmp_path)
    )
    monkeypatch.setenv(f"SFTP_{connection_name}_REMOTE_FOLDER", ".")

    assert SFTPConnectionService.get(connection_name).remote_folder == "."

```
