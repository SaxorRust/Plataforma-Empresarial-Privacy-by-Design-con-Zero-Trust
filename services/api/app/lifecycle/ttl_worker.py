import asyncio
from datetime import datetime, timezone
import logging
from threading import Lock
from uuid import UUID

from app.models.lifecycle import TTLStatusResponse, TTLSweepResponse
from app.repositories.clinical_repo import ClinicalRecordRepository
from app.vault.service import VaultPIIVaultService, VaultServiceError, VaultTokenNotFoundError

logger = logging.getLogger(__name__)


class TTLSweepService:
    """
    Motor de Retención Temporal Automatizada (MB-01):
    - Identifica registros clínicos cuya marca `ttl_expires_at` ha vencido.
    - Sobrescribe y elimina los registros expirados en `clinical.medical_records`.
    - Purga el token opaco `pat_...` en HashiCorp Vault únicamente cuando ya no existen
      otros expedientes activos vinculados a ese paciente.
    """

    def __init__(
        self,
        *,
        clinical_repo: ClinicalRecordRepository,
        vault_service: VaultPIIVaultService,
        enabled: bool = True,
        interval_seconds: int = 60,
    ) -> None:
        self._clinical_repo = clinical_repo
        self._vault_service = vault_service
        self._enabled = enabled
        self._interval_seconds = max(5, int(interval_seconds))
        self._lock = Lock()
        self._scheduler_running = False
        self._total_sweeps = 0
        self._total_records_purged = 0
        self._total_vault_tokens_purged = 0
        self._last_run_at: datetime | None = None
        self._last_error: str | None = None

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def interval_seconds(self) -> int:
        return self._interval_seconds

    def set_scheduler_running(self, running: bool) -> None:
        with self._lock:
            self._scheduler_running = running

    def get_status(self) -> TTLStatusResponse:
        with self._lock:
            return TTLStatusResponse(
                enabled=self._enabled,
                scheduler_running=self._scheduler_running,
                interval_seconds=self._interval_seconds,
                total_sweeps=self._total_sweeps,
                total_records_purged=self._total_records_purged,
                total_vault_tokens_purged=self._total_vault_tokens_purged,
                last_run_at=self._last_run_at,
                last_error=self._last_error,
            )

    def run_sweep(
        self,
        *,
        now: datetime | None = None,
        triggered_by: str = "system_ttl_scheduler",
    ) -> TTLSweepResponse:
        executed_at = now if now is not None else datetime.now(timezone.utc)
        if executed_at.tzinfo is None:
            executed_at = executed_at.replace(tzinfo=timezone.utc)

        purged_record_ids: list[UUID] = []
        candidate_tokens: set[str] = set()
        purged_vault_tokens: list[str] = []
        skipped_tokens: list[str] = []

        try:
            expired_records = self._clinical_repo.list_expired_records(executed_at)
            for rec in expired_records:
                if self._clinical_repo.overwrite_and_delete_record(rec.record_id):
                    purged_record_ids.append(rec.record_id)
                    candidate_tokens.add(rec.opaque_patient_token)

            for token in sorted(candidate_tokens):
                remaining_active = self._clinical_repo.count_active_records_for_token(token)
                if remaining_active > 0:
                    skipped_tokens.append(token)
                    continue
                try:
                    self._vault_service.purge_patient(token)
                    purged_vault_tokens.append(token)
                except VaultTokenNotFoundError:
                    # El token ya había sido purgado previamente
                    continue
                except VaultServiceError as exc:
                    logger.warning(
                        "TTL sweep no pudo purgar un registro en Vault (se reintentará): %s",
                        exc,
                    )
        except Exception as exc:
            with self._lock:
                self._last_run_at = executed_at
                self._last_error = str(exc)
            raise

        with self._lock:
            self._total_sweeps += 1
            self._total_records_purged += len(purged_record_ids)
            self._total_vault_tokens_purged += len(purged_vault_tokens)
            self._last_run_at = executed_at
            self._last_error = None

        return TTLSweepResponse(
            triggered_by=triggered_by,
            executed_at=executed_at,
            purged_records_count=len(purged_record_ids),
            purged_record_ids=purged_record_ids,
            purged_vault_tokens_count=len(purged_vault_tokens),
            purged_vault_tokens=purged_vault_tokens,
            skipped_vault_tokens_with_active_records=skipped_tokens,
        )


class TTLBackgroundScheduler:
    """Ejecuta `TTLSweepService.run_sweep()` periódicamente durante el ciclo de vida FastAPI."""

    def __init__(self, sweep_service: TTLSweepService) -> None:
        self._sweep_service = sweep_service
        self._stop_event: asyncio.Event | None = None
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        if not self._sweep_service.enabled:
            self._sweep_service.set_scheduler_running(False)
            return
        self._stop_event = asyncio.Event()
        self._sweep_service.set_scheduler_running(True)
        self._task = asyncio.create_task(self._loop(), name="ttl-retention-scheduler")

    async def stop(self) -> None:
        if self._stop_event is not None:
            self._stop_event.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                # Cancelación esperada durante el apagado ordenado del ciclo lifespan.
                pass
            self._task = None
        self._sweep_service.set_scheduler_running(False)

    async def _loop(self) -> None:
        stop_event = self._stop_event
        if stop_event is None:
            return
        while not stop_event.is_set():
            try:
                await asyncio.to_thread(
                    self._sweep_service.run_sweep,
                    triggered_by="system_ttl_scheduler",
                )
            except Exception as exc:
                logger.warning("Ejecución periódica de TTL encontró error transitorio: %s", exc)

            try:
                await asyncio.wait_for(
                    stop_event.wait(),
                    timeout=float(self._sweep_service.interval_seconds),
                )
            except TimeoutError:
                continue
