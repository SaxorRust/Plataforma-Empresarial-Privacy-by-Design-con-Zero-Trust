from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import logging

from app.models.auth import UserRole
from app.models.vault import PatientPIIRequest
from app.repositories.auth_repo import DuplicateUsernameError, UserRepository
from app.repositories.clinical_repo import ClinicalRecordRepository
from app.security.passwords import Argon2idPasswordService
from app.vault.service import VaultPIIVaultService, VaultServiceError

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AccountSeedSpec:
    username: str
    role: UserRole
    label: str


DEFAULT_TEAM_ACCOUNTS: tuple[AccountSeedSpec, ...] = (
    AccountSeedSpec(username="medico_demo", role="medico", label="Medico"),
    AccountSeedSpec(username="enfermeria_demo", role="enfermeria", label="Enfermeria"),
    AccountSeedSpec(username="analista_demo", role="analista", label="Analista"),
    AccountSeedSpec(username="auditor_arco", role="auditor_arco", label="AuditorArco"),
    AccountSeedSpec(username="admin_sec", role="admin_sec", label="AdminSec"),
    AccountSeedSpec(username="paciente_demo", role="paciente", label="Paciente"),
)


def seed_default_team_accounts(
    repo: UserRepository,
    password_service: Argon2idPasswordService,
    *,
    suffix: str,
) -> list[str]:
    """
    Crea de forma idempotente las 6 cuentas genéricas del equipo (roles ABAC Zero Trust)
    si aún no existen en `auth_identity.users`.
    """
    ensure_fn = getattr(repo, "ensure_role_constraint", None)
    if callable(ensure_fn):
        ensure_fn()

    created_usernames: list[str] = []
    for spec in DEFAULT_TEAM_ACCOUNTS:
        if repo.get_user_by_username(spec.username) is not None:
            continue
        passphrase = f"{spec.label}{suffix}"
        hashed = password_service.hash_password(passphrase)
        try:
            repo.create_user(
                username=spec.username,
                role=spec.role,
                password_hash=hashed,
            )
            created_usernames.append(spec.username)
        except DuplicateUsernameError:
            continue

    if created_usernames:
        logger.info(
            "Cuentas genéricas del equipo inicializadas (%d): %s",
            len(created_usernames),
            ", ".join(created_usernames),
        )
    return created_usernames


def seed_demo_patient_record(
    user_repo: UserRepository,
    clinical_repo: ClinicalRecordRepository,
    vault_service: VaultPIIVaultService,
) -> str | None:
    """
    Aprovisiona de forma idempotente un expediente segregado (Vault PII + PostgreSQL)
    vinculado exclusivamente al titular `paciente_demo` mediante su `opaque_patient_token`,
    si aún no cuenta con uno asignado.
    """
    patient_user = user_repo.get_user_by_username("paciente_demo")
    if patient_user is None or patient_user.role != "paciente":
        return None
    if patient_user.opaque_patient_token:
        return None

    link_fn = getattr(user_repo, "set_user_opaque_patient_token", None)
    if not callable(link_fn):
        return None

    demo_pii = PatientPIIRequest(
        full_name="María Fernanda Morales Vega",
        curp="MOVM920514MPLRGD07",
        nss="22119248315",
        contact_email="paciente.demo@hospital-zt.local",
        contact_phone="+522221984321",
    )
    tokenized = vault_service.tokenize_patient(demo_pii)
    try:
        clinical_repo.create_record(
            opaque_patient_token=tokenized.opaque_patient_token,
            age_years=34,
            zip_prefix="72000",
            gender="F",
            diagnosis_cie10="E11.9",
            diagnosis_summary=(
                "Control ambulatorio de diabetes mellitus tipo 2; "
                "evolución estable con seguimiento nutricional y perfil glucémico en metas."
            ),
            department="medicina_interna",
            purpose_scope="atencion_medica",
            ttl_expires_at=datetime.now(timezone.utc) + timedelta(hours=720),
        )
        link_fn(patient_user.id, tokenized.opaque_patient_token)
    except Exception:
        try:
            vault_service.purge_patient(tokenized.opaque_patient_token)
        except VaultServiceError:
            pass
        raise

    logger.info("Expediente segregado inicial vinculado al titular paciente_demo.")
    return tokenized.opaque_patient_token
