from dataclasses import dataclass
import logging

from app.models.auth import UserRole
from app.repositories.auth_repo import DuplicateUsernameError, UserRepository
from app.security.passwords import Argon2idPasswordService

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
