from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from app.audit.syslog_client import (
    SYSLOG_SEVERITY_NOTICE,
    SYSLOG_SEVERITY_WARNING,
    SyslogAuditClient,
)
from app.models.auth import (
    AdminRevokeSessionsResponse,
    AdminUserCreateRequest,
    AdminUserUpdateRequest,
    AuthenticatedUser,
    CurrentUserResponse,
    LogoutResponse,
    PasswordLoginRequest,
    TokenResponse,
    UserPublicResponse,
    UserRecord,
    UserRegisterRequest,
    WebAuthnCredentialResponse,
    WebAuthnLoginBeginRequest,
    WebAuthnLoginCompleteRequest,
    WebAuthnOptionsResponse,
    WebAuthnRegisterCompleteRequest,
    WebAuthnRegisterCompleteResponse,
)
from app.repositories.auth_repo import (
    DatabaseUnavailableError,
    DuplicateCredentialError,
    DuplicateUsernameError,
    UserRepository,
)
from app.security.dependencies import (
    get_audit_client,
    get_current_user,
    get_jwt_service,
    get_password_service,
    get_user_repository,
    get_webauthn_service,
    require_roles,
)
from app.security.jwt_auth import JWTService
from app.security.passwords import Argon2idPasswordService
from app.security.webauthn_service import WebAuthnService, WebAuthnServiceError

router = APIRouter(prefix="/auth", tags=["autenticacion-ma01"])

PUBLIC_SELF_REGISTER_ROLE = "paciente"


def _to_public_user(user: UserRecord) -> UserPublicResponse:
    return UserPublicResponse(
        id=user.id,
        username=user.username,
        role=user.role,
        webauthn_enabled=user.webauthn_enabled,
        is_active=user.is_active,
        created_at=user.created_at,
    )


@router.post(
    "/register",
    response_model=UserPublicResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Auto-registro público Zero Trust (solo rol `paciente` con Argon2id)",
)
def register_user(
    payload: UserRegisterRequest,
    request: Request,
    repo: UserRepository = Depends(get_user_repository),
    password_service: Argon2idPasswordService = Depends(get_password_service),
    audit_client: SyslogAuditClient = Depends(get_audit_client),
) -> UserPublicResponse:
    if payload.role != PUBLIC_SELF_REGISTER_ROLE:
        audit_client.emit_event(
            msg_id="AUTH_PRIVILEGE_ESCALATION_BLOCKED",
            message=f"Intento de auto-registro público con rol privilegiado '{payload.role}' bloqueado",
            severity=SYSLOG_SEVERITY_WARNING,
            actor=payload.username,
            role=payload.role,
            action="register_privileged_blocked",
            outcome="denied",
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Acceso denegado (Zero Trust): el registro público solo permite el rol 'paciente'. "
                "El rol 'super_admin' es único y los roles institucionales deben ser aprovisionados "
                "por un administrador en POST /auth/users."
            ),
        )

    password_hash = password_service.hash_password(payload.password)
    try:
        user = repo.create_user(
            username=payload.username,
            role=PUBLIC_SELF_REGISTER_ROLE,
            password_hash=password_hash,
        )
    except DuplicateUsernameError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc

    audit_client.emit_event(
        msg_id="AUTH_REGISTER",
        message="Auto-registro público de titular (paciente) con Argon2id",
        actor=user.username,
        role=user.role,
        action="register",
        outcome="success",
        request=request,
    )
    return _to_public_user(user)


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Iniciar sesión con contraseña Argon2id (salt único + pepper) y emitir JWT",
)
def login_with_password(
    payload: PasswordLoginRequest,
    request: Request,
    repo: UserRepository = Depends(get_user_repository),
    password_service: Argon2idPasswordService = Depends(get_password_service),
    jwt_service: JWTService = Depends(get_jwt_service),
    audit_client: SyslogAuditClient = Depends(get_audit_client),
) -> TokenResponse:
    try:
        user = repo.get_user_by_username(payload.username)
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc

    if user is None or not user.is_active:
        # Mitigación de enumeración de usuarios mediante costo temporal equivalente
        password_service.verify_dummy(payload.password)
        audit_client.emit_event(
            msg_id="AUTH_LOGIN_FAILED",
            message="Intento fallido de inicio de sesión por contraseña",
            severity=SYSLOG_SEVERITY_WARNING,
            actor=payload.username,
            action="login_password",
            outcome="failure",
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not password_service.verify_password(payload.password, user.password_hash):
        audit_client.emit_event(
            msg_id="AUTH_LOGIN_FAILED",
            message="Intento fallido de inicio de sesión por contraseña",
            severity=SYSLOG_SEVERITY_WARNING,
            actor=user.username,
            role=user.role,
            action="login_password",
            outcome="failure",
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if password_service.needs_rehash(user.password_hash):
        new_hash = password_service.hash_password(payload.password)
        try:
            repo.update_password_hash(user.id, new_hash)
        except DatabaseUnavailableError:
            # Rehash oportuno no bloqueante: el login ya fue verificado válidamente.
            pass

    amr = ["pwd"]
    access_token, _, _ = jwt_service.create_access_token(user, amr=amr)
    audit_client.emit_event(
        msg_id="AUTH_LOGIN_SUCCESS",
        message="Inicio de sesión exitoso mediante Argon2id",
        actor=user.username,
        role=user.role,
        action="login_password",
        outcome="success",
        request=request,
    )
    return TokenResponse(
        access_token=access_token,
        expires_in=jwt_service.expire_seconds,
        inactivity_timeout_seconds=jwt_service.inactivity_timeout_seconds,
        amr=amr,
        user=_to_public_user(user),
    )


@router.get(
    "/me",
    response_model=CurrentUserResponse,
    summary="Consultar identidad y claims de la sesión JWT activa",
)
def get_me(
    current_user: AuthenticatedUser = Depends(get_current_user),
    repo: UserRepository = Depends(get_user_repository),
    jwt_service: JWTService = Depends(get_jwt_service),
) -> CurrentUserResponse:
    try:
        user = repo.get_user_by_id(current_user.user_id)
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario inactivo o inexistente.",
        )

    return CurrentUserResponse(
        user_id=user.id,
        username=user.username,
        role=user.role,
        amr=current_user.amr,
        jti=current_user.jti,
        expires_at=current_user.exp,
        inactivity_timeout_seconds=jwt_service.inactivity_timeout_seconds,
        webauthn_enabled=user.webauthn_enabled,
    )


@router.post(
    "/logout",
    response_model=LogoutResponse,
    summary="Revocar inmediatamente la sesión JWT actual (Zero Trust)",
)
def logout(
    request: Request,
    current_user: AuthenticatedUser = Depends(get_current_user),
    jwt_service: JWTService = Depends(get_jwt_service),
    audit_client: SyslogAuditClient = Depends(get_audit_client),
) -> LogoutResponse:
    jwt_service.revoke_token(current_user)
    audit_client.emit_event(
        msg_id="AUTH_LOGOUT",
        message="Sesión JWT revocada explícitamente",
        actor=current_user.username,
        role=current_user.role,
        action="logout",
        outcome="success",
        request=request,
    )
    return LogoutResponse(jti=current_user.jti)


@router.post(
    "/webauthn/register/begin",
    response_model=WebAuthnOptionsResponse,
    summary="Iniciar registro de Passkey FIDO2/WebAuthn para el usuario autenticado",
)
def webauthn_register_begin(
    current_user: AuthenticatedUser = Depends(get_current_user),
    repo: UserRepository = Depends(get_user_repository),
    webauthn_service: WebAuthnService = Depends(get_webauthn_service),
) -> WebAuthnOptionsResponse:
    try:
        user = repo.get_user_by_id(current_user.user_id)
        if user is None or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuario inactivo o inexistente.",
            )
        existing_credentials = repo.list_webauthn_credentials(user.id)
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc

    options = webauthn_service.begin_registration(user, existing_credentials)
    return WebAuthnOptionsResponse(
        options=options,
        rp_id=webauthn_service.rp_id,
        expires_in=webauthn_service.challenge_ttl_seconds,
    )


@router.post(
    "/webauthn/register/complete",
    response_model=WebAuthnRegisterCompleteResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Verificar y persistir Passkey FIDO2/WebAuthn del usuario autenticado",
)
def webauthn_register_complete(
    payload: WebAuthnRegisterCompleteRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    repo: UserRepository = Depends(get_user_repository),
    webauthn_service: WebAuthnService = Depends(get_webauthn_service),
) -> WebAuthnRegisterCompleteResponse:
    try:
        user = repo.get_user_by_id(current_user.user_id)
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario inactivo o inexistente.",
        )

    try:
        verified = webauthn_service.complete_registration(user, payload.credential)
    except WebAuthnServiceError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    try:
        saved = repo.add_webauthn_credential(
            user_id=user.id,
            credential_id=verified.credential_id,
            public_key=verified.public_key,
            sign_count=verified.sign_count,
            transports=verified.transports,
        )
    except DuplicateCredentialError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc

    return WebAuthnRegisterCompleteResponse(
        credential_id=webauthn_service.encode_credential_id(saved.credential_id),
        sign_count=saved.sign_count,
        transports=saved.transports,
        webauthn_enabled=True,
    )


@router.post(
    "/webauthn/login/begin",
    response_model=WebAuthnOptionsResponse,
    summary="Generar reto FIDO2/WebAuthn para inicio de sesión con Passkey",
)
def webauthn_login_begin(
    payload: WebAuthnLoginBeginRequest,
    repo: UserRepository = Depends(get_user_repository),
    webauthn_service: WebAuthnService = Depends(get_webauthn_service),
) -> WebAuthnOptionsResponse:
    try:
        user = repo.get_user_by_username(payload.username)
        credentials = repo.list_webauthn_credentials(user.id) if user and user.is_active else []
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc

    if user is None or not user.is_active or not credentials:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No hay Passkeys FIDO2 disponibles para el usuario especificado.",
        )

    try:
        options = webauthn_service.begin_authentication(user, credentials)
    except WebAuthnServiceError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return WebAuthnOptionsResponse(
        options=options,
        rp_id=webauthn_service.rp_id,
        expires_in=webauthn_service.challenge_ttl_seconds,
    )


@router.post(
    "/webauthn/login/complete",
    response_model=TokenResponse,
    summary="Verificar aserción FIDO2/WebAuthn (Passkey) y emitir JWT",
)
def webauthn_login_complete(
    payload: WebAuthnLoginCompleteRequest,
    request: Request,
    repo: UserRepository = Depends(get_user_repository),
    webauthn_service: WebAuthnService = Depends(get_webauthn_service),
    jwt_service: JWTService = Depends(get_jwt_service),
    audit_client: SyslogAuditClient = Depends(get_audit_client),
) -> TokenResponse:
    try:
        user = repo.get_user_by_username(payload.username)
        credentials = repo.list_webauthn_credentials(user.id) if user and user.is_active else []
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc

    if user is None or not user.is_active or not credentials:
        audit_client.emit_event(
            msg_id="AUTH_WEBAUTHN_FAILED",
            message="Autenticación FIDO2/WebAuthn rechazada (usuario o credenciales inválidas)",
            severity=SYSLOG_SEVERITY_WARNING,
            actor=payload.username,
            action="login_webauthn",
            outcome="failure",
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autenticación FIDO2/WebAuthn rechazada.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        verified = webauthn_service.complete_authentication(user, payload.credential, credentials)
    except WebAuthnServiceError as exc:
        audit_client.emit_event(
            msg_id="AUTH_WEBAUTHN_FAILED",
            message="Autenticación FIDO2/WebAuthn rechazada en verificación criptográfica",
            severity=SYSLOG_SEVERITY_WARNING,
            actor=user.username,
            role=user.role,
            action="login_webauthn",
            outcome="failure",
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    try:
        repo.update_webauthn_sign_count(verified.credential_id, verified.new_sign_count)
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc

    amr = ["webauthn", "fido2"]
    access_token, _, _ = jwt_service.create_access_token(user, amr=amr)
    audit_client.emit_event(
        msg_id="AUTH_WEBAUTHN_SUCCESS",
        message="Inicio de sesión exitoso mediante Passkey FIDO2/WebAuthn",
        actor=user.username,
        role=user.role,
        action="login_webauthn",
        outcome="success",
        request=request,
    )
    return TokenResponse(
        access_token=access_token,
        expires_in=jwt_service.expire_seconds,
        inactivity_timeout_seconds=jwt_service.inactivity_timeout_seconds,
        amr=amr,
        user=_to_public_user(user),
    )


@router.get(
    "/webauthn/credentials",
    response_model=list[WebAuthnCredentialResponse],
    summary="Listar Passkeys FIDO2 registradas por el usuario autenticado",
)
def list_webauthn_credentials(
    current_user: AuthenticatedUser = Depends(get_current_user),
    repo: UserRepository = Depends(get_user_repository),
    webauthn_service: WebAuthnService = Depends(get_webauthn_service),
) -> list[WebAuthnCredentialResponse]:
    try:
        creds = repo.list_webauthn_credentials(current_user.user_id)
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc

    return [
        WebAuthnCredentialResponse(
            id=cred.id,
            credential_id=webauthn_service.encode_credential_id(cred.credential_id),
            sign_count=cred.sign_count,
            transports=cred.transports,
            created_at=cred.created_at,
        )
        for cred in creds
    ]


@router.delete(
    "/webauthn/credentials/{credential_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revocar una Passkey FIDO2 perteneciente al usuario autenticado",
)
def delete_webauthn_credential(
    credential_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
    repo: UserRepository = Depends(get_user_repository),
    webauthn_service: WebAuthnService = Depends(get_webauthn_service),
) -> Response:
    try:
        cred_bytes = webauthn_service.decode_credential_id(credential_id)
    except WebAuthnServiceError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    try:
        deleted = repo.delete_webauthn_credential(current_user.user_id, cred_bytes)
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Passkey no encontrada para el usuario autenticado.",
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _assert_super_admin_guard(
    *,
    actor: AuthenticatedUser,
    target_role: str | None,
    existing_role: str | None = None,
) -> None:
    if target_role == "super_admin" and existing_role != "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Acceso denegado (Zero Trust): el rol 'super_admin' es único en la plataforma "
                "y no puede asignarse a cuentas adicionales."
            ),
        )
    if actor.role != "super_admin" and existing_role == "super_admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Acceso denegado (Zero Trust): solo 'super_admin' puede "
                "administrar la cuenta 'super_admin'."
            ),
        )


@router.get(
    "/users",
    response_model=list[UserPublicResponse],
    summary="Listar cuentas institucionales registradas (solo admin_sec o super_admin)",
)
def admin_list_users(
    _actor: AuthenticatedUser = Depends(require_roles("admin_sec")),
    repo: UserRepository = Depends(get_user_repository),
) -> list[UserPublicResponse]:
    try:
        users = repo.list_users()
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc
    return [_to_public_user(user) for user in users]


@router.post(
    "/users",
    response_model=UserPublicResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Aprovisionar cuenta institucional con rol ABAC (solo admin_sec o super_admin)",
)
def admin_create_user(
    payload: AdminUserCreateRequest,
    request: Request,
    actor: AuthenticatedUser = Depends(require_roles("admin_sec")),
    repo: UserRepository = Depends(get_user_repository),
    password_service: Argon2idPasswordService = Depends(get_password_service),
    audit_client: SyslogAuditClient = Depends(get_audit_client),
) -> UserPublicResponse:
    _assert_super_admin_guard(actor=actor, target_role=payload.role)
    password_hash = password_service.hash_password(payload.password)
    try:
        user = repo.create_user(
            username=payload.username,
            role=payload.role,
            password_hash=password_hash,
        )
    except DuplicateUsernameError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc

    audit_client.emit_event(
        msg_id="AUTH_USER_PROVISIONED",
        message=f"Cuenta '{user.username}' aprovisionada con rol '{user.role}'",
        severity=SYSLOG_SEVERITY_NOTICE,
        actor=actor.username,
        role=actor.role,
        action="admin_create_user",
        outcome="success",
        resource=user.username,
        request=request,
    )
    return _to_public_user(user)


@router.patch(
    "/users/{user_id}",
    response_model=UserPublicResponse,
    summary="Actualizar rol o estado activo de una cuenta y revocar sus sesiones activas",
)
def admin_update_user(
    user_id: UUID,
    payload: AdminUserUpdateRequest,
    request: Request,
    actor: AuthenticatedUser = Depends(require_roles("admin_sec")),
    repo: UserRepository = Depends(get_user_repository),
    jwt_service: JWTService = Depends(get_jwt_service),
    audit_client: SyslogAuditClient = Depends(get_audit_client),
) -> UserPublicResponse:
    if payload.role is None and payload.is_active is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Debes especificar al menos 'role' o 'is_active' para actualizar la cuenta.",
        )

    try:
        existing = repo.get_user_by_id(user_id)
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc

    if existing is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cuenta de usuario no encontrada.",
        )

    _assert_super_admin_guard(
        actor=actor,
        target_role=payload.role,
        existing_role=existing.role,
    )
    if existing.id == actor.user_id and (
        payload.is_active is False or (payload.role is not None and payload.role != actor.role)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No puedes desactivar ni degradar tu propia cuenta en sesión activa.",
        )

    try:
        updated = repo.update_user(user_id, role=payload.role, is_active=payload.is_active)
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc

    if updated is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cuenta de usuario no encontrada.",
        )

    # Zero Trust: revocar inmediatamente sesiones activas si cambió rol o se desactivó la cuenta
    if payload.role is not None or payload.is_active is False:
        jwt_service.revoke_user_sessions(updated.id)

    audit_client.emit_event(
        msg_id="AUTH_USER_UPDATED",
        message=(
            f"Cuenta '{updated.username}' actualizada "
            f"(role={updated.role}, is_active={updated.is_active})"
        ),
        severity=SYSLOG_SEVERITY_NOTICE,
        actor=actor.username,
        role=actor.role,
        action="admin_update_user",
        outcome="success",
        resource=updated.username,
        request=request,
    )
    return _to_public_user(updated)


@router.post(
    "/users/{user_id}/revoke-sessions",
    response_model=AdminRevokeSessionsResponse,
    summary="Revocar inmediatamente todas las sesiones JWT activas de un usuario",
)
def admin_revoke_user_sessions(
    user_id: UUID,
    request: Request,
    actor: AuthenticatedUser = Depends(require_roles("admin_sec")),
    repo: UserRepository = Depends(get_user_repository),
    jwt_service: JWTService = Depends(get_jwt_service),
    audit_client: SyslogAuditClient = Depends(get_audit_client),
) -> AdminRevokeSessionsResponse:
    try:
        target = repo.get_user_by_id(user_id)
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc

    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Cuenta de usuario no encontrada.",
        )

    _assert_super_admin_guard(actor=actor, target_role=None, existing_role=target.role)
    revoked_count = jwt_service.revoke_user_sessions(target.id)
    audit_client.emit_event(
        msg_id="AUTH_USER_SESSIONS_REVOKED",
        message=f"Revocación forzada de sesiones para '{target.username}' ({revoked_count} JWT)",
        severity=SYSLOG_SEVERITY_NOTICE,
        actor=actor.username,
        role=actor.role,
        action="admin_revoke_sessions",
        outcome="success",
        resource=target.username,
        request=request,
    )
    return AdminRevokeSessionsResponse(
        user_id=target.id,
        username=target.username,
        revoked_sessions=revoked_count,
    )
