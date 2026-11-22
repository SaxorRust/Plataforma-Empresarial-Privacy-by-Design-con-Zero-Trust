from fastapi import APIRouter, Depends, HTTPException, Response, status

from app.models.auth import (
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
    get_current_user,
    get_jwt_service,
    get_password_service,
    get_user_repository,
    get_webauthn_service,
)
from app.security.jwt_auth import JWTService
from app.security.passwords import Argon2idPasswordService
from app.security.webauthn_service import WebAuthnService, WebAuthnServiceError

router = APIRouter(prefix="/auth", tags=["autenticacion-ma01"])


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
    summary="Registrar usuario con respaldo Argon2id (salt único + pepper)",
)
def register_user(
    payload: UserRegisterRequest,
    repo: UserRepository = Depends(get_user_repository),
    password_service: Argon2idPasswordService = Depends(get_password_service),
) -> UserPublicResponse:
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

    return _to_public_user(user)


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Iniciar sesión con contraseña Argon2id (salt único + pepper) y emitir JWT",
)
def login_with_password(
    payload: PasswordLoginRequest,
    repo: UserRepository = Depends(get_user_repository),
    password_service: Argon2idPasswordService = Depends(get_password_service),
    jwt_service: JWTService = Depends(get_jwt_service),
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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not password_service.verify_password(payload.password, user.password_hash):
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
            pass

    amr = ["pwd"]
    access_token, _, _ = jwt_service.create_access_token(user, amr=amr)
    return TokenResponse(
        access_token=access_token,
        expires_in=jwt_service.expire_seconds,
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
        webauthn_enabled=user.webauthn_enabled,
    )


@router.post(
    "/logout",
    response_model=LogoutResponse,
    summary="Revocar inmediatamente la sesión JWT actual (Zero Trust)",
)
def logout(
    current_user: AuthenticatedUser = Depends(get_current_user),
    jwt_service: JWTService = Depends(get_jwt_service),
) -> LogoutResponse:
    jwt_service.revoke_token(current_user)
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
    repo: UserRepository = Depends(get_user_repository),
    webauthn_service: WebAuthnService = Depends(get_webauthn_service),
    jwt_service: JWTService = Depends(get_jwt_service),
) -> TokenResponse:
    try:
        user = repo.get_user_by_username(payload.username)
        credentials = repo.list_webauthn_credentials(user.id) if user and user.is_active else []
    except DatabaseUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc

    if user is None or not user.is_active or not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autenticación FIDO2/WebAuthn rechazada.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        verified = webauthn_service.complete_authentication(user, payload.credential, credentials)
    except WebAuthnServiceError as exc:
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
    return TokenResponse(
        access_token=access_token,
        expires_in=jwt_service.expire_seconds,
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
