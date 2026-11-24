-- =============================================================================
-- Esquema Base Segregado — Privacy-by-Design (Hospitalaria)
-- Los identificadores directos (Nombre, CURP, NSS) NO residen junto a los
-- diagnósticos médicos; se almacenan en HashiCorp Vault y se vinculan por
-- tokens opacos.
-- =============================================================================

CREATE SCHEMA IF NOT EXISTS auth_identity;
CREATE SCHEMA IF NOT EXISTS clinical;
CREATE SCHEMA IF NOT EXISTS compliance;

-- Usuarios del sistema (Médicos, Analistas, Auditores, Pacientes)
CREATE TABLE IF NOT EXISTS auth_identity.users (
    id UUID PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    role VARCHAR(32) NOT NULL CHECK (role IN ('medico', 'enfermeria', 'analista', 'auditor_arco', 'admin_sec', 'paciente')),
    password_hash TEXT NOT NULL, -- Argon2id (salt único + pepper de aplicación)
    webauthn_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    opaque_patient_token VARCHAR(128)
);

-- Credenciales FIDO2 / WebAuthn (Passkeys)
CREATE TABLE IF NOT EXISTS auth_identity.webauthn_credentials (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth_identity.users(id) ON DELETE CASCADE,
    credential_id BYTEA UNIQUE NOT NULL,
    public_key BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    transports TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Atributos clínicos sensibles vinculados ÚNICAMENTE mediante opaque_patient_token
CREATE TABLE IF NOT EXISTS clinical.medical_records (
    record_id UUID PRIMARY KEY,
    opaque_patient_token VARCHAR(128) NOT NULL,
    age_years INTEGER NOT NULL CHECK (age_years >= 0 AND age_years <= 130),
    zip_prefix VARCHAR(5) NOT NULL,
    gender VARCHAR(16) NOT NULL,
    diagnosis_cie10 VARCHAR(16) NOT NULL,
    diagnosis_summary TEXT NOT NULL,
    department VARCHAR(64) NOT NULL,
    purpose_scope VARCHAR(64) NOT NULL DEFAULT 'atencion_medica',
    ttl_expires_at TIMESTAMPTZ,
    is_sanitized BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_medical_records_token
    ON clinical.medical_records (opaque_patient_token);

CREATE INDEX IF NOT EXISTS idx_medical_records_ttl
    ON clinical.medical_records (ttl_expires_at)
    WHERE ttl_expires_at IS NOT NULL;

-- Registro de Certificados de Sanitización NIST SP 800-88 (Módulo B)
CREATE TABLE IF NOT EXISTS compliance.sanitization_certificates (
    certificate_id UUID PRIMARY KEY,
    opaque_patient_token VARCHAR(128) NOT NULL,
    method VARCHAR(32) NOT NULL CHECK (method IN ('NIST_800_88_CLEAR', 'NIST_800_88_PURGE')),
    sha256_hash CHAR(64) NOT NULL,
    requested_by VARCHAR(64) NOT NULL,
    executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    certificate_json JSONB NOT NULL
);
