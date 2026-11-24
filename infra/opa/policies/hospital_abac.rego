package hospital.authz

import rego.v1

# ==============================================================================
# Motor ABAC / Zero Trust — Prevención de Function Creep y Minimización (MA-03, MA-04)
# ==============================================================================
# Principios:
#   1. Default Deny (Zero Trust): toda operación sin coincidencia explícita se deniega.
#   2. Purpose Limitation: cada rol solo opera bajo su finalidad declarada y autorizada.
#   3. Quantitative Minimization: solo se devuelven las columnas estrictamente necesarias.
#   4. Qualitative Minimization: generalización (edad -> rango, CP -> prefijo) y
#      enmascaramiento de tokens según necesidad clínica/operativa.
# ==============================================================================

policy_version := "1.1.0"

default allow := false

default generalize_fields := false

default mask_token := false

# Normalización defensiva de banderas opcionales del recurso
resource_is_sanitized if {
	input.is_sanitized == true
}

resource_purpose_compatible if {
	not input.resource_purpose
}

resource_purpose_compatible if {
	input.resource_purpose == ""
}

resource_purpose_compatible if {
	input.resource_purpose == input.purpose
}

# El procesamiento estadístico secundario está permitido SOLO si los datos
# fueron recabados bajo atención médica o investigación y se generalizan.
resource_purpose_compatible if {
	input.role == "analista"
	input.purpose == "investigacion_estadistica"
	input.resource_purpose in ["atencion_medica", "investigacion_estadistica"]
}

# El ejercicio de derechos ARCO tiene habilitación legal sobre cualquier finalidad previa.
resource_purpose_compatible if {
	input.role == "auditor_arco"
	input.purpose == "ejercicio_arco"
}

# El titular puede consultar sus propios registros recabados en atención médica.
resource_purpose_compatible if {
	input.role == "paciente"
	input.purpose == "acceso_titular"
	input.resource_purpose in ["atencion_medica", "investigacion_estadistica"]
}

# ------------------------------------------------------------------------------
# Reglas de autorización (rol + propósito + acción + estado del recurso)
# ------------------------------------------------------------------------------
allow if {
	valid_role_purpose
	resource_purpose_compatible
	record_state_allowed
}

# Los registros ya sanitizados (NIST SP 800-88) solo son visibles para auditoría ARCO
record_state_allowed if {
	not resource_is_sanitized
}

record_state_allowed if {
	resource_is_sanitized
	input.role == "auditor_arco"
	input.purpose == "ejercicio_arco"
}

valid_role_purpose if {
	input.role == "medico"
	input.purpose == "atencion_medica"
	input.action in [
		"create_record",
		"read_record",
		"read_single_record",
		"update_record",
		"detokenize_pii",
	]
}

valid_role_purpose if {
	input.role == "enfermeria"
	input.purpose == "atencion_medica"
	input.action in ["read_record", "read_single_record"]
}

# Analista: solo lecturas colectivas generalizadas y exportación anonimizada.
# Se prohíbe `read_single_record` para evitar singularización (singling-out).
valid_role_purpose if {
	input.role == "analista"
	input.purpose == "investigacion_estadistica"
	input.action in ["read_record", "export_anonymized"]
}

valid_role_purpose if {
	input.role == "auditor_arco"
	input.purpose == "ejercicio_arco"
	input.action in [
		"read_record",
		"read_single_record",
		"read_audit",
		"erase_nist_800_88",
		"run_ttl_sweep",
	]
}

# Separación de funciones: admin_sec solo puede ejecutar mantenimiento TTL
# (nunca leer expedientes ni diagnósticos clínicos).
valid_role_purpose if {
	input.role == "admin_sec"
	input.purpose == "mantenimiento_ttl"
	input.action == "run_ttl_sweep"
}

valid_role_purpose if {
	input.role == "paciente"
	input.purpose == "acceso_titular"
	input.action in ["read_record", "read_single_record"]
	input.resource_owner_match == true
}

# Nota de separación de funciones (Zero Trust):
# `super_admin` es estrictamente gestor de cuentas e identidades (IAM en /auth/users)
# y carece deliberadamente de permisos sobre expedientes clínicos, PII, exportaciones o ARCO.

# ------------------------------------------------------------------------------
# Minimización cuantitativa (MA-04): proyección estricta de columnas permitidas
# ------------------------------------------------------------------------------
allowed_fields := [
	"record_id",
	"opaque_patient_token",
	"age_years",
	"zip_prefix",
	"gender",
	"diagnosis_cie10",
	"diagnosis_summary",
	"department",
	"purpose_scope",
	"ttl_expires_at",
	"created_at",
] if {
	allow
	input.role == "medico"
	input.purpose == "atencion_medica"
} else := [
	"record_id",
	"opaque_patient_token",
	"department",
	"diagnosis_summary",
] if {
	allow
	input.role == "enfermeria"
	input.purpose == "atencion_medica"
} else := [
	"age_range",
	"zip_generalized",
	"gender",
	"diagnosis_cie10",
	"department",
] if {
	allow
	input.role == "analista"
	input.purpose == "investigacion_estadistica"
} else := [
	"record_id",
	"opaque_patient_token",
	"purpose_scope",
	"is_sanitized",
	"ttl_expires_at",
	"created_at",
] if {
	allow
	input.role == "auditor_arco"
	input.purpose == "ejercicio_arco"
} else := [
	"record_id",
	"department",
	"diagnosis_summary",
	"purpose_scope",
	"ttl_expires_at",
	"created_at",
] if {
	allow
	input.role == "paciente"
	input.purpose == "acceso_titular"
} else := []

# ------------------------------------------------------------------------------
# Minimización cualitativa (MA-04): generalización y enmascaramiento por rol
# ------------------------------------------------------------------------------
generalize_fields if {
	allow
	input.role == "analista"
	input.purpose == "investigacion_estadistica"
}

mask_token if {
	allow
	input.role == "enfermeria"
	input.purpose == "atencion_medica"
}

# ------------------------------------------------------------------------------
# Motivo auditable de decisión (para respuestas 403 y trazabilidad SIEM)
# ------------------------------------------------------------------------------
reason := "Autorizado conforme a propósito declarado y política de minimización" if {
	allow
} else := "Acceso denegado: propósito declarado ausente (X-Purpose obligatorio — prevención de function creep)" if {
	not input.purpose
} else := "Acceso denegado: propósito declarado ausente (X-Purpose obligatorio — prevención de function creep)" if {
	input.purpose == ""
} else := "Acceso denegado: separación de funciones Zero Trust (super_admin solo gestiona cuentas IAM, sin acceso a datos clínicos ni ciclo de vida)" if {
	input.role == "super_admin"
} else := "Acceso denegado: registro sanitizado conforme a NIST SP 800-88 (solo visible para auditoría ARCO)" if {
	resource_is_sanitized
	input.role != "auditor_arco"
} else := "Acceso denegado: consulta individual prohibida para analista (prevención de singularización)" if {
	input.role == "analista"
	input.action == "read_single_record"
} else := "Acceso denegado: separación de funciones Zero Trust (admin_sec no tiene acceso a diagnósticos clínicos)" if {
	input.role == "admin_sec"
} else := "Acceso denegado: finalidad incompatible con el alcance de recolección del registro (prevención de function creep)" if {
	valid_role_purpose
	not resource_purpose_compatible
} else := "Acceso denegado: rol, acción o propósito declarado inválido (prevención de function creep)"

decision := {
	"allow": allow,
	"allowed_fields": allowed_fields,
	"generalize_fields": generalize_fields,
	"mask_token": mask_token,
	"reason": reason,
	"policy_version": policy_version,
}
