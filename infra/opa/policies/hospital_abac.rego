package hospital.authz

import rego.v1

# Denegar por defecto (Zero Trust / Default Deny)
default allow := false

# Regla base de validación de propósito (Prevención de Function Creep)
allow if {
    valid_role_purpose
}

valid_role_purpose if {
    input.role == "medico"
    input.purpose == "atencion_medica"
    input.action in ["read_record", "create_record", "update_record"]
}

valid_role_purpose if {
    input.role == "enfermeria"
    input.purpose == "atencion_medica"
    input.action == "read_record"
}

valid_role_purpose if {
    input.role == "analista"
    input.purpose == "investigacion_estadistica"
    input.action == "export_anonymized"
}

valid_role_purpose if {
    input.role == "auditor_arco"
    input.purpose == "ejercicio_arco"
    input.action in ["read_audit", "erase_nist_800_88"]
}

# Minimización cuantitativa (columnas permitidas) y cualitativa (generalización)
allowed_fields := ["record_id", "opaque_patient_token", "age_years", "zip_prefix", "diagnosis_cie10", "diagnosis_summary", "department"] if {
    input.role == "medico"
    input.purpose == "atencion_medica"
} else := ["record_id", "opaque_patient_token", "department", "diagnosis_summary"] if {
    input.role == "enfermeria"
    input.purpose == "atencion_medica"
} else := ["age_range", "zip_generalized", "gender", "diagnosis_cie10"] if {
    input.role == "analista"
    input.purpose == "investigacion_estadistica"
} else := ["record_id", "opaque_patient_token", "is_sanitized", "ttl_expires_at"] if {
    input.role == "auditor_arco"
} else := []

generalize_fields := true if {
    input.role == "analista"
} else := false

decision := {
    "allow": allow,
    "allowed_fields": allowed_fields,
    "generalize_fields": generalize_fields,
    "reason": reason,
}

reason := "Autorizado conforme a propósito declarado" if {
    allow
} else := "Acceso denegado: rol o propósito declarado inválido (prevención de function creep)"
