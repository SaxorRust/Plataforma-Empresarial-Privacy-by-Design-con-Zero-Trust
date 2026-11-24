package hospital.authz

import rego.v1

test_medico_atencion_medica_allowed if {
	d := decision with input as {
		"role": "medico",
		"purpose": "atencion_medica",
		"action": "read_record",
		"resource_purpose": "atencion_medica",
		"is_sanitized": false,
	}
	d.allow == true
	d.generalize_fields == false
	d.mask_token == false
	"diagnosis_cie10" in d.allowed_fields
	"opaque_patient_token" in d.allowed_fields
}

test_medico_marketing_denied_function_creep if {
	d := decision with input as {
		"role": "medico",
		"purpose": "marketing",
		"action": "read_record",
	}
	d.allow == false
	count(d.allowed_fields) == 0
}

test_missing_purpose_denied if {
	d := decision with input as {
		"role": "medico",
		"purpose": "",
		"action": "read_record",
	}
	d.allow == false
	contains(d.reason, "X-Purpose")
}

test_enfermeria_minimized_and_masked if {
	d := decision with input as {
		"role": "enfermeria",
		"purpose": "atencion_medica",
		"action": "read_record",
	}
	d.allow == true
	d.mask_token == true
	d.generalize_fields == false
	"diagnosis_summary" in d.allowed_fields
	not ("diagnosis_cie10" in d.allowed_fields)
	not ("age_years" in d.allowed_fields)
}

test_enfermeria_cannot_create_or_detokenize if {
	d_create := decision with input as {
		"role": "enfermeria",
		"purpose": "atencion_medica",
		"action": "create_record",
	}
	d_create.allow == false

	d_detok := decision with input as {
		"role": "enfermeria",
		"purpose": "atencion_medica",
		"action": "detokenize_pii",
	}
	d_detok.allow == false
}

test_analista_generalized_statistical_read if {
	d := decision with input as {
		"role": "analista",
		"purpose": "investigacion_estadistica",
		"action": "read_record",
		"resource_purpose": "atencion_medica",
	}
	d.allow == true
	d.generalize_fields == true
	"age_range" in d.allowed_fields
	"zip_generalized" in d.allowed_fields
	not ("record_id" in d.allowed_fields)
	not ("opaque_patient_token" in d.allowed_fields)
	not ("diagnosis_summary" in d.allowed_fields)
}

test_analista_blocked_from_single_record_singling_out if {
	d := decision with input as {
		"role": "analista",
		"purpose": "investigacion_estadistica",
		"action": "read_single_record",
	}
	d.allow == false
	contains(d.reason, "singularización")
}

test_auditor_arco_sees_lifecycle_only_no_diagnoses if {
	d := decision with input as {
		"role": "auditor_arco",
		"purpose": "ejercicio_arco",
		"action": "read_record",
		"is_sanitized": true,
	}
	d.allow == true
	"is_sanitized" in d.allowed_fields
	"ttl_expires_at" in d.allowed_fields
	not ("diagnosis_cie10" in d.allowed_fields)
	not ("diagnosis_summary" in d.allowed_fields)
}

test_medico_blocked_on_sanitized_record if {
	d := decision with input as {
		"role": "medico",
		"purpose": "atencion_medica",
		"action": "read_single_record",
		"is_sanitized": true,
	}
	d.allow == false
	contains(d.reason, "NIST SP 800-88")
}

test_admin_sec_separation_of_duties if {
	d := decision with input as {
		"role": "admin_sec",
		"purpose": "atencion_medica",
		"action": "read_record",
	}
	d.allow == false
	contains(d.reason, "separación de funciones")
}

test_admin_sec_allowed_ttl_maintenance_without_clinical_fields if {
	d := decision with input as {
		"role": "admin_sec",
		"purpose": "mantenimiento_ttl",
		"action": "run_ttl_sweep",
	}
	d.allow == true
	count(d.allowed_fields) == 0
}

test_auditor_arco_erase_and_ttl_sweep_allowed if {
	d_erase := decision with input as {
		"role": "auditor_arco",
		"purpose": "ejercicio_arco",
		"action": "erase_nist_800_88",
	}
	d_erase.allow == true

	d_ttl := decision with input as {
		"role": "auditor_arco",
		"purpose": "ejercicio_arco",
		"action": "run_ttl_sweep",
	}
	d_ttl.allow == true
}

test_medico_cannot_erase_or_export_anonymized if {
	d_erase := decision with input as {
		"role": "medico",
		"purpose": "atencion_medica",
		"action": "erase_nist_800_88",
	}
	d_erase.allow == false

	d_exp := decision with input as {
		"role": "medico",
		"purpose": "atencion_medica",
		"action": "export_anonymized",
	}
	d_exp.allow == false
}

test_admin_sec_denied_clinical_pii_export_and_arco if {
	d_read := decision with input as {
		"role": "admin_sec",
		"purpose": "atencion_medica",
		"action": "read_record",
		"resource_purpose": "atencion_medica",
	}
	d_read.allow == false
	d_read.allowed_fields == []

	d_detok := decision with input as {
		"role": "admin_sec",
		"purpose": "atencion_medica",
		"action": "detokenize_pii",
	}
	d_detok.allow == false

	d_erase := decision with input as {
		"role": "admin_sec",
		"purpose": "ejercicio_arco",
		"action": "erase_nist_800_88",
	}
	d_erase.allow == false

	d_exp := decision with input as {
		"role": "admin_sec",
		"purpose": "investigacion_estadistica",
		"action": "export_anonymized",
	}
	d_exp.allow == false
}

test_unknown_or_removed_role_default_deny if {
	d_unknown := decision with input as {
		"role": "super_admin",
		"purpose": "atencion_medica",
		"action": "read_record",
	}
	d_unknown.allow == false
	d_unknown.allowed_fields == []
}


