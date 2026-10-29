output "rules_files" {
  description = "Paths of the rule files the circuit writes on each host."
  value       = concat(["/etc/audit/rules.d/audit.rules", "/etc/audit/rules.d/50-conn3x.rules"], [for p in var.presets : "/etc/audit/rules.d/${p}.rules"])
}
