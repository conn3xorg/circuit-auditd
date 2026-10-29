variable "hosts" {
  type        = any
  description = "Hosts to configure: a map of names to addresses, or to host objects with an address and optional host_key, user, port, private_key_file, jump_hosts or os."

  validation {
    condition     = alltrue([for h in var.hosts : contains(["debian", "ubuntu", "rocky", "almalinux", "rhel", "centos", "fedora"], try(h.os, "debian"))])
    error_message = "A host object's os must be one of debian, ubuntu, rocky, almalinux, rhel, centos or fedora."
  }
}

variable "ssh_user" {
  type        = string
  default     = "root"
  description = "User to log in as."
}

variable "ssh_port" {
  type        = number
  default     = 22
  description = "SSH port."
}

variable "ssh_private_key_file" {
  type        = string
  default     = null
  description = "Path to a private key. When null, Conn3x uses the SSH agent."
}

variable "ssh_known_hosts_file" {
  type        = string
  default     = null
  description = "known_hosts file to check host keys against. When null, ~/.ssh/known_hosts."
}

variable "ssh_become" {
  type        = bool
  default     = false
  description = "Run commands as root through sudo."
}

variable "presets" {
  type        = list(string)
  default     = []
  description = "Sample rule files from the audit package to copy into /etc/audit/rules.d, by name without .rules, such as [\"11-loginuid\", \"30-stig\"]."

  validation {
    condition     = alltrue([for p in var.presets : can(regex("^[0-9]{2}-[a-z0-9][a-z0-9.-]*$", p))])
    error_message = "Each preset is the name of a sample rule file without .rules, such as \"30-stig\" or \"30-pci-dss-v31\"."
  }

  validation {
    condition     = length(distinct(var.presets)) == length(var.presets)
    error_message = "presets names the same file twice."
  }
}

variable "rules" {
  type        = list(string)
  default     = []
  description = "Your own audit rules, one per line in auditctl syntax, such as [\"-w /etc/sudoers -p wa -k sudoers\"]. They go in /etc/audit/rules.d/50-conn3x.rules."

  validation {
    condition     = alltrue([for r in var.rules : can(regex("^-", r)) && !strcontains(r, "\n")])
    error_message = "Each rule is one line that starts with -, such as \"-w /etc/passwd -p wa -k identity\"."
  }

  validation {
    condition     = alltrue([for r in var.rules : !can(regex("^(-[eDbf]|--backlog_wait_time)(\\s|$)", r))])
    error_message = "Set -e with immutable, and -b and -f with backlog_limit and failure_mode. -D is always first."
  }
}

variable "immutable" {
  type        = bool
  default     = false
  description = "Lock the rules with -e 2 once they load. Changing them afterwards takes a reboot."
}

variable "backlog_limit" {
  type        = number
  default     = 8192
  description = "Audit messages the kernel buffers while auditd catches up (-b)."

  validation {
    condition     = var.backlog_limit >= 1 && floor(var.backlog_limit) == var.backlog_limit
    error_message = "backlog_limit must be a whole number, 1 or more."
  }
}

variable "failure_mode" {
  type        = number
  default     = 1
  description = "What the kernel does when it can't record an event (-f): 0 nothing, 1 logs to the kernel log, 2 panics."

  validation {
    condition     = contains([0, 1, 2], var.failure_mode)
    error_message = "failure_mode must be 0, 1 or 2."
  }
}

variable "auditd_conf" {
  type        = map(string)
  default     = {}
  description = "Settings for /etc/audit/auditd.conf, such as { max_log_file = \"50\", num_logs = \"10\" }. Settings left out keep their current value."

  validation {
    condition     = alltrue([for k, v in var.auditd_conf : can(regex("^[a-z][a-z0-9_]*$", k)) && can(regex("^[^\\n]+$", v))])
    error_message = "auditd_conf keys are auditd.conf setting names, such as max_log_file, and each value is one line."
  }

  validation {
    condition     = alltrue([for k, v in var.auditd_conf : !endswith(k, "_action") || can(regex("(?i)^(ignore|syslog|rotate|keep_logs|suspend|single|halt|email|exec /\\S+)$", v))])
    error_message = "An *_action setting is one of ignore, syslog, rotate, keep_logs, suspend, single, halt, email or exec /path/to/program."
  }
}
