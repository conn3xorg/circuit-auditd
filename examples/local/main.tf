variable "port" {
  type    = number
  default = 2297
}

module "auditd" {
  source = "../.."

  hosts                = { box = "127.0.0.1" }
  ssh_port             = var.port
  ssh_private_key_file = "./id_ed25519"
  ssh_known_hosts_file = "./known_hosts"

  presets = ["11-loginuid", "30-pci-dss-v31"]
  rules   = ["-w /etc/conn3x-test -p wa -k conn3x"]

  auditd_conf = {
    max_log_file        = "50"
    num_logs            = "10"
    max_log_file_action = "ROTATE"
    space_left_action   = "SYSLOG"
  }
}
