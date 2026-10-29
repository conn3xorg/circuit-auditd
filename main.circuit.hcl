# Facts give each host's family, which picks the package: auditd on Debian
# and Ubuntu, audit on the Red Hat family.
data "conn3x_host" "facts" {
  for_each = var.hosts

  ssh {
    host             = try(each.value.address, each.value)
    host_key         = try(each.value.host_key, null)
    user             = try(each.value.user, var.ssh_user)
    port             = try(each.value.port, var.ssh_port)
    private_key_file = try(each.value.private_key_file, var.ssh_private_key_file)
    jump_hosts       = try(each.value.jump_hosts, null)
    known_hosts_file = var.ssh_known_hosts_file
  }

  lifecycle {
    postcondition {
      condition     = try(each.value.os, self.os_id) == self.os_id
      error_message = "Host ${each.key} is ${self.os_id}, not the ${try(each.value.os, "")} its os says."
    }
  }
}

locals {
  # A host object's os stands in for the facts of a host created in the
  # same plan, which can't be read until it exists.
  os     = { for name, h in var.hosts : name => try(h.os, data.conn3x_host.facts[name].os_id) }
  debian = { for name, o in local.os : name => contains(["debian", "ubuntu"], o) }

  # Debian and Ubuntu ship the sample rules as documentation, in a folder
  # whose name changed with audit 4. The Red Hat family ships them in the
  # audit-rules package. The last folder is where the circuit unpacks them
  # on hosts that leave out /usr/share/doc.
  sample_dirs = "/usr/share/audit-rules /usr/share/doc/auditd/examples/audit-rules /usr/share/doc/auditd/examples/rules /var/lib/conn3x-auditd/samples"
  marker      = "## Copied by Conn3x from the audit sample rules. Changes here are overwritten on the next apply."
  rules_dir   = "/etc/audit/rules.d"
  find_sample = "src=$(for d in ${local.sample_dirs}; do [ -f \"$d/%[1]s.rules\" ] && echo \"$d/%[1]s.rules\" && break; done)"

  header = "## Written by Conn3x. Changes here are overwritten on the next apply.\n"

  # augenrules puts the last -D, -b and -f it reads at the top, whatever
  # file they come from. audit.rules sorts after the numbered files, so
  # these win over a preset such as 10-base-config.
  base_rules = <<-EOT
    ${trimspace(local.header)}
    -D
    -b ${var.backlog_limit}
    --backlog_wait_time 60000
    -f ${var.failure_mode}
  EOT

  custom_rules = join("", concat(
    [local.header],
    [for r in var.rules : "${r}\n"],
    var.immutable ? ["## No rule changes until the next boot.\n-e 2\n"] : [],
  ))

  sample_hosts = { for name, h in var.hosts : name => h if local.debian[name] && length(var.presets) > 0 }

  # Lists the files this circuit copied earlier that are no longer in
  # presets. The /dev/null pattern keeps grep valid with no presets.
  stale = "grep -l -x -F '${local.marker}' ${local.rules_dir}/*.rules 2>/dev/null | grep -v -x -F -e /dev/null ${join(" ", [for p in var.presets : "-e ${local.rules_dir}/${p}.rules"])}"
}

circuit "auditd" {
  hosts = var.hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  step "package" {
    package {
      name = local.debian[each.key] ? "auditd" : "audit"
    }
  }

  # Only the keys in auditd_conf. The rest keep the distribution's values,
  # or whatever another tool, such as an OpenSCAP remediation, set.
  step "settings" {
    for_each = var.auditd_conf
    line {
      path   = "/etc/audit/auditd.conf"
      regexp = "^\\s*${item.key}\\s*="
      line   = "${item.key} = ${item.value}"
    }
  }

  # Replaces the distribution's own audit.rules. Fedora's turns off
  # syscall auditing for every process, which no watch survives.
  step "base" {
    file {
      path    = "${local.rules_dir}/audit.rules"
      content = local.base_rules
      mode    = "0600"
    }
  }

  step "rules" {
    file {
      path    = "${local.rules_dir}/50-conn3x.rules"
      content = local.custom_rules
      mode    = "0600"
    }
  }

  # The copy carries a marker line, so a later apply can tell it from files
  # other tools write here and remove it when it leaves presets. It follows
  # the package: an upgrade that changes the sample is copied again.
  step "presets" {
    for_each   = toset(var.presets)
    depends_on = [conn3x_command.samples__fetch]
    command {
      command = "${format(local.find_sample, item.value)}; [ -n \"$src\" ] || { echo \"This host's audit package has no ${item.value}.rules sample.\" >&2; exit 1; }; umask 077 && { echo '${local.marker}'; cat \"$src\"; } > ${local.rules_dir}/${item.value}.rules.tmp && mv ${local.rules_dir}/${item.value}.rules.tmp ${local.rules_dir}/${item.value}.rules"
      unless  = "${format(local.find_sample, item.value)}; [ -n \"$src\" ] && { echo '${local.marker}'; cat \"$src\"; } | cmp -s - ${local.rules_dir}/${item.value}.rules"
    }
  }

  step "prune" {
    command {
      command = "${local.stale} | xargs -r rm -f"
      unless  = "[ -z \"$(${local.stale})\" ]"
    }
  }

  step "enabled" {
    service {
      name    = "auditd"
      enabled = true
    }
  }

  # The kernel only takes audit control messages from the host's first PID
  # namespace, so in a container auditd can't start and rules can't load.
  # There the circuit stops once the files are written.
  step "running" {
    command {
      command = "systemctl start auditd"
      unless  = "systemd-detect-virt -cq || systemctl is-active -q auditd"
    }
  }

  # auditd.service refuses a manual stop on the Red Hat family, so neither
  # a restart nor a handler works there. SIGHUP has auditd read
  # auditd.conf again.
  step "reload" {
    command {
      command  = "systemd-detect-virt -cq || auditctl --signal reload"
      triggers = { for k, v in var.auditd_conf : k => conn3x_line.auditd__settings["${each.key}/${k}"].revision }
    }
  }

  # augenrules joins rules.d into /etc/audit/audit.rules, which is what
  # loads at boot, then loads it. There is no dry run: the kernel checks
  # each rule as it's added, and auditctl stops at the first it rejects.
  # When that happens, the rules that ran before go back in, so the host
  # isn't left with half a policy, and the apply fails. Once -e 2 has
  # locked the rules, nothing loads: the new ones wait for the next boot,
  # when augenrules joins rules.d again.
  step "load" {
    command {
      command = "if systemd-detect-virt -cq; then exec augenrules; fi; if [ \"$(auditctl -s | awk '$1 == \"enabled\" { print $2 }')\" = 2 ]; then echo 'The rules are locked until the next boot, which loads the new ones.'; exit 0; fi; cp -p /etc/audit/audit.rules /run/conn3x-audit.rules; augenrules --load && exit 0; cp -p /run/conn3x-audit.rules /etc/audit/audit.rules; auditctl -R /etc/audit/audit.rules >/dev/null 2>&1; echo 'The kernel rejected a rule, so the previous rules were loaded again.' >&2; exit 1"
      triggers = {
        base    = conn3x_file.auditd__base[each.key].revision
        rules   = conn3x_file.auditd__rules[each.key].revision
        presets = join(",", [for p in var.presets : conn3x_command.auditd__presets["${each.key}/${p}"].revision])
        prune   = conn3x_command.auditd__prune[each.key].revision
      }
    }
  }
}

# On Debian and Ubuntu, images that drop /usr/share/doc, such as Ubuntu's
# container image, have no sample rules. They come from the package file
# instead, once.
circuit "samples" {
  hosts = local.sample_hosts

  ssh {
    user             = var.ssh_user
    port             = var.ssh_port
    private_key_file = var.ssh_private_key_file
    known_hosts_file = var.ssh_known_hosts_file
    become           = var.ssh_become
  }

  # shortcut: the unpacked copy isn't refreshed when auditd is upgraded;
  # delete /var/lib/conn3x-auditd/samples to fetch it again.
  step "fetch" {
    depends_on = [conn3x_package.auditd__package]
    command {
      command = "d=$(mktemp -d) && cd \"$d\" && apt-get download -q auditd && dpkg-deb -x auditd_*.deb x && mkdir -p /var/lib/conn3x-auditd/samples && cp x/usr/share/doc/auditd/examples/*/*.rules /var/lib/conn3x-auditd/samples/; rc=$?; rm -rf \"$d\"; exit $rc"
      unless  = "ls /usr/share/doc/auditd/examples/*/*.rules >/dev/null 2>&1 || ls /var/lib/conn3x-auditd/samples/*.rules >/dev/null 2>&1"
    }
  }
}
