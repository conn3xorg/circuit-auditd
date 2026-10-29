# circuit-auditd

A Conn3x circuit that installs the Linux audit daemon and keeps its rules the way you wrote them. The kernel's audit system records who touched what: a change to `/etc/sudoers`, a module loaded at 3 a.m., a file read by someone who shouldn't have. auditd writes those events to `/var/log/audit/audit.log`, and `ausearch` finds them again when you need to know what happened.

You pick from the rule sets the audit package itself ships, such as PCI DSS or the STIG, add rules of your own, and the circuit writes them to `/etc/audit/rules.d` and loads them on Debian, Ubuntu, Fedora and Rocky Linux alike. If the kernel turns a rule down, the apply fails and the rules that ran before go back in, so a typo never leaves a host half-audited.

## Usage

```hcl
module "auditd" {
  source = "github.com/conn3xorg/circuit-auditd?ref=v0.1.0"

  hosts                = { web1 = "203.0.113.10", web2 = "203.0.113.11" }
  ssh_private_key_file = "~/.ssh/id_ed25519"

  presets = ["11-loginuid", "30-pci-dss-v31"]
  rules = [
    "-w /etc/nginx/ -p wa -k nginx-config",
    "-a always,exit -F arch=b64 -S init_module,finit_module -k modules",
  ]

  auditd_conf = {
    max_log_file        = "50"
    num_logs            = "10"
    max_log_file_action = "ROTATE"
  }
}
```

Then run `conn3x init` and `conn3x apply`. A second `conn3x plan` says `No changes.` To see what a rule caught:

```sh
ssh root@203.0.113.10 'auditctl -l; ausearch -k nginx-config -i'
```

For hosts created in the same plan, pass host objects with the host key you generated, so Conn3x checks it without a known_hosts entry. Give each one's distribution in `os` too: the circuit picks its package by distribution, and Conn3x can't ask a host that doesn't exist yet. If `os` turns out not to match the host, Conn3x stops before configuring it. Set `os` as well when you put `depends_on` on this module: `depends_on` holds back reading the hosts until the apply, so without `os` the plan fails with `Invalid for_each argument`.

```hcl
hosts = {
  for name, d in digitalocean_droplet.web : name => {
    address  = d.ipv4_address
    host_key = tls_private_key.host[name].public_key_openssh
    os       = "ubuntu"
  }
}
```

To try it on a throwaway container first, see [examples/local](examples/local). A container can't load audit rules, so that shows you the files, not the events.

## Presets

The audit package ships a folder of sample rule files, each a piece of a policy, and `presets` copies the ones you name into `/etc/audit/rules.d`. You name them as the files are named, without `.rules`. Every supported distribution has these:

| Preset | What it records |
| --- | --- |
| `10-base-config` | Nothing on its own: buffer size and failure mode. The circuit sets those already, so you don't need it. |
| `10-no-audit` | Turns syscall auditing off. Don't mix it with anything else. |
| `11-loginuid` | Makes the login ID immutable, so a process can't pass itself off as another user. |
| `12-cont-fail`, `12-ignore-error` | Have `auditctl` carry on past a rule it can't load. See [Checking rules](#checking-rules). |
| `20-dont-audit` | Examples of rules that leave events out, all commented out. |
| `21-no32bit` | Any 32-bit syscall on a 64-bit host, which can be a sign of someone exploiting the 32-bit ABI. |
| `22-ignore-chrony`, `23-ignore-filesystems` | Leave out chrony's clock updates, and events from tracefs and debugfs. |
| `30-pci-dss-v31` | PCI DSS 3.1, section 10. |
| `30-stig` | The DISA STIG's audit rules. |
| `30-ospp-v42` and its `30-ospp-v42-*` parts | The Common Criteria OSPP 4.2 rules. |
| `31-privileged` | Commented-out commands that generate rules for each setuid program on a host. On its own, it loads nothing. |
| `32-power-abuse` | Root reading files in users' home folders. |
| `40-local` | An empty file for your own rules. Use `rules` instead. |
| `41-containers`, `42-injection`, `43-module-load`, `44-installers` | Namespace changes from container tools, `ptrace` injection, kernel modules loading and unloading, and package managers such as `dnf`, `pip` and `npm` running. |
| `70-einval` | Syscalls that fail with `EINVAL`, for finding badly written programs. The sample itself says it's not for production. |
| `71-networking` | Every `accept` and `connect`, so every network connection in or out. |
| `99-finalize` | `-e 2`, commented out. Use `immutable` instead. |

Ubuntu 24.04's audit 3.1 also has `30-nispom`; Debian 13, Fedora and Rocky Linux, on audit 4, don't. Naming a preset a host's package doesn't have fails the apply on that host.

The samples are written for a typical Red Hat host on x86_64. On Debian and Ubuntu, `30-stig` watches `/etc/NetworkManager/`, which a server there usually doesn't have, and the kernel turns that rule down; `30-nispom` failed the same way on Ubuntu 24.04. The samples' own README warns that not every architecture has the same syscalls: arm64 has no `open`, which `30-stig` names. For those hosts, put the rules you want in `rules`, or copy the sample and fix it up there.

Each copy starts with a line saying Conn3x copied it, and the circuit compares it with the sample on every plan. When a package upgrade changes the sample, the next apply copies it again. Remove a name from `presets` and the next apply deletes the copy. Files in `/etc/audit/rules.d` without that line, such as ones you or another tool wrote, are left alone and still load.

## Immutable rules

With `immutable = true`, the rules end with `-e 2`. Once that loads, the kernel refuses every change to the audit rules, from anyone, root included, until the next boot. An attacker who gets root can't switch auditing off quietly. Neither can you.

> **With `immutable` on, a change to the rules needs a reboot.** The apply writes the new files and says the rules are locked. The host keeps running the old rules, and a second plan has nothing to do, so nothing reminds you. The new rules load at the next boot. Turning `immutable` off works the same way: it takes effect after a reboot.

## Checking rules

There's no dry run for audit rules. `auditctl` checks the syntax, but the kernel decides whether it takes a rule: it turns down a watch on a folder that doesn't exist, a syscall the architecture doesn't have, or a rule that's already loaded. The only way to find out is to load it.

So the circuit loads them, with `augenrules --load`, and checks the result. `auditctl` stops at the first rule the kernel won't take, which leaves the rules before it loaded and the rest missing. When that happens, the circuit puts back the rules that ran before, fails the apply, and shows you the error with the line it's on:

```
Error: command failed with exit status 1: Error sending add rule data request (No such file or directory)
There was an error in line 34 of /etc/audit/audit.rules
The kernel rejected a rule, so the previous rules were loaded again.
```

The line number is in `/etc/audit/audit.rules`, the file `augenrules` builds from `rules.d`. The bad rule is still in `rules.d`, so fix it or take it out and apply again. Until you do, the host runs its previous rules, and a reboot would load everything up to the bad one.

`12-cont-fail` has `auditctl` carry on past a bad rule, but it still exits with an error, so the apply still fails and puts the old rules back. `12-ignore-error` has it carry on and exit with success, so the apply passes with every rule but the bad ones loaded. Use it only if that's what you want.

## With circuit-hardening and circuit-openscap

circuit-hardening leaves auditd alone on purpose. Use both, in any order.

circuit-openscap's remediation, with a CIS or STIG profile, adds audit rules of its own in `/etc/audit/rules.d` and sets values in `/etc/audit/auditd.conf`. This circuit leaves other tools' rule files where they are and only touches the `auditd.conf` settings you put in `auditd_conf`, so the two can share a host. Two things to watch:

- A rule that's loaded twice is one the kernel turns down. If a preset and OpenSCAP's remediation add the same rule, the load fails. Pick one owner for the benchmark's rules: either let OpenSCAP remediate them and keep `presets` empty, using `rules` only for your own, or use a preset and leave OpenSCAP's audit rules out with its `skip_rules`.
- A setting in `auditd_conf` wins over OpenSCAP's on every apply, and the next scan flags it if it isn't what the profile wants. Leave a setting out of `auditd_conf` to let OpenSCAP set it, or give it the value the profile expects, such as `max_log_file_action = "keep_logs"` for the STIG.

If remediation edits one of this circuit's own files, the next apply writes it back.

## What it does

On each host, in order:

1. Installs `auditd` on Debian and Ubuntu, or `audit` on the Red Hat family.
2. On Debian and Ubuntu, if there are presets and the host has no sample rules in `/usr/share/doc`, downloads the auditd package file once and unpacks its samples to `/var/lib/conn3x-auditd/samples`. Some images, such as Ubuntu's container image, leave out `/usr/share/doc`.
3. Sets each setting in `auditd_conf` in `/etc/audit/auditd.conf`, one line per setting, and leaves the rest of the file alone.
4. Writes `/etc/audit/rules.d/audit.rules` with `-D`, `-b`, `--backlog_wait_time 60000` and `-f`. That replaces the distribution's own file, which has the same lines everywhere except Fedora, where it turns syscall auditing off.
5. Writes your `rules`, and `-e 2` if `immutable` is on, to `/etc/audit/rules.d/50-conn3x.rules`.
6. Copies each preset from the package's samples to `/etc/audit/rules.d/<name>.rules`, and deletes copies it made earlier that are no longer in `presets`.
7. Turns auditd on at boot and starts it.
8. When `auditd_conf` changed, has auditd read its configuration again with `auditctl --signal reload`.
9. When any rule file changed, loads the rules with `augenrules --load`, as in [Checking rules](#checking-rules).

The rules files are mode `0600`, owned by root.

auditd can't be restarted the usual way on the Red Hat family: its unit refuses a manual stop, so `systemctl restart auditd` fails. That's why the circuit reloads it with a signal and loads rules with `augenrules` instead of using a handler.

At boot, the distribution loads the rules the same way: `augenrules --load` runs from `audit-rules.service` on audit 4, or from `auditd.service` on Ubuntu 24.04's audit 3.1.

### In a container

The kernel only takes audit control messages from the host's initial PID namespace, so auditd can't start in a container and rules can't load there. When the host is a container, the circuit installs auditd, writes every file, enables auditd and runs `augenrules` to build `/etc/audit/audit.rules`, then stops. Nothing loads and auditd doesn't run. That's what CI tests.

### What it doesn't do

- It doesn't send events anywhere else. auditd's plugins, such as `audisp-remote` and the syslog plugin in `audispd-plugins`, aren't set up.
- It doesn't check that an `auditd_conf` setting makes sense beyond its shape. A setting auditd doesn't understand is logged by auditd on reload, not reported by the apply.
- It doesn't rotate or ship the log. auditd rotates it itself, by `max_log_file` and `num_logs`.
- It doesn't generate `31-privileged`'s list of setuid programs for each host.
- Deleting the module leaves auditd installed and running with the last rules.

## Inputs

| Name | Type | Default | Description |
| --- | --- | --- | --- |
| `hosts` | any | Required | Hosts to configure, by name. Each value is an address, such as `"203.0.113.10"`, or a host object such as `{ address = "203.0.113.10", host_key = "ssh-ed25519 AAAA..." }`. A host object can also set `user`, `port`, `private_key_file`, `jump_hosts` and `os`, the distribution's ID, such as `ubuntu` or `rocky`, which a host created in the same plan needs. The two forms can be mixed. |
| `ssh_user` | string | `"root"` | User to log in as. |
| `ssh_port` | number | `22` | SSH port. |
| `ssh_private_key_file` | string | `null` | Path to a private key. When null, Conn3x uses the SSH agent. |
| `ssh_known_hosts_file` | string | `null` | known_hosts file to check host keys against. When null, `~/.ssh/known_hosts`. Not used for a host object with `host_key`. |
| `ssh_become` | bool | `false` | Run commands as root through sudo. Set it when `ssh_user` isn't root. |
| `presets` | list(string) | `[]` | Sample rule files to copy, by name without `.rules`, such as `["11-loginuid", "30-pci-dss-v31"]`. See [Presets](#presets). |
| `rules` | list(string) | `[]` | Your own rules, one per item in `auditctl` syntax, such as `"-w /etc/sudoers -p wa -k sudoers"`. `-e`, `-D`, `-b`, `-f` and `--backlog_wait_time` aren't allowed here; the inputs below set them. |
| `immutable` | bool | `false` | Lock the rules with `-e 2` once they load. Changing them afterwards takes a reboot. See [Immutable rules](#immutable-rules). |
| `backlog_limit` | number | `8192` | Events the kernel holds while auditd catches up, `-b`. Raise it on a busy host if `auditctl -s` shows `lost` going up. |
| `failure_mode` | number | `1` | What the kernel does when it can't record an event, `-f`: `0` nothing, `1` writes to the kernel log, `2` panics the host. |
| `auditd_conf` | map(string) | `{}` | Settings for `/etc/audit/auditd.conf`, such as `{ max_log_file = "50", space_left_action = "SYSLOG" }`. Settings left out keep their current value. An `*_action` setting must be one of `ignore`, `syslog`, `rotate`, `keep_logs`, `suspend`, `single`, `halt`, `email` or `exec /path`. |

## Outputs

| Name | Description |
| --- | --- |
| `rules_files` | Paths of the rule files the circuit writes on each host, such as `["/etc/audit/rules.d/audit.rules", "/etc/audit/rules.d/50-conn3x.rules", "/etc/audit/rules.d/30-pci-dss-v31.rules"]`. |

## Requirements

Requires Conn3x v0.6.9 or later and systemd on each host, with a package mirror the host can reach. The kernel must have auditing on, which it does unless it booted with `audit=0`.

## Tested on

Ubuntu 24.04, Debian 13, Fedora 45 and Rocky Linux 10. CI applies [examples/local](examples/local) to each in a container on amd64 and checks that the second plan has no changes. Containers can't load audit rules, so CI checks what a container can: the `auditd.conf` settings, the copied presets, the rules `augenrules` builds from them with `-D` first and Fedora's `-a task,never` gone, and that auditd is enabled.

Loading was tested by hand on Ubuntu 24.04, Debian 13, Rocky Linux 10 (SELinux enforcing) and Fedora 44 droplets, amd64, with `11-loginuid`, `30-pci-dss-v31` and the watch `-w /etc/conn3x-test -p wa -k conn3x`. On each, `auditctl -l` listed the rules, touching `/etc/conn3x-test` left an event `ausearch -k conn3x` found, the `auditd.conf` reload showed up as a `DAEMON_CONFIG` success in the audit log, and the second plan had no changes. After a reboot, the rules were loaded again and the plan still had no changes. With `immutable = true`, `auditctl -s` showed `enabled 2`; adding a rule then applied cleanly, left the old rules running, and the new rule was loaded after a reboot. A watch on a folder that doesn't exist failed the apply on all four, and each was back on its previous rules. Rocky Linux and Fedora logged no SELinux denials. `30-stig` loaded on Rocky Linux and Fedora and was turned down on Debian and Ubuntu, as in [Presets](#presets).

## License

MPL-2.0. See [LICENSE](LICENSE). The Linux audit userspace and its sample rules are GPL-2.0-or-later; the circuit copies the samples from each host's own package and doesn't ship them.
