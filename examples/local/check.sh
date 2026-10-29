#!/bin/sh
# Checks the example on its host: run it there, such as with
# podman exec -i circuit-auditd sh < check.sh, or over ssh on a real host.
# A container can't load audit rules, so there it checks the files and the
# rules augenrules put together. On a real host it also checks the rules
# are loaded and that touching the watched file leaves an event.
set -eu
grep -qx 'max_log_file = 50' /etc/audit/auditd.conf
grep -qx 'num_logs = 10' /etc/audit/auditd.conf
for f in 11-loginuid 30-pci-dss-v31; do
  head -n 1 /etc/audit/rules.d/$f.rules | grep -q 'Copied by Conn3x'
done
rules=/etc/audit/audit.rules
[ "$(sed -n 2p $rules)" = -D ]
grep -qx -- '-w /etc/conn3x-test -p wa -k conn3x' $rules
grep -qx -- '--loginuid-immutable' $rules
grep -q '10.2.2-priv-config-changes' $rules
# Fedora's own audit.rules turns off syscall auditing; the circuit's
# replaces it.
! grep -qx -- '-a task,never' $rules
systemctl is-enabled -q auditd

if systemd-detect-virt -cq; then
  echo "Files check out. This is a container, so no rules were loaded."
  exit 0
fi

systemctl is-active -q auditd
auditctl -l | grep -qx -- '-w /etc/conn3x-test -p wa -k conn3x'
touch /etc/conn3x-test
sleep 1
# --input-logs reads the log files even when stdin isn't a terminal.
ausearch --input-logs -k conn3x -i | grep -q 'name=/etc/conn3x-test'
echo "Rules loaded ($(auditctl -l | wc -l)), and the watch saw /etc/conn3x-test change."
