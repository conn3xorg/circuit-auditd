# Local example

Applies circuit-auditd to a throwaway Rocky Linux 10 container with systemd, with the `11-loginuid` and `30-pci-dss-v31` presets, a watch on `/etc/conn3x-test` and a few `auditd.conf` settings. You need Conn3x and Podman.

A container can't load audit rules or run auditd: the kernel only takes those from the host's initial PID namespace. So here the circuit installs auditd, writes every file and builds `/etc/audit/audit.rules`, and stops there. It's for seeing what the circuit writes. To see events, apply the same module to a VM or a server.

```sh
./up.sh
conn3x init
conn3x apply
conn3x plan
```

The second plan says `No changes.` To look at the result:

```sh
ssh -p 2297 -i id_ed25519 -o UserKnownHostsFile=known_hosts root@127.0.0.1 'ls /etc/audit/rules.d; cat /etc/audit/audit.rules'
```

`check.sh` runs the checks CI runs. It works on a real host too, where it also checks the rules are loaded and that touching `/etc/conn3x-test` leaves an event:

```sh
podman exec -i circuit-auditd sh < check.sh
```

`up.sh` listens on `127.0.0.1:2297`. Set `PORT` to use another port, and pass the same port to Conn3x with `-var port=PORT`. Set `CONTAINERFILE` to test another distro, such as one of the images in Conn3x's `test/images`, which CI uses. On a Mac, rootful Podman is simplest: `export CONTAINER_CONNECTION=podman-machine-default-root`.

`./down.sh` removes the container, its volumes, the key and the state.
