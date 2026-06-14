# cfs

`cfs` is a small learning container runtime written in C. It follows the shape
of Lizzie Dixon's "Linux containers in 500 lines of code" guide, but uses the
cgroup v2 unified hierarchy instead of the guide's cgroup v1 controller
directories.

The program is not production container software. It is a hands-on experiment
for understanding the Linux primitives behind containers:

- namespaces for separate mount, PID, IPC, network, UTS, and user views
- `pivot_root` and bind mounts for switching to a small root filesystem
- Linux capabilities for reducing privileged operations inside the container
- seccomp for blocking selected risky syscalls
- cgroup v2 files for memory, PID, and CPU weighting limits

## Current process flow

At a high level, the parent process prepares the container process, waits for it
to exit, and then cleans up host-side resources.

```text
parse CLI args
validate host kernel and architecture
create socketpair for parent-child setup messages
allocate child stack
clone child with new mount, PID, IPC, network, and UTS namespaces
create /sys/fs/cgroup/contained-<child-pid>
write cgroup v2 limits: memory.max, pids.max, cpu.weight
move child into the cgroup by writing its PID to cgroup.procs
write UID/GID maps for the child's user namespace
child sets hostname, pivots to the requested rootfs, drops capabilities,
  installs seccomp filters, and execs the requested command
parent waits with waitpid
parent removes the cgroup directory
```

The simplest cgroup v2 path is used for now: the child is moved into a cgroup
after `clone()`. The program does not currently try to make the cgroup namespace
view line up with the created cgroup.

There is a small race in this learning version: after `clone()`, the child is
schedulable before the parent has finished creating the cgroup and writing the
child PID to `cgroup.procs`. In practice, the child blocks later during the user
namespace handshake before it reaches `execve()`, so the requested command should
start after the cgroup is ready. Early child setup work, such as hostname and
mount setup, can still run before cgroup placement. A stricter implementation
would add an initial child-start barrier so the parent can finish cgroup setup
before the child performs any setup work.

## Build

Install build dependencies on Debian or Ubuntu:

```sh
sudo apt-get update
sudo apt-get install -y build-essential libcap-dev libseccomp-dev
```

Build the binary:

```sh
make
```

## Create a BusyBox root filesystem for testing

Install static BusyBox:

```sh
sudo apt-get install -y busybox-static
```

Create a minimal root filesystem under `/tmp/rootfs`:

```sh
sudo rm -rf /tmp/rootfs
sudo mkdir -p /tmp/rootfs/bin /tmp/rootfs/proc /tmp/rootfs/sys /tmp/rootfs/dev /tmp/rootfs/tmp
sudo cp /usr/bin/busybox /tmp/rootfs/bin/busybox
sudo ln -s busybox /tmp/rootfs/bin/sh
sudo ln -s busybox /tmp/rootfs/bin/ls
sudo ln -s busybox /tmp/rootfs/bin/cat
sudo ln -s busybox /tmp/rootfs/bin/echo
sudo ln -s busybox /tmp/rootfs/bin/ps
sudo chmod 755 /tmp/rootfs/bin/busybox
```

The static BusyBox binary is useful here because it does not need shared
libraries copied into the test root filesystem.

## Run

Run the container with `/tmp/rootfs` as the new root and BusyBox `sh` as the
initial command:

```sh
sudo ./contained -m /tmp/rootfs -u 1000 -c /bin/sh
```

The program writes cgroup v2 files under `/sys/fs/cgroup`, so it normally needs
root privileges unless you run it inside a delegated cgroup subtree.

Useful checks from inside the shell:

```sh
hostname
echo $$
ls /
cat /proc/self/cgroup
```

If `/proc` is not mounted inside the root filesystem yet, commands that depend
on `/proc` may be limited. The core test is that `/bin/sh` starts inside the
pivoted BusyBox root filesystem.
