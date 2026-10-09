"""Parse ausearch output for AVC and FANOTIFY events."""

import re


def parse_avc_denials(raw: str) -> list[dict]:
    """Parse ausearch -m AVC output into structured denials."""
    if not raw.strip() or "no matches" in raw.lower() or "<no matches>" in raw:
        return []

    denials = []
    current_time = ""

    for line in raw.split("\n"):
        line = line.strip()

        if line.startswith("time->"):
            current_time = line[6:].strip()
            continue

        if "type=AVC" not in line or "avc:  denied" not in line:
            continue

        denial: dict = {"timestamp": current_time}

        perms = re.search(r"denied\s+\{\s*([^}]+)\}", line)
        if perms:
            perm_list = perms.group(1).strip().split()
            denial["permission"] = perm_list[0] if len(perm_list) == 1 else perm_list
            denial["permissions"] = perm_list

        pid_match = re.search(r"pid=(\d+)", line)
        if pid_match:
            denial["pid"] = int(pid_match.group(1))

        comm_match = re.search(r'comm="([^"]+)"', line)
        if comm_match:
            denial["comm"] = comm_match.group(1)

        name_match = re.search(r'name="([^"]+)"', line)
        if name_match:
            denial["target_name"] = name_match.group(1)

        path_match = re.search(r'path="([^"]+)"', line)
        if path_match:
            denial["path"] = path_match.group(1)

        scontext = re.search(r"scontext=(\S+)", line)
        if scontext:
            parts = scontext.group(1).split(":")
            denial["source_context"] = scontext.group(1)
            if len(parts) >= 3:
                denial["source_type"] = parts[2]

        tcontext = re.search(r"tcontext=(\S+)", line)
        if tcontext:
            parts = tcontext.group(1).split(":")
            denial["target_context"] = tcontext.group(1)
            if len(parts) >= 3:
                denial["target_type"] = parts[2]

        tclass = re.search(r"tclass=(\S+)", line)
        if tclass:
            denial["tclass"] = tclass.group(1)

        perm_match = re.search(r"permissive=(\d)", line)
        if perm_match:
            denial["permissive"] = perm_match.group(1) == "1"

        denials.append(denial)

    return denials


def parse_fanotify_denials(raw: str) -> list[dict]:
    """Parse ausearch -m FANOTIFY output into structured denials."""
    if not raw.strip() or "no matches" in raw.lower() or "<no matches>" in raw:
        return []

    denials = []
    current_time = ""

    for line in raw.split("\n"):
        line = line.strip()

        if line.startswith("time->"):
            current_time = line[6:].strip()
            continue

        if "type=FANOTIFY" not in line:
            continue

        denial: dict = {"timestamp": current_time}

        resp_match = re.search(r"resp=(\d+)", line)
        if resp_match:
            resp = int(resp_match.group(1))
            denial["response"] = resp
            denial["decision"] = "deny" if resp == 2 else "allow"

        pid_match = re.search(r"pid=(\d+)", line)
        if pid_match:
            denial["pid"] = int(pid_match.group(1))

        uid_match = re.search(r"uid=(\d+)", line)
        if uid_match:
            denial["uid"] = int(uid_match.group(1))

        exe_match = re.search(r'exe="([^"]+)"', line)
        if exe_match:
            denial["exe"] = exe_match.group(1)

        subj_match = re.search(r"subj=(\S+)", line)
        if subj_match:
            denial["subject_context"] = subj_match.group(1)

        trust_match = re.search(r"obj_trust=(\d+)", line)
        if trust_match:
            denial["obj_trust"] = int(trust_match.group(1))

        denials.append(denial)

    return denials
