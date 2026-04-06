from collections import Counter
import re

def parse_fail2ban_lines(lines: list[str]):
    bans = []
    for ln in lines:
        if " Ban " in ln:
            m = re.search(r"\[(.*?)\].*Ban\s+(\S+)", ln)
            if m:
                bans.append({"jail": m.group(1), "ip": m.group(2), "raw": ln})
    return bans

def analytics(lines: list[str]):
    bans = parse_fail2ban_lines(lines)
    by_jail = Counter([b["jail"] for b in bans])
    by_ip = Counter([b["ip"] for b in bans])
    return {
        "total_bans": len(bans),
        "top_jails": by_jail.most_common(10),
        "top_ips": by_ip.most_common(25),
    }
