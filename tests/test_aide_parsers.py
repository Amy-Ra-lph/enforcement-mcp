"""Tests for AIDE parsers."""

from enforcement_mcp.parsers.aide_cli import parse_aide_check, parse_aide_config


class TestParseAideCheck:
    def test_parses_clean_check(self):
        stdout = """\
AIDE found NO differences between database and filesystem. Looks okay!!

Number of entries:	125432

---------------------------------------------------
The attributes of the (uncompressed) database(s):
---------------------------------------------------

Total number of entries:	125432
"""
        result = parse_aide_check(stdout)
        assert result.added == 0
        assert result.removed == 0
        assert result.changed == 0
        assert result.total_files_checked == 125432

    def test_parses_changes(self):
        stdout = """\
AIDE found differences between database and filesystem!!

Summary:
  Added entries:           2
  Removed entries:         1
  Changed entries:         3

Total number of entries:	50000

---------------------------------------------------
Added entries:
---------------------------------------------------

/etc/new_config.conf
/tmp/suspicious_file

---------------------------------------------------
Removed entries:
---------------------------------------------------

/etc/old_config.conf

---------------------------------------------------
Changed entries:
---------------------------------------------------

/etc/passwd
/etc/shadow
/usr/bin/curl
"""
        result = parse_aide_check(stdout)
        assert result.added == 2
        assert result.removed == 1
        assert result.changed == 3
        assert result.total_files_checked == 50000
        assert len(result.changes) == 6
        assert result.changes[0].path == "/etc/new_config.conf"
        assert result.changes[0].change_type == "added"
        assert result.changes[2].path == "/etc/old_config.conf"
        assert result.changes[2].change_type == "removed"
        assert result.changes[3].path == "/etc/passwd"
        assert result.changes[3].change_type == "changed"

    def test_handles_empty_output(self):
        result = parse_aide_check("")
        assert result.added == 0
        assert result.changes == []


class TestParseAideConfig:
    def test_parses_config(self):
        stdout = """\
# AIDE configuration
database=file:/var/lib/aide/aide.db.gz
database_out=file:/var/lib/aide/aide.db.new.gz

# Custom rules
NORMAL = p+i+n+u+g+s+m+c+acl+selinux+xattrs+sha256
DATAONLY = p+n+u+g+s+acl+selinux+xattrs+sha256

# Watched paths
/boot   NORMAL
/bin    NORMAL
/sbin   NORMAL
/etc    NORMAL
!/etc/mtab
/var/log   DATAONLY
"""
        result = parse_aide_config(stdout)
        assert result.database_path == "file:/var/lib/aide/aide.db.gz"
        assert result.database_out_path == "file:/var/lib/aide/aide.db.new.gz"
        assert len(result.custom_rules) == 2
        assert result.custom_rules[0]["name"] == "NORMAL"
        assert len(result.rules) >= 5
        paths = [r["path"] for r in result.rules]
        assert "/boot" in paths
        assert "!/etc/mtab" in paths

    def test_handles_empty_config(self):
        result = parse_aide_config("")
        assert result.database_path == ""
        assert result.rules == []
