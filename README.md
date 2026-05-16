# NFS Backup & Restore

Scripts for creating encrypted compressed backups to NFS storage and restoring from them. Backups are AES-256 encrypted, tiered by age, and copied to one or more NFS mount points.

---

## Scripts

| Script | Purpose |
|--------|---------|
| `nfs.sh` | Create, encrypt, and copy backups; apply retention policy |
| `restore.sh` | Decrypt and extract a backup interactively |

---

## Prerequisites

- Run as **root**
- NFS destinations mounted (default: `/mnt/kp/kefs1/`)
- Required commands: `tar`, `openssl`, `rsync`, `mountpoint`, `find`, `awk`, `mktemp`
- Optional: `ionice`, `nice` (used automatically to reduce I/O priority)
- `.env` file at `/etc/backups/.env`

---

## Configuration

### `/etc/backups/.env`

```bash
# Preferred — key file
ENCRYPTION_KEY_FILE=/etc/backups/key

# Fallback — inline key (key file takes precedence)
ENCRYPTION_KEY=your-passphrase-here
```

Generate a key file:
```bash
mkdir -p /etc/backups
openssl rand -base64 48 > /etc/backups/key
chmod 600 /etc/backups/key
```

### Defaults (in `nfs.sh`)

| Setting | Default |
|---------|---------|
| Source dirs | `/var/www`, `/etc/caddy`, `/var/log/`, `/opt/` |
| Destination | `/mnt/katapult/kefs1/backups/` |
| Encryption | AES-256-CBC |
| Recent retention | 60 days — keep every backup |
| Mid retention | 150 days — keep one per day |
| Full retention | 180 days — keep one per week; purge older |

---

## Usage

### Create a Backup

```bash
sudo ./nfs.sh
```

**Common flags:**

| Flag | Description |
|------|-------------|
| `--dry-run` | Simulate — no files written or deleted |
| `--no-retention` | Skip the retention/cleanup step |
| `--retention-only` | Run retention cleanup only; no new backup |
| `--syslog` | Also send log output to `logger` |
| `--dest "D1 D2"` | Override destination dirs (space-separated, quoted) |
| `--sources "S1 S2"` | Override source dirs (space-separated, quoted) |
| `--key-file PATH` | Override encryption key file path |
| `--log-file PATH` | Override log file path |

**Examples:**

```bash
# Dry run to verify what would happen
sudo ./nfs.sh --dry-run

# Custom destination
sudo ./nfs.sh --dest "/mnt/backup1 /mnt/backup2"

# Retention cleanup only
sudo ./nfs.sh --retention-only
```

---

### Restore a Backup

```bash
sudo ./restore.sh
```

The script interactively:
1. Scans configured NFS roots for available backups
2. Presents a menu to select a backup file
3. Decrypts and extracts to a chosen directory

**Common flags:**

| Flag | Description |
|------|-------------|
| `--dry-run` | Simulate restore without extracting |
| `--force` | Skip overwrite confirmations |
| `--verify-only` | Decrypt and verify integrity without extracting |

---

## Logs

| Script | Log file |
|--------|----------|
| `nfs.sh` | `/var/log/backup.log` |
| `restore.sh` | `/var/log/restore.log` |

Backup logs are rotated daily, keeping the last 5 rotations.

---

## Cron Example

Run a backup daily at 2 AM:

```bash
0 2 * * * root /path/to/scripts/backups/master/nfs.sh --syslog >> /var/log/backup-cron.log 2>&1
```
