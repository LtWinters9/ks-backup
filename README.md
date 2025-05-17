# 🔐 Encrypted Backup Script

This Bash script automates the process of securely backing up critical directories, encrypting the archive, and distributing it to multiple destinations with retention and cleanup policies.

## ✅ Features

- **Backup Sources**: `/var/www`, `/etc/caddy`, `/var/log/caddy`, `/var/log/`
- **Destinations**: `/mnt/nfs/primary`, `/mnt/nfs/secondary`
- **Encryption**: AES-128-CBC with PBKDF2 and SHA-3-256 hashed key
- **Retention Policy**: Deletes backups older than 60 days
- **Logging**: Logs success/failure of backup transfers
- **Safety Checks**: Verifies disk space before copying
- **Cleanup**: Removes temporary files after completion

## 🧩 Script Workflow

1. **Setup**: Creates and secures necessary directories
2. **Compression**: Archives source directories into a `.tar.gz` file
3. **Encryption**: Encrypts the archive using OpenSSL
4. **Disk Check**: Ensures enough space is available at destinations
5. **Copy**: Transfers encrypted backup to all destinations
6. **Cleanup**: Deletes temporary files
7. **Retention**: Removes old backups based on defined policy

## 🛡️ Security

- Uses a hashed encryption key stored securely in `/etc/backups/encryption_key.txt`
- Encrypted backups are stored with `.tar.gz.enc` extension

## 📌 Usage

Run the script manually or schedule it via `cron` for automated backups.
