# NodeWarden → 坚果云自动备份

已按以下要求预设：

- 每天 **上海时间 06:00**
- **最多保留 60 份**
- **包含附件**
- 备份名格式：`nodewarden_backup_YYYYMMDDHHMM.zip`

## 需要放到 GitHub 仓库的文件

- `.github/workflows/backup-to-jianguoyun.yml`
- `scripts/nodewarden_backup_to_webdav.py`

## 需要配置的 GitHub Secrets

- `NODEWARDEN_BASE_URL`
- `NODEWARDEN_EMAIL`
- `NODEWARDEN_MASTER_PASSWORD`
- `JIANGUOYUN_WEBDAV_USERNAME`
- `JIANGUOYUN_WEBDAV_PASSWORD`

## 当前工作流说明

- GitHub Actions 的 `cron` 用 **UTC**
- `0 22 * * *` = **每天 UTC 22:00**
- 对应 **上海时间次日 06:00**

## 备注

- WebDAV 目录默认：`nodewarden/github-actions`
- 坚果云地址默认：`https://dav.jianguoyun.com/dav`
- 时区默认：`Asia/Shanghai`
