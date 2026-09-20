# uninstall.ps1 — 卸载三合一自动签到的两个计划任务
# 用法：powershell -ExecutionPolicy Bypass -File .\uninstall.ps1

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "三合一自动签到 · 卸载" -ForegroundColor Cyan
Write-Host ("-" * 30) -ForegroundColor DarkGray

foreach ($name in @("AutoCheckinBoot", "AutoCheckinDaily")) {
    Write-Host ("删除 {0} ..." -f $name) -NoNewline
    try {
        Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop
        Write-Host " 完成" -ForegroundColor Green
    } catch {
        Write-Host " 不存在或已删除" -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "计划任务已清除。脚本与日志仍保留在本目录，可手动删除整个文件夹。" -ForegroundColor Cyan
Write-Host ""
