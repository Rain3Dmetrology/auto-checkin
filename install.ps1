# install.ps1 — 三合一自动签到一键安装（Windows 计划任务）
#
# 整合 88lin/workbuddy-auto-signin 的安装逻辑（MIT），统一调度
# WorkBuddy + Trae + Qoder CN 三个签到脚本。
#
# 用法：在本目录下，用 PowerShell 运行
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
#
# 创建两个计划任务（全部静默、无窗口、错过自动补跑）：
#   AutoCheckinBoot   用户登录后 90 秒    开机即签（等网络就绪）
#   AutoCheckinDaily  每天 00:23 / 08:07 / 12:37 / 19:07 / 22:37（随机延迟数分钟错峰）
#
# 说明：
#   - 00:23 是 Trae 的最佳签到窗口（避开 00:00-00:10 整点排队限流高峰）
#   - 后续时间点为补签兜底：三个签到全部幂等（已签自动跳过，零多余请求）
#   - 必须以当前用户身份运行（DPAPI 解密 Qoder 凭据依赖用户上下文）

$ErrorActionPreference = "Stop"

# ====== 一般不用改；自动探测失败时手动填这两个 ======
$ManualPythonw = ""   # 例如 C:\Python313\pythonw.exe
$ManualRunAll  = ""   # 例如 C:\Users\You\auto-checkin\run_all.py
# ====================================================

function Find-Pythonw {
    # 1) PATH 里就有 pythonw
    $c = (Get-Command pythonw -ErrorAction SilentlyContinue).Source
    if ($c -and (Test-Path $c)) { return $c }

    # 2) PATH 里有 python.exe，取同目录的 pythonw
    $py = (Get-Command python -ErrorAction SilentlyContinue).Source
    if ($py) {
        $c = Join-Path (Split-Path $py) "pythonw.exe"
        if (Test-Path $c) { return $c }
    }

    # 3) 常见安装目录（很多 Windows 装机 Python 并不进 PATH，这一步最常命中）
    foreach ($pat in @(
        "C:\Python3*\pythonw.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python3*\pythonw.exe",
        "C:\Program Files\Python3*\pythonw.exe"
    )) {
        $hit = Get-ChildItem $pat -ErrorAction SilentlyContinue |
               Sort-Object FullName -Descending | Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }

    # 4) py 启动器（装在 C:\Windows，几乎总在）
    $launcher = Join-Path $env:SystemRoot "py.exe"
    if (Test-Path $launcher) {
        try {
            $exe = (& $launcher -3 -c "import sys;print(sys.executable)" 2>$null | Select-Object -Last 1)
            if ($exe) {
                $c = Join-Path (Split-Path $exe.Trim()) "pythonw.exe"
                if (Test-Path $c) { return $c }
            }
        } catch { }
    }
    return $null
}

Write-Host ""
Write-Host "三合一自动签到（WorkBuddy + Trae + Qoder CN）· 一键安装" -ForegroundColor Cyan
Write-Host ("-" * 56) -ForegroundColor DarkGray

# --- 1. 定位 pythonw.exe ---
Write-Host "[1/3] 定位 pythonw.exe ..." -NoNewline
$pythonw = $ManualPythonw
if (-not $pythonw -or -not (Test-Path $pythonw)) { $pythonw = Find-Pythonw }
if (-not $pythonw -or -not (Test-Path $pythonw)) {
    Write-Host " 失败" -ForegroundColor Red
    Write-Host ""
    Write-Host "没找到 pythonw.exe。请先安装 Python 3：https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "装好后重跑本脚本；或把脚本顶部的 `$ManualPythonw 填成完整路径。" -ForegroundColor Yellow
    exit 1
}
Write-Host " $pythonw" -ForegroundColor Green

# --- 2. 定位 run_all.py ---
Write-Host "[2/3] 定位 run_all.py ..." -NoNewline
$runall = $ManualRunAll
if (-not $runall -or -not (Test-Path $runall)) {
    if ($PSScriptRoot) { $runall = Join-Path $PSScriptRoot "run_all.py" }
}
if (-not $runall -or -not (Test-Path $runall)) { $runall = Join-Path (Get-Location) "run_all.py" }
if (-not $runall -or -not (Test-Path $runall)) {
    Write-Host " 失败" -ForegroundColor Red
    Write-Host ""
    Write-Host "没找到 run_all.py。请保持本目录结构完整后重跑。" -ForegroundColor Yellow
    exit 1
}
$runall = (Resolve-Path $runall).Path
Write-Host " $runall" -ForegroundColor Green

# --- 3. 创建计划任务 ---
Write-Host "[3/3] 创建计划任务 ..." -NoNewline
try {
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive

    # 任务 1：开机/登录即签（延迟 90 秒等网络与桌面就绪）
    $actB = New-ScheduledTaskAction -Execute $pythonw -Argument "`"$runall`" --boot"
    $triB = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    $triB.Delay = "PT90S"
    $setB = New-ScheduledTaskSettingsSet -StartWhenAvailable -Hidden `
            -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries `
            -ExecutionTimeLimit (New-TimeSpan -Minutes 35)
    Register-ScheduledTask -TaskName "AutoCheckinBoot" `
        -Action $actB -Trigger $triB -Settings $setB -Principal $principal `
        -Description "Auto checkin on logon (WorkBuddy+Trae+Qoder, silent)" -Force | Out-Null

    # 任务 2：每日定时 + 多次补签（独立 Daily 触发器：实测“Daily+间隔重复”的重复
    # 实例一旦错过就永久跳过，独立触发器配合 StartWhenAvailable 每次都能补跑）
    #   00:23  Trae 最佳窗口（避开整点高峰）；其余为幂等补签兜底
    #   -RandomDelay 再加 0-5 分钟随机抖动，避免与同批用户撞车
    $triD = @()
    foreach ($hh in @("00:23", "08:07", "12:37", "19:07", "22:37")) {
        $t = New-ScheduledTaskTrigger -Daily -At $hh -RandomDelay (New-TimeSpan -Minutes 5)
        $triD += $t
    }
    $actD = New-ScheduledTaskAction -Execute $pythonw -Argument "`"$runall`""
    $setD = New-ScheduledTaskSettingsSet -StartWhenAvailable -Hidden `
            -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries `
            -ExecutionTimeLimit (New-TimeSpan -Minutes 35)
    Register-ScheduledTask -TaskName "AutoCheckinDaily" `
        -Action $actD -Trigger $triD -Settings $setD -Principal $principal `
        -Description "Auto checkin daily + catch-up (WorkBuddy+Trae+Qoder, silent)" -Force | Out-Null
} catch {
    Write-Host " 失败" -ForegroundColor Red
    Write-Host ""
    Write-Host "错误信息：$($_.Exception.Message)" -ForegroundColor Red
    Write-Host "如果提示拒绝访问，请右键 PowerShell 选『以管理员身份运行』后重试" -ForegroundColor Yellow
    exit 1
}
Write-Host " 完成" -ForegroundColor Green

# --- 收尾汇报 ---
Write-Host ""
Write-Host "两个计划任务已就位：" -ForegroundColor Green
foreach ($row in @(
    @{ Name = "AutoCheckinBoot";  When = "每次登录后90秒" },
    @{ Name = "AutoCheckinDaily"; When = "00:23/08:07/12:37/19:07/22:37" }
)) {
    $t = Get-ScheduledTask -TaskName $row.Name
    $i = Get-ScheduledTaskInfo -TaskName $row.Name
    Write-Host ("  {0,-18} {1,-8} 下次运行 {2}" -f $row.Name, $t.State, $i.NextRunTime)
}

Write-Host ""
Write-Host "日志目录：$(Split-Path $runall)\logs" -ForegroundColor Cyan
Write-Host "立即手动跑一轮看效果：" -ForegroundColor DarkGray
Write-Host "  python `"$runall`"" -ForegroundColor DarkGray
Write-Host "部署体检（凭据/网络/任务状态）：" -ForegroundColor DarkGray
Write-Host "  python `"$(Join-Path (Split-Path $runall) 'check.py')`"" -ForegroundColor DarkGray
Write-Host ""
Write-Host "卸载（两个任务一起删）：" -ForegroundColor DarkGray
Write-Host '  powershell -ExecutionPolicy Bypass -File .\uninstall.ps1' -ForegroundColor DarkGray
Write-Host ""
