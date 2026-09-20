# 三合一自动签到（WorkBuddy + Trae SOLO + Qoder CN）

开机即自动签到，无需打开任何软件。全部零依赖（纯 Python 标准库，无需 pip install）、
无窗口静默运行、错过时间点自动补跑、重复运行幂等安全。

## 前置条件

| 条件 | 说明 |
|------|------|
| Windows 10/11 | Qoder 凭据解密依赖 Windows DPAPI（用户级） |
| Python 3.8+ | 安装时勾选 "Add python.exe to PATH" 可省去手动配置 |
| 三个软件已登录 | WorkBuddy、Trae/TRAE SOLO、Qoder CN 桌面端至少登录过一次 |

## 下载与部署（三步）

```powershell
# 1. 下载到固定位置（安装后勿移动）。两种方式任选：
#    方式 A · git clone（推荐，日后更新只需 git pull）：
git clone https://github.com/Rain3Dmetrology/auto-checkin.git C:\Tools\auto-checkin
#    方式 B · 网页下载：仓库页 Code → Download ZIP → 解压到 C:\Tools\auto-checkin

# 2. 进入目录，先体检（可选但强烈建议）：确认三件套凭据、网络、依赖全部就绪
cd C:\Tools\auto-checkin
python check.py

# 3. 一键安装计划任务（在本目录下，需管理员 PowerShell）
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

安装完成后立即手动跑一轮看效果（控制台直接可见输出）：

```powershell
python run_all.py
```

## 运行时间表

| 任务 | 触发时间 | 行为 |
|------|---------|------|
| AutoCheckinBoot | 每次登录后 90 秒 | 等网络就绪后签到（开机即签） |
| AutoCheckinDaily | 每天 00:23 | 主力签到（Trae 避开整点限流高峰） |
| AutoCheckinDaily | 08:07 / 12:37 / 19:07 / 22:37 | 补签兜底（已签自动跳过，零多余请求） |

所有触发点带 0-5 分钟随机抖动错峰；关机/睡眠错过的时间点，开机后自动补跑
（StartWhenAvailable）。

## 工作原理

```
run_all.py（计划任务统一入口，pythonw.exe 静默运行）
 ├─ workbuddy\signin.py silent      WorkBuddy 签到 + 成长中心
 │   └─ 凭据: %LOCALAPPDATA%\CodeBuddyExtension\...\workbuddy-desktop.info
 ├─ trae\trae_checkin.py            Trae 签到（抗 9074 限流）
 │   └─ 凭据: run_all 自动解密 %APPDATA%\TRAE SOLO CN\...\storage.json
 │        （纯标准库 AES 解出 refreshToken，经环境变量传递，不落盘）
 └─ qoder\qoder_checkin.py          Qoder CN 签到
     └─ 凭据: DPAPI 解密 %APPDATA%\com.qodercn.app.stable\auth.v1.dat
          （dt- token 过期时自动用 drt- 续期，缓存在 qoder\state.json）
```

三个子任务互相隔离：任何一个失败/未安装不影响其余两个。今日已签到的软件
后续轮询只发一个状态查询请求，幂等安全。

## 日志

| 位置 | 内容 |
|------|------|
| `logs\run_YYYY-MM-DD.log` | 调度总日志（每次运行三个子任务的结果汇总） |
| `workbuddy\signin.log` | WorkBuddy 详细结果（JSON 行） |
| `trae\.trae_checkin_state.json` | Trae 当日状态（避免重复请求） |
| `qoder\checkin.log` | Qoder 详细结果（JSON 行） |

查看今天的运行结果：

```powershell
Get-Content logs\run_$(Get-Date -Format yyyy-MM-dd).log
```

## 常见问题

**Q: Trae 签到显示 9074 / 待重试？**
正常现象。9074 是服务端按时间窗排队的容量限制（与你的网络无关），脚本会自动
记冷却并交给下一个时间点补签。实测 00:23 前后成功率最高，全天共 6+ 次机会。

**Q: Qoder 提示 token 过期/续期失败？**
dt- token 约 30 天有效。脚本会用 refreshToken（约 1 年有效）自动续期。若
refreshToken 也失效，打开一次 Qoder CN 桌面端重新登录即可（凭据文件会刷新）。

**Q: WorkBuddy 提示 NO_SESSION？**
登录会话失效，打开一次 WorkBuddy 桌面端即恢复。

**Q: 某天断签了？**
检查 `logs\` 当天日志。关机一整天的情况，开机触发（AutoCheckinBoot）会补签。
注意各平台的连签奖励规则（部分平台允许补签）。

**Q: 怎么确认签到成功？**
看 `logs\run_*.log` 的"本轮结果"，或打开各软件查看积分/连签天数。

## 更新

- git clone 方式：目录内 `git pull` 即可。计划任务指向目录路径，文件原地更新后
  无需重装 `install.ps1`。
- ZIP 方式：重新下载解压，覆盖到原目录。
- 上游 `signin.py` / `trae_checkin.py` 发布新版时，可直接替换对应子目录文件。

## 卸载

```powershell
powershell -ExecutionPolicy Bypass -File .\uninstall.ps1
# 然后删除整个 auto-checkin 文件夹即可（无注册表、无其他残留）
```

## 技术来源与许可

| 组件 | 来源 | 许可 |
|------|------|------|
| workbuddy\signin.py | github.com/88lin/workbuddy-auto-signin | MIT |
| trae\trae_checkin.py | github.com/L0NE-6/Trae-AutoCheckin | 见原仓库 |
| qoder 签到流程 | github.com/hope0719/qoder-check-in | 见原仓库 |
| qoder Windows 解密 | qoder2api-hub（DPAPI + AES-GCM 逆向实现） | 见原仓库 |
| run_all.py / check.py / install.ps1 | 本整合包 | MIT |

凭据安全：全程只读本机凭据文件，不回写官方客户端数据、不上传、日志与输出
中不含任何令牌。

风险声明：签到接口均逆向自各官方客户端，服务端改版可能导致失效；失效后请
关注上述上游仓库获取更新（signin.py 与 trae_checkin.py 可直接替换新版）。
