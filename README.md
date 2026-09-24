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

> **编码注意**：`install.ps1` / `uninstall.ps1` 均为 **UTF-8 with BOM**。
> Windows PowerShell 5.1 对无 BOM 的 UTF-8 会按 ANSI（中文系统 = GBK）解析，
> 中文注释会直接导致语法错误。用编辑器修改这两个脚本后另存时，务必保留 BOM。

安装完成后立即手动跑一轮看效果（控制台直接可见输出）：

```powershell
python run_all.py
```

## 运行时间表

| 任务 | 触发时间 | 行为 |
|------|---------|------|
| AutoCheckinBoot | 每次登录后 90 秒 | 等网络就绪后签到（开机即签） |
| AutoCheckinDaily | 每天 00:23 | 主力签到（Trae 避开整点限流高峰） |
| AutoCheckinDaily | 10:07 | 对齐 Qoder CN 每日 10:00 开放的新一轮领取窗口 |
| AutoCheckinDaily | 08:07 / 12:37 / 19:07 / 22:37 | 补签兜底（已签自动跳过，无多余领取请求） |

所有触发点带 0-5 分钟随机抖动错峰；关机/睡眠错过的时间点，开机后自动补跑
（StartWhenAvailable）。

> **Qoder 物理限制**：官方活动每日 10:00 开新窗口、持续至次日 10:00，**错过不可补领、
> 不累计**。`StartWhenAvailable` 只能让 Windows 任务在开机后补跑，无法让 Qoder 把已关闭
> 的上一轮奖励补回来；且计划任务以 `Interactive`（当前登录用户）身份运行（DPAPI 解密
> 凭据依赖用户上下文），故需保证每个领取窗口内电脑至少有一次开机并登录。

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
| `logs\health.json` | 运行健康：各任务连续失败计数、最近成功/失败时间与错误 |
| `logs\fail_任务_时间.txt` | 失败任务当轮的完整输出（总日志只留尾部摘要） |
| `workbuddy\signin.log` | WorkBuddy 详细结果（JSON 行） |
| `trae\.trae_checkin_state.json` | Trae 当日状态（避免重复请求） |
| `qoder\checkin.log` | Qoder 详细结果（JSON 行） |

查看今天的运行结果：

```powershell
Get-Content logs\run_$(Get-Date -Format yyyy-MM-dd).log
```

## 失败自动处理

每个子任务的结果被归入三态，调度器据此决定后续动作：

| 状态 | 含义 | 处理方式 |
|------|------|---------|
| OK | 成功 / 已签 / 设计内跳过（未安装、未登录） | 正常退出 |
| RETRY | 瞬时失败（网络、超时、服务端 5xx、9074 限流） | 当前轮不重试，下一个触发点自动补签（每天 6+ 次机会，已签幂等跳过） |
| NEEDS_HUMAN | 凭据/会话失效（重新登录才能解决）；或 Qoder 活动接口响应结构异常/未知状态（疑似 API 改版，`SCHEMA_FAIL`） | 重试无意义，落盘完整输出等待人工处理 |

> **Qoder fail-close 说明**：Qoder 走官方活动领取接口 `GET /sash/api/v1/me/campaigns`
> （必须带 `Cosy-ClientType:10` 头，否则服务端返回空列表），从返回的活动里严格筛出
> "每日 100 Credits"目标（`CLAIM_BENEFIT` + `CREDITS` + `amount==100` + `ALL_MODELS`，
> 以区分账号里可能存在的一次性致歉 500 包等其它活动）。判定：目标 `CLAIMED`→已领(exit0)；
> `CLAIMABLE`→`POST .../{campaignId}/claim` 领取，缺显式成功证据时复查 campaigns 确认变
> `CLAIMED` 才算成功；未领取一律按失败上报，绝不静默判绿——目标是"真的领到 100"。
> 失败分两类：`NO_CAMPAIGN`（未到 10:00 窗口/活动刚开放传播延迟）与 `CLAIM_FAIL`（瞬时
> 网络/5xx）归 RETRY，靠后续触发点兜底；`SCHEMA_FAIL`（结构异常/未知 `claimStatus`，疑似
> 改版）归 NEEDS_HUMAN 立即暴露。
>
> 历史背景：旧版脚本调的 `daily check-in` 端点已被官方退役（服务端只回 legacy 活动的
> `DISABLED`），曾导致"GUI 显示已领取、脚本却报 DISABLED"的矛盾；现已迁移到 campaigns 接口。

- 连续失败计数记在 `logs\health.json`（`consecutive_failures`），成功一次即清零。
- 任何失败任务当轮的完整输出（不止日志摘要）写入 `logs\fail_<任务>_<时间>.txt`，用于追溯根因。
- `python check.py` 的"运行健康"一节汇总显示三件套健康状态：NEEDS_HUMAN 或连续失败 ≥5 次会标红，并给出单任务排查命令。

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
检查 `logs\` 当天日志；连续失败看 `logs\health.json`，失败根因看 `logs\fail_*.txt`
完整输出，或直接跑 `python check.py` 看运行健康汇总。关机一整天的情况，开机触发
（AutoCheckinBoot）会补签。注意各平台的连签奖励规则（部分平台允许补签）。

**Q: 怎么确认签到成功？**
看 `logs\run_*.log` 的"本轮结果"，或打开各软件查看积分/连签天数。

## 更新

- git clone 方式：目录内 `git pull` 即可。**普通 Python 脚本更新无需重装计划任务**
  （任务指向目录路径，文件原地生效）。
- **若本次更新改动了 `install.ps1` / 调度时间**（例如新增触发点），`git pull` 不会
  自动改变已注册的 Windows 计划任务——必须重新运行一次 installer 才会生效：
  ```powershell
  powershell -ExecutionPolicy Bypass -File .\install.ps1
  ```
  脚本用 `Register-ScheduledTask -Force`，会原地更新已有任务，不会重复创建。
  可运行 `python check.py` 确认计划任务里已包含最新触发点（如 10:07）。
- ZIP 方式：重新下载解压，覆盖到原目录（同样：涉及调度变更需重跑 `install.ps1`）。
- 上游 `signin.py` / `trae_checkin.py` 发布新版时，可直接替换对应子目录文件。

## 开发与测试

```powershell
python -m unittest tests.test_core    # 零依赖：退出码契约/轮签/失败分类/健康计数/Qoder 状态机/AES 向量
```

子脚本退出码契约（调度器失败分类的依据）：`run_all.py` 0 全部成功；1 存在失败项。
`trae_checkin.py` 0 成功/已签/软限流/未开放，1 硬失败或鉴权失败；`qoder_checkin.py`
0 成功/已领，2 凭据缺失或解密失败，3 token 失效无法续期或活动接口拒绝鉴权，4 未领取
（一律 fail-close，绝不静默判成功）——其中 `NO_CAMPAIGN`/`CLAIM_FAIL` 归可重试、
`SCHEMA_FAIL`（疑似 API 改版）归需人工排查。

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
| qoder 签到流程 | github.com/hope0719/qoder-check-in（旧 daily check-in，已退役） | 见原仓库 |
| qoder campaigns 协议 | 反编译官方桌面端 app.asar 实证，并交叉参考 caigee-cmd/cli2api、techysy/10router、LeiSureLyYrsc/Qoder2OAPI | 见各原仓库 |
| qoder Windows 解密 | qoder2api-hub（DPAPI + AES-GCM 逆向实现） | 见原仓库 |
| run_all.py / check.py / install.ps1 | 本整合包 | MIT |

凭据安全：全程只读本机凭据文件，不回写官方客户端数据、不上传、日志与输出
中不含任何令牌。

风险声明：签到接口均逆向自各官方客户端，服务端改版可能导致失效；失效后请
关注上述上游仓库获取更新（signin.py 与 trae_checkin.py 可直接替换新版）。
