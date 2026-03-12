# Attendance Monitoring Service

Windows Service untuk mendeteksi **login, logout, shutdown, restart, crash, dan sleep** dari Windows Event Log, lalu mengirimkan data tersebut ke **SharePoint Lists**.

Service ini dirancang agar:

- tidak ada event yang hilang
- tidak ada event diproses dua kali
- service bisa **replay event saat restart**
- klasifikasi **shutdown akurat**

---

# System Overview

Service membaca dua Windows Event Log.

| Log | Event |
|---|---|
| Security Log | Login / Logout |
| System Log | Shutdown / Restart / Crash / Sleep |

Pipeline utama:
Windows Event Log → Event Processing → PersistentEventQueue → SharePoint Raw List → SharePoint Summary List


---

# Shutdown Event Classification

Service menggunakan **priority system** untuk menentukan jenis shutdown.

| Priority | Event ID | Condition | Label |
|---|---|---|---|
| 5 | 6006 | Ada paired 1074 yang confirmed shutdown/power-off | Shutdown Completed (Confirmed) |
| 4 | 1074 | Shutdown/power-off initiated | Shutdown Initiated |
| 3 | 6006 | Tidak ada paired 1074 | Shutdown Completed (Unconfirmed) |
| 2 | 4647 | User logout eksplisit | User Logout |
| 1 | 6008 | Unexpected shutdown (power loss) | Unexpected Shutdown |
| 1 | 41 | System crash / kernel panic | System Crash |
| 0 | 1074 | Restart initiated | Restart Initiated |
| 0 | 42 | System sleep | Sleep |

Catatan:

- **1074 → 6006 pairing window = 60 detik**
- Jika 6006 muncul tanpa 1074 → dianggap **unconfirmed shutdown**

---

# Windows Event IDs Used

## Security Log

| Event ID | Description |
|---|---|
| 4624 | User login |
| 4647 | User logout |

## System Log

| Event ID | Description |
|---|---|
| 1074 | Shutdown / restart initiated |
| 6006 | Event Log service stopped |
| 6008 | Unexpected shutdown |
| 41 | Kernel power crash |
| 42 | Sleep |

---

# Application Log Event IDs

Service menulis log ke **Windows Application Log** untuk debugging dan monitoring.

## Service Lifecycle

| Event ID | Level | Source | Description |
|---|---|---|---|
| 0 | Info | Attendance-Service | Service started successfully |
| 0 | Info | Attendance-Service | Service stopped successfully |
| 1001 | Error | Application | Constructor failed to initialize EventLog |
| 1002 | Error | Application | Service failed to start after retries |
| 1004 | Error | Application | Failed to decrypt configuration |

---

## Checkpoint

| Event ID | Level | Source | Description |
|---|---|---|---|
| 1017 | Warning | Application | Failed to save checkpoint |
| 1018 | Info | Application | Saving checkpoint |
| 1019 | Info | Application | Checkpoint saved |
| 1020 | Info | Application | Checkpoint path info |
| 1021 | Info | Application | Directory created |
| 1022 | Info | Application | Checkpoint written to primary + backup |
| 1023 | Warning | Application | Checkpoint fallback triggered |
| 1024 | Info | Application | Checkpoint loaded from primary |
| 1025 | Info | Application | Bootstrap checkpoint seeded |
| 1026 | Warning | Application | Bootstrap checkpoint failed |
| 1027 | Warning | Application | Checkpoint load exception |
| 1043 | Warning | Application | Replay checkpoint stale |

---

## Replay

| Event ID | Level | Source | Description |
|---|---|---|---|
| 1029 | Info | Application | No checkpoint found |
| 1030 | Info | Application | Replay system events |
| 1031 | Info | Application | Processing system event |
| 1032 | Info | Application | Replay security events |
| 1033 | Info | Application | Processing security event |
| 1034 | Info | Application | Replay time window |
| 1035 | Warning | Application | Security replay skipped |
| 1036 | Warning | Application | System replay skipped |
| 1037 | Info | Application | Live event skipped during replay |

---

## Queue & Dispatch

| Event ID | Level | Source | Description |
|---|---|---|---|
| 1015 | Warning | Application | Queue processing error |
| 1016 | Info | Application | Duplicate event skipped |
| 1028 | Warning | Application | Dispatch failed |
| 4001 | Warning | Application | Token null |
| 4002 | Info | Application | Dispatch details |
| 4003 | Info | Application | Raw record sent |
| 4004 | Info | Application | Login summary sent |
| 4005 | Info | Application | Shutdown summary sent |
| 4006 | Info | Application | Summary dispatched |
| 4007 | Info | Application | Dispatch completed |

---

## Cleanup (SharePoint Retention)

| Event ID | Level | Source | Description |
|---|---|---|---|
| 5001 | Info | Application | Cleanup started — cutoffDate, retentionMonths, listId, summaryListId |
| 5001 | Info | Application | Per-list scanning info — total items fetched |
| 5001 | Warning | Application | Token null during cleanup — skipping |
| 5002 | Info | Application | Raw list cleanup completed — N items deleted |
| 5002 | Info | Application | Raw list empty — nothing to delete |
| 5003 | Info | Application | Summary list cleanup completed — N items deleted |
| 5004 | Warning | Application | Failed to fetch items — HTTP status |
| 5005 | Warning | Application | Failed to delete item — itemId + HTTP status |
| 5005 | Warning | Application | Exception during delete — itemId + exception |
| 1013 | Warning | Application | Exception in CleanupOldRecordsAsync |

---

# Crash Handling

| Event ID | Level | Source | Description |
|---|---|---|---|
| 9996 | Error | Application | Unhandled exception in system event handler |
| 9997 | Error | Application | Unhandled exception in security event handler |
| 9998 | Error | Application | Unobserved task exception |
| 9999 | Error | Application | Global unhandled exception |

---

# Event ID Range Allocation

| Range | Purpose |
|---|---|
| 0 | Service lifecycle |
| 1001–1043 | Service infrastructure |
| 2001–2021 | Debug system event parsing |
| 3001–3018 | SharePoint summary |
| 4001–4025 | Dispatch & raw SharePoint |
| 5001–5005 | SharePoint cleanup |
| 9996–9999 | Crash handling |

---

# Checkpoint System

Service menggunakan **checkpoint file** untuk mengetahui event terakhir yang diproses.

## Checkpoint Files

| File | Location | Content |
|---|---|---|
| event-stop.checkpoint | %ProgramData%\Attendance-Monitoring-Service | Last processed event timestamp |
| event-stop.checkpoint.bak | same | Backup checkpoint |
| event-replay.checkpoint | same | Replay upper bound |

---

## Atomic Write

Checkpoint ditulis menggunakan **atomic file replacement**.
write checkpoint.tmp
rename checkpoint.tmp → checkpoint


Jika service crash:

- file `.tmp` rusak
- file utama tetap valid

---

# Replay System

Jika service restart, event akan direplay dari checkpoint.

## Replay Flow
OnStart → Enable Event Listeners → Load Checkpoint → Replay Security Events → Replay System Events → Save Replay Checkpoint → Start Live Monitoring


---

# Replay Windows

| Parameter | Value |
|---|---|
| MaxReplayLookback | 7 days |
| DedupWindow | 10 minutes |
| Replay buffer | 5 minutes |

---

# Cleanup Task

| Parameter | Value |
|---|---|
| Schedule | 03:00 daily |
| Retention | 6 months |
| Random delay | 0–5 minutes |

Random delay digunakan untuk mencegah semua komputer melakukan cleanup bersamaan.

---

# Reliability Guarantees

Service dirancang untuk memastikan:

- tidak ada event hilang
- tidak ada event double
- checkpoint aman dari crash
- replay otomatis saat restart

 
