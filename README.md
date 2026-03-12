# Attendance Monitoring Service - Technical Documentation

Dokumentasi ini mencakup **Event ID**, **checkpoint & replay system**, **deduplication**, **shutdown priority**, dan **cleanup task** untuk Attendance Monitoring Service.

---

# 0. Shutdown Priority

| Priority | Event ID | Condition                                    | Label                                 |
| -------- | -------- | -------------------------------------------- | ------------------------------------ |
| 5        | 6006     | Ada paired 1074 yang confirmed shutdown     | Shutdown Completed (Confirmed)       |
| 4        | 1074     | Shutdown/power-off initiated                 | Shutdown Initiated                    |
| 3        | 6006     | Tidak ada paired 1074                        | Shutdown Completed (Unconfirmed)     |
| 2        | 4647     | User logout eksplisit                        | User Logout                           |
| 1        | 6008     | Unexpected shutdown (power loss)             | Unexpected Shutdown                   |
| 1        | 41       | System crash / kernel panic                  | System Crash                          |
| 0        | 1074     | Restart initiated                             | Restart Initiated                     |
| 0        | 42       | Sleep                                        | Sleep                                 |

> Catatan: 1074 → 6006 pairing window = 60 detik.

---

# 1. Windows Event Log IDs

## 1.1 Security Log

| Event ID | Description        |
| -------- | ----------------- |
| 4624     | User login         |
| 4647     | User logout        |

## 1.2 System Log

| Event ID | Description                 |
| -------- | --------------------------- |
| 1074     | Shutdown / restart initiated|
| 6006     | Event Log service stopped   |
| 6008     | Unexpected shutdown         |
| 41       | Kernel power crash          |
| 42       | Sleep                       |

---

# 2. Application Log Event IDs

| Event ID | Level   | Source       | Description                                           |
| -------- | ------- | ------------ | ----------------------------------------------------- |
| 0        | Info    | Attendance-Service | Service start/stop                                   |
| 1001-1043 | Info/Warning/Error | Application | Service infrastructure, checkpoint, replay, errors |
| 2001-2021 | Info/Warning | Application | Debug system events (1074/6006 processing)         |
| 3001-3018 | Info    | Application | SharePoint summary updates                            |
| 4001-4025 | Info/Warning | Application | Dispatch & Raw SharePoint                             |
| 5001-5005 | Info/Warning | Application | Cleanup task                                         |
| 9996-9999 | Error   | Application | Crash & unhandled exceptions                          |

### Cleanup Event IDs

| Event ID | Level   | Source       | Description                                          |
| -------- | ------- | ------------ | --------------------------------------------------- |
| 5001     | Info    | Application | Cleanup started — cutoffDate, retentionMonths, listId, summaryListId |
| 5001     | Info    | Application | Per-list: total items fetched, scanning info       |
| 5001     | Warning | Application | Token null — skip cleanup                            |
| 5002     | Info    | Application | Raw ListId cleanup completed — N items deleted     |
| 5002     | Info    | Application | Raw list empty — nothing to delete                 |
| 5003     | Info    | Application | SummaryListId cleanup completed — N items deleted  |
| 5004     | Warning | Application | Failed fetch items — HTTP status                    |
| 5005     | Warning | Application | Failed delete per item — itemId + HTTP status      |
| 5005     | Warning | Application | Exception during delete per item                    |
| 1013     | Warning | Application | Exception in CleanupOldRecordsAsync (existing)     |

---

# 3. Checkpoint System

## 3.1 Checkpoint Files

| File                        | Location                                       | Content                                                 | Written When                                                                                  |
| --------------------------- | ---------------------------------------------- | ------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `event-stop.checkpoint`     | `%ProgramData%\Attendance-Monitoring-Service\` | Last processed event timestamp (`eventTime - 1 detik`) | Per-event enqueue, heartbeat tiap 1 menit, OnStop/OnShutdown (`Now - 5 detik`, jika lebih baru) |
| `event-stop.checkpoint.bak` | sama                                           | Backup identik                                         | Ditulis bersamaan menggunakan atomic write                                                   |
| `event-replay.checkpoint`   | sama                                           | Replay upper bound (`replayTo`)                        | Setelah `ReplayMissedEventsFromCheckpoint()` selesai                                          |

---

## 3.2 Atomic Write
Primary write:
1. Write → event-stop.checkpoint.tmp
2. File.Move(tmp → event-stop.checkpoint, overwrite:true)

Backup write:
1. Write → event-stop.checkpoint.bak.tmp
2. File.Move(tmp → event-stop.checkpoint.bak, overwrite:true)

- Crash-safe: file `.tmp` rusak → file utama tetap valid.

---

## 3.3 Writers

| Layer                                       | Trigger                                      | Value Written               | Purpose                              |
| ------------------------------------------- | -------------------------------------------- | ---------------------------- | ------------------------------------ |
| Per-event                                   | ProcessEvent enqueue                        | `eventTime - 1 detik`       | Akurasi checkpoint                    |
| Heartbeat                                   | Timer 1 menit                               | `DateTime.Now`              | Safety net saat idle                  |
| OnStop / OnShutdown                         | Service stop normal                          | `Now - 5 detik`             | Graceful stop                         |
| Crash handler (UnhandledException)          | Unhandled exception                           | `Now - 1 menit`             | Last-resort checkpoint                |
| Crash handler (UnobservedTaskException)    | Task exception                                | `Now - 1 menit`             | Last-resort checkpoint                |
| EnsureCheckpointBootstrap                   | Service start, no checkpoint                 | `Now - 1 menit`             | Seed awal untuk replay                 |

---

# 4. Replay System

## 4.1 LoadStopCheckpoint Fallback

| Level                  | Condition                                       | `replayFrom` Value           | Event ID |
| ---------------------- | ----------------------------------------------- | ---------------------------- | -------- |
| Primary                | checkpoint ada dan valid                        | file content                 | 1024     |
| Backup                 | primary hilang/rusak                            | file.bak                     | 1023     |
| Derived                | checkpoint tidak ada, replay checkpoint ada     | replayCheckpoint - 5 menit  | 1023     |
| Derived Stale          | derived < Now - 7 hari                           | Now - 7 hari                 | 1043     |
| Fresh Install          | tidak ada checkpoint                             | today 00:00:00               | 1023     |

---

## 4.2 Replay Flow
OnStart()
→ EnableRaisingEvents = true
→ ReplayMissedEventsFromCheckpoint()
→ replayTo = Now
→ replayUpperBound = replayTo
→ replayInProgress = true
→ replayFrom = LoadStopCheckpoint()
→ ReplaySecurityEvents(replayFrom, replayTo)
→ scan Security log
→ filter eventTime > replayFrom && <= replayTo
→ filter EventId 4624, 4647
→ pre-filter LogonType
→ sort ascending
→ process one-by-one
→ ReplaySystemEvents(replayFrom, replayTo)
→ scan System log
→ filter eventTime > replayFrom && <= replayTo
→ filter EventId 1074, 6006, 6008, 41, 42
→ sort ascending
→ process one-by-one
→ SaveReplayCheckpoint(replayTo)
→ replayInProgress = false
→ StartCheckpointHeartbeat()


---

## 4.3 Replay Order Reasoning

| Reason                               | Explanation                                                     |
| ------------------------------------ | --------------------------------------------------------------- |
| lastActiveUser harus tersedia         | System events (6006, 6008, 41) membutuhkan fallback user        |
| Replay security terlebih dahulu       | 4624 login event mengisi lastActiveUser                         |
| 1074 harus sebelum 6006               | TryResolve1074StateFor6006 membutuhkan last1074Username          |
| Sorting ascending menjamin urutan    | 1074 → 6006 benar-benar di-process sesuai prioritas             |

---

# 5. Deduplication

| Mechanism                                           | Description                                                                    |
| --------------------------------------------------- | ------------------------------------------------------------------------------ |
| ShouldSkipLiveEntryDuringReplay                     | Skip live events jika `eventTime <= replayUpperBound`                           |
| PersistentEventQueue.EnqueueIfNotDuplicateAsync     | Event duplicate jika EventId+Username+ComputerName sama dalam window 10 menit  |

Special for 4624: incoming lebih awal → replace existing.

---

# 6. Login & Username Filtering

## 6.1 LogonType

| LogonType | Name                    | Processed |
| --------- | ----------------------- | --------- |
| 2         | Interactive             | ✅         |
| 7         | Unlock                  | ✅         |
| 10        | RemoteInteractive (RDP) | ✅         |
| 11        | CachedInteractive       | ✅         |
| 3         | Network                 | ❌         |
| 4         | Batch                   | ❌         |
| 5         | Service                 | ❌         |
| Others    | —                       | ❌         |

## 6.2 Username Filtering

| Condition                                                     | Result             |
| ------------------------------------------------------------- | ------------------ |
| Kosong / whitespace                                           | ❌ rejected        |
| SYSTEM, LOCAL SERVICE, LOCAL_SYSTEM, NETWORK SERVICE          | ❌ rejected        |
| ANONYMOUS LOGON, Guest, DefaultAccount, Administrator         | ❌ rejected        |
| Berakhiran `$`                                                | ❌ computer account|
| Prefix DWM-, UMFD-, NT Service                                 | ❌ system account  |
| Valid                                                         | ✅ processed       |

## 6.3 Username Resolution (System Events)

| Order | Source                         | Condition                           |
| ----- | ------------------------------ | ----------------------------------- |
| 1     | GetUserFromSystem1074Message   | Hanya untuk 1074                    |
| 2     | TryResolve1074StateFor6006     | Pair dengan 1074 dalam 60 detik     |
| 3     | lastActiveUser                 | Setiap 4624 login                   |
| 4     | GetMostRecentUser              | Scan Security log 12 jam            |
| 5     | Drop event                      | Jika username tetap tidak ditemukan |

---

# 7. Shutdown Event Pairing

| Parameter              | Value    | Description                                  |
| ---------------------- | -------- | -------------------------------------------- |
| Max diff (1074 → 6006) | 60 detik | Pairing timeout                             |
| ShutdownEventWindow    | 2 menit  | Window skip network wait saat dispatch      |

---

# 8. Cleanup Task

| Parameter      | Value                                                         |
| -------------- | ------------------------------------------------------------- |
| Schedule       | 03:00 setiap hari                                             |
| Retention      | 6 bulan                                                       |
| Target Lists   | ListId (EventTime), SummaryListId (WorkDate)                  |
| Random delay   | 0–5 menit                                                     |
| Random seed    | MachineName.GetHashCode()                                     |
| Missed cleanup | Jika service start > 03:00, cleanup langsung dijalankan       |

---

# 9. Event ID Ranges

| Range       | Purpose                                     |
| ----------- | ------------------------------------------- |
| 0           | Service lifecycle                            |
| 1001–1043   | Service infrastructure (checkpoint/replay)  |
| 2001–2021   | Debug system event parsing                   |
| 3001–3018   | SharePoint summary updates                   |
| 4001–4025   | Dispatch & Raw SharePoint                     |
| 5001–5005   | Cleanup tasks                                |
| 9996–9999   | Crash & unhandled exceptions                 |

