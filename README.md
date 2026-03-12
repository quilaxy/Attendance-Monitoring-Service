# Attendance Monitoring Service - Technical Documentation

Dokumentasi ini mencakup **Event ID**, **checkpoint & replay system**, **deduplication**, **shutdown priority**, dan **cleanup task** untuk Attendance Monitoring Service.

---
## 0. Publish & Deploy Service
Run as administrator

### 0.1 Publish
dotnet build

dotnet publish Attendance-Monitoring-Service.csproj -c Release -o ".\Attendance-Monitoring-Service" -p:DebugType=None

### 0.2 Install Service
sc create Attendance-Service binPath= "C:\Program Files\Attendance-Monitoring-Service\Attendance-Monitoring-Service.exe" start= auto

### 0.3 Start/Stop Service
sc start Attendance-Service
sc stop Attendance-Service

### 0.4 Remove Service
sc delete Attendance-Service

---

# 1. Shutdown Priority

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

# 2. Windows Event Log IDs

## 2.1 Security Log

| Event ID | Description        |
| -------- | ----------------- |
| 4624     | User login         |
| 4647     | User logout        |

## 2.2 System Log

| Event ID | Description                 |
| -------- | --------------------------- |
| 1074     | Shutdown / restart initiated|
| 6006     | Event Log service stopped   |
| 6008     | Unexpected shutdown         |
| 41       | Kernel power crash          |
| 42       | Sleep                       |

---

# 3. Application Log Event IDs

| Event ID | Level   | Source       | Description                                           |
| -------- | ------- | ------------ | ----------------------------------------------------- |
| 0        | Info    | Attendance-Service | Service start/stop                                   |
| 1001     | Error   | Application | Constructor error — gagal inisialisasi EventLog      |
| 1002     | Error   | Application | Gagal start setelah max retries                       |
| 1004     | Error   | Application | Failed to decrypt configuration                       |
| 1015     | Warning | Application | Error in ProcessQueuedEventsTask                      |
| 1016     | Info    | Application | Duplicate event skipped                                |
| 1017     | Warning | Application | Failed to save stop checkpoint                         |
| 1018     | Info    | Application | Saving checkpoint (OnStop/OnShutdown)                 |
| 1019     | Info    | Application | Checkpoint saved (OnStop/OnShutdown)                  |
| 1020     | Info    | Application | SaveStopCheckpoint: dir + path info                   |
| 1021     | Info    | Application | SaveStopCheckpoint: created directory                 |
| 1022     | Info    | Application | SaveStopCheckpoint: written to primary + backup       |
| 1023     | Warning | Application | LoadStopCheckpoint: fallback / exception             |
| 1024     | Info    | Application | LoadStopCheckpoint: loaded from primary               |
| 1025     | Info    | Application | EnsureCheckpointBootstrap: seeded missing checkpoint |
| 1026     | Warning | Application | EnsureCheckpointBootstrap failed                       |
| 1027     | Warning | Application | LoadStopCheckpoint: exception                          |
| 1029     | Info    | Application | ReplayMissedEvents: no checkpoint found, skipping     |
| 1030     | Info    | Application | ReplaySystemEvents: found N events                    |
| 1031     | Info    | Application | ReplaySystemEvents: processing EventId=X             |
| 1032     | Info    | Application | ReplaySecurityEvents: found N events                  |
| 1033     | Info    | Application | ReplaySecurityEvents: processing EventId=X           |
| 1034     | Info    | Application | ReplayMissedEvents: replayFrom + replayTo            |
| 1035     | Warning | Application | ReplaySecurityEvents: fromTime null — skipping       |
| 1036     | Warning | Application | ReplaySystemEvents: fromTime null — skipping         |
| 1037     | Info    | Application | Live event skipped during replay overlap             |
| 1040     | Warning | Application | Queue: recovered from backup after JsonException     |
| 1041     | Warning | Application | Queue: backup recovery failed                         |
| 1042     | Warning | Application | Queue: JSON corrupted, resetting queue               |
| 1043     | Warning | Application | LoadStopCheckpoint: replay checkpoint stale          |
| 2001     | Warning | Application | DBG-1074: NULL message — skipping                     |
| 2002     | Info    | Application | DBG-1074: message preview                              |
| 2003     | Info    | Application | DBG-1074: GetUserFromSystem1074Message result        |
| 2004     | Info    | Application | DBG-1074: Stored state username + shutdownType       |
| 2005     | Info    | Application | DBG-6006: resolved username + confirmed shutdownType|
| 2006     | Info    | Application | DBG-eventId: username null, fallback lastActiveUser |
| 2007     | Info    | Application | DBG-eventId: GetMostRecentUser result                |
| 2008     | Warning | Application | DBG-eventId: DROPPING event — no username resolved  |
| 2010     | Info    | Application | DBG-6006: TryResolve — no prior 1074 state in memory|
| 2011     | Info    | Application | DBG-6006: TryResolve — diff >60s                     |
| 2012     | Info    | Application | DBG-6006: TryResolve — matched username + diff      |
| 2020     | Info    | Application | DBG-1074: broad fallback matched candidate          |
| 2021     | Warning | Application | DBG-1074: GetUserFromSystem1074Message exception   |
| 3001     | Info    | Application | UpsertLogin: user, computer, loginTime, workDate, summaryKey |
| 3002     | Info    | Application | UpsertLogin: row exists, storedLogin vs incoming    |
| 3003     | Info    | Application | UpsertLogin: updating to earlier loginTime          |
| 3004     | Info    | Application | UpsertLogin: creating new row                        |
| 3005     | Info    | Application | UpsertLogin: successfully created row               |
| 3010     | Info    | Application | TryUpdateShutdown: user, computer, shutdownTime, eventId |
| 3011     | Info    | Application | TryUpdateShutdown: SKIP — no matching summary row  |
| 3012     | Info    | Application | TryUpdateShutdown: found row — loginTime, expectedTimeOut, currentShutdown |
| 3013     | Info    | Application | TryUpdateShutdown: SKIP — IsValidShutdownCandidate=false |
| 3014     | Info    | Application | TryUpdateShutdown: SKIP — priority too low          |
| 3015     | Info    | Application | TryUpdateShutdown: SKIP — same priority, existing later |
| 3016     | Info    | Application | TryUpdateShutdown: PATCHING — detail priority + isNewSession |
| 3017     | Info    | Application | TryUpdateShutdown: PATCH success                    |
| 3018     | Info    | Application | TryUpdateShutdown: NEW SESSION detected — reset priority |
| 4001     | Warning | Application | Token null — skipping dispatch                       |
| 4002     | Info    | Application | DISPATCH: detail queueId, eventId, needsRaw, needsSummary |
| 4003     | Info    | Application | DISPATCH: Raw record sent                             |
| 4004     | Info    | Application | DISPATCH-SUMMARY→ListId: sending/OK login          |
| 4005     | Info    | Application | DISPATCH-SUMMARY→ListId: sending/OK shutdown       |
| 4006     | Info    | Application | DISPATCH: Summary dispatched                        |
| 4007     | Info    | Application | DISPATCH: Done — doneRaw + doneSummary              |
| 4010     | Info    | Application | Waiting 30s for network on fresh boot               |
| 4011     | Warning | Application | Token attempt failed: HTTP status                   |
| 4012     | Warning | Application | Token attempt network error (SocketException)       |
| 4013     | Warning | Application | Token attempt exception                              |
| 4020     | Info    | Application | RAW: Inserting — title, eventTime, eventType        |
| 4021     | Info    | Application | RAW: Idempotency — record exists, skipping         |
| 4022     | Info    | Application | RAW: Insert success                                 |
| 4023     | Warning | Application | RAW: Insert attempt failed — HTTP status           |
| 4024     | Warning | Application | RAW: Insert attempt exception                        |
| 4025     | Info    | Application | RAW: Idempotency hit detail — diff seconds         |
| 5001-5005 | Info/Warning | Application | Cleanup events                                      |
| 9996     | Error   | Application | Unhandled exception in OnSystemEventWritten        |
| 9997     | Error   | Application | Unhandled exception in OnSecurityEventWritten      |
| 9998     | Error   | Application | Unobserved task exception                           |
| 9999     | Error   | Application | Unhandled exception (crash handler)                |

---

# 4. Checkpoint System

## 4.1 Checkpoint Files

| File                        | Location                                       | Content                                                 | Written When                                                                                  |
| --------------------------- | ---------------------------------------------- | ------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `event-stop.checkpoint`     | `%ProgramData%\Attendance-Monitoring-Service\` | Last processed event timestamp (`eventTime - 1 detik`) | Per-event enqueue, heartbeat tiap 1 menit, OnStop/OnShutdown (`Now - 5 detik`, jika lebih baru) |
| `event-stop.checkpoint.bak` | sama                                           | Backup identik                                         | Ditulis bersamaan menggunakan atomic write                                                   |
| `event-replay.checkpoint`   | sama                                           | Replay upper bound (`replayTo`)                        | Setelah `ReplayMissedEventsFromCheckpoint()` selesai                                          |

---

## 4.2 Atomic Write
Primary write:
1. Write → event-stop.checkpoint.tmp
2. File.Move(tmp → event-stop.checkpoint, overwrite:true)

Backup write:
1. Write → event-stop.checkpoint.bak.tmp
2. File.Move(tmp → event-stop.checkpoint.bak, overwrite:true)

- Crash-safe: file `.tmp` rusak → file utama tetap valid.

---

## 4.3 Writers

| Layer                                       | Trigger                                      | Value Written               | Purpose                              |
| ------------------------------------------- | -------------------------------------------- | ---------------------------- | ------------------------------------ |
| Per-event                                   | ProcessEvent enqueue                        | `eventTime - 1 detik`       | Akurasi checkpoint                    |
| Heartbeat                                   | Timer 1 menit                               | `DateTime.Now`              | Safety net saat idle                  |
| OnStop / OnShutdown                         | Service stop normal                          | `Now - 5 detik`             | Graceful stop                         |
| Crash handler (UnhandledException)          | Unhandled exception                           | `Now - 1 menit`             | Last-resort checkpoint                |
| Crash handler (UnobservedTaskException)    | Task exception                                | `Now - 1 menit`             | Last-resort checkpoint                |
| EnsureCheckpointBootstrap                   | Service start, no checkpoint                 | `Now - 1 menit`             | Seed awal untuk replay                 |

---

# 5. Replay System

## 5.1 LoadStopCheckpoint Fallback

| Level                  | Condition                                       | `replayFrom` Value           | Event ID |
| ---------------------- | ----------------------------------------------- | ---------------------------- | -------- |
| Primary                | checkpoint ada dan valid                        | file content                 | 1024     |
| Backup                 | primary hilang/rusak                            | file.bak                     | 1023     |
| Derived                | checkpoint tidak ada, replay checkpoint ada     | replayCheckpoint - 5 menit  | 1023     |
| Derived Stale          | derived < Now - 7 hari                           | Now - 7 hari                 | 1043     |
| Fresh Install          | tidak ada checkpoint                             | today 00:00:00               | 1023     |

---

## 5.2 Replay Flow
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

## 5.3 Replay Order Reasoning

| Reason                               | Explanation                                                     |
| ------------------------------------ | --------------------------------------------------------------- |
| lastActiveUser harus tersedia         | System events (6006, 6008, 41) membutuhkan fallback user        |
| Replay security terlebih dahulu       | 4624 login event mengisi lastActiveUser                         |
| 1074 harus sebelum 6006               | TryResolve1074StateFor6006 membutuhkan last1074Username          |
| Sorting ascending menjamin urutan    | 1074 → 6006 benar-benar di-process sesuai prioritas             |

---

# 6. Deduplication

| Mechanism                                           | Description                                                                    |
| --------------------------------------------------- | ------------------------------------------------------------------------------ |
| ShouldSkipLiveEntryDuringReplay                     | Skip live events jika `eventTime <= replayUpperBound`                           |
| PersistentEventQueue.EnqueueIfNotDuplicateAsync     | Event duplicate jika EventId+Username+ComputerName sama dalam window 10 menit  |

Special for 4624: incoming lebih awal → replace existing.

---

# 7. Login & Username Filtering

## 7.1 LogonType

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

## 7.2 Username Filtering

| Condition                                                     | Result             |
| ------------------------------------------------------------- | ------------------ |
| Kosong / whitespace                                           | ❌ rejected        |
| SYSTEM, LOCAL SERVICE, LOCAL_SYSTEM, NETWORK SERVICE          | ❌ rejected        |
| ANONYMOUS LOGON, Guest, DefaultAccount, Administrator         | ❌ rejected        |
| Berakhiran `$`                                                | ❌ computer account|
| Prefix DWM-, UMFD-, NT Service                                 | ❌ system account  |
| Valid                                                         | ✅ processed       |

## 7.3 Username Resolution (System Events)

| Order | Source                         | Condition                           |
| ----- | ------------------------------ | ----------------------------------- |
| 1     | GetUserFromSystem1074Message   | Hanya untuk 1074                    |
| 2     | TryResolve1074StateFor6006     | Pair dengan 1074 dalam 60 detik     |
| 3     | lastActiveUser                 | Setiap 4624 login                   |
| 4     | GetMostRecentUser              | Scan Security log 12 jam            |
| 5     | Drop event                      | Jika username tetap tidak ditemukan |

---

# 8. Shutdown Event Pairing

| Parameter              | Value    | Description                                  |
| ---------------------- | -------- | -------------------------------------------- |
| Max diff (1074 → 6006) | 60 detik | Pairing timeout                             |
| ShutdownEventWindow    | 2 menit  | Window skip network wait saat dispatch      |

---

# 9. Cleanup Task

| Parameter      | Value                                                         |
| -------------- | ------------------------------------------------------------- |
| Schedule       | 03:00 setiap hari                                             |
| Retention      | 6 bulan                                                       |
| Target Lists   | ListId (EventTime), SummaryListId (WorkDate)                  |
| Random delay   | 0–5 menit                                                     |
| Random seed    | MachineName.GetHashCode()                                     |
| Missed cleanup | Jika service start > 03:00, cleanup langsung dijalankan       |

---

# 10. Event ID Ranges

| Range       | Purpose                                     |
| ----------- | ------------------------------------------- |
| 0           | Service lifecycle                            |
| 1001–1043   | Service infrastructure (checkpoint/replay)  |
| 2001–2021   | Debug system event parsing                   |
| 3001–3018   | SharePoint summary updates                   |
| 4001–4025   | Dispatch & Raw SharePoint                     |
| 5001–5005   | Cleanup tasks                                |
| 9996–9999   | Crash & unhandled exceptions                 |

