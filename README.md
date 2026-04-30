# siem-detection-engine

Müəssisə mühitlərində təhdidləri aşkar etmək üçün mərkəzləşdirilmiş, versiyaya nəzarət edilən aşkarlama qaydaları anbarı. Bütün qaydalar **MITRE ATT&CK®** çərçivəsinə uyğunlaşdırılmış və CI/CD pipeline vasitəsilə Splunk-a avtomatik yerləşdirilir.

---

## Mündəricat

- [Ümumi baxış](#ümumi-baxış)
- [Qovluq strukturu](#qovluq-strukturu)
- [Detection-as-Code iş axını](#detection-as-code-iş-axını)
- [MITRE ATT&CK əhatəsi](#mitre-attck-əhatəsi)
- [Splunk qaydaları](#splunk-qaydaları)
- [CI/CD pipeline](#cicd-pipeline)
- [Başlanğıc](#başlanğıc)
- [Töhfə vermək](#töhfə-vermək)

---

## Ümumi baxış

Bu anbar **Detection Engineering** üçün mərkəzləşdirilmiş bir mərkəz rolunu oynayır. Məqsəd — müəssisə mühitlərində təcavüzkarların davranışlarını (TTP-ləri) aşkar edən peşəkar səviyyəli qaydalar kitabxanası yaratmaq və bunu tam avtomatlaşdırılmış **Detection-as-Code (DaC)** prinsipinə əsasən idarə etməkdir.

**Dəstəklənən SIEM platforması:** Splunk (SPL)

---

## Qovluq strukturu

```
siem-detection-engine/
├── .github/workflows/
│   └── deploy_rules.yml        # CI/CD — sintaksis yoxlama + avtomatik API push
├── splunk/
│   └── security/               # Yüksək səviyyəli SPL bildirişləri (15 qayda)
│       ├── BloodHoundLDAPRecon.spl
│       ├── DCSyncAttack.spl
│       ├── DLLHijacking.spl
│       ├── Kerberoasting.spl
│       ├── LOLbinsabuse.spl
│       ├── PowerShellEncodedCommand.spl
│       ├── PrivilegedAccountOff-HoursLogin.spl
│       ├── RansomwareBehavior.spl
│       ├── ScheduledTaskAbuse.spl
│       ├── SuspiciousOutboundConnection.spl
│       ├── WMIPersistence.spl
│       ├── WebShellDetection.spl
│       ├── dnstunneling.spl
│       ├── lsass.spl
│       └── pass-the-hash.spl
└── scripts/
    └── siem_api_sync.py        # Splunk REST API inteqrasiya mühərriki
```

---

## Detection-as-Code iş axını

Hər aşkarlama qaydası aşağıdakı mərhələlərdən keçir:

```
Develop ──▶ Version ──▶ Validate ──▶ Deploy
  │             │            │           │
SPL yazılır   GitHub      CI/CD       Splunk
              commit      yoxlama     REST API
```

1. **Develop** — Qaydalar SPL dilində yazılır, MITRE ATT&CK texnikası ilə etiketlənir.
2. **Version** — Hər dəyişiklik GitHub commit və Pull Request vasitəsilə izlənir.
3. **Validate** — `deploy_rules.yml` CI/CD sintaksis və məntiq xətalarını yoxlayır.
4. **Deploy** — `siem_api_sync.py` qaydaları REST API vasitəsilə Splunk-a push edir.

---

## MITRE ATT&CK əhatəsi

| Taktika | Qayda sayı |
|---|---|
| Credential Access | 5 |
| Privilege Escalation | 4 |
| Persistence | 4 |
| Defense Evasion | 4 |
| Execution | 3 |
| Discovery | 3 |
| Lateral Movement | 2 |
| Exfiltration | 1 |
| Command & Control | 1 |
| Impact | 1 |

---

## Splunk qaydaları

**Log mənbələri:** WinEventLog (Security, System), Sysmon, Network Traffic  
**Dil:** SPL (Search Processing Language)  
**Cəmi:** 15 qayda

### Active Directory hücumları — Credential Access

| Fayl | Məqsəd | Ciddilik |
|---|---|---|
| `BloodHoundLDAPRecon.spl` | AD strukturunu xəritələndirmək üçün BloodHound aləti istifadəsini aşkar edir | Critical |
| `DCSyncAttack.spl` | Domain Controller-dən şifrə hash-larını oğurlamaq cəhdini aşkar edir | Critical |
| `Kerberoasting.spl` | Kerberos biletlərini oğurlayaraq offline şifrə sındırma cəhdini aşkar edir | Critical |
| `lsass.spl` | Windows-un şifrə yaddaşına (LSASS prosesi) icazəsiz giriş cəhdini aşkar edir | Critical |
| `pass-the-hash.spl` | Şifrə yerinə hash istifadə edərək autentifikasiyaya girişi aşkar edir | Critical |

### Davamlılıq mexanizmləri — Persistence

| Fayl | Məqsəd | Ciddilik |
|---|---|---|
| `WMIPersistence.spl` | Sistem yenidən başladıqda zərərli kodun işləməsi üçün WMI istifadəsini aşkar edir | High |
| `ScheduledTaskAbuse.spl` | Zərərli scheduled task yaradılmasını aşkar edir | High |
| `WebShellDetection.spl` | Veb server üzərindən uzaqdan idarəetmə (webshell) cəhdlərini aşkar edir | Critical |

### Müdafiədən yayınma — Defense Evasion / Execution

| Fayl | Məqsəd | Ciddilik |
|---|---|---|
| `DLLHijacking.spl` | Zərərli DLL faylı ilə proqramın ələ keçirilməsini aşkar edir | High |
| `LOLbinsabuse.spl` | Legit sistem alətlərinin (`certutil`, `wmic`, `mshta`) zərərli istifadəsini aşkar edir | High |
| `PowerShellEncodedCommand.spl` | Gizlədilmiş (base64) PowerShell əmrlərini aşkar edir | High |

### Şəbəkə və kənarlaşdırma — C2 / Exfiltration

| Fayl | Məqsəd | Ciddilik |
|---|---|---|
| `SuspiciousOutboundConnection.spl` | Şübhəli xarici bağlantıları aşkar edir | High |
| `dnstunneling.spl` | DNS protokolu vasitəsilə məlumat ötürülməsini aşkar edir | High |

### Giriş anomaliyaları — Privilege Escalation

| Fayl | Məqsəd | Ciddilik |
|---|---|---|
| `PrivilegedAccountOff-HoursLogin.spl` | Admin hesabların iş saatlarından kənar girişlərini aşkar edir | High |

### Təsir — Impact

| Fayl | Məqsəd | Ciddilik |
|---|---|---|
| `RansomwareBehavior.spl` | Ransomware-ə xas fəaliyyəti (kütləvi fayl şifrələmə) aşkar edir | Critical |

---

## CI/CD pipeline

`deploy_rules.yml` GitHub Actions iş axını:

1. `main` və ya `staging` branch-ə push olduqda avtomatik işə düşür.
2. SPL sintaksis yoxlaması aparılır.
3. Test dataset-ləri əsasında məntiq yoxlanışı icra edilir.
4. Uğurlu olduqda qaydalar Splunk-a REST API vasitəsilə push edilir.

---

## Başlanğıc

```bash
# Reponu klon et
git clone https://github.com/Ayan-blue-team/siem-detection-engine.git
cd siem-detection-engine

# Python asılılıqlarını yüklə
pip install -r requirements.txt

# API sinxronizasiyasını əl ilə icra et
python scripts/siem_api_sync.py --target splunk --env prod
```

---

## Töhfə vermək

1. Yeni branch yarat:
```bash
git checkout -b detection/yeni-qayda-adi
```

2. Qaydanı SPL dilində yaz, fayl başlığına MITRE ATT&CK texnikasını əlavə et:
```spl
| ` MITRE: T1003.001 — OS Credential Dumping `
```

3. Pull Request aç — CI avtomatik yoxlayacaq.

---

## Lisenziya

Bu anbar Millisec şirkətinin daxili SOC mühəndislik infrastrukturunun bir hissəsidir.
