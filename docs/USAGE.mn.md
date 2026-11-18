# Шаардлага ба ашиглах

[English](USAGE.md) · [← README](../README.mn.md)

## Шаардлага

- Windows 10 / 11 (Server 2016+ бас ажиллана) · PowerShell 5.1+ (PowerShell 7 дэмжинэ)
- Linux: Debian/Ubuntu эсвэл RHEL/CentOS/Fedora (bash 4+, coreutils)
- Бүрэн цуглуулгад **Administrator / root** зөвлөж байна.

## Ашиглах

```powershell
# Windows
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
.\Tatar.ps1 -All -OutputPath E:\Evidence -CaseId IR-2026-014 -Examiner "Enkhbat.O" -Compress
.\Tatar.ps1 -List          # модулиудыг харах
.\Tatar.ps1 -All -DryRun   # төлөвлөгөө харах: гаралтын зам, модулийн дараалал, feed-ийн бэлэн байдал (юу ч бичихгүй)
.\Tatar.ps1 -All -Silent   # автоматжуулалт (exit code буцаана)
```

```bash
# Linux
chmod +x tatar-linux.sh
sudo ./tatar-linux.sh --all --output /mnt/usb/evidence --caseid IR-2026-014 --examiner "Enkhbat.O"
./tatar-linux.sh --list
sudo ./tatar-linux.sh --all --dry-run   # төлөвлөгөө харах (юу ч бичихгүй)
```

### Флагууд

| Флаг | Тайлбар |
|--------|-------------|
| `-Quick` / `--quick` | Хамгийн өндөр дохиотой дэд олонлог, ~10 сек. *"Энэ хост дээр ямар нэг зүйл буруу байна уу"* гэдэгт хариулна; `-All` нь *"яаж ийшээ орж ирсэн бэ"* гэдэгт. Бүрэлдэхүүнийг **хэмжилтээр** сонгосон, `-List` түүнийг тэмдэглэнэ — жагсаалт нэг л газар, кодонд байна |
| `-All` / `--all` | Бүх модулийг ажиллуулна |
| `-Modules a,b,c` | Зөвхөн нэрлэсэн модулиудыг ажиллуулна |
| `-List` | Модулиудыг жагсаагаад гарна |
| `-Help` | Тусламж хэвлээд гарна |
| `-OutputPath <зам>` | Гаралтын үндсэн хавтас (default `C:\Forensic`; **гадаад дискийг илүүд үз**) |
| `-CaseId <id>` | Chain of custody-д бичих case / incident ID |
| `-Examiner <нэр>` | Chain of custody-д бичих шинжээчийн нэр |
| `-Compress` | Төгсгөлд нь гаралтыг zip болгож SHA-256 авна |
| `-CollectHives` | SAM/SECURITY/SYSTEM/SOFTWARE + NTUSER-ийг хадгална (credential материал; EDR сэрээж болзошгүй) |
| `-ExportEvtx` | Бүтэн `.evtx` лог export хийнэ |
| `-MemoryDump` | `tools\winpmem.exe`-ээр санах ойн raw image авна (EDR сэрээж болзошгүй) |
| `-Silent` / `-Quiet` | Консолын **бүх** гаралтыг дарна (banner, явц, төлөв). Файлууд — `tatar.log` ч мөн — хэвээр бичигдэнэ. WinRM / хуваарьт / автомат run-д зориулав |
| `-DryRun` / `-Preview` | Тодорхойлсон гаралтын хавтас, модулиудыг ажиллах дарааллаар нь, аль gated үйлдэл асаалттайг, allowlist / IOC feed уншигдаж байгаа эсэхийг хэвлээд `0`-ээр гарна — **юу ч үүсгэхгүй, юу ч бичихгүй** |
| `-Allowlist <json>` | Мэдэгдэж байгаа цэвэр finding-ийг зам, Authenticode нийтлэгч, эсвэл SHA-256-аар нууна. Suppressed finding аудитад үлдэнэ, устдаггүй |
| `-IOCFile <json>` | Finding болон цуглуулсан нотолгоог офлайн IOC feed-тэй тулгана (hashes = зөвхөн SHA-256, ips, domains, filenames). Таарвал allowlist-ийг **давж**, High болгож өсгөнө |

### Exit code

`0` = амжилт · `1` = fatal/usage алдаа · `2` = алдаатай дууссан (лог шалга). Заавал утга шаардах флаг (Windows дээр `-OutputPath`, Linux дээр `--output`) утгагүй байвал `1`.

| Code | Утга |
|------|---------|
| `0` | Цуглуулга амжилттай дууссан |
| `1` | Fatal / usage алдаа (юу ч сонгоогүй, утга шаардах флаг утгагүй, гаралтын хавтас үүсгэж чадаагүй, хүчинтэй модуль алга) |
| `2` | Цуглуулга дууссан ч нэг буюу хэд хэдэн алхам алдаа бүртгүүлсэн — `tatar.log`-ийг шалга. Уншигдахгүй `-Allowlist` / `-IOCFile` зам, танигдахгүй флаг, байхгүй модулийн нэр энд унана. |
