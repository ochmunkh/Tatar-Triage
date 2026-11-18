# Нотлох баримт юу болох нь

[English](EVIDENCE.md) · [← README](../README.mn.md)

## Нотлох баримт юу болох нь: `artifactClass`

`category` нь аль модуль finding гаргасныг хэлнэ. `artifactClass` нь нотлох
баримт **юу болохыг** хэлнэ — ялгаа нь ажиллагааных. `persistence` гэдэг нэг
шошгон доор Run key, IFEO, Winlogon, Startup хавтас, scheduled task, COM hijack
бүгд багтдаг тул ангиллын эсрэг бичсэн allowlist буюу IOC дүрэм тэдгээрийн аль
нэгийг онож чадахгүй. HijackThis яг энэ ялгааг `O4` / `O20` кодоор хийсэн бөгөөд
*«O20 бараг үргэлж муу»* гэх мэдлэгийг бичиж, дахин ашиглах боломжтой болгосон
шалтгаан нь тэр.

Нэршил нь **хаалттай**: коллектор зарлагдаагүй ангилал гаргахаас татгалзаж,
таамгийн оронд `unknown` гаргана, мөн shell хувилбар Windows-ийн мэдэхгүй
ангилал зарлавал `check_docs_parity.py` build-ийг унагаана. Энэ нь
`ARTIFACTS.md`-ийн файлд хэрэглэдэг яг тэр нэршил, finding дээр хэрэглэгдсэн нь.
Schema 1.5-д нэмэгдсэн.

| | Windows | Linux |
|---|---|---|
| Зарласан ангилал | 46 | 18 |
| Гаргадаг нь | `Get-ArtifactClass` | `map_artifact_class` |
| Unit тестийн кейс | 42 | 20 |

### Persistence-ийн гурван нэмэлт техник

`persistence` одоо эдгээрийг ч уншина — бүгд энгийн registry уншилт, хэмжсэн
өртөг **+1.0 секунд**:

| Техник | ATT&CK | Юуг тэмдэглэх |
|---|---|---|
| COM hijack | T1546.015 | `HKCU\Software\Classes` **ба** HKLM хоёуланд бүртгэгдсэн CLSID — хэрэглэгчийн хуулбар машиныхыг халхалдаг, суулгахад Administrator шаардахгүй |
| netsh helper DLL | T1546.007 | DLL нь **хэрэглэгч бичих боломжтой** байрлалд байгаа helper |
| Protocol handler / filter | — (HijackThis `O18`) | **хэрэглэгч бичих боломжтой** байрлалын DLL-ээр үйлчлүүлж буй схем |

Дүрэм бүр түлхүүрийн зүгээр л оршин байхыг биш, *халхлалт* буюу *хазайлтыг*
хайна. Эхний ноорогууд илэрхий зүйлийг хийсэн — «миний анхдагч netsh жагсаалтад
байхгүй», «`%SystemRoot%`-ээс гадна байгаа DLL» — цэвэр ажлын станц дээр долоон
finding гаргасан бөгөөд бүгд нь Microsoft Office эсвэл Windows өөрөө байв.
Эцсийн хувилбарт орсон дүрмүүд тэнд нэгийг ч гаргахгүй.

Өртгийн тухай нэг тэмдэглэл, учир нь энэ өөрөөр эргэж барагтай байсан:
`HKLM\Software\Classes\CLSID` дор **байхгүй** түлхүүр дээрх `Test-Path` нь
ойролцоогоор хоёр секунд авдаг бөгөөд хорин хоёр ийм хайлт 0.8 секундын
модулийг 22 секунд болгосон. `persistence` нь `-Quick`-д байдаг тул хайлтууд
.NET-ийн registry API-аар явдаг болсон — тэр нь олдоогүй үед шууд буцдаг.

### Known-answer баталгаа

```powershell
powershell -NoProfile -File tests\Test-KnownAnswer.ps1
bash tests/test-known-answer.sh
```

Аюулгүй байдал ба тэсвэрлэлтийн тест: `bash tests/test-security.sh` (Linux), `tests\Test-Security.ps1` (Windows); fuzz тест: `python3 tests/fuzz.py`, `tests\Test-Fuzz.ps1`. Юуг хамарч, OWASP/NIST-тэй хэрхэн харгалзаж, юуг хамаардаггүйг [docs/SECURITY-TESTING.md](SECURITY-TESTING.md)-ээс үз.

`SHA256SUMS.txt` нийтлэх нь таны гар дээрх файл нь гаргасан файл мөн гэдгийг
нотолно. Гэхдээ **энэ build, энэ машин дээр зөв ажиллаж байна уу** гэдгийг
хэлэхгүй. Энэ нь хэлнэ: бичигдсэн finding багцыг жинхэнэ шинжилгээний кодоор
дахин тоглуулж, кодын хийдэг зүйлээс биш **дүрмээс** гаргасан хариутай
тулгана. Юу ч цуглуулахгүй, хостод хүрэхгүй — тиймээс зөрүү гарвал энэ нь
build-ийнх, орчиных биш.

Энэ нь зориудаар `--self-test` **биш** — сэжигтэй харагдах файл суулгаад олдог
эсэхийг шалгадаг хувилбар биш. Linux-ийн contract suite түүний нэг хэлбэрийг
хийдэг бөгөөд өөрийн probe-оо ажиллуулж чадаагүй хост дээр аль хэдийн нэг удаа
унасан; Windows дээр тэр санаа бол Defender-ийн илрүүлэлт хүлээж байгаа хэрэг,
AV сэрээхгүй байх нь энэ хэрэгслийн нэгдүгээр хязгаарлалт.

---

### Аль платформ юуг цуглуулдаг вэ

Хоёр хувилбар модулийн жагсаалтаа биш, **гаралтын contract**-аа хуваалцдаг —
Windows дээр 33, Linux дээр 18 модуль. Энэ нь shell талын дутагдал биш:
ялгааны ихэнх нь Linux дээр эквивалентгүй Windows-ийн артефактууд бөгөөд
shell хувилбар нь Windows дээр цуглуулах зүйлгүй зүйлсийг цуглуулдаг.

| | Модулиуд |
|---|---|
| **Хоёуланд** (11) | `sysinfo` `network` `process` `sessions` `users` `services` `persistence` `apps` `indicators` `hashes` `timeline` |
| **Зөвхөн Windows** (22) | `memory` `autoruns` `shares` `firewall` `drivers` `prefetch` `usb` `pshistory` `obfscan` `rdp` `lateral` `privesc` `browser` `fsartifacts` `deleted` `shadow` `eventlogs` `hives` `mft` `rmm` `useractivity` `motw` |
| **Зөвхөн Linux** (7) | `suid` `sshkeys` `bashhistory` `kernelmods` `logs` `containers` `integrity` |

Зөвхөн Windows-ийн баганын ихэнх нь registry, NTFS, Windows event log —
Prefetch, Shellbags, Mark-of-the-Web, UserAssist, shadow copy, registry hive
зэрэг нь Linux дээр огт байдаггүй. Харин Linux дээр хариу арга хэмжээ авагч
юуг алдаж байгааг нэрлэх нь зүйтэй: **гүйцэтгэлийн нотолгооны модуль байхгүй**
(`prefetch` / `useractivity`-ийн хос алга), **файл хаанаас ирснийг мэдэх
боломжгүй** (`motw` — COR-01 зөвхөн Windows байдгийн шалтгаан нь энэ), мөн
**RMM илрүүлэлт байхгүй** (`rmm`). Анхаарах гурван цоорхой нь модулийн тоо
биш, яг эдгээр.
