# AV / EDR safety

**English** · [Монгол](#монгол)

TATAR exists so that a first responder can collect triage data from a live,
production endpoint *without* first negotiating with the security team. That is
only true while the collector keeps behaving the way this document says it
does. So the claims below are not promises in a README — each one has an ID,
and each ID has a check in
[`.github/scripts/check_av_safety.py`](../.github/scripts/check_av_safety.py)
that runs on every push. If a commit breaks a claim, the build fails and names
the claim, the file and the line.

The cross-reference goes both ways: a claim written here with no check behind
it fails the build too. Neither half can drift ahead of the other.

## The claims

| ID | Claim | How it is enforced |
|----|-------|--------------------|
| **AV-01** | No network egress | No HTTP/DNS/mail client, no `/dev/tcp`, no download cmdlet anywhere in the execution path. The collector never contacts anything — no update check, no telemetry, no reputation lookup. |
| **AV-02** | No credential material is read | No LSASS access of any kind, and no credential-dumping API. On Linux `/etc/shadow` is read only to list accounts whose password field is **empty**; the check is pinned to an `awk` program that prints the username and never the hash. |
| **AV-03** | No AMSI, ETW or AV tampering | The AMSI internals, `Set-MpPreference`, `setenforce` and friends must not appear in the source *at all* — not even inside a string, which is where a bypass would hide them. |
| **AV-04** | No dynamic or obfuscated execution | No `Invoke-Expression`, no `[scriptblock]::Create`, no `FromBase64String`, no `-EncodedCommand`, no `eval`, no `base64 -d`. Everything the tool runs is readable in the file you are reading. |
| **AV-05** | EDR-sensitive operations are off by default | `-CollectHives`, `-ExportEvtx`, `-MemoryDump` and `--dump-deleted` all default to off, and each module is checked to still honour its flag before doing anything. A default flipped to on fails the build. |
| **AV-06** | No driver or binary is shipped | The repository is scanned for `.exe`, `.sys`, `.dll`, `.so`, `.bin`, `.msi` and `.scr`. There are none. Memory acquisition is pinned to an operator-supplied `tools\winpmem.exe` that this project does not distribute. |
| **AV-07** | Host state is not modified | No delete, no permission change, no process or service control, no registry write. The only `rm` allowed is on the collector's own `mktemp` scratch files — a literal path, or a variable not assigned from `mktemp`, fails the build. The one permission change allowed takes access *away* from the collector's own evidence folder (`chmod -R go-rwx "$OUTDIR"` on Linux, a protected ACL on that folder on Windows); any other `chmod` or `Set-Acl` fails the build. |
| **AV-08** | No persistence is installed | No service, no scheduled task, no cron entry, no Run key, nothing written under `/etc`. Collection ends when the process ends. |
| **AV-09** | Collected text cannot execute in the analyst's tools | Every CSV this tool writes carries host-controlled text, and a cell beginning with `=`, `+`, `@` or `-` is a **formula** in Excel, LibreOffice and Sheets. A file named `=cmd\|'/c calc'!A1.txt` on the suspect host would otherwise run code on the *analyst's* machine. All five CSV writers go through one guard; a bare `ConvertTo-Csv` or `Export-Csv` fails the build. A negative number is left alone. |

## What an EDR *will* see

Being honest about this is the point of the document. A triage collector that
nothing noticed would not be collecting anything.

A default run reads process, network, service, autorun and account state
through the platform's own interfaces, reads registry values and user-activity
artifacts on Windows, walks parts of the filesystem, and runs a handful of
built-in utilities (`arp`, `route`, `ipconfig`, `netstat`, `wevtutil`, `reg
query`; `ps`, `ss`, `systemctl`, `dpkg`/`rpm`, `find` on Linux). An EDR with
script-block logging on will see the script, and should — it is not hidden.
What it will not see is any of the behaviour in the table above, which is what
actually generates alerts.

Three operations are gated behind flags precisely because they *do* look like
an attack, and they are off unless you ask:

- **`-CollectHives`** — `reg save` of `SAM`, `SECURITY`, `SYSTEM`, `SOFTWARE`.
  This is a credential-theft technique and mature EDR products alert on it.
  The output contains credential material; encrypt it and handle it per policy.
- **`-ExportEvtx`** — exporting full event logs. Noisy, occasionally flagged.
- **`-MemoryDump`** — requires you to place a third-party acquisition tool in
  `tools\`. It is not shipped, and the driver it loads is commonly blocked by
  HVCI / Memory Integrity on Windows 10 and 11.

## What is not claimed

The checks prove things about the **source in this repository**. They do not
prove that the copy you are holding is that source — verify the release hash
against the tag — and they cannot promise that no AV product will ever produce
a false positive on a large PowerShell script that enumerates autoruns. They
are a guarantee about behaviour, not about every vendor's heuristics.

## Verify it yourself

```bash
python3 .github/scripts/check_av_safety.py .
```

The script is about 300 lines and each claim is a single named function. If you
do not trust the summary, read the function — that is why the IDs are here.

---

<a name="монгол"></a>

# 🇲🇳 AV / EDR аюулгүй байдал

[English](#av--edr-safety) · **Монгол**

TATAR-ийн оршин байх гол шалтгаан нь дараах зүйл юм: анхан шатны хариу арга
хэмжээ авагч нь ажиллаж байгаа, үйлдвэрлэлийн орчны хостоос triage мэдээлэл
цуглуулахдаа аюулгүй байдлын багтай **урьдчилан тохиролцох шаардлагагүй** байх.
Гэхдээ энэ нь цуглуулагч энэ баримтад бичсэн ёсоороо ажиллаж байгаа цагт л үнэн.
Тиймээс доорх мэдэгдлүүд нь README дээрх энгийн амлалт биш. Тус бүр нь ID-тай,
ID бүр нь
[`.github/scripts/check_av_safety.py`](../.github/scripts/check_av_safety.py)
дотор шалгалттай бөгөөд push бүр дээр ажиллана. Хэрэв аль нэг commit мэдэгдлийг
зөрчвөл build амжилтгүй болж, аль мэдэгдэл, аль файлын аль мөрөнд зөрчигдсөнийг
нэрлэж өгнө.

Хөндлөн шалгалт хоёр тийш ажиллана: энд бичсэн боловч шалгалтгүй мэдэгдэл бас
build-ийг амжилтгүй болгоно. Баримт бичиг, шалгалт хоёрын аль нэг нь нөгөөгөөсөө
түрүүлж чадахгүй.

## Мэдэгдлүүд

| ID | Мэдэгдэл | Хэрхэн баталгаажсан |
|----|----------|---------------------|
| **AV-01** | Сүлжээнд гардаггүй | Гүйцэтгэлийн замд HTTP/DNS/mail клиент, `/dev/tcp`, татаж авах cmdlet огт байхгүй. Шинэчлэлт шалгахгүй, телеметр илгээхгүй, нэр хүндийн лавлагаа хийхгүй. |
| **AV-02** | Нууц үгийн материал уншдаггүй | LSASS-д ямар ч хандалт байхгүй. Linux дээр `/etc/shadow`-г зөвхөн **хоосон нууц үгтэй** бүртгэлийг жагсаахад уншина; шалгалт нь зөвхөн хэрэглэгчийн нэрийг хэвлэдэг `awk` програмд тогтоогдсон — hash хэзээ ч уншигдахгүй. |
| **AV-03** | AMSI, ETW, AV-д халддаггүй | AMSI-ийн дотоод нэрс, `Set-MpPreference`, `setenforce` зэрэг нь эх кодод **огт** байж болохгүй — тэмдэгт мөр дотор ч гэсэн. Яг тэнд bypass нуугддаг. |
| **AV-04** | Динамик буюу далдалсан гүйцэтгэл байхгүй | `Invoke-Expression`, `[scriptblock]::Create`, `FromBase64String`, `-EncodedCommand`, `eval`, `base64 -d` аль нь ч байхгүй. Хэрэгслийн ажиллуулдаг бүхэн таны уншиж буй файлд ил бичигдсэн. |
| **AV-05** | EDR-д мэдрэг үйлдлүүд анхдагчаар унтраалттай | `-CollectHives`, `-ExportEvtx`, `-MemoryDump`, `--dump-deleted` бүгд анхдагчаар унтраалттай бөгөөд модуль бүр үйлдэл хийхээсээ өмнө өөрийн флагаа шалгасаар байгааг нотолно. Анхдагчийг асаавал build унана. |
| **AV-06** | Driver, binary нийлүүлдэггүй | Репог `.exe`, `.sys`, `.dll`, `.so`, `.bin`, `.msi`, `.scr` өргөтгөлөөр шүүнэ. Нэг ч байхгүй. Санах ойн зураг авалт нь энэ төслийн тараадаггүй, операторын өөрөө байрлуулах `tools\winpmem.exe`-д тогтоогдсон. |
| **AV-07** | Хостын төлөвийг өөрчилдөггүй | Устгалт, эрхийн өөрчлөлт, процесс/үйлчилгээний удирдлага, бүртгэлийн бичилт байхгүй. Зөвшөөрөгдсөн цорын ганц `rm` нь цуглуулагчийн өөрийн `mktemp` түр файлууд — шууд зам бичих, эсвэл `mktemp`-ээс үүсээгүй хувьсагч заавал build-ийг унагаана. Зөвшөөрөгдсөн цорын ганц эрхийн өөрчлөлт нь цуглуулагчийн өөрийн нотлох баримтын хавтаснаас хандалтыг *хасах* (Linux: `chmod -R go-rwx "$OUTDIR"`, Windows: тухайн хавтасны хамгаалагдсан ACL); өөр `chmod`, `Set-Acl` build-ийг унагаана. |
| **AV-08** | Байнгажуулалт суулгадаггүй | Үйлчилгээ, төлөвлөсөн даалгавар, cron бичлэг, Run түлхүүр байхгүй, `/etc` дор юу ч бичихгүй. Процесс дуусахад цуглуулалт дуусна. |
| **AV-09** | Цуглуулсан текст шинжээчийн хэрэгсэл дээр ажиллаж чадахгүй | Энэ хэрэгслийн бичдэг CSV бүр хостын хяналтанд байсан текст агуулдаг бөгөөд `=`, `+`, `@`, `-`-аар эхэлсэн нүд нь Excel, LibreOffice, Sheets дээр **томьёо** болдог. Сэжигтэй хост дээрх `=cmd\|'/c calc'!A1.txt` нэртэй файл эс бөгөөс *шинжээчийн* машин дээр код ажиллуулна. Таван CSV бичигч бүгд нэг хамгаалалтаар дамжина; ил `ConvertTo-Csv` буюу `Export-Csv` байвал build унана. Сөрөг тоонд хүрэхгүй. |

## EDR юуг **харах** вэ

Үүнийг шударгаар хэлэх нь энэ баримтын гол зорилго. Хэн ч анзаардахгүй triage
цуглуулагч гэдэг нь юу ч цуглуулаагүй гэсэнтэй адил.

Анхдагч ажиллагаа нь процесс, сүлжээ, үйлчилгээ, autorun, бүртгэлийн төлөвийг
платформын өөрийн интерфэйсээр уншина. Windows дээр бүртгэлийн утга болон
хэрэглэгчийн идэвхийн ул мөрийг уншиж, файлын системийн зарим хэсгийг тойрч,
цөөн хэдэн суурин хэрэгсэл ажиллуулдаг (`arp`, `route`, `ipconfig`, `netstat`,
`wevtutil`, `reg query`; Linux дээр `ps`, `ss`, `systemctl`, `dpkg`/`rpm`,
`find`). Script-block logging асаалттай EDR энэ скриптийг харна — харах нь ч
зөв, учир нь хэрэгсэл нуугдахыг оролддоггүй. Харин дээрх хүснэгтэд жагсаасан зан
төлөвийг харахгүй, яагаад гэвэл яг тэдгээр нь дохиолол үүсгэдэг.

Дараах гурван үйлдэл нь халдлагатай төстэй харагддаг тул флагийн ард хаалттай
байдаг бөгөөд та өөрөө тусгайлан асаахгүй бол ажиллахгүй:

- **`-CollectHives`** — `SAM`, `SECURITY`, `SYSTEM`, `SOFTWARE`-ийн `reg save`.
  Энэ бол нууц үг хулгайлах техник бөгөөд чанартай EDR бүтээгдэхүүнүүд дохио
  өгдөг. Гаралтад нууц үгийн материал орно; шифрлэж, дотоод журмынхаа дагуу
  хадгална уу.
- **`-ExportEvtx`** — үйл явдлын бүрэн лог экспортлох. Чимээ шуугиантай,
  хааяа тэмдэглэгддэг.
- **`-MemoryDump`** — `tools\` дотор гуравдагч талын хэрэгсэл байрлуулахыг
  шаардана. Энэ хэрэгсэл түүнийг дагалдуулдаггүй бөгөөд ачаалагдах driver нь
  Windows 10/11 дээр HVCI / Memory Integrity-д ихэвчлэн хориглогддог.

## Юуг мэдэгдээгүй вэ

Шалгалтууд нь **энэ репо дахь эх кодын** тухай нотолгоо өгдөг. Таны гар дээрх
хувилбар яг тэр эх код мөн эсэхийг нотлохгүй — үүний тулд release-ийн hash-ийг
tag-тай нь тулгаж шалгана уу. Мөн autorun жагсаадаг том PowerShell скрипт дээр
ямар ч AV бүтээгдэхүүн хэзээ ч худал сэрэмжлүүлэг (false positive) өгөхгүй гэж амлах боломжгүй. Эдгээр нь зан
төлөвийн баталгаа болохоос үйлдвэрлэгч бүрийн эвристикийн баталгаа биш.

## Өөрөө шалгах

```bash
python3 .github/scripts/check_av_safety.py .
```

Скрипт ойролцоогоор 300 мөр бөгөөд мэдэгдэл бүр нэртэй ганц функц. Хэрэв та
хураангуйд итгэхгүй бол функцийг нь уншина уу — ID-уудыг яг үүний тулд тавьсан.
