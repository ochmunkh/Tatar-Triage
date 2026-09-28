# Security Policy

> Монголоор: доод хэсгийг үзнэ үү.

## Supported versions

Only the most recent release is supported.

| Version | Supported |
|---|---|
| Latest release | Yes |
| Anything older | No — update first |

TATAR is a single file per platform with nothing to install, so updating means
replacing `Tatar.ps1` or `linux/tatar-linux.sh` with the current release. There
are no long-lived branches and no backports: a fix ships in the next release.

Verify what you downloaded before running it. Every release carries
`SHA256SUMS.txt`, and that file — not this repository's documentation — is the
source of truth for hashes.

## Reporting a vulnerability

**Please use [private vulnerability reporting](https://github.com/ochmunkh/Tatar-Triage/security/advisories/new)** —
it is enabled on this repository. The report stays private, the discussion stays
attached to the advisory, and a fix can be prepared before anything is public.

If you would rather not use GitHub, email **nkhbat@yahoo.com**.

Please do not open a public issue for a vulnerability.

A useful report says which edition and version (`summary.json` → `version`),
what an attacker gains, and the shortest sequence that demonstrates it. A
minimal allowlist / IOC file or a redacted output folder is worth more than a
long description.

### What to expect

This is a one-person project, so **no response time is promised.** Reports are
read and taken seriously, but nothing here commits to a deadline that cannot be
met — an unmet promise in a security policy is worse than no promise. You will
be told what was decided and when a fix ships.

Please give a fix a chance to ship before disclosing publicly. Credit is given
in the CHANGELOG unless you ask otherwise. There is no bug bounty.

## What counts as a vulnerability here

TATAR is a read-only evidence collector that runs, with privilege, on a host
that may already be compromised. So the interesting failures are the ones that
break that premise:

- **Anything that writes to or modifies the host under examination** outside the
  output directory the operator chose. Read-only-first is the project's central
  promise; breaking it destroys evidence.
- **Code or command execution through input** — a crafted allowlist or IOC file,
  a filename or path that reaches a shell or gets evaluated.
- **Writing outside the chosen output path** (path traversal, a symlink in the
  output directory being followed).
- **Evidence integrity** — a way to make the SHA-256 manifest, chain of custody
  or `summary.json` disagree with what was actually collected, or to suppress a
  finding without it being recorded as suppressed.
- **Credential or secret exposure in the output** beyond what the README states
  is collected.
- **Anything that sends data off the host.** The tool is offline by design;
  network traffic caused by a normal run is a vulnerability, not a feature.

## What does not count

These are real issues worth reporting — as ordinary
[issues](https://github.com/ochmunkh/Tatar-Triage/issues), not as
vulnerabilities:

- **A false positive or a missed detection.** Findings are heuristic pattern
  matches and are documented as review leads, not verdicts. A wrong finding is a
  bug in a heuristic; it is not a security vulnerability.
- **AV or EDR flagging the script.** It is an unsigned collector that reads
  memory, registry and event logs. That is expected — allow-list it after
  reviewing the source, which is the whole reason the source is readable.
- **Needing Administrator or root** for some artifacts. Documented.
- **The findings a run reports about your own host.** Those are for you to
  triage, not a report about TATAR.

---

# Аюулгүй байдлын журам

## Дэмжигдэх хувилбар

**Зөвхөн хамгийн сүүлийн release дэмжигдэнэ.**

| Хувилбар | Дэмжигдэх эсэх |
|---|---|
| Хамгийн сүүлийн release | Тийм |
| Түүнээс хуучин бүх хувилбар | Үгүй — эхлээд шинэчил |

TATAR нь платформ тус бүрт нэг файл, суулгах шаардлагагүй. Тиймээс шинэчлэх
гэдэг нь `Tatar.ps1` эсвэл `linux/tatar-linux.sh`-ыг одоогийн release-ээр дарж
бичих. Урт хугацааны салбар, backport байхгүй — засвар нь дараагийн release-д
гарна.

Ажиллуулахаасаа өмнө татсан файлаа шалга. Release бүр `SHA256SUMS.txt`-тэй
гарна, хэшийн эх сурвалж нь тэр файл — документ биш.

## Эмзэг байдлыг хэрхэн мэдээлэх

**[Private vulnerability reporting](https://github.com/ochmunkh/Tatar-Triage/security/advisories/new)-ыг
ашиглана уу** — энэ репод асаалттай. Мэдээлэл нь хувийн хэвээр байж, хэлэлцүүлэг
advisory дээрээ хадгалагдаж, ил болохоос өмнө засвар бэлдэх боломж гарна.

GitHub ашиглахыг хүсэхгүй бол **nkhbat@yahoo.com** руу имэйл бичнэ.

Эмзэг байдлын талаар нээлттэй issue үүсгэхгүй байхыг хүсье.

Хэрэгтэй мэдээлэлд: аль edition, ямар хувилбар (`summary.json` → `version`),
халдагч юу олж авах, түүнийг үзүүлэх хамгийн багц дараалал. Жижиг allowlist /
IOC файл, эсвэл эмзэг хэсгийг нь хассан гаралтын хавтас нь урт тайлбараас илүү
үнэ цэнэтэй.

### Юу хүлээх вэ

Энэ бол нэг хүний төсөл, тиймээс **хариу өгөх тодорхой хугацаа амлахгүй.**
Мэдээллийг уншиж, нухацтай авч үзнэ, гэхдээ биелүүлж чадахгүй хугацаа бичихгүй —
аюулгүй байдлын журам дээрх биелээгүй амлалт нь амлалт байхгүйгээс дор. Ямар
шийдвэр гарсныг, засвар хэзээ гарахыг мэдэгдэнэ.

Засвар гарах хүртэл ил тод зарлахгүй байхыг хүсье. Хүсэхгүй гэж хэлээгүй бол
CHANGELOG дээр нэрийг дурдана. Bug bounty байхгүй.

## Энд юу нь эмзэг байдалд тооцогдох вэ

TATAR бол аль хэдийн халдлагад өртсөн байж болох хост дээр, өндөр эрхээр
ажилладаг, зөвхөн уншдаг нотолгоо цуглуулагч. Тиймээс сонирхолтой бүтэлгүйтэл нь
яг тэр үндсэн зарчмыг эвддэг зүйлс:

- **Шинжилж буй хостыг оператор сонгосон гаралтын хавтаснаас гадна бичих,
  өөрчлөх** ямар ч зүйл. Read-only-first бол төслийн гол батламж; түүнийг эвдэх
  нь нотолгоог сүйтгэнэ.
- **Оролтоор дамжсан код эсвэл команд ажиллуулах** — тусгайлан бэлдсэн allowlist
  эсвэл IOC файл, shell-д хүрдэг эсвэл evaluate болдог файлын нэр, зам.
- **Сонгосон гаралтын замаас гадна бичих** (path traversal, гаралтын хавтас
  доторх symlink-ийг дагах).
- **Нотолгооны бүрэн бүтэн байдал** — SHA-256 manifest, chain of custody эсвэл
  `summary.json` нь бодитоор цуглуулсантай зөрөх арга, эсвэл finding-ийг
  suppressed гэж бүртгэлгүйгээр нуух арга.
- **README-д бичсэнээс хэтэрсэн credential, secret гаралтад орох.**
- **Хостоос гадагш өгөгдөл илгээх ямар ч зүйл.** Хэрэгсэл нь зориудаар offline;
  хэвийн run-ийн улмаас гарсан сүлжээний трафик нь боломж биш, эмзэг байдал.

## Юу нь тооцогдохгүй

Эдгээр нь мэдээлэх нь зүйтэй бодит асуудлууд, гэхдээ эмзэг байдал биш —
[issue](https://github.com/ochmunkh/Tatar-Triage/issues) хэлбэрээр:

- **False positive эсвэл алдсан detection.** Finding нь эвристик pattern match
  бөгөөд review хийх сэжүүр, эцсийн дүгнэлт биш гэж документлэгдсэн. Буруу
  finding нь эвристикийн bug, аюулгүй байдлын эмзэг байдал биш.
- **AV / EDR скриптийг тэмдэглэх.** Энэ нь санах ой, registry, event log уншдаг,
  гарын үсэг зураагүй collector. Хүлээгдэж байгаа зүйл — эх кодыг хянаад
  allow-list хий; эх код уншигдахаар байгаагийн гол шалтгаан нь яг энэ.
- **Зарим artifact-д Administrator эсвэл root шаардагдах.** Документлэгдсэн.
- **Run нь чиний өөрийн хостын талаар гаргасан finding-ууд.** Тэдгээр нь чиний
  triage хийх зүйл, TATAR-ийн талаарх мэдээлэл биш.
