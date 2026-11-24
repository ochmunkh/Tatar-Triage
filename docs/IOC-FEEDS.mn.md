# Мэдэгдсэн malware-ийн feed

[English](IOC-FEEDS.md) · [← README](../README.mn.md)

Tatar Triage юуг ч онлайнаар шалгадаггүй. Аль хэдийн мэдэгдсэн malware-ийг танихын тулд feed өг: өөрийн машин дээр бэлдсэн indicator-уудын JSON файлыг `-IOCFile` (Windows) эсвэл `--iocfile` (Linux)-аар дамжуулна. Таарвал indicator-ыг нэрлэсэн, confidence 0.95-тай High finding болно.

## Feed юу чадах, юу чадахгүй

- **Яг тэр файлыг таньдаг.** SHA-256 програмын нэг build-ийг тодорхойлдог бөгөөд дахин build хийсэн sample шинэ hash-тай болно. Нийтийн том цуглуулгууд түгээмэл гэр бүлийн олон build агуулдаг тул мэдэгдсэн commodity malware ихэвчлэн баригдана; нэг байгууллагад зориулж build хийсэн sample баригдахгүй.
- **Сүлжээний indicator hash-аас удаан хүчинтэй.** Command-and-control domain эсвэл хаяг binary өөрчлөгдсөн ч ихэвчлэн хэвээр байдаг тул feed-д зөвхөн hash биш domain, IP-г ч оруул.
- **Hash-ийг гүйлтийн hash-лах файлуудад л тулгана:** ажиллаж буй програмууд болон Windows дээр үйлчилгээнүүд (`binary_hashes.txt`-д жагсдаг), мөн finding-ийн нэрлэсэн аливаа файл. Диск дээр хэвтэж, ажиллаагүй файлыг hash-лахгүй.
- **Зөвхөн SHA-256-г тулгана.** MD5, SHA-1 бичилтийг үл тооно.
- **Шинэ malware-д indicator хараахан байхгүй.** Шинэ зүйлийг барьдаг нь зан төлөвийн шалгалтууд (persistence, алсаас удирдах хэрэгсэл, Mark-of-the-Web, хачин parent ба child процесс, корреляци).

## Feed хэр том байж болох вэ

2026-11-23-нд юутай ч таарахгүй санамсаргүй indicator-оор хэмжсэн тул хугацаа нь зөвхөн feed-ийн өртөг. Windows: Windows 11 workstation, PowerShell 5.1, админ эрхгүй, `-All`, ойролцоогоор 1.5 MB-ийн 23 нотлох текст файл; хугацаа нь summary болон IOC шат. Linux: Linux виртуал машин, `--quick`, root-гүй; хугацаа нь бүтэн гүйлт.

| Feed | Windows | Linux |
|---|---|---|
| 1 hash | 1.5 сек | 0.7 сек |
| 10,000 hash | 3.6 сек | 0.8 сек |
| 100,000 hash, 10,000 IP, 10,000 domain | 6.7 сек | 1.9 сек |
| 1,000,000 hash, 100,000 IP, 100,000 domain | 35 сек | 13.8 сек |

1.12.4 хувилбараас өмнө indicator бүрийг тусад нь хайдаг байсан бөгөөд 10,000 hash Windows дээр 413 сек, Linux дээр 37 сек зарцуулдаг байв. Нийтийн эх сурвалжийн сүүлийн хэдэн долоо хоногийн feed асуудалгүй багтана. Сая сая бичилттэй бүтэн архив ажиллана, гэхдээ хэдэн арван секунд нэмж, том файл болно: дээрх 1.2 сая бичилт 72 MB JSON.

## Feed бэлдэх

1. Интернеттэй шинжээчийн машин дээр итгэдэг эх сурвалжаасаа сүүлийн export-уудыг тат: жишээ нь abuse.ch MalwareBazaar (sample hash), ThreatFox (malware гэр бүлтэй indicator), URLhaus (malware host), үндэсний CERT, эсвэл MISP export. Эх сурвалж бүрийн ашиглалтын нөхцөлийг унш.
2. Утгуудыг дөрвөн текст файлд мөр бүрт нэгээр хий: `hashes.txt` (SHA-256), `ips.txt`, `domains.txt`, `filenames.txt`. `#`-ээр эхэлсэн мөрийг үл тооно.
3. Доорх кодоор хөрвүүл. Зөвхөн Python-ий стандарт сан ашиглаж, SHA-256 hash-ийг л үлдээнэ.
4. `ioc.json`-ийг хариу арга хэмжээ авагчийн зөөвөрлөгч дээр хэрэгслийн хажууд хуул. Dry run (`-DryRun` эсвэл `--dry-run`) юу ч цуглуулахаас өмнө feed уншигдах эсэхийг хэлнэ.
5. Ажил бүрийн өмнө feed-ийг шинэчил. Хуучин feed түүнээс хойш гарсныг алдана.

```python
import json, re

def load(name):
    try:
        with open(name, encoding="utf-8-sig") as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        return []

hashes = [h.lower() for h in load("hashes.txt")]
good = sorted({h for h in hashes if re.fullmatch(r"[0-9a-f]{64}", h)})
feed = {"hashes": good, "ips": sorted(set(load("ips.txt"))),
        "domains": sorted(set(load("domains.txt"))), "filenames": sorted(set(load("filenames.txt")))}
with open("ioc.json", "w", encoding="utf-8") as f:
    json.dump(feed, f)
print("hashes kept:", len(good), "- not SHA-256, skipped:", len(hashes) - len(good))
```

Дараа нь хэрэгслийг түүгээр ажиллуул:

```powershell
.\Tatar.ps1 -All -IOCFile ioc.json
sudo ./tatar-linux.sh --all --iocfile ioc.json
```

## Хоёрдмол хэрэглээтэй үйлчилгээний watchlist

Зарим үйлчилгээг энгийн хүмүүс өдөр бүр ашигладаг, мөн халдлага command-and-control эсвэл дараагийн шатаа байршуулахад ашигладаг, учир нь тэдний traffic ялгарч харагддаггүй: Telegram Bot API, Discord-ийн файлын CDN, paste сайтууд. Тэд collector-ын өөрийн дүрэмд хамаарахгүй, учир нь хэрэглэгч нь Telegram-аар чатладаг хост дээр таарсан нь юу ч хэлэхгүй. Нөхцөл байдал сэжигтэй болгож байвал, жишээ нь тэдгээрийг ашиглах шалтгаангүй сервер эсвэл workstation дээр, feed-дээ оруулж болно.

- **Авч үзэх нэрс:** `api.telegram.org` (bot, Telegram аппын өөрийн traffic биш), `cdn.discordapp.com`, `pastebin.com`, `paste.ee`. Өөрийн тохиолдлууд болон CERT-ийн мэдээлснийг нэм.
- **Зөвхөн яг нэр.** Feed дэх домэйн тэр нэртэй л таарна, дэд домэйнтэй нь биш: `example.com` нь `a.example.com`-той таарахгүй. Хэрэглэгч бүрт шинэ дэд домэйн өгдөг tunnel үйлчилгээг эцэг домэйнээр нь жагсааж болохгүй; тохиолдолд харагдсан нэрсийг жагсаа.
- **Нэр хаанаас олддог вэ.** Windows дээр DNS cache (`dns_cache.txt`) хостын саяхан resolve хийсэн нэрсийг хадгалдаг тул таарах магадлал тэнд өндөр. Linux дээр resolver cache цуглуулагддаггүй тул нэр зөвхөн цуглуулсан бусад текстэд байвал олдоно.
- **Таарсан нь lead.** Feed-ийн таарал бүр, эдгээр нэрсийнх ч, confidence 0.95-тай High болно. Тайлагнахаасаа өмнө аль програм нэрийг resolve хийсэн, хэрэглэгчид энэ үйлчилгээг ашиглах шалтгаан байгаа эсэхийг шалга.

## Офлайн, нууцлалтай байлга

- **Feed-ийг уншдаг, хаашаа ч илгээдэггүй.** Feed юу ч агуулсан гүйлт офлайн хэвээр.
- **Онлайн шалгалт бол тусдаа алхам.** Нотлох баримтын hash (`binary_hashes.txt`) эсвэл хостын холбогдож байсан нийтийн хаягийг (`external_ips.txt`) VirusTotal зэрэг онлайн үйлчилгээнд шалгах нь цуглуулалтын дараа, шинжээчийн машин дээр хийгдэнэ. Энэ нь харилцагчийн hash-ийг гуравдагч талд илгээдэг тул эхлээд харилцагчтай тохир.
