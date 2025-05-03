# cpackages

**cpackages**, [Chrona Linux](https://chronalinux.org.tr) için geliştirilmiş, **Alpine Linux tabanlı** resmi paket kaynak deposudur. Bu depo, Chrona Linux’un kendi ekosistemine ait yazılım paketlerinin **APKBUILD** dosyalarını ve ilgili yardımcı dosyaları içerir.

Chrona Linux, Alpine Linux'un güvenli, hızlı ve hafif yapısını temel alarak geliştirilen, özellikle düşük sistem kaynaklarıyla çalışan cihazları hedefleyen bir işletim sistemidir. **cpackages** deposu, bu sistemin temel bileşenlerini oluşturur ve sürekli güncellenen açık kaynaklı bir geliştirme altyapısı sunar.

---

## Geliştirme Durumu

> ⚠️ **Not:** Chrona Linux halen **beta** aşamasındadır.  
> `cpackages` deposundaki birçok paket hâlâ test sürecindedir.  
> Bu nedenle sistemin tamamı kararsız olabilir ve aktif geliştirme süreci devam etmektedir.  
> Katkı sağlamak, test etmek ve geri bildirimde bulunmak isteyen kullanıcılar için hazırlanmıştır.

---

## Dizin Yapısı

### `main/` – Kararlı Paketler
- Sistem için temel yazılımlar burada bulunur.
- Test edilmiş ve stabil çalışması beklenen paketlerdir.

### `test/` – Deneme ve Beta Paketler
- Geliştirme aşamasındaki paketler burada yer alır.
- Bu paketler sorunlu olabilir ve sistem kararlılığını etkileyebilir.

---

## Kullanım

```sh
apk add abuild alpine-sdk fakeroot sudo
cd main/ornekpaket
abuild -r
```

---

## Katkıda Bulunmak

- Yeni bir paket `test/` dizinine eklenebilir.
- Mevcut paketleri iyileştirip `pull request` gönderebilirsiniz.

---

## Lisans

Her paketin altında uygun açık kaynak lisans bilgisi yer almalıdır.

---

## İletişim ve Topluluk

- Web Sitesi: [https://chronalinux.org.tr](https://chronalinux.org.tr)
- GitHub: [https://github.com/chronalinux](https://github.com/chronalinux)

---

# English Version

**cpackages** is the official **package source repository** for [Chrona Linux](https://chronalinux.org.tr), a lightweight and Alpine Linux-based operating system.

This repository contains the **APKBUILD** files and related build scripts for the software packages used by Chrona Linux.

---

## Development Status

> ⚠️ **Note:** Chrona Linux is currently in **beta** stage.  
> Many of the packages in this repository are still under development and testing.  
> The system may be unstable. Users are encouraged to contribute and report issues.

---

## Directory Structure

### `main/` – Stable Packages
- Contains core and stable packages.
- Used in base system installation.

### `test/` – Beta/Testing Packages
- Includes unstable or experimental packages.
- Once verified, packages are moved to `main/`.

---

## Building a Package

Install required tools and run:

```sh
apk add abuild alpine-sdk fakeroot sudo
cd main/samplepackage
abuild -r
```

Resulting `.apk` files will appear in `~/packages`.

---

## Contributing

- New packages should be added to the `test/` directory.
- Submit improvements via pull requests with clear commit messages.

---

## License

Most packages are based on Alpine Linux and are subject to their respective open-source licenses.

---

## Contact & Community

- Website: [https://chronalinux.org.tr](https://chronalinux.org.tr)
- GitHub: [https://github.com/chronalinux](https://github.com/chronalinux)
