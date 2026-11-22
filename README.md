# BHM_Gnioki
Zadanie techniczne do testu eliminacyjnego BHM zespołu Gnioki.

# pcapreport

Narzędzie w C dla Linuksa, które analizuje ruch TCP i UDP z plików `.pcap` / `.pcapng`
i generuje **raport PDF** oraz **8 wykresów PNG**: statystyki ruchu, charakterystykę
komunikacji (przepływy, hosty, usługi, kondycja TCP) oraz wykryte nieprawidłowości.

```
pcapreport -o raport/ -t "Segment DMZ - 20.11" dzien1.pcap dzien2.pcapng
```

## Struktura projektu

```
pcapreport/
├── Makefile
├── README.md
├── src/
│   ├── main.c          CLI (getopt_long), kody wyjścia, orkiestracja
│   ├── util.[ch]       logowanie, alokacja z kontrolą OOM, bufor dynamiczny, formatowanie
│   ├── pcap_reader.[ch] strumieniowy parser pcap (LE/BE, µs/ns) i pcapng (SHB/IDB/EPB/SPB/PB)
│   ├── decode.[ch]     dekodowanie L2-L4: Ethernet/VLAN/QinQ/PPPoE/MPLS, SLL/SLL2, RAW,
│   │                   loopback; IPv4, IPv6 + nagłówki rozszerzeń; TCP, UDP; sumy kontrolne
│   ├── analyzer.[ch]   liczniki globalne, tablica przepływów (hash), hosty, szereg czasowy
│   ├── anomaly.[ch]    metryki pochodne i detektory anomalii (progi w anomaly.h)
│   ├── zcompat.[ch]    kompresja zlib albo wbudowane bloki "stored" (NO_ZLIB=1), CRC32
│   ├── raster.[ch]     płótno RGB: prostokąty, linie z antyaliasingiem, tekst
│   ├── font.h, font_data.c  font bitmapowy (wygenerowany, ASCII, 8-bit alpha)
│   ├── chart.[ch]      wykresy: szereg czasowy (warstwowy/liniowy), słupki poziome i pionowe
│   ├── png_writer.[ch] koder PNG (IHDR/IDAT/IEND, filtr Sub)
│   ├── pdf_writer.[ch] minimalny generator PDF 1.4 (fonty standardowe, obrazy, xref)
│   ├── report.[ch]     skład raportu PDF, eksport PNG, podsumowanie tekstowe
│   └── version.h
├── tests/
│   ├── gen_pcap.py     generator syntetycznych plików pcap/pcapng ze znanymi scenariuszami
│   └── run_tests.sh    testy funkcjonalne (50 asercji) + valgrind
└── tools/
    └── gen_font.py     (tylko dla deweloperów) regeneracja src/font_data.c
```

## Zależności

| Zależność | Po co | Wymagana? |
|---|---|---|
| kompilator C11 (gcc ≥ 7 lub clang), `make` | budowanie | tak |
| **zlib** (`zlib1g-dev`) | kompresja DEFLATE strumieni PNG i PDF | nie — `make NO_ZLIB=1` buduje wersję bez żadnych zależności |
| python3 | tylko generator danych testowych | nie (tylko `make test`) |
| valgrind, qpdf | dodatkowa weryfikacja w `make test` | nie |

zlib to jedyna biblioteka zewnętrzna: jest w każdej dystrybucji (i zwykle już zainstalowana
jako zależność systemu), a bez niej PNG i strumienie PDF byłyby nieskompresowane
(wykres 900×450 zajmuje ~1,2 MB zamiast ~25 kB).

```
# Debian / Ubuntu
sudo apt install build-essential zlib1g-dev
# Fedora / RHEL / Rocky
sudo dnf install gcc make zlib-devel
# Arch
sudo pacman -S base-devel zlib
# Alpine
sudo apk add build-base zlib-dev
```

## Kompilacja

```
make              # wersja produkcyjna (-O2, zlib)
make NO_ZLIB=1    # bez żadnej zależności poza libc i libm
make debug        # AddressSanitizer + UndefinedBehaviorSanitizer
make test         # generuje dane testowe i uruchamia testy (wymaga python3)
sudo make install # /usr/local/bin/pcapreport  (PREFIX=... aby zmienić)
```

Kod kompiluje się bez ostrzeżeń z `-Wall -Wextra -Wpedantic -Wshadow -Wformat=2`
w gcc i clang.

## Uruchomienie

```
pcapreport [opcje] PLIK.pcap [PLIK2.pcapng ...]

  -o, --output DIR      katalog wyjściowy (domyślnie ./pcapreport-out)
  -t, --title TEXT      tytuł raportu
  -n, --top N           długość list top-N w tabelach i wykresach (1-50, domyślnie 10)
      --max-flows N     limit śledzonych przepływów (domyślnie 1 000 000, ~208 B każdy)
      --max-hosts N     limit śledzonych hostów (domyślnie 1 000 000)
      --no-checksum     nie weryfikuj sum kontrolnych IPv4/TCP/UDP
      --no-pdf          nie twórz report.pdf
      --no-png          nie twórz wykresów PNG
  -s, --summary         wypisz podsumowanie i listę ustaleń na stdout
  -q, --quiet / -v, --verbose
  -V, --version / -h, --help
```

`-` jako nazwa pliku oznacza standardowe wejście, np. przechwytywanie na żywo:

```
sudo tcpdump -i eth0 -w - -c 50000 | pcapreport -o live/ -
```

Przykłady:

```
pcapreport -o out/ capture.pcap
pcapreport -s -n 20 -t "Incydent #4711" -o raport_4711/ /var/captures/*.pcapng
pcapreport --no-pdf -o wykresy/ ruch.pcap          # tylko PNG
```

**Pliki wyjściowe** (w katalogu `-o`):
`report.pdf`, `01_throughput.png`, `02_packet_rate.png`, `03_protocols.png`,
`04_packet_sizes.png`, `05_top_talkers.png`, `06_top_services.png`, `07_tcp_flags.png`,
`08_tcp_events.png`.

**Kody wyjścia:** `0` sukces · `1` błąd składni wywołania · `2` żaden plik nie dał się odczytać
(raport nie powstaje) · `3` raport utworzony, ale część plików wejściowych była nieczytelna ·
`4` błąd zapisu wyników. Plik obcięty w połowie rekordu nie jest błędem: przetwarzane są
wszystkie kompletne rekordy, a stan pliku trafia do raportu i na stderr.

## Weryfikacja działania

1. **Testy automatyczne** — `make test`. Skrypt generuje pliki ze znaną zawartością
   i sprawdza m.in.: wykrycie każdego zasymulowanego scenariusza, identyczne statystyki dla
   tego samego ruchu zapisanego jako pcap (LE, µs) i pcapng (BE, ns), obsługę plików
   obciętych, uszkodzonych, pustych, losowych bajtów, katalogu zamiast pliku, stdin,
   kody wyjścia, a na koniec przepuszcza przypadki przez valgrind (`--leak-check=full`).

2. **Ręcznie na przykładowym pliku:**
   ```
   python3 tests/gen_pcap.py /tmp/demo
   ./pcapreport -s -o /tmp/demo/out /tmp/demo/sample.pcap
   ```
   Oczekiwane (lista na stdout, szczegóły w rozdziale 8 PDF): skan portów
   10.0.0.66 → 10.0.0.20 (306 portów), sweep TCP/445 (60 hostów), SYN flood na 10.0.0.30:80,
   beaconing 10.0.0.15 → 203.0.113.50:8443 co 30 s, amplifikacja DNS w kierunku 10.0.0.40,
   pakiety z nieprawidłowymi flagami, retransmisje na połączeniu 10.0.0.11 (ok. 8%),
   zero-window, pakiet LAND, 2 uszkodzone pakiety.

3. **Na własnym ruchu i porównanie z Wiresharkiem:**
   ```
   sudo tcpdump -i any -w /tmp/moj.pcap -c 20000
   ./pcapreport -s -o /tmp/moj_out /tmp/moj.pcap
   capinfos /tmp/moj.pcap                 # liczba pakietów, bajtów, czas trwania
   tshark -r /tmp/moj.pcap -q -z conv,tcp # porównaj z tabelą "Largest flows"
   tshark -r /tmp/moj.pcap -q -z io,phs   # porównaj z udziałem protokołów
   ```
   Uwaga: przy przechwytywaniu na hoście nadawcy pakiety wychodzące mają zwykle złe sumy
   kontrolne (offload karty sieciowej) — narzędzie rozpoznaje ten przypadek i oznacza
   go jako INFO, a nie problem sieci.

4. **Sanitizery i fuzzing** — `make debug`, a następnie uruchamianie na zmutowanych plikach.
   W trakcie tworzenia narzędzie przeszło 400 iteracji fuzzingu mutacyjnego oraz cały
   korpus testowy tcpdump (831 rzeczywistych, często celowo uszkodzonych plików, dziesiątki
   typów łącza) bez żadnego zgłoszenia ASan/UBSan.

## Kluczowe decyzje projektowe

**Własny parser pcap/pcapng zamiast libpcap.** Formaty są proste i dobrze udokumentowane,
a własny parser daje pełną kontrolę nad obsługą błędów: każde pole długości jest walidowane
(limit 16 MiB/rekord), obcięty ostatni rekord kończy plik „miękko”, uszkodzony nagłówek
rekordu zatrzymuje ten plik z czytelnym komunikatem, a pozostałe pliki są przetwarzane dalej.
Odczyt jest strumieniowy (bufor 1 MiB, jeden rekord w pamięci), więc pamięć nie zależy od
rozmiaru pliku: 1,2 GB / 1,8 mln pakietów to ~1,2 s i ~8 MB RSS. Obsługiwane są oba formaty
w obu kolejnościach bajtów, rozdzielczości µs/ns i dowolne `if_tsresol`/`if_tsoffset` w pcapng.

**Własny PDF i PNG zamiast cairo/libharu/libpng/gnuplot.** Potrzebne prymitywy (tekst,
prostokąty, linie, obrazy RGB) mieszczą się w ~600 liniach; ciężkie biblioteki graficzne
(cairo pociąga za sobą pixman, freetype, fontconfig) nie są wszędzie dostępne w wersji
deweloperskiej. PDF używa 14 standardowych fontów (Helvetica, Courier), które każdy
czytnik ma wbudowane, więc nic nie trzeba osadzać, a tabela szerokości znaków z AFM daje
dokładny skład i zawijanie tekstu. Wykres jest renderowany raz do bufora RGB, a potem ten
sam obraz trafia do PNG i do PDF (XObject z FlateDecode): oba wyjścia są spójne.

**Raport po angielsku.** Standardowe fonty PDF obsługują wyłącznie kodowanie WinAnsi,
w którym brak znaków ą, ę, ł, ś, ż, ź, ć, ń. Polskie znaki wymagałyby osadzenia fontu
TrueType (dodatkowa zależność lub kilkaset kB w binarce), dlatego raport jest anglojęzyczny,
jak większość raportów technicznych.

**Bez „płaskiego” zapisu wszystkich pakietów.** Szereg czasowy ma adaptacyjną rozdzielczość
(1 ms → 2 ms → 10 ms → … aż wszystko zmieści się w 600 przedziałach), więc stała, mała
pamięć wystarcza zarówno dla 2-sekundowego, jak i tygodniowego przechwycenia. Przepływy
i hosty trzymane są w tablicach mieszających z alokacją blokową i twardymi limitami
(`--max-flows`, `--max-hosts`); przekroczenie limitu jest raportowane, a sumy globalne
pozostają dokładne.

**Znaczniki czasu.** Pakiety z czasem sprzed 1995 r. lub z przyszłości (zegar niesprawny)
są liczone, ale wyłączone z osi czasu — inaczej jeden błędny znacznik „rozciągnąłby” wykres
na 50 lat. Fakt ten trafia do ustaleń.

## Co jest analizowane

* **Statystyki:** pakiety/bajty per protokół (TCP, UDP, ICMP, inne/nie-IP), IPv4/IPv6,
  fragmenty, przepustowość średnia i szczytowa, tempo pakietów, rozkład rozmiarów ramek.
* **Komunikacja:** przepływy dwukierunkowe (5-krotka), strona klienta/serwera (z SYN lub
  heurystyki portów), top hosty, top usługi (port serwera), największe przepływy ze stanem
  (closed/reset/unanswered/rejected/mid-stream).
* **Kondycja TCP:** ustanowione / nieodebrane / odrzucone połączenia, RTT handshake
  (min/mediana/p95/max), retransmisje per kierunek (z wyłączeniem keep-alive), luki w
  numeracji sekwencji (utrata przed punktem przechwytu), zero-window, flagi.

### Wykrywane nieprawidłowości (progi w `src/anomaly.h`)

| Detektor | Kryterium (domyślne) | Poziom |
|---|---|---|
| Skan pionowy portów (TCP/UDP) | ≥ 50 różnych portów jednego celu bez nawiązanej sesji | HIGH |
| Sweep (skan poziomy) | ≥ 25 hostów na tym samym porcie bez sesji | HIGH |
| SYN flood | ≥ 100 półotwartych SYN do jednej usługi, ≥ 50% jej SYN, ≥ 3 źródła | HIGH |
| Amplifikacja UDP | port 53/123/161/1900/11211…, odpowiedź/zapytanie ≥ 10×, ≥ 100 KB | HIGH |
| UDP flood | ≥ 10 000 pakietów UDP i ≥ 1000 pkt/s do hosta, prawie bez odpowiedzi | HIGH |
| Nieprawidłowe flagi TCP | SYN+FIN, SYN+RST, NULL, XMAS, FIN bez ACK | MEDIUM/HIGH |
| LAND / adres multicast jako źródło / port 0 | dowolne wystąpienie | HIGH/MEDIUM |
| Beaconing (C2 / polling) | ≥ 8 połączeń, odstęp ≥ 1 s, zmienność odstępów ≤ 15% | MEDIUM |
| Retransmisje | globalnie ≥ 2% (≥ 10% = HIGH); per połączenie ≥ 5% | MEDIUM/HIGH |
| Nieudane połączenia | ≥ 30% prób TCP bez odpowiedzi lub z RST | MEDIUM/HIGH |
| Zero-window, burze RST (≥ 100 od hosta) | dowolne wystąpienie / próg | MEDIUM |
| Pakiety uszkodzone | złe IHL/długości, obcięte nagłówki, data offset < 5, zła długość UDP, zepsuty łańcuch IPv6 | MEDIUM/HIGH |
| Złe sumy kontrolne | ≥ 90% od jednego hosta → offload (INFO), w innym przypadku MEDIUM | INFO/MEDIUM |
| Jakość przechwytu | obcięcie przez snaplen, cofające się/niewiarygodne znaczniki czasu, luki sekwencji, nieobsługiwane typy łącza, przekroczone limity | INFO/MEDIUM |

Są to heurystyki na ruchu obserwowanym pasywnie — wskazują wzorce warte zbadania,
a nie dowód ataku. Ładunek (payload) nie jest analizowany.

## Ograniczenia

* Fragmenty IP są liczone, ale nie składane (porty ma tylko pierwszy fragment).
* Nieobsługiwane typy łącza (np. 802.11/radiotap, USB, Bluetooth) są liczone tylko w sumach
  i wymienione w ustaleniach.
* Utraty pakietów przez sam mechanizm przechwytywania nie da się odróżnić od utraty w sieci
  inaczej niż przez licznik luk w numeracji sekwencji.
