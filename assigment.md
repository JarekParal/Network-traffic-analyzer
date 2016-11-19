
# Analyzátor sieťovej prevádzky (Ing. Holkovič)

## Popis:
Vytvorte konzolovú aplikáciu pre analýzu sieťovej prevádzky uloženej vo formáte libpcap ( https://wiki.wireshark.org/Development/LibpcapFileFormat ). Aplikácia bude počítať počet prenesených bajtov na základe definovaných položiek v sieťových rámcoch. Možné položky:
MAC adresa
IPv4 adresa
IPv6 adresa
TCP port
UDP port

Pričom počítanie každej položky je možné ďalej špecifikovať podľa pozície v komunikácii:
zdroj
cieľ
zdroj alebo cieľ
Ďalej musí byť aplikácia schopná vygenerovať zoznam 10 položiek s najväčším počtom bajtov (zoradený zoznam od najväčšieho po najmenší). Napr. 10 IP adries generujúcich najväčšie množstvo dát.

## Použitie:
./analyzer [-i subor] [ -f typFiltra ] [ -v hodnotaFiltra ] [ -s ] [ -d ]
-i subor - (povinný parameter) vstupný súbor vo formáte libpcap
-f typFiltra - (povinný parameter) určenie podľa ktorej položky sa počíta objem dát. Možné hodnoty: mac, ipv4, ipv6, tcp, udp
-v hodnotaFiltra - (povinný parameter) hodnota filtra. Možné hodnoty napr.: 5C:D5:96:2C:38:63 (pre mac), 192.168.1.1 (pre ipv4), 2001::1 (pre ipv6), 80 (pre tcp, udp), top10 (pre mac, ipv4, ipv6, tcp, udp)
-s - (minimálne jeden z parametrov s/d musí byť zadaný) filter sa aplikuje na zdrojové adresy (MAC, IPv4, IPv6, port)
-d - (minimálne jeden z parametrov s/d musí byť zadaný) filter sa aplikuje na cieľové adresy (MAC, IPv4, IPv6, port)

## Formát výstupu:
Výpis aplikácie na stderr bude ignorovaný. Výstup na stdout bude závisieť od zvoleného filtra (hodnota1 a hodnota2 je vysvetlená v ďalšej sekcii):
filter top10 - zoznam max. 10 riadkov v tvare adresa_hodnota1_hodnota2 (kde _ je jeden znak medzery). Napr. 192.168.0.1_120_80
ostatné filtre - výstup bude v tvare hodnota1_hodnota2. Napr. 234_189

## Počítanie bajtov:
hodnota1 - súčet bajtov od druhej vrstvy (t.j. hlavička L2 + hlavička L3 + hlavička L4 + samotné dáta). Pozor: ako určite viete, nie všetky rámce majú všetky hlavičky.
hodnota2 -v prípade filtru "mac", sa počítajú dáta od konca L2 hlavičky. V prípade filtru "ipv4","ipv6" sa počítajú dáta od konca L3 hlavičky. V prípade filtru "tcp", "udp" sa počítajú dáta od konca L4 hlavičky.

## Testovanie:
Program si otestujete zachytením sieťovej komunikácie napr. pomocou Wiresharku, ktorú uložíte ako "Wireshark/tcpdump/...-pcap".
Časom budú dodané testovacie pcap súbory (zo začiatku sa očakáva, že si súbory vytvoríte sami).

## Ukážkový pcap - http://www.stud.fit.vutbr.cz/~iholkovic/isa.pcap:
-f udp -v 101,104 -s => 796 628
-f tcp -v 101 -s -d => 6162 5484
-f tcp -v 103 -s => 5373 4857
-f ipv4 -v 10.10.10.60 -d => 1132 860
-f ipv4 -v 10.10.10.100 -s -d => 354 184
-f mac -v 00:00:00:00:00:05 -s => 11620 10606

## Možné rozšírenia:
A (1.5b) - Možnosť zadania viacerých hodnôt filtra. Parameter -v bude môcť obsahovať viacero položiek oddelených čiarkami (pred ani za čiarkou nebude medzera). Napr.: "192.168.1.1,192.168.1.2,192.168.1.3".
B (3.5b) - Možnosť zadať viacero typov filtrov súčasne. Parameter -f bude môcť obsahovať viacero položiek oddelených bodkočiarkami [středník] (pred ani za ňou nebude medzera). Napr.: "ipv4;tcp". Parameter -v bude môcť obsahovať viacero položiek pre viacero filtrov. Najlepšie je to asi vysvetliť na príklade: "-f ipv4;tcp -v 192.168.1.1,192.168.1.2;80,8080 -s -d". V tomto príklade berieme do úvahy správy odoslané/prijaté z IP adresy 192.168.1.1/192.168.1.2 na porte 80/8080. Pozor: toto rozšírenie nahradzuje predchádzajúce za 1.5b. Takže pri implementovaní tohto rozšírenia dostanete iba 3.5b a nie 5.0b !!!
Ďalšie nápady na rozšírenia píšte do fóra.

## Ďalšie informácie:
povolené jazyky sú C/C++
preklad aplikácie musí byť realizovaný pomocou Makefilu (príkaz "make" bez parametrov)
aplikácia bude testovaná vo virtuálnom stroji, ktorý máte k dispozícii
v prípade nejasností ohľadom zadania prosím využite príslušné vlákno vo fóre (WIS)
program musí skončiť v rozumnom čase, napr. spracovanie súboru s 10 paketmi by nemalo trvať 10 minút
obsahom súboru README bude IBA login autora, zoznam implementovaných rozšírení a zoznam vecí, ktoré nie sú implementované