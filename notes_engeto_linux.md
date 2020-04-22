Lekce 1
============

historie bash
-----------
- `history` vypise cislovanou historii prikazu
- `ctrl+r` hledani v historii od konce, `ctrl+r` pro skok na dalsi shodu
- `!!` spusti posledni prikaz, muzu ho doplnit napr `sudo !!`
- `!34` spusti 34. prikaz hisotrie, bez moznosti modifikace
- `fc 34` otevre 34. prikaz historie v textovem editoru, po uprave a ulozeni se vykona


Lekce 2
=============

/bin - vsechny binarky prikazum, primarni nastroje
/sbin - podobne jako bin, ale ne primarni prikazy, spis zalohy, dodatecny sw a nastroje, primo nespustitelne
/boot - soubory spoustene po startu systemu
/dev - devicy, disky, virtualni disky (vda), terminaly, generatory znaku
/etc - soubory s nastavenim systemu, konfiguraky doplnku a nastroju
/home - adresare uzivatelu
/lib /lib64 - binarni knihovny sdilene mezi programy (shared, libraries)
/media - mountovani cd?
/mnt - defaul mount point (flashka)
/opt - optionals, sw tretich stran, viditelne oddelene ze neni soucasti systemu
/proc - zde si drzi data bezici procesy
/root - home adr roota
/run - run files, data se kterymi system potrebuje docasne pracovat
	/srv - neni standardne, nevim
	/sys - neni standardne, nevim, monza ftp?
/tmp - docasne soubory, nahravam sem instalacky, nektere logy, prostor pro testovani generatoru napr (preplneni by nemelo znamenat zhrouceni systemu), vetsinou se pravidelne maze
/usr - ?
/var - logy, konfigurace ktere nejsou staticke (jinak etc), /var/log systemove logy, /messages, /wwww content weboveho serveru


cat
-----
- concatination, tedy zretezeni. Vypise za sebe obsah souboru
- casteji se pouzivat jako rychly vypis jednoho souboru a pipe `cat file.txt | grep xxx`

cd ~student // prejde do home konkretniho uzivatele

word count
----------
wc [file]
wc -l [file]	number of lines
wc -w [file]	number of words 
wc -m [file]	number of chars 
...

pocet souboru v adresari
------------------------
ls -l | wc -l
ls -la | wc -l

tee
---------
- vypis na terminal a do souboru
ls -l | tee output.txt

grep
---------
- print lines matchin a pattern
grep [OPTIONS] PATTERN [FILE...]
grep citron fruits.txt
cat fruits.txt | grep citron
grep -v pattern file 	radky ktere patern neobsahuji
grep -i pattern file	case insensitive

cut
--------
- parsovani sloupcu
cut OPTION... [FILE]...
cut -c 1,2-3 file	rozsah znaku
cut -d ":" -f 1 file	specifikace oddelovace a sloupce
cut -d: -f1 file

tr
--------
- preklad znaku v souboru / nahrazeni znaku
- neumi brat soubor, vzdy pipe
tr [OPTION]... SET1 [SET2]
echo ABCD | tr A B	-> BBCD
echo bike | tr ike eer	-> beer
echo bike | tr eik re	-> beer
echo beer | tr -d e	-> br, -d smazat
echo "hello    beer" | tr -s " "	-> hello beer, -s nahradi opakujici se znaky jednim znakem
echo ABCDEF | tr [:upper:] [:lower:]

sort
--------
- sort lines of a text file
sort [OPTION]... [FILE]...
sort file
sort -r file 	reverse
sort -u file	odstrani duplicity

uniq
-------
- delete repeated lines
- vetsinou v kompbinaci se sort
uniq [OPTION]... [INPUT [OUTPUT]]
sort fruits.txt | uniq

nl
-----
- vypis s cislovanim radku
nl file
nl -i 2 file	interval cislovani
nl -n ln file	zarovnani vlevo, podobne rn vpravo
nl -n rz file	zarovnani vpravo a vypleneni mezerami
nl -w 3 file	nastaveni poctu mezer

diff
-------
- porovnani soboru po radcich
diff soubor1 soubor2
diff fruits.txt fruits-sorted.txt
diff -u fruits.txt fruits-sorted.txt	prehlednejsi vystup


Lekce 3
=======================================================


tar
---------
- tape archive, zabaleni dat do jednoho souboru, primarne bez komprese, pokud neni pouzit option pro kompresi  
- uchovava puvodni soubor  
- vzdy je potreba nejaky prepinac  
- `tar [OPTION...] [FILE]...`  
- `tar -cf archive.tar file1 file2` archivace souboru
- `-c` create, vyrobi balik  
- `-f` filename	
- `-v` verbose, ukecany  
- `tar -tvf archive.tar` vypise obsah archivu (t) podrobne (v)  
- `-x` extrahuje, rozbali balik  
- tar zaroven komprimuje: `-z` gzip, `-j` bzip2, `-J` xz
- `tar -xvf file` extrahuje, pripadne i rozbali, pokud obsahuje kompresi
- `tar -czvf archive.tar.gz file1 file2` komprimace gzip s verbose vypisem

zip, unzip
---------
- zabali a kompresuje, umoznuje pridavat
- `zip archive.zip file1 file2`	vytvori archiv
- `zip archive.zip file3 file4`	prida do archivu
- `-r` pridani slozky i s obsahem
- `-d` smazani soboru z archivu
- `-e` encrypt, zahesluje, heslo se zada do konzole
- `unzip -l archive.zip` vypise zabalena data
- `unzip archive.zip` rozbali	
- `unzip archive.zip -d FOLDER`	rozbaleni do adresare

gzip, gunzip
----------
- gzip je na linuxu castejsi nez zip
- gzip NEARCHIVUJE, pracuje s jednotlivymi soubory, proto se casto pouziva s archivem tar
- gzip NEZACHOVAVA originalni soubory, vytvori .gz soubor
- `gzip file` -> `file.gz`
- `gunzip file.gz` -> `file`

vi, vim
--------
- vi je licensovany, vim je open source
- a - insert na dalsim znaku
- A - insert na konci radku
- o - insert na novem radku
- r - vymeni znak za znak
- w - vpred na zacatek slova (W neresi interpunkci)
- e - vpred na konec slova (E neresi interpunkci)
- b - zpet na zacatek slova (B neresi interpunkci)
- x - smaze znak
- y - kopiruj ve visual modu, yy kopiruj radek
- p - odradkuj a vloz pod, P odradkuj a vloz nad
- dw - smaze slovo (mazani vpred), db mazani slova vzad
- dd - smaze radek 
- set -o vi	prepne shell do vi modu
- set +o vi	vypne vi mod
- :%/The/Das - nahrazeni slova, subtitute
- :noh - zrusit zvyrazneni, treba po hledani


presmerovani vystupu STDOUT STDERR
---------------------
- operatory `> >> 2> 2>>`
- `cmd > file`	vystup zapise do soboru, prepise ho, stejne jako 1>
- `cmd >> file`	prida na konec souboru, append, 1>>
- `cmd 2> file`	presmerovani erroru
- `cmd 2>> file` append erroru
- primarni stdout a stderr ma defaulne vystup do terminalu
- stdin 0, stdout 1, stderr 2
- `cat file1 file2 > fileout 2> fileerr`		out do jednoho souboru, error do druheho
- `cat file1 file2 > file 2>&1`			out i err do jednoho souboru file 
- presmerovani ma prednost pred vsim, okamzite dojde k prepsani a smazani souboru, radeji pouzivat >> (append)

presmerovani vstupu STDIN
------
- do programu muzu posilat vstup PRIMO uzivatelsky, napr `cat > log.txt`, tedy program cat je bez argumentu a interaktivne zachytava uzivatelsky vstup a uklada do souboru dokud neni ukonce `ctrl+d`.  
- `cat | tr [:lower:] [:upper:] >> file`
- vstup muzu posilat NEPRIMO pomoci operatoru: `<` vstup ze souboru, `<<` zarazka, ` <<<` predem napsany string
- `<` posle soubor na vstup programu
- `cat FILE` a `cat < FILE` dela to same, zasila soubor na vsup programu (v prvnim pripade argument?), pripadne `cat FILE | cat`
- `tr` napr neumi prijmout soubor jako argument, musi se zaslat na vstup bud jako `cat FILE | tr a b` nebo `tr a b < FILE`
- `<<` zarazka definuje jak bude vypadat ukoncovaci string
- `cat << EOF >> file`	prijima na vstup dokud neni na vstupu EOF a uklada do souboru
- `<<<` posila na vstup string
- `cat <<< ahoj` vypise `ahoj`
- `cat <<< text` dela to same jako `echo text`

locate
-------
- hledani souboru v celem systemu, extra rychly
- je treba aktualizovat databazi `updatedb`, jinak neukazuje aktualni vysledky
- v /etc/updatedb.conf je konfigurace, napr vyjimky kde nehledat

find
-------
- hledani soboru v danem adresari (podadresarich), siroka parametrizovatelnost, napr podle data
- nemusi byt stejny na vsech systemech, napr na linuxu a macos se muze chovat jinak
- pomalejsi nez locate, nema predvytvorenou databazi
- pouziva se pri skriptovani
- `find PATH OPTIONS` adresar piseme PRED prepinac 
- `find .` vypise vsecny soubory, neni specifikovany patern
- `find . -name patern`	hledej patern v aktualnim adresari
- `find Documents/ -maxdepth 1`
- `-name` hledani paternu, `-iname` case insensitive
- `-maxdepth` `-mindepth` min a max uroven prohledavani
- `-type d` `-type f` hleda jen slozky/soubory
- `find . -maxdepth 1  -name "file*"` zastupne znaky `*` a `?` do ovozovek nebo `\*`
- `find ~ -iname \*athletes\*` vrati celou absolutni cestu, `find . -iname \*athletes\*` vrati relativni cestu

file
-----
- informace o souboru 
- `file soubor.txt`
- `file *`

du
-----
- disk usage, velikost souboru, kolik zabira na disku (kolik zabira bloku)
- minimalni alokovatelna velikost na disku je napr 4K, velikost bloku napr 1K
- `du -h` velikost vsech adresaru, human readable
- `du -ak` vsechny soubory v adresari (a zanorenych) v kB
- `du Documents/ -h` suma za cely adresar
- `du Documents/ -ah` velikost souboru uvnitr adresare
- `ls -lh` zobrazuje realnou velikost souboru, napr 24B, `du` ukaze 4 (bloky), `du -h` pak 4kB, protoze blok ma 1kB a min alokovatelna velikost pro soubor je 4kB

df
-------
- file system disk usage, prehled volneho mista v pameti 
- `df -hT` human readable, typ souborovych systemu

date
------
- zobrazeni a nastaveni casu
- bohate moznosti formatovani\
- `date +%Y` vypis pouze rok\
- `date +%A/%I/%Y/%Z` vice parametru najednou\
- `date +%u` UTC cas\
- `date -d "tomorrow" +%Y` zobrazeni data z retezce spolu s formatovanim\


Lekce 4
=======================================================

uzivatele, users
------
- opravdovi (nesystemovi) vs functional (systemovi) users
- seznam useru v `/etc/passwd`
- nazev uzivatele : kdysi heslo : user id : group id : komentar : domovsky adr : shell
- root ma id vzdy 0, 0-1000 functional users, 1000+ fyzicti uzivatele (neni to ale pravidlo)
- vsichni uzivatele krome root jsou v terminalu oznaceni `$`
- root (superuser) ma id 0, ma maximalni pravomoci, v terminalu oznacen `#`

skupin, groups
------
- skupiny definuji permissions pro uzivatele, kteri jsou jejimi cleny
- uzivatel muze byt clenem vice skupin
- informace o skupinach najdeme v `/etc/group`

id
-------
- vypise informace o uzivateli, bez argumentu aktualnim 

who
-------
- vypis PRAVE PRIPOJENYCH uzivatelu
- `whoami` aktualni user

users
-------
- jednoduchy seznam PRIPOJENYCH uzivatelu

w
-----
- rozsireny seznam PRIPOJENYCH uzivatelu 

superuser, root, admin ..
------------------------
- `su` prepnuti uzivatele-substitute, eskalace prav jineho usera, bez parametru na root, je pozadovano heslo ciloveho uzivatele. Prepnuty uzivatel se spusti v novem shellu (subshellu), prepnuti zpet pomoci `exit`
- `su -c 'prikaz1 prikaz2 ...'`, `su uzivatel -c 'prikaz prikaz'` provedeni prikazu pod root/uzivatelem
- `sudo` (super user do) vykonej prikaz jmenem root, eskalace prav. Uzivatel musi mit pravo pouzivat sudo. Pri sudo uzivatel pouziva sve heslo. 
- sudo muze byt povoleno jen na nektere binarky, je to definovano v `/etc/sudoers` 
- `/etc/sudoers` se edituje pomoci `visudo`, kontroluje spravnost
- `sudo su` prepnuti na root bez znalosti root hesla, prikaz musi byt ale povoleny
- `sudo` na jednotlive prikazy, neni potreba zadavat heslo pokazde, `su` na vetsi praci, vzdy heslo pri prepinani

sudoers
-----
- definice prav superusera s omezenym pristupem (sudo)
- `user ALL=(ALL) ALL` a `%group ALL=(ALL) ALL`: prvni ALL je vzadlene zarizeni (host) pro ktere plati podminky (pro pripad distribuovaneho suders, druhy (ALL) je specifikace uzivatelu kterym zvysujeme prava, treti ALL oznacuje povolene prikazy 
- `ALL ALL=(ALL) ALL` a `ALL ALL=(ALL) NOPASSWD: ALL` umoznuje komukoliv prihlasenemu spustit cokoliv pres sudo, v druhem pripade i bez hesla

hesla v linuxu
-------------
- `/etc/shadow` seznam hesel, uzivatelsky zadana hesla jsou ulozena jako hash, pristup ma jen root. Struktura: user : hash hesla : posledni zmena dny od 1.1.1970 : mid dnu mezi zmenami : max dnu platnost hesla : pocet dni pred upozornenim na platnost : neaktivita dny po vyprseni
- uzivatelska hesla (u roota ne) musi splnovat dictionary check

passwd
--------
- zmena hesla, bez parametru aktualniho usera
- `passwd user1` zmena hesla pro konkretniho usera, nutno znat jeho heslo

user management
--------------
- `useradd USER` vytvoreni usera, vytvaret muze jen root (pripadne sudo) 
- novy user obdrzi ke vsemu defaultni hodnoty
- `sudo useradd -u 111 -g 999 -d /home/other_user -c "Doplnkovy text" other_new_user` ruzne prepinace
- `usermod [options] USER` zmena nastaveni usera, stejne prepinace jako u `useradd`
- `usermod -G group1,group2 user` pridani uzivatele do skupiny/skupin
- `userdel USER` defaultne smaze uzivatele, zaznamy apod, ale zachova email a home adresar
- `userdel -r USER` smaze vsechno, i home
- `passwd USER` zmena hesla uzivatele, nastaveni hesla pro noveho

group management
------------
- `/etc/group` seznam group; nazev : heslo? : groupid : seznam uzivatelu odelen carkami
- soubor muzu editovat, pripsat uzivatele do groupy
- `groupadd GROUP` pridani prazdne groupy
- `groupmod` pro zmenu skupiny, napr `groupmod -n new_name name` pro prejmenovani
- `groupdel`
- `groups USER` vypise skupiny uzivatele

vlastnictvi
------------
- `ls -l` prvni sloupec vlastnicvi usera, druhy vlastnictvi group
- `chown USER FILE` zmena vlastnictvi souboru
- `chgrp USER FILE` zmena vlastnictvi skupiny u souboru
- `chown USER:GROUP FILE` muzu zmenit jen usera, nebo jen group, nebo oboje

permission
------
- pristupova prava k souborum
- rwx|rwx|rwx - jake maji prava user|group|ostatni
- u adresare x znamena moznot vlezt do adresare (stat se validni adresou)
- `chmod` zmena prav, dva typy zapisu, symbolicky a numericky
- symbolicy: napr. u+x (ugoa)(+-=)(rwx), = znamena presne tyto parametry
- numericka: r-4 w-2 x-1, napr. `chmod 755 FILE`, pri 000 muze jenom root
- specielni permissions, `chmod +s`
- sticky bit - aby mohl mit nejakou funkci, musi byt soubor executable, pokud je `S` tak neplatne, musi byt `s`
- SUID - `s`, proces pobezi pod tim userem, kdo je owner, priklad `/bin/chmod` je pokazde spusten pod rootem, stejne tak pri zmene hesla pomoci `/usr/bin/passwd` je diky suid vzdycky provedeno jako root a muze tak modifikovat soubor s hesly `/etc/shadow` vlastneny rootem
- SGID - `s`, soubor bude spusten jako by jej spustila skupina ktera jej vlastni
- sticky bit na adresari - `t`, ma treba `/tmp`, i kdyz mam vsechny prava 777, muzu modifikovat/mazat jen sve souboru, neboli Ber ohled na vlastnictvi souboru
- SUID, SGID a sticky se nastavuji v numericke notaci na zacatku, napr `4xxx`, 4-SUID, 2-GUID, 1-sticky; symbolicky `u+s`, `g+s`, `+t`

umask
------
- defaultni permissions pro nove soubory, dane cislo se odecita od 0777 v pripade adresaru, 0666 u souboru (soubor po vytvoreni neni nikdy executable)
- `umask 0266` nove soubory budou -r--------
- kazdy user muze mit sve umask, umask se musi pridat do .bashrc pro trvalou zmenu

acccess control list ACL
---------------------------
- dodatecna modifikace prav, vhodne spise pro nestandardni/okrajove pripady 
- `getfacl FILE` vypise ACL
- `setfacl -m <ug>:<USERNAME>:<rwx> <FILE>` upravi prava pro soubor pro konkretniho usera/skupinu
- `setfacl -x u:student /etc/services` odstranit konkretni ACL
- `setfacl -b /etc/services` zrusit vsechny ACL
- ve vypisu (ls -l) se zobrazuje jako + na konci prav



Lekce 5
==================================

procesy
-------
- proces jako jedna z mala veci v linuxu neni soubor, proces je bezici instance programu, program je tedy v operacni pameti
- `ps` list bezicich procesu prihlaseneho uzivatele
- `ps -ef` podrobny vypis vsech procesu, vcetne PPID
- `po --forest` graficke znazorneni vazby rodic potomek
- `ps -aux` vsechny bezici procesy, vyuziti procesoru, ram
- `ps f` vetve procesu
- `PID` unikantni cislo procesu, nejnizsi 1, `PPID` parent proces id
- `echo $$` vypise PID aktualniho shellu
- `top` dynamicky vypis procesu
- `top -b -d 5` batch mode, postupny vypis do terminalu, perioda 5s
- `top -b | grep loop0` sleduje jeden proces
- `htop` graficky dynamicky vypis procesu
- `pstree` strom procesu

adresar /proc
-----------
- vyse uvedene prikazy zjistuji informace z /proc, kde jsou procesy ulozeny jako soubory
- `/proc` kazdy ciselny adresar patri danemu procesu, kratkodobe ulozeni dat procesu
- adresar je virtualni souborovy system, soubory nejsou skutecne, nejsou ulozeny na disku, pri kazdem `ls` musi seznam system vygenerovat znova 
- `/proc/PID/fd` ls -l file descriptory, odkud kam tecou data, ukazuje jednotlive streamy kam se ukladaji 
- `cat /proc/cpuinfo` `cat /proc/cpuinfo | grep "model name"` info o procesoru
- `cat /proc/meminfo` informace o vyuziti pameti

signaly
-------
- signaly mezi user space a kernel space, prcesy posilaji signaly i mezi sebou
- `man 7 signal` manual k linuxovym standard (POSIX) signalum, taky `kill -l` 
- 1 `SIGHUP` hang up signal indikujici ukonceni pri odpojeni 
- 2 `SIGINT` interupt proces ctrl+c
- 9 `SIGKILL` nasilne ukonceni procesu
- 11 `SIGSEGV` posle kernel pokud chceme sahnout na zabranou pamet, odkaz na neplatnou pamet
- 15 `SIGTERM` slusne ukonceni procesu
- 18 `SIGCONT` spusti zastaveny proces
- 19 `SIGSTOP` zastaveni prikazem
- 20 `SIGSTOP` zastaveni klavesovou zkratkou `ctrl+z`

kill
-------
- `sleep 1000&` uspani na 1000s, vznikne novy proces (na testovani), `&` spusti proces na pozadi
- `kill` bez specifikace signalu znamena `SIGTERM`
- `kill -<SIG> PID` pro specifikaci procesu, `kill -<SIG> %JOBID` pro specifikaci jobu
- `kill -15 PID` posle signal termination danemu procesu 
- `kill -0 PID` odesle prazdny signal, pro kontrolu existence procesu
- `killall` ukoncuje procesy podle jmena, vsechny s danym jmenem
- `killall -u user proces` ukonci vsechny procesy se jmenem proces od uzivatele user, parametrizovatelne

subshell
-------
- prikaz `bash` spusti novy bash jako subshell, ukonceni `exit` nebo `ctrl+d`. V `ps -ef` vidime ze novy bash ma PPID rovno PID puvodniho shellu - je jeho child
- program muzu spustit v inline subshell pomoci $(PROGRAM) nebo `PROGRAM`. Rodicem spusteneho programu je subshell, nikoli puvodni shell.

pouziti $() ${}
-------------
- `$( prikaz1 | prikaz2 )` spusti skupinu prikazu v subshellu
- `${ prikaz1 | prikaz2 }` spusti skupinu prikazu v aktualnim shellu


priority
-----------
- niceness NI, zaporne cislo je zvyseni priority, kladne cislo snizeni priority, defaultne 0
- priorita PR, celkova priorita procesu, cim nizsi cislo tim vyssi priorita
- PR=20+NI
- `nice -n -20 sleep 1000&` nastaveni niceness pro novy process
- `renice -n 10 PID` zmena niceness beziciho procesu

lsof
------
- list open files
- `lsof` vsechny soubory na kter ukazuje file descriptor, `lsof | grep PID` s jakymi soubory pracuje proces
- `lsof <FILE>` jake procey pracuji se souborem
- `lsof -p <PID>` s jakymi soubory proces pracuje

process status
-------------
- `ps -aux` sloupec STAT
- zombie proces - proces ktery se ukoncil ale parent to nepotvrdil, zustane viset v procesech, nejde killnout

vytizeni zdroju, informace o systemu a hw
-------------
- `cat /etc/os-release` verze systemu
- `w`
- `uptime`
- `free` vyuziti pameni, `free -h` human readable
- `cat /proc/meminfo`

jobs
----
- job je process spusteny aktualnim shellem, ma svoje ID
- nekdy se tak nazyva nekolik procesu vykonavajici jistou ulohu
- `jobs` vypise ulohy/joby, `+` znamena posledni spustena, `-` predposledni, prvni sloupec ID jobu
- `&` (operator) za prikazem zpusobi, ze se prikaz spusti na pozadi
- `bg` spusti obnovi beh pozastaveneho jobu, spusti jej na pozadi aby neblokoval konzoli
- `bg` bez parametru spusti posledni job, `bg %1`/`bg 1` spusti job ID 1
- `fg` presunuti a spusteni jobu v popredi
- proces do pozadi si spustim tehdy, kdyz nechci aby blokoval konzoli (napr dlouha instalace). Pomoci `jobs` zjistim bezici procesy a pomoci `fg` ho muzu opet vyvolat do popredi. Nasledne jej pomoci `ctrl+z` pozastavim a pomoci `bg` presunu na pozadi a muzu opet pracovat v konzoli.

pgrep pkill
-----------
- `pgrep` vypise vsechny procesy s danym jmenem, `pkill` je vsechny i zabije, parametrizovatelne
- `pgrep bash` procesy s bash v nazvu 
- `pgrep -u student` procesy studenta
- vice uzitecnych prepinacu v man

at
------
- odlozene vykonani prikazu

crontab
----------
- daemon pro odlozene/periodicke spousteni prikazu
- `/etc/crontab`, edituje se v textovem editoru
- `crontab` je prikaz ktery s `/etc/crontab` pracuje, `-u` pod konkretnim userem

Lekce 6
============

package management
------------
- high level pkg mngmnt - postara se o sehnani sw, dependencies, vyresi konflikty a zkontroluje cesty, zkontroluje volne misto na disku, rozbali balicek na spravne mista
- low level pkg mngmnt - pouze instaluje balicek, napr `.rpm`, potrdi uspesnost instalace, neresi dependencies, neumi se konfigurovat v zavislosti na masine,
- RedHat - balickovaci system RPM, pkg mngmnt HL: yum, dnf; LL: rpm
- Debian - balickovaci system DEB, pkg mngmnt HL: apt; LL: dpkg
- `/etc/yum.repos.d/` seznam repozitaru pro yum, kazdy muze obsahovat radu mirroru, ne vsechny musi byt enabled

yum
-----
- `yum list available` - dostupne balicky v repozitarich
- `yum list installed` - nainstalovane balicky
- `yum list update` - balicky k aktualizaci
- `yum search pkg`, `yum info pkg` ...
- `yum update` - update balicku (aktualizace)
- `yum install pkg`, `yum update pkg`, `yum downgrade pkg`, yum remove|erase pkg` ...

rpm
-----
- `rpm -ivh package-1.0-4.x86_64.rpm` - install, verbose, hash progress bar
- `-U` upgrade, `e` erase

yes
------
- `yes <ZNAK>` vypisuje periodicky dany znak, muze se pouzit pro odpoved na prompty
- napr. `yes y | yum install <PKG>`

devices
------
- zarizeni, adr `/dev`, reprezentuji hw, nebo nastroje obsluhujici hw
- `tty` zarizeni ktere simuluji displej, rozhrani mezi shellem a terminalem
- `c` na prvnim miste v `ls -l`,  charakter device
- `b` blok device, napr disk, muzeme primountovat
- `p` pipe, predavani dat mezi procesy, je to pseudodevice, neni to zarizeni, ve file nic neni, na disku nic neni, je to predani informaci v ramci pameti
- `l` link

mkfifo
------
- vytvoreni pipe, oznaceni `p` v `ls -l`
- posilani dat z procesu do procesu
- `mkfifo pipe`, v jednom shellu `echo Hello > pipe`, v druhem shellu `cat pipe`

pseudodevices, pseudozarizeni
------
- `full` - zarizeni tvarici se jako plny disk
- `null` - zapsana data zmizi
- `random` - pomaly generator velmi nahodnych znaku
- `urandom` - extremne rychly generator
- `zero` - generator logickych nul

mountovani
------------
- `/etc/fstab` tabulka souborovych systemu, ktere se mountuji pri bootu
- `fdisk -l` seznam oddilu pripojenych zarizeni
- `/dev/sd*` fyzicke disky, pismeno znaci disk, cislo oddil, neni zde mozne prohlizet data, je to blok device, nutno nejprve namountovat
- `mount /dev/sd* /home/USER/DIR` mountovani zarizeni na konkretni misto - mount point
- `mount -t ntfs /dev/sd* /home/USER/DIR` specifikace souboroveho systemu
- `umount /home/USER/DIR` odmountovani
- pri `umount` nesmim byt v danem mount pointu nebo bezet jine procery vyuzivajici zarizeni
- `lsof /dev/sd**` vypise aktualni procesy

dd
-----
- vytvori bitovou kopiu
- pokud na vstupu pouzivam generator, vzdycky definovat blocksize a count

inode
-----
- inode obsahuje metadate o filesystemu - velikost, UID, GID, typ, velikost, pocet bloku, odkaz na blok na disku (vice bloku), prava, ACL atd., NEobsahuje nazev souboru a data
- je oznaceny jednoznacnym cislem, muzeme pomoci nej smazat i poskozeny file
- `ls -li` vypise inody v prvni lekci
- `df -i` pocet inodu v souborovych systemech
- inode tabulka - databaze inodu, zaklad filesystemu, definuje pocet inodu (pevny/dynamicky)
- pri vytvoreni souboru/slozky je alokovan jeden inode

link
-----
- hardlink - `ln <SOUBOR> <HLINK>`, odkaz na konkretni inode, na exisujici soubor, nemuze byt mezi filesystemy kvuli unikatnosti inodu, hardlinky se tvari jako originalni file; pridanim hardlinku pribyde jedna reference (`ls -l` druhy sloupec), pri smazani puvodniho souboru ubyde reference a soubor je zachovan (maze se az kdyz pocet odkazu=0); nevytvari se novy inode; opravneni, vlastnici atd zustavaji puvodni; hardlink neumi odkazovat na adresare; hledani `find . -samefile sample`
- symlink - `ln -s <SOUBOR> <SLINK>, odkazuje na adresu (aboslutni/relativni cestu), je to tedy retezec znaku; netvari se jako file, ale jako `l`; muzeme linkovat i na jiny filesystem; pokud je cilovy sobor smazan, symlink prestane fungovat (broken link); umi odkazovat i na adresare; pro symlink se vytvori novy inode; hledani `find . -type l -name "sample*"`


Linux 7
============
- `/etc/resolv.conf` dns servery
- `/etc/hosts` prvni misto kde se dela DNS resolve, ma prednost pred DNS servery v `/etc/recolv.conf`, na Windows je obdony soubor
- `dig <ADDR>` zjisteni jaka DNS se pouzila, pod polozkou SERVER
- `netstat -rt` zobraz routing table
- `netstat -tulpn` otevrene porty

Linux 8
==========

boot process
------------
- BIOS na zacatku zkontroluje hw, podle MBR master boot record (prvnich 512B disku) skoci na bootovaci oddil?
- GRUB - prvni kus sw linuxu, je na disku, spusti kernel, zacne bootovat
- kernel init
- init - prvni proces systemd, zacne konfigurovat system, zapinat potrebne procesy
- runlevely 0-6

rc - run commands
----------
- `/etc/rc.d/` obsahuje jednotlive runlevely

services
------
- `systemctl` ridi systemd system a managuje servicy
- `systemctl list-units` seznam
- `systemctl statsu httpd` status http deamon servicy
- service muze mit vice procesu
- systemctl reload, restart a dalsi options
- starsi verze systemctl je service

httpd
----------
- apache server
- `/var/www/html/` zde jsou zdrojaky pro httpd
- `/etc/httpd/conf/httpd.conf` konfigurace httpd service
- `systemctl start httpd` zapnuti service
- `systemctl status httpd` kontrola statusu
- `curl localhost` zobrazi obsah souboru definovaeneho v httpd.conf

filesystems
-----------
- `fdisk`

LVM
----
- Logical Volume Manegement
- fyzicke disky spojim do jednoho poolu, ktery pak delim na logicke disky nezavisle na fyzickych discich

logy
-----
- `/var/log/messages` systemove logy, zaznamy o podstatnem deni v systemu
- `/var/log/secure` logy o security


webinar 19.3.
==========

- `if [ -e /etc/passw ]; then echo Yes;else echo No;fi`

alias
-----
- `alias hello='echo Hello World'`
- `alias hello2='echo -e "\n\t"'`, pak `hello2 Hello` udela to same jako `echo -e "\n\t" Hello`
- `unalias`
- list alias?
- alias funguje jen instanci daneho shellu, pri zavreni zanikne

expansions
------
- `echo {1,2,3} list
- `echo {0..5}` vypise posloupnost, `{0..10..2}` definovani kroku 2
- `echo {a..z}`, vypise abecedu, pracuje s tabulkou znaku tak jak jsou za sebou ulozene
- `echo -e "\n\t" Hello`
- `echo file_{a..c}{1..3}.txt` hodi se na generovani nazvu souboru
- `echo {a..c}{1..3}` udela kombinace, `echo {a..c} {1..3}` udela dve nezavisle posloupnosti
- `echo ~` `echo ~student` vypise home adresare uzivatele, hodi se do skriptovani
- `echo a*` vypise vsechny soubory zacinajici a v danem adresari
- 'echo $VARa' vyhodnoti neexistujici promenno VAR, `echo ${VAR}a` vypise promennou a prida k ni `a`, nejprve se udela expansion a pak substitution ??

substitutions
-----------
- `$` znamena substituce/nahrada
- `ls -l $(echo * | cut -f1-3 -d" ")` ls vypise soubory ktere dostane zpet od prikazu v subshellu
- matematika `echo $((1+1))`
- promenna `a=12`, pak `echo $a` vypise hodnotu

uvozovky
------
- dvojite uvozovky `""` vypise substituci a potlaci expanzi; vytvori jeden argument, napr kdyz chci predat argument s mezerou, musim zabalit do dvojitych uvozovek; pouzivaji se pro text a substituci najedno
- `echo "pocet souboru $(ls -l | wc -l)"`
- `echo a"*"` potlaceni funkce hvezdicky, bere to jako retezec
- jednoduche uvozovky `''` potlaci vsechny prikazy, expanzi i substituci, vse bere jako text
- backlash `\` potlaci funkci escape znaku, tedy `echo "\$(ls)"` vypise $(ls), pez lomitka vypise obsah adresare

promenne
-----------
- promena se definuje pomoci rovnitka, nesmi obsahovat mezeru, napr `a=1`
- `for i in {1..5};do echo $((i+1));done`

eval
-------
- pokusi se spustit retezec az jsou vsechny bashove prikazy vyhodnocene ??
- `eval "echo {1..$VAR}"` prvni dosadi promennou, potom az udela expansion

xargs
-----
- rozlozi do rady ??

webinar 24.3.
============

promenne a environment
------------
- set, env, export, unset
- nova promenna se ulozi v lokalnim shellu, viz `set`, nededi se do subshellu
- `export` na ulozeni promenne do env, globalni promenna ktera se dedi do subshellu
- .bash_profile se vola pred .bashrc, existuje i global /etc/bashrc, 
- .bash_logout se provede pri odpojovani od shellu, treba pri ukoncovani ssh
- `source` nacteni souboru, nacteni promennych atd a ulozeni do aktualniho environmentu

bc
----
- kalkulacka, program, umi desetinne cisla a dalsi veci co neumi matematika v substitution `$(())`, umi i logicke vyrazy

skriptovani
------------
- v elerningu kurz skriptovani
- buldin promenne drzi informace o skriptu a jeho argumentech, jsou to promenne 0-9, 0 je path skriptui ze ktere byl volan, zbytek argumenty skriptu
- specialni promenne, $# pocet argumentu, $$ pid shellu, $@ vsechny argumenty seznam, to same $* ale nejaky rozdil tam je, $? exit status posledniho prikazu, $0 aktualne pouzivany shell (bash, zsh..), ve skriptu vypise cestu jakou byl spusten
- promenne nesmi zacinat cislem, jsou to rezervovane promenne pro argumenty skriptu, shell se takovou promennou snazi spustit jako command
- systemove promenne - napr $PATH $USER $RANDOM $SECONDS (sekundy od zacatku skriptu), $LINENUM?  - shell vsechno co neexistuje bere jako prazdnou promennou a vypise prazdny radek v pripade echo, nevyhodi chybu - exit status - 0 uspech, zbytek nejake chyby, grep vyjimka vraci 1 kdyz nenajde zadny radek, coz neni vlastne chyba
- `exit` na konci skriptu ukonci s hodnotou 0, pripadne s predanou hodnotou
- binarky `true` a `false` vraci exit hodnoty 0 resp 1
- shell umi pracovat jenom s jednim typem dat a je to text, az pri samotnem pouziti se vyhodnocuje jestli to neni cislo
- funkce je blok kodu, `function sayHello() {echo hello}`, volat se musi az po definici, klicove slovo `function` neni nutne, funkce pouzivaji vlastni argumenty $1 $2 atd, nejsou to ty same jako argumenty skriptu
- funkci muzu napsat i v shellu, ulozi se do aktualniho environmentu (bude videt v `set`)
- `exit` ukonci shell a nastavi exit status, `return` ukonci funkci a nastavi exit status

| Vestavene promenna | Hodnota |
| ------------------ | ------- |
| `$1` - `$9`        | prvnich 9 argumentu skriptu |
| `$0`               | cesta kterou byl skript zavolan, v shellu vrati pouzity typ shellu |
| `$#`               | pocet argumentu skriptu |
| `$@`               | seznam vsech argumentu |
| `$$`               | PID shellu |
| `$?`               | exit status posledniho prikazu |

webinar 26.3.
===============
- testy, podminky a cykly

testy
--------
- `test` binarka testuje podminku a vraci 0/1, napr `test 1 -eq 2'
- to same pomoci hranatych zavorek `[ 1 -eq 2 ]'
- to same pomoci dvou hranatych zavorek `[[ 1 -eq 2 ]]', PREFEROVANA VARIANTA
- `test` i `[` by mely fungovat  vzdy, byvaji jako binarky v systemu (`which`) i soucasti shellu (`type`), `[[` je novejsi a podporuji vetsi sadu vyrazu
- vysledek testu je mozne vycist pres exit hodnotu `$?`
- testy pro cisla: `-eq -nq -le -ge -lt -gt` 
- testy pro string: `== != -z -n`, napr `[[ -z $VAR ]]` 
- stringy je dobre davat do dvojitych uvozovek pro prevod na retezec, protoze muze mit vice casti a specialni znaky, taky kvuli prehlednosti
- pro soubory: existence `-e -f -d`, prava `-r -x -w`, velikost true vetsi nez 0 `-s`
- `!` pro negaci vyrazu, `[[ ! -f test.txt ]]` nebo `! [[ -f test.txt ]]`
- mezi jednotlivymi prvnky v testu musi byt mezery

| Operator    | Popis |
| ----------- | ----- |
| Aritmeticke |
| `-eq`       | equal |
| `-nq`       | not-equal |
| `-gt`       | greater then |
| `-lt`       | less then |
| `-ge`       | greatr or equal |
| `-le`       | less or equal |
| Retezce     |
| `-z`        | empty |
| `-n`        | existing (non-empty) string |
| `==`        | equal |
| `!=`        | not-equal |
| Soubory     |
| `-e`        | exist |
| `-f`        | exist, file - bezny soubor |
| `-d`        | exist, directory |
| `-r`        | exist, readable pro akt. usera |
| `-w`        | exist, writable pro akt. usera |
| `-x`        | exist, executable pro akt. usera |

retezeni prikazu
-------
- logicke navaznosti - retezeni vyrazu na zaklade logickych operatoru, AND `&&` a OR `||`
- `yum install cowsay && cowsay hello` nasledujici operace se provede pouze pokud bude exit status 0 u predchozi, u OR se provede pri exit 1 ?
- `[[ -d DIR ]] || mkdir DIR && cd DIR`

(jednoduchy odpocet)
----------------
- `for i in {60..1};do echo $i;sleep 1;done && echo FINISH`
- `for i in {5..1};do echo $i;sleep 1;done && while true;do printf "COFFEE ";sleep 0.01;done` coffee stopky

podminky
----------
- `if [[ $1 -ef 1 ]];then echo "arg is 1";else echo "arg not 1";fi 
- if se rozhoduje podle exit status testu, pokud je test syntax chybny, stejne se vetveni provede podle exitu, proti jinym jakzykum je benevolentni
- `if TEST;then NECO;elif TEST;then NECO;else NECO;fi
- (na zacatku skriptu je dobre testovat jestli je uzivatel root, pokud je pro bez skriptu potreba root)
- `case $i in; 1); echo "1";; 2); echo "2";; *); echo "jine";;esac` jako inline nejak nefunguje

cykly
-------
- v bashi tri druhy: while, until, for
- for je iterator, iterovat muzu list cisel, radky vypisu atd
- `for i in 1 2 3 4;do ...;done`
- `for i in $(ls);do cp $i $i.bck;done` ???? zalohovani otestovat
- `for (( var=0; var<=10; var+=2 ));do echo $var;done` C-ckova syntaxe
- `while [[ TEST]];do NECO;done`
- `until [[ TEST ]];do NECO;done` probiha dokud nezacne byt podminka pravdiva, pokud je platna od pocatku telo se neprovede ani jednou
- `break` okamzite ukonci cyklus, z ktereho je zavolan, program pokracuje za klicovym slovem `done`
- `continue` prerusi bezici iteraci cyklu z ktereho je zavolan a zacne novy cyklus
- `break 3` `continue 2` moznost specifikovat kolik vnorenych cyklu se ma prerusit/pokracovat ?

skriptovani poznamky --------
- `./script.sh` spusti se v subshellu
- `. ./script.sh` spusti se v aktualnim shellu
- `shift` posouva argumenty skriptu/funkce smerem k prvnimu, `echo $1;shift;echo $1` vypise prvni a nasledne druhy argument

webinar 31.3.
=======
- `read` vstup u
- `cat < /dev/tcp/192.168.0.103/22` zpusob jak se pripojit na host/port, nejedna s o cestu, ale o built-in prikaz
- `true > /dev/tcp/192.168.0.103/22` testovani portu
- pokud ve skriptu nechci vypisovat chyby tak `>2 /dev/null`

webinar 2.4.
========
- regularni vyrazy
- `ls | grep -E '(\.sh|\.py)$'` soubory s danou koncovkou
- `grep ^# hosts` a `grep ^[^#] hosts` radky s komentarem/bez komentare
- `grep -E` je pokrocily regularni vyraz, regex musi byt v uvozovkach
- hodne se pouzivaji s `grep` a `sed`
- `grep -E "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9] [0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])" hostfile_smp` konrola ip adresy
- `sed` nahrada znaku ??

read
------
- cteni uzivatelskeho vstupu z konzole po stisknuti entru
- pokud neni predana promenna na ulozeni, ulozi se do `REPLY`
- `read VAR` ulozeni do promenne
- `read VAR1 VAR2 VAR3` nacte tri promenne oddelene (defaultne) mezerou, do posledni se uklozi zbytek
- `read -p "Zaadej jmeno a prijmeni: " NAME SURNAME` zobrazeni promptu
- `read -n1 VAR` nacti pouze jeden znak a ukonci (pripadne jiny pocet), `read -n1 -p "Continue (y/n): " VAR`

webinar 7.4. - databaze
=======
- `sqlite3 tamago.db 'CREATE TABLE creatures (id INTEGER PRIMARY KEY, name TEXT NOT NULL, food INTEGER NOT NULL, health INTEGET NOT NULL, is_dead INTEGER NOT NULL DEFAULT 0 );'` 
- query nejsou case sensitive, ale pro lepsi citelnost VELKYMI
- `sqlite` mozno zapnout v interaktivnim rezimu, nebo jako command v argumentem

- `nohup script.sh &` spusti na pozadi 
- `tail -f nohup.out` vypise co vypisuje skript na pozadi


webinar 14.4.
========

beh na pozadi
-----
- `&` na konci radku prikazu spusti prikaz na pozadi
- `nohup`
- `disown`

ruzne
-----
- `cp /tmp/file.txt{,.bck}` shell udela prvni expanzi, taktze vytvori dva argumenty pro cp,, vytvori zalohu file
- `stty -echo` a `stty echo` vypne/zapne zobrazeni psanych znaku, vstup ale existuje na pozadi a prikaz se provede

inicializace linuxu po instalaci
------
- pouzivat dotfiles, vhodne jen na konfiguraci konfigurovatelnych veci (programu), nejde pouzit napr pro vytvareni uzivatelu
- binarni kopie nakonfigurovatelneho systemu, jde pouzit jen ja stejne hw
- Docker images
- automaticky deploy pomoci specialnich nastroju (Ansible, spise na vetsi deploymenty, servery)
- instalacni skript, posloupnost commandu jako se psaly do shellu


webinar 16.4.
=====

prompty
-----
- `$PS1` struktura standardniho promptu, muzu zmenit napr `PS1="[\u@\h]" 
- `$PS2` ?
- `$PS3` ?

porty
-----
- `netstat -tulpn` prehled otevrenych portu
- upnp protokol pro pristup z vnejsi site do vnitrni, jinak pomoci port forwardingu


RUZNE PROBLEMY
------------
- odstraneni pocatecnich nul ze stringu (cisla): `echo 007 | awk '{printf "%d\n",$0}'` nebo `echo 007 | sed 's/^0*//'` (smaze vsechny nuly i v pripade 000)
