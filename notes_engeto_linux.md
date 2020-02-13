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
`tar [OPTION...] [FILE]...`  
`tar -cf archive.tar file1 file2`  
`-c` create, vyrobi balik  
`-f` filename	
`-v` verbose, ukecany  
'tar -tvf archive.tar` vypise obsah archivu (t) podrobne (v)  
`-x` extrahuje, rozbali balik  
- tar zaroven komprimuje: `-z` gzip, `-j` bzip2, `-J` xz
`tar -czvf archive.tar.gz file1 file2` komprimace gzip s verbose vypisem

zip, unzip
---------
- zabali a kompresuje, umoznuje pridavat
\\ `zip archive.zip file1 file2`	vytvori archiv
\\ `zip archive.zip file3 file4`	prida do archivu
\\ `-r` pridani slozky i s obsahem
\\ `-d` smazani soboru z archivu
\\ `unzip -l archive.zip`	vypise zabalena data
\\ `unzip archive.zip`		rozbali	
\\ `unzip archive.zip -d FOLDER`	rozbaleni do adresare


gzip, gunzip
----------

- gzip je na linuxu castejsi nez zip
- gzip NEARCHIVUJE, pracuje s jednotlivymi soubory, proto se casto pouziva s archivem tar
- gzip NEZACHOVAVA originalni soubory, vytvori .gz soubor
// `gzip file` -> `file.gz`
// `gunzip file.gz` -> `file`


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
- operatory > >> 2> 2>>\
`cmd > file`	vystup zapise do soboru, prepise ho, stejne jako 1>
cmd >> file	prida na konec souboru, append, 1>>
cmd 2> file	presmerovani erroru
cmd 2>> file	append erroru
- primarni stdout a stderr ma defaulne vystup do terminalu
- stdin 0, stdout 1, stderr 2
- cat file1 file2 > fileout 2> fileerr		out do jednoho souboru, error do druheho
- cat file1 file2 > file 2>&1			out i err do jednoho souboru file 
- presmerovani ma prednost pred vsim, okamzite dojde k prepsani a smazani souboru, radeji pouzivat >>

presmerovani vstupu STDIN
------
- operatory < << <<<
cat | tr [:lower:] [:upper:] >> file
cat << EOF >> file	prijima na vstup dokud neni na vstupu EOF a uklada do souboru
cat < filex	je to same jako		cat filex | cat		posli na vstup 
bc <<< cmd	nejprve vyhodnoti cmd a posle na vstup bc

locate
-------
- hledani souboru v celem systemu, extra rychly
- je treba aktualizovat databazi updatedb
- v /etc/updatedb.conf je konfigurace, napr vyjimky kde nehledat

find
-------
- hledani soboru v danem adresari, siroka parametrizovatelnost, napr podle data
- nemusi byt stejny na vsech systemech, napr na linuxu a macos
find . -name patern	hledej patern v aktualnim adresari

du
------
- velikost souboru, kolik zabira na disku
- minimalni alokovatelna velikost na disku je 4K, napr
du -ak	vsechny soubory v adresari (a zanorenych) v kB
du -ah	variabilni jednotka velikosti

df
-------
- disk free
df -h	human readable
du vs df ????

date
------
- zobrazeni a nastaveni casu
- bohate moznosti formatovani\
`date +%Y` vypis pouze rok\
`date +%A/%I/%Y/%Z` vice parametru najednou\
`date +%u` UTC cas\
`date -d "tomorrow" +%Y` zobrazeni data z retezce spolu s formatovanim\


Lekce 4
=======================================================

users
------
- opravdovi vs functional users
- seznam useru v `/etc/passwd`
- nazev uzivatele : kdysi heslo : user id : group id : komentar : domovsky adr : shell
- root ma id vzdy 0, 0-1000 functional users, 1000+ fyzicti uzivatele (neni to ale pravidlo)

id
-------
- vypise informace o aktualnim uzivateli

who
-------
- vypis pripojenych uzivatelu
\\ `whoami` aktualni user

users
-------
- seznam pripojenych uzivatelu

superuser, root, admin ..
------------------------
\\ `su` prepnuti na jineho usera, bez parametru na root, je pozadovano heslo ciloveho uzivatele
\\ `sudo` vykonej prikaz jmenem root, eskalace prikazu. Uzivatel musi mit pravo pouzivat sudo. Pri sudo uzivatel pouziva sve heslo. 
- sudo muze byt povoleno jen na nektere binarky, je to definovano v `/etc/sudoers` 
- `/etc/sudoers` se edituje pomoci `visudo`, kontroluje spravnost
- `sudo su` prepnuti na root bez znalosti root hesla, prikaz musi byt ale povoleny

hesla v linuxu
-------------
- `/etc/shadow` seznam hesel, uzivatelsky zadana hesla jsou ulozena jako hash, pristup ma jen root
- uzivatelska hesla (u roota ne) musi splnovat dictionary check

passwd
--------
- zmena hesla, bez parametru aktualniho usera
\\ `passwd user1` zmena hesla pro konkretniho usera, nutno znat jeho heslo

user management
--------------
\\ `useradd USER` vytvoreni usera, vytvaret muze jen root (pripadne sudo) 
- novy user obdrzi ke vsemu defaultni hodnoty
\\ `usermod [options] LOGIN` zmena nastaveni usera
\\ `usermod -u -G` user id, group 
\\ `userdel USER` defaultne smaze uzivatele, zaznamy apod, ale zachova email a home adresar
\\ `userdel -r USER` smaze vsechno, u home

group management
------------
\\ `/etc/group` seznam group; nazev : heslo? : groupid : seznam uzivatelu
- soubor muzu editovat, pripsat uzivatele do groupy
\\ `groupadd GROUP` pridani prazdne groupy
\\ `groupmod`
\\ `groupdel`

vlastnictvi
------------
\\ `ls -l` prvni sloupec vlastnicvi usera, druhy vlastnictvi group
\\ `chown USER FILE` zmena vlastnictvi souboru
\\ `chgrp` zmena groupy u souboru
\\ `chown USER:GROUP FILE` muzu zmenit jen usera, nebo jen group, nebo oboje

permission
------
- pristupova prava k souborum
- rwx|rwx|rwx - jake maji prava user|group|ostatni
- u adresare x znamena moznot vlezt do adresare (stat se validni adresou)
\\ `chmod` zmena prav, dva typy zapisu, symbolicky a numericky
- symbolicy: napr. u+x (ugoa)(+-=)(rwx), = je presne tyto parametry
- numericka: r-4 w-3 x-1, napr. `chmod 755 FILE`, pri 000 muze jenom root
- specielni permissions, `chmod +s`
- sticky bit - aby mohl mit nejakou funkci, musi byt soubor executable, pokud je `S` tak neplatne, musi byt `s`
- sticky bit na userovi - proces pobezi pod tim userem, kdo je owner, priklad `/bin/chmod` je pokazde spusten pod rootem
- sticky bit na group - kdokoliv zavola, ma prava dane skupiny??
- sticky bit na adresari - znaceny `t`, ma treba `/tmp`, i kdyz mam vsechny prava 777, muzu modifikovat/mazat jen sve souboru, neboli Ber ohled na vlastnictvi souboru

umask
------
- defaultni permissions pro nove soubory, dane cislo se odecita od 0777 v pripade adresaru, 0666 u souboru (soubor po vytvoreni neni nikdy executable)
\\ `umask 0266` nove soubory budou -r--------
- kazdy user muze mit sve umask

acccess control list ACL
---------------------------
- dodatecna modifikace prav 
\\ `getfacl -m` upravi prava pro soubor pro konkretniho usera
- ve vypisu (ls -l) se zobrazuje jako + na konci prav
\\ `getfacl FILE` vypise ACL


