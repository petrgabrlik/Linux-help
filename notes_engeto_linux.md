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

tar
---------
- tape archive, zabaleni dat do jednoho souboru, primarne bez komprese, pokud neni pouzit option
tar [OPTION...] [FILE]...
-c		vyrobi balik
-x		rozbali balik
-v		verbose, vypise co zabali apod
-f		uloz do souboru	
tar -cf archive.tar	zabal do souboru

zip, unzip
---------
- zabali a kompresuje, umoznuje pridavat
zip archive.zip file1 file2	vytvori archiv
zip archive.zip file3 file4	prida do archivu
unzip -l archive.zip		vypise zabalena data
unzip archive.zip		rozbali	

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

redirections
-------------
- operatory > >> 2> 2>>
cmd > file	vystup zapise do soboru, prepise ho, stejne jako 1>
cmd >> file	prida na konec souboru, append, 1>>
cmd 2> file	presmerovani erroru
cmd 2>> file	append erroru
- primarni stdout a stderr ma defaulne vystup do terminalu
- stdin 0, stdout 1, stderr 2
- cat file1 file2 > fileout 2> fileerr		out do jednoho souboru, error do druheho
- cat file1 file2 > file 2>&1			out i err do jednoho souboru file 
- presmerovani ma prednost pred vsim, okamzite dojde k prepsani a smazani souboru, radeji pouzivat >>

stdin
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

