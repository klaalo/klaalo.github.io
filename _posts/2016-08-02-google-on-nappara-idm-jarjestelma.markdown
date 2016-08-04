---
layout: post
title: "Google on näppärä pieni IdM-järjestelmä"
date: "2016-08-02 22:10:00 +0300"
---
Salasanat ovat minkä tahansa sellaisen sovelluksen ylläpitäjän päänvaiva, johon pitää sallia käyttäjän turvallinen pääsy. Tai ainakin niin pitäisi olla silloin, kun järjestelmässä käsitellään salasanoja.

## Paljon menetelmiä salasanakannan suojaamiseen

Kehittäjän tai pääkäyttäjän tärkeimpiä huolia on säilyttää salasanoja niin, että niitä ei voida hyödyntää, vaikka niinkin epätodennäköinen tapahtuma sattuisi, että salasanat pääsisivät vääriin käsiin. Luonnollisesti pääsy salasanakantaan on tehty niin vaikeaksi, että sellaista ei pitäisi päästä tapahtumaan. Käytäntö on osoittanut, että niin käy.

Toistuvista salasanavuodoista johtuen on keskusteltu paljon salasanakannan suojaamisesta. Salaisuuksia ei pitäisi tallentaa selväkielisessä muodossa, vaan ne suojataan hajautusalgoritmilla (hash). Salasana säilytetään sellaisessa muodossa, että siitä ei voi päätellä selväkielistä käyttäjän varsinaista salasanaa. Käyttäjän kirjautuessa antamasta salasanasta lasketaan hajautusalgoritmilla tiiviste. Jos salasanakantaan tallennettu tiiviste vastaa käyttäjän kirjautuessa antamasta salasanasta laskettuun, varsinaiset selväkieliset salasanat vastaavat toisiaan ja pääsy voidaan sallia.

Kun järjestelmien ylläpitäjät ovat siirtyneet tiivisteiden käyttöön, myös hyökkääjien menetelmät ovat kehittyneet. Sateenkaaritaulujen (rainbow table) avulla pystytään löytämään heikot salasanat. Sateenkaaritaulussa on vastaavuus tyypillisimmin salasanana käytettyjen merkkijonojen tiivisteisiin. Vertaamalla varastettun salasanakannan tiivisteitä sateenkaaritaulun vastaavuuksiin voidaan löytää käyttäjän alkuperäinen, selväkielinen salasana.

Sateenkaaritauluja vastaan hajautusalgoritmien yhteydessä käytetään suolaamista (salt). Varsinaisesta selväkielisestä salasanasta ei muodosteta tiivistettä sellaisenaan, vaan parhaimmillaan hyvän satunnaisen suolan kera. Näin kahdesta samanlaisesta selväkielisestä salasanasta ei muodostu samanlaista tiivistettä, jolloin sateenkaaritaulu muuttuu hyödyttömäksi.

Kun tunnetaan suojausmenetelmien perusteet, voidaan alkaa väitellä metodeista. Hajautusalgoritmejä on hyviä, huonoja ja erityisesti salasanojen tallentamiseen soveltuvia.

Törmäykseksi kuvaillaan tilannetta, jossa kahdesta eri merkkijonosta muodostuu yhdellä hajautusalgoritmillä sama tiiviste. Tämä on salasanan käsittelyssä hankalaa, sillä se mahdollistaa pääsyn järjestelmään. Törmäykseksi voidaan kuvata myös tilannetta, jossa kokeilemalla erilaisia merkkijonoja onnistutaan löytämään tiiviste, joka kuvaa käyttäjän salasanaa ja tällä tavalla hankitaan oikeudeton pääsy.

Huonoon hajautusalgoritmiin on helppoa ja nopeaa tuottaa törmäyksiä. Salasanakäytössä hyvän hajautusalgoritmin tiivisteen laskeminen on niin monimutkaista, että erilaisten merkkijonojen kokeileminen oikean tiivisteen löytämiseksi (brute force) kestää mahdottoman pitkään.

Osaava ja kokenutkin järjestelmäkehittäjä on helposti hukassa erilaisten suolaamismenetelmien, hajautusalgoritmien ja salasanojen suojaamismenetelmien kanssa. Toivottavasti jokainen kehittäjä toivoo, että salasanoja ei tarvitsisi käsitellä. Aina, kun salasanan käsittelyn voi antaa jollekin toiselle, niin pitäisi tehdä.

## Paljon vaivaa salasanasta

Salasanojen suojattu tallentaminen ei ole ainoa ylläpitäjän tai kehittäjän huoli. Perusongelma salasanojen käytössä, etenkin sellaisten, joita käytetään harvoin, on niiden unohtaminen.

Salasanoihin perustuvaan järjestelmään on kehitettävä menetelmä, jolla unohtunut salasana voidaan palauttaa. Salasanaa palautettaessa käyttäjä on tunnistettava vähintään yhtä vahvasti, kuin se on tehty silloin, kun käyttäjä muodosti käyttäjäprofiilinsa järjestelmään (ensitunnistaminen).

Uuden salasanan luovuttaminen on tehtävä suojatusti. Käyttäjälle on annettava mahdollisuus luoda itse uusi salasana tai uusi salasana on toimitettava käyttäjälle turvallisesti. Valtavan moni nykypäivän palvelu luottaa käyttäjän sähköpostiin. Uusi salasana toimitetaan käyttäjän sähköpostiin, vaikka ei ole mitään tietoa, kuinka vahvasti suojattu se on. Vaihtoehtoisesti sähköpostia käytetään tunnistamisen välineenä, jolloin kuka tahansa, jolla on pääsy käyttäjän sähköpostiin voi saada pääsyn myös niihin palveluihin, joiden unohtuneen salasanan palauttaminen perustuu sähköpostiin.

Nykyisin palvelimet perustetaan lyhytikäisiksi. Varsinainen palveluosoite ohjataan  palvelimelle, joka perustetaan pilvipalveluun nopeasti orkestrointityökalulla. Palvelun saavutettavuutta parannetaan hajauttamalla palvelu useammalle palvelimelle ja suunnittelemalla sellaiset palvelimen perustamismenetelmät, että kun yhdessä palvelimessa ilmenee ongelmia tai sen ohjelmisto vanhenee, uusi pystytetään nopeasti ja palveluliikenne ohjataan uudelle palvelimelle. Yksittäisen palvelimen mahdollisesti fyysisiä tai tietoliikenteen reititykseen liittyviä ongelmia ei selvitetä pitkään, vaan palvelu siirretään paremmin toimivalle alustalle.

Tällaisessa notkeassa ylläpidossa salasanatietokannan turvallinen toimittaminen palvelua tuottavalle alustalle on omanlaisensa haaste.

## Mielummin muuten, kuin salasanalla

Jos se vain on mahdollista, on parempi olla käyttämättä salasanaa. Selaimella käytettäviin verkkopalveluihin kannattaa toteuttaa federoitu kirjautuminen. Se voi perustua sellaiseen organisaatiorajat ylittävään tunnistamiseen, jossa käyttäjäjoukko on jäsenenä.

Jos käyttäjäjoukko on heterogeeninen, sosiaalisen median palvelut tarjoavat ratkaisun. Google, Facebook ja Microsoft mahdollistavat tunnistautumisen ulkoisiin palveluihin tuottamiensa palvelujen käyttäjäprofiileista. Menetelmät ovat yleisiä ja standardoituja. Palvelut tarjoavat myös omat rajapintansa, työkalunsa ja hyvät ohjeet käyttäjien tunnistamiseen.

Toinen hyvin yleinen esimerkki salasanattomasta tunnistamisesta on pääsy palvelimien konsolille. SSH-yhteyskäytäntö mahdollistaa epäsymmetrisen salauskäytännön, jossa pääsy palvelimelle varmistetaan käyttäjän julkisen avaimen avulla. Käyttäjä allekirjoittaa salaisella avaimellaan haasteen, joka voidaan tarkastaa käyttäjästä tiedossa olevalla julkisella avaimella.

On palveluja, joihin salasanaton tunnistaminen ei vielä helposti sovellu. Harmiksemme sähköposti on tällainen vanha, mutta edelleen päivittäin tarpeellinen palvelu. IMAP- ja SMTP-yhteyskäytännöt edellyttävät tunnistamista (SMTP silloin, kun halutaan varmistaa, että käyttäjällä on oikeus lähettää postia ulospäin). Kumpaankaan ei vielä toistaiseksi ole saatavilla sellaista käytännössä toimivaa tunnistamisratkaisua, joka ei perustuisi jaettuun salaisuuteen. 

## Google apuun

Sähköpostipalvelunkin tarjoamisessa salasanakannan suojaamisen ratkaisujen pohtimista parempi ratkaisu on ulkoistaa salasanoista huolehtiminen sellaiselle taholle, joka on jo ratkaissut niiden käsittelyyn liittyvät haasteet.

Google on toteuttanut kaksivaiheisen tunnistamisen, jolla sallitaan pääsy käyttäjätiliin vain, jos käyttäjällä on toinen elementti (esim. fyysinen esine) sen lisäksi, että hänellä on tiedossa avain, jolla palvelu aukeaa (salasana).

Kaksivaiheinen tunnistaminen on tämän artikkelin käyttötarkoituksessa eduksi myös siinä, että se tekee mahdolliseksi sovelluskohtaiset salasanat. Käyttäjä voi määritellä sovelluksille irrallisia salasanoja. Sähköpostiohjelmalla voi olla eri salasana, kuin kalenterilla. Vaikka kalenterin salasana päätyisi vääriin käsiin ja pitää kuolettaa, tämä ei vaikuta sähköpostin toimintaan. Jokaiselle ulkoista tunnistamista vaativalle palvelulle voi määrittää erillisen salasanan.

Sovellussalasanoja käytettäessä ohjelmille tai ulkoisille palveluille ei tarvitse luovuttaa sitä käyttäjän omaa henkilökohtaista salasanaa, jota hän itse käyttää kirjautuessaan henkilökohtaisesti Googlen palveluihin. Ne erottavat käyttäjän oman suoran toiminnan ohjelmallisesti käyttäjän puolesta suoritettavista toiminnoista. &lsqb;1&rsqb;

Google on ratkaissut myös salasanan palauttamisen.

Google	 varoittaa, jos käyttäjätiliin yritetään saada pääsy sellaisesta päätteestä tai paikasta, joka ei ole käyttäjälle tyypillistä. Käyttäjällä on mahdollisuus varhaisessa vaiheessa havaita ja estää oikeudeton pääsy käyttäjätilin resursseihin.

## Google on paha - en salli sille pääsyä sähköpostiini

Kyllä, Googlen käytänteet kerätä ja hyödyntää massiivisia määriä henkilötietoja liiketoimintansa toteuttamiseen ovat epämiellyttäviä. Oman sähköpostipalvelun ylläpitämisen perussyy saattaa olla nimenomaan välttää kaupallisia palveluja, joille käyttäjän tuottama data on yrityksen tulon tekijä.

Monelle Google on välttämätön paha ja käyttäjätili on jo olemassa Googlen palveluissa. Jos tili on olemassa, miksi sitä ei hyödyntäisi? Käyttäjätilin hyödyntäminen käyttäjän tunnistamisessa ei vielä mahdollista Googlelle suoraa pääsyä sähköpostin sisältöön. Kun Googlen käyttäjätiliä hyödynnetään autentikaatioon, on toki mahdollista, että Google voi väärentää kirjautumistapahtuman. Jos se on palvelun toteuttamisessa huomioitu ja palvelun lokit tallennetaan sellaiseen paikkaan, jossa niiden jälkikäteinen väärentäminen ei ole mahdollista, oikeudettomasta käytöstä jää jälki.

Olisi hyvin lyhytnäköistä Googlen kaltaiselta yritykseltä yrittää sellaista käyttäjän henkilökohtaiseen dataan kohdistuvaa urkintaa, josta jää käyttäjälle todistusaineistoa. On myöskin kysyttävä, kuinka todennäköistä on, että Google ensinnä löytää juuri tietyn käyttäjän palvelun tai toisaalta, että tietty käyttäjä olisi niin mielenkiintoinen, että tällaista riskialtista urkintaa kannattaisi yrittää.

## Ulkoista salasanat, pidä sähköposti

Google tarjoaa pääsyn omaan sähköpostipalvelunsa web-käyttöliittymän lisäksi myös perinteisille sähköpostiohjelmille tarkoitetulla IMAP-yhteyskäytännöllä. Samaa IMAP-protokollaa käyttävät myös mobiililaitteet hakiessaan saapuneen sähköpostin. Tätä IMAP-palvelua voi hyödyntää käyttäjän tunnistamiseen.

Samoin, kun Googlen IMAP-palvelin tunnistaa Gmail-sähköpostiin yrittävän käyttäjän, se voi tunnistaa ulkoisen sähköpostipalvelun käyttäjän. [Dovecot-IMAP](http://www.dovecot.org) -palvelinohjelmiston voi määrittää proxy-palvelimeksi, joka pyytää käyttäjää tunnistautumaan ja välittää tämän tunnistautumispyynnön edelleen Googlen IMAP-palveluun. Jos käyttäjä tunnistetaan Googlen IMAP-palvelussa, pääsy voidaan sallia myös käyttäjän omaan sähköpostipalveluun.

Dovecot-ohjelmisto sisältää myös SASL-toteutuksen, jota puolestaan voidaan hyödyntää Postfix SMTP-ohjelmistossa. Postfix välittää SASL-käytännöllä autentikaation Dovecot-palvelimelle, joka välittää sen edelleen Googlen IMAP-palveluun.

Dovecot-IMAP -ohjelmistolle Googlen Gmail-palvelu määritetään tunnistusmenetelmäksi esimerkiksi seuraavasti:

```
passdb {
    driver = imap
    args = host=imap.gmail.com port=993 ssl=imaps username=%u@gmail.com
}
```

Dovecotin oma ohjeistus IMAP:n käyttämisestä käyttäjän tunnistamisessa löytyy [tästä linkistä](http://wiki2.dovecot.org/PasswordDatabase/IMAP). Kehittäjän on tunnistamisen lisäksi ratkaistava vielä käyttäjätietokannan ylläpito. Siihen on monia [toteutusmahdollisuuksia](http://wiki2.dovecot.org/UserDatabase). Käyttäjätietokanta ei ole aivan niin sensitiivistä dataa, kuin salasanatietokanta, joten sopivissa olosuhteissa sen suojaamisessa ei tarvita niin monimutkaisia menetelmiä, kuin salasanojen kanssa. 

## Google tunnistaa kaikki käyttäjänsä

Ulkoisen IMAP-palvelun käytössä on ymmärrettävä, että se tunnistaa kaikki omat käyttäjänsä. Jos omaa palvelua ei haluta antaa kaikkille ulkoisen palvelun käyttäjille, on käyttöä jotenkin rajoitettava. Edellä mainittu käyttäjätietokanta voi olla tähän yksi ratkaisu.

SMTP-palvelun yhteydessä ulospäin lähetettävää sähköpostiliikennettä voi olla tarpeen rajoittaa. Tämä onnistuu [määrittämällä Postfixille](http://www.postfix.org/SMTPD_ACCESS_README.html#relay) esimerkiksi:

```
smtpd_sender_login_maps = hash:/etc/postfix/controlled_envelope_senders
smtpd_recipient_restrictions =
    reject_sender_login_mismatch
```

## Googlen lisäksi muitakin mahdollisuuksia

Sähköpostipalvelun tapauksessa mahdollisia ratkaisuja salasanojen ylläpidon ulkoistamiseen on Googlen lisäksi myös muita. Microsoft tarjoaa Outlook.com -sähköpostia ja Applen iCloud-palveluun sisältyy sähköposti ja IMAP-palvelu. Jos se soveltuu, oman sähköpostipalvelunsa pystyttäjä voi hyödyntää tunnistamiseen vaikka internetoperaattorinsa IMAP-palvelua, mutta tallentaa sähköpostit omaan IMAP-palvelimeen. Ennen operaattorin sähköpostipalvelun käyttöä, lue [tämä](suomalaisoperaattorit-eivat-suojaa-sahkoposteja).

&lsqb;1&rsqb; Muokattu 4.8.2016 - lisätty sovellussalasanoista