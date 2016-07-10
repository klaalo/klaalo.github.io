---
layout: post
title: "Suomalaisoperaattorit eivät suojaa sähköposteja"
date: "2016-07-10 13:59:30 +0300"
---

# Suomalaisoperaattorit eivät suojaa sähköposteja

Sähköpostiviestit kulkevat internet-verkossa yleensä suojattomina. Sähköpostia on verrattu postikortin lähettämiseen. Kuka hyvänsä postikortin kuljetusketjussa voi lukea siihen kirjoitetun viestin. Sama pätee sähköpostiin. Jos viestiä ei suojata salauksella, sen kuljettamiseen osallistuvat voivat lukea viestin.

Sähköpostiviestien salaamiseen päästä päähän lähettäjältä vastaanottajalle on kehitetty menetelmiä. Suomalainen henkilökortti on näistä eräs vaihtoehto, mutta vaatisi tietokoneeseen kytkettävän kortinlukijan ja soveltuvan sähköpostiohjelmiston. Harva kirjoittaa viestejä yksinomaan tietokoneella ja vielä harvemmalla on henkilökortin käyttöön tarvittava kortinlukija.

## Starttls palvelimien välillä

Sähköpostiviestinnän luottamuksen parantamiseksi on kehitetty starttls yhteyskäytäntö, joka suojaa sähköpostiliikenteen palvelimien välillä salaamalla viestinvälityksen. Samaa yhteyskäytäntöä tai TLS-salausta voi hyödyntää myös loppukäyttäjän ja varsinaisen sähköpostilaatikon välillä. Jos kaikki sähköpostin kulkureitillä olevat palvelimet noudattavat salaavaa käytäntöä, viesti kulkee parhaimmillaan koko matkan salattuna siitä huolimatta, että varsinaista viestiä itsessään ei olisi salattu.

Vaikka viesti on salattu matkalla, jokainen sen kuljettamiseen osallistuva palvelin salaa liikenteen erikseen. Postia välittävät palvelimet siis pystyvät edelleen lukemaan viestin. Viestiliikenteen salaaminen palvelimien välillä vähentää silti merkittävästi osapuolia, joilla on pääsy viestin sisältöön.

Yleisesti ja laajasti internetissä käytetyt sähköpostia välittävät ohjelmistot osaavat starttls-yhteyskäytännön ja se on kytketty käyttöön ohjelmistojen oletuskonfiguraatiossa. Usein ei ole merkitystä, käyttääkö salauksessa yleisesti hyväksyttyä varmennetta, vaan useimmiten asennusvaiheessa muodostettu itseallekirjoitettu varmenne toimii ilman ongelmia. Sähköpostipalvelun ylläpitäjän ei tarvitse kiinnittää salaukseen huomiotaan erityisesti, vaan useimmiten se toimii heti oletusasennuksen jälkeen sellaisenaan.

## Palvelimen salaustuen tarkastaminen on helppoa

Sähköpostin välittämiseen osallistuvien palvelimien tuki starttls-yhteyskäytännölle on helppo selvittää. Vastaanotettujen sähköpostiviestien otsakkeista näkee, mitkä viestin kuljetusketjuun osallistuneet palvelimet ovat salanneet viestiliikenteen. Jos käyttäjällä on oma sähköpostipalvelin, hän voi sen lokista katsoa, mitkä palvelimet ovat käyttäneet salausta.

Starttls-yhteyskäytännön tuen voi testata myös komentoriviltä. Tämä edellyttää pääsyä palvelimelle, jonka internetyhteyden SMTP-porttia 25 ei ole estetty, kuten suomalaiskuluttajien internetliittymissä on tehty Viestintäviraston ohjeeseen perustuen. Jotkin operaattorit estävät liikenteen molempiin suuntiin, vaikka ohje määrää estämään vain lähtevän liikenteen. Ohjeen tarkoitus on vähentää kuluttajaliittymistä lähetettävää roskapostia. Postin vastaanottaminen on sallittua myös kuluttajaliittymissä.

Ensin on selvitettävä, mikä palvelin huolehtii esimerkiksi osoitteen matti.meikalainen<span></span>@welho.com -osoitteen sähköpostien vastaanottamisesta.

    $ dig MX welho.com
    ;; ANSWER SECTION:
    welho.com.		600	IN	MX	10 mx.welho.com.


Kun on tiedossa palvelin, jota halutaan testata, otetaan telnet-komennolla yhteys sen porttiin 25.



    $ telnet mx.welho.com 25
    Trying 83.102.41.21...
    Connected to mx.welho.com.
    Escape character is '^]'.
    220 welho-mx2.welho.com ESMTP Postfix
    ehlo foo.com
    250-welho-mx2.welho.com
    250-PIPELINING
    250-SIZE 22000000
    250-ETRN
    250-ENHANCEDSTATUSCODES
    250 8BITMIME
    starttls
    502 5.5.1 Error: command not implemented

Palvelimen vastattua sitä tervehditään `ehlo`-komennolla. Palvelin kertoo ominaisuuksistaan. Edellisestä listasta jo näkee, että starttls-tuki puuttuu. Palvelinta voi kuitenkin yrittää komentaa aloittamaan starttls-kättelyn `starttls`-komennolla. Edellisessä tapauksessa palvelin antoi virheilmoituksen, eli palvelin ei pysty käynistämään salaavaa yhteyskäytöntöä.

## Operaattorit välinpitämättömiä

Asiakkaan kysyessä salauksesta, osa operaattoreista reagoi kysymykseen jämptisti ja lupasivat selvittää asiaa. Asiaan ei lupauksista huolimatta palattu. Osa operaattoreista sivuutti kysymyksen täysin reagoimatta siihen mitenkään.

<blockquote class="twitter-tweet" data-lang="en"><p lang="fi" dir="ltr">.<a href="https://twitter.com/klaalo">@klaalo</a> Enpä osaa suoralta kädeltä sanoa, pitää laittaa tästä fiksummille kyselyä eteenpäin. :) Palaan asiaan mahd. pian. //Ville <a href="https://twitter.com/hashtag/sonera?src=hash">#sonera</a></p>— SoneraAsiakaspalvelu (@Sonera_palvelu) <a href="https://twitter.com/Sonera_palvelu/status/692404158180298756">January 27, 2016</a></blockquote> <script async src="//platform.twitter.com/widgets.js" charset="utf-8"></script>

## Kuluttajan vaihtoehdot vähissä

Perinteisesti internet-operaattorin sähköpostipalvelu oli ensimmäinen vaihtoehto, kun peruskuluttaja otti sähköpostin käyttöönsä. Jos ei huomioida maksuttomia mainosrahoitteisia sähköpostipalveluja, kuluttajalle ei edelleenkään juurikaan ole vaihtoehtoja sähköpostipalvelun hankkimiseen.

Hosting-operaattoreilta on saatavilla erikseen sähköpostipalvelua tai sitä myydään web-hotellipakettien yhteydessä, mutta nämä ovat turhan teknisiä peruskuluttajalle.

Operaattorien mielenkiinto luotettavan ja turvallisen sähköpostipalvelun tarjoamiseen lienee vähentynyt, kun valtaosa kuluttajista on siirtynyt maksuttomien mainosrahoitteisten sähköpostipalvelujen käyttäjiksi. Myös uudet sosiaalisen median ja mobiilit viestintäpalvelut vähentävät sähköpostin tarvetta, tai ainakin sen merkitystä päivittäisessä viestinnässä.