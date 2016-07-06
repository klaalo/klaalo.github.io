---
layout: post
title:  "Käyttäjän voi tunnistaa identifioimatta"
date:   2014-11-04
categories: henkilotieto autentikaatio
---
Wordpressin oletetun nollapäivähaavoittuvuuden uutisointi muistutti Ylen websivujen [tunnistamiseen liittyvästä keskustelusta](http://yle.fi/yleisradio/ajankohtaista/yle-toivoo-sahkoisen-tunnistautumisen-etenevan-nopeasti). Käyttäjän tunnistamisesta on enemmän hyötyä, kuin yleisesti tunnutaan ymmärrettävän.

Wordpressin oletetun nollapäivähaavoittuvuuden uutisointi muistutti Ylen websivujen tunnistamiseen liittyvästä keskustelusta. Käyttäjän tunnistamisesta on enemmän hyötyä, kuin yleisesti tunnutaan ymmärrettävän. Blogikommentoinnissa ja Ylen käyttötarkoituksessa käyttäjän tunnistamisen hyöty on nähtävissä.

Wordpressin haavoittuvuus ilmeisesti liittyy trackback-kommentointiin tai kommentointiominaisuuteen yleensä. Olipa mikä blogialusta hyvänsä, suosiota saavutettuaan kommentiroska alkaa joka tapauksessa haitata sivustoa. Käyttäjän tunnistaminen on omiaan vähentämään niin haavoittuvuuksiin kuin roskakommentteihin liittyviä ongelmia. Omalla nimellä kommentoidessa joutuu harkitsemaan kommentin asiallisuutta. Vaikka kommentointi tehtäisiin anonyymisti, mutta tunnistamisen kautta, rajoittuisi kommentointi luonnollisiin henkilöihin. Käyttäjän tunnistaminen poistaisi luonnostaan spam-bottien tuotokset.

Ylen palveluissa voi puolestaan kuvitella käyttäjän tunnistamisesta olevan hyötyä esimerkiksi silloin, kun halutaan rajoittaa jonkin sisällön katselua vain suomalaisille. Voi olla, että Yle joutuu tekemään ohjelmien levityksistä sopiessa rajoituksia kohdeyleisöön. Ohjelman näyttäminen vain suomalaisille ja Suomessa asuville on todennäköisesti edullisempaa, kuin mahdollisuus näyttää ohjelmaa koko maailmalle.

Ylen kaltaiset sisältöpalveluntarjoajat perinteisesti rajoittavat sisältöön pääsyä käyttäjän IP-osoitteen perusteella. Tähän liittyy kaksi perustavanlaatuista ongelmaa. Ensinnä, kohdemaan IP-osoitteen käyttäminen on helppoa mm. VPN-palveluiden avulla. Toiseksi, IP-osoitteella rajaamalla rajataan palvelusta ulos sellaiset kotimaiset käyttäjät, jotka tilapäisesti vierailevat ulkomailla.

Ylen sivujen keskustelussa kommentoijat alkoivat välittömästi pauhata, kuinka valtiovalta haluaa valvoa ja tarkkailla enemmän kansalaisten toimia. Se, että Yle tunnistaisi käyttäjänsä, lisäisi valvontaa. Blogikommentointiin puolestaan yleisesti halutaan mahdollisuus anonyymiyteen sillä perusteella, että aroista aiheista keskustellessa pakotettu nimellä esiintyminen rajoittaa keskustelua tai sen syvyyttä.

Molemmissa tapauksissa on unohtunut, että käyttäjät olisi mahdollista tunnistaa identifioimattomasti. Yleisesti käyttäjän tunnistamisesta puhuttaessa unohtuu, että tunnistaja ja tunnisteen vastaanottaja eli palvelu voivat olla eri toimijoita. Palvelun ei tarvitse tietää käyttäjästään hänen identiteettiään, vaan käyttäjään voidaan viitata sellaisella yksilöllisellä tunnisteella, josta ei yksistään voida selvittää, kehen tosielämän henkilöön se viittaa. Tällainen käyttäjän yksilöivä identifioimaton tunniste on mm. -skeemassa kuvattu [eduPersonTargetedId](http://www.internet2.edu/media/medialibrary/2013/09/04/internet2-mace-dir-eduperson-201203.html#eduPersonTargetedID).

Ylen tapauksessa identifioimattoman yksilöllisen tunnisteen lisäksi voitaisiin luovuttaa tieto siitä, että käyttäjä on Suomen kansalainen tai hänen vakituinen asuinpaikkansa on Suomessa. Blogikommentoinnin yhteydessä riittää pelkkä yksilöivä identifioimaton tunniste osoittamaan, että käyttäjä on tunnistettu tosielämän henkilö.

Tilanne vaan on se, että vielä ei ole sellaista yleiskäyttöistä luotettavaa tunnistuspalvelua, joka tunnistaisi käyttäjän ja luovuttaisi yksilöivän identifioimattoman tunnisteen. Tällainen luotettava ja laadukas tunnistuspalvelu parantaisi käyttäjien yksityisyyttä, kun palvelujen ei tarvitsisi vastaanottaa käyttäjistä tietoa, jota palvelu ei tarvitse.