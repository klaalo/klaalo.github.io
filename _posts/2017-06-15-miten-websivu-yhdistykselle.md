---
layout: post
title: "Miten web-sivu yhdistykselle?"
date: "2017-06-15 23:19:00 +0300"
---
Kirjoittelin jokunen vuosi artikkelin web sivun perustamisesta vastauksena yleistasoiseen kysymykseen. Samantyyppinen aihe tuli uudelleen eteen ja aihetta on nyt ajankohtaista tarkastella uudelleen.

Jokunen vuosi sitten uudistin oman verkko-osoitteeni toteutustavan. Halusin helpon tavan joskus harvoin kirjoitella ihan vain huvikseni jotain, jos kirjoittamiseen syntyy inspiraatio. En halunnut vaivaa palvelimien, käyttöjärjestelmien ja sovellusten ylläpidosta. Halusin, että toteutus on helposti siirrettävissä ja että kirjoitetut artikkelit säilyvät myös omassa hallussani. Jo kauan on ollut vaatimuksena oma verkko-osoite. Haluan pitää asiat omassa hallussani. Tärkeä edellytys oli, että toteutuksen pitää olla edullinen, mielellään ilmainen. Edullisuus ei saa perua mainoksiin.

Nyt kun viimeisin uudistus on osoittanut muutaman vuoden kokemuksella tyydyttäväksi, uskallan ehdottaa sitä referenssinä esimerkiksi pienelle yhdistykselle, joka haluaa ajoittain julkaista seuraajilleen tietoa tai ihan vain ylläpitää yhdistyksen kotisivua verkossa mahdollisimman pienin panostuksin.

Toteutuksessa on keskeistä muutamien maksuttomien pilvipalvelunen yhdistely. Esittelen ensin erilliset palaset ja yritän sitten kuvata, miten palaset on liimattu yhteen toimivaksi kokonaisuudeksi.

## Github Pages
[Github](https://github.com) on ohjelmistojen lähdekoodin hallintaan tarkoitettu palvelu (SCM - Software Configuration Management). Avoimen lähdekoodiprojektien hallinta on Githubissa maksutonta. Suljettujen projektien ylläpidossa on rajoituksia. Githubin ansaintalogiikka perustuukin suljettujen projektien hallinnnasta perittäviin maksuihin.

Githubin yhteyteen on toteutettu [Github Pages](https://pages.github.com) toiminto ohjelmistokoodin hallintaan liittyvää julkaisua varten. Käytännössä Pages-palvelussa voi julkaista web-sivuna sivuston, joka on lähdekoodisäilö (repository) tai sellaisen haara Github-palvelussa.

Tyypillisesti Pages-sivusto julkaistaan Githubin verkko-osoitteessa. Pages-palvelu tukee maksutta myös mukautettuja verkko-osoitteita, eli käyttäjä voi osoittaa oman verkko-osoitteensa Pages-palveluun, jolloin sivusto julkaistaan käyttäjän omalla osoitteella.

Pages-palvelun vahvin voima on kuitenkin [Jekyll](https://jekyllrb.com)-tuki. Jekyll on ohjelmisto, jolla ylläpitäjä voi helposti suodattaa tekstimuotoisista ([markdown](https://en.wikipedia.org/wiki/Markdown)) artikkeleista HTML-sivuja, jotka sopivat www-selaimille. Jekyll tukee myös käyttäjän toteuttamaa ulkoasua, joten Jekyll:n ja Pages-palvelun avulla voi toteuttaa aivan omannäköisensä sivuston.

Hienointa kokonaisuudessa on, että Jekyll toimii taustalla automaattisesti. Käyttäjän ei tarvitse viritellä omia CI-työnkulkuja (CI - [Continuous Integration](https://en.wikipedia.org/wiki/Continuous_integration)). Kun sivuston säilöön tallennetaan uusi artikkeli tai sitä muuten päivitetään, pyöräyttää Pages-palvelu Jekyll-prosessin ja päivittää näin julkaistavan sivuston.

Silloin, kun viimeksi tarkastin, Pages-palvelu ei tue omalla verkko-osoitteella julkaistun sivuston tls-suojausta, eli salausta. Voi olla, että joku muu voi ottaa alkuperäisen idean omakseen, mutta näkyvästi asia tuli esiin, kun Google ilmoitti heikentävänsä salaamattomien sivustojen sijoitusta hakutuloksissa. Useat IT-alan yritykset ovatkin yhdessä käynnistäneet aloitteen kaiken verkossa siirrettävän datan salaamiseksi (<https://encryptallthethings.net>).

Salaus toki parantaa käyttäjien yksityisyydensuojaa, kun esimerkiksi operaattorit eivät niin helposti voi seurata käyttäjiensä tekemisiä. Suomessahan ja ETA-alueella internetin yksityisyyden suoja on tältä osin paremmin, kuin Yhdysvalloissa, jossa operaattorit voivat seurata ja myydä mainostajille tietoa tilaajiensa internet-käyttäytymisestä.

Niinpä siis asiaansa vihkiytyneen web-julkaisijan kuuluu salata sivustonsa. Koska Github ei palvelussaan tätä tue, tarvitaan jotain sivuston eteen.

## Cloudflare

[Cloudflare](https://www.cloudflare.com) on sisällön jakeluun (CDN - [Content Delivery Network](https://en.wikipedia.org/wiki/Content_delivery_network)) keskittyvä palvelu. Silläkin on tutustumiseen ja asiakkaiden houkutteluun tarkoitettuja maksuttomia palveluja.

Jakeluverkothan ovat omiaan yrityksille, joilla on paljon julkaistavaa tai palveluja, joiden saatavuudella on suuri merkitys. Ne auttavat myös suojautumaan palvelunestohyökkäyksiltä ja muulta häirinnältä. Jakeluverkossa on usein kyse silkasta voimasta. Jakeluverkkolla leveät kaistat maailmanlaajuisiin runkoverkkoihin.

Oman kotisivun tai pienen yhdistyksen kannalta ei ole niin olennaista, että palvelu on aina ja kaikkialta saatavilla. Palvelunestohyökkäykset nyt voivat olla jonkinlainen uhka, riippuen yhdistyksen toiminnasta. Kotisivun julkaisun kannalta Cloudflarella on eräs mainio etu.

Cloudflaren maksuton kokeilupalvelu sisältää [One-Click SSL](https://www.cloudflare.com/ssl/) -ominaisuuden. Ei ehkä kirjaimellisesti aivan yhdellä, mutta muutamalla hiiren klikkauksella julkaisijalla on mahdollisuus saada edustapalvelin, joka salaa taustalla toimivan palvelun liikenteen.

Näitä kahta palvelua yhdistämällä on siis saatavilla näppärä, suurta kuormaa kestävä yhdistelmä, joilla on mukava julkaista kotisivusto.

## Verkko-osoitteen tukipalvelut

Kuten aina, piru piilee yksityiskohdissa. Ennen, kuin julkaisijalla on edes oma verkko-osoite, joitakin asioita on pitänyt tapahtua. Ensimmäinen tehtävä on tietysti verkko-osoitteen rekisteröinti. Suomalaisia ylätason .fi -osoitteita jakelee Viestintävirasto (VRK - <http://domain.ficora.fi>). 

Enää ei VRK mahdollista yksittäisten henkilöiden rekisteröidä suoraan verkko-osoitteita, vaan rekisteröinti on tehtävä verkkotunnusvälittäjän avulla. Sama pätee kaikkiin verkkotunnuksiin, ne on rekisteröitävä jostain.

Rekisteröintiähän yleensä tekevät perinteiset hosting-palveluyritykset. Nyt web-hotellia ei tarvita, joten on tarpeetonta maksaa hosting-yritykselle verkkotunnuksen rekisteröinnistä. Rekisteröinnin voi kuitenkin helposti tehdä myös esim. <https://joker.com>-palvelun avulla. Aina rekisteröinti kuitenkin maksaa jotakin, mutta Joker on käsittääkseni rekisteröijistä edullisimpia, ellei tuttavapiirissä ole välittäjää, joka voi tehdä esim. .fi-verkko-osoitteen rekisteröinnin.

Verkkotunnus ei toimi ilman nimipalvelua. Se ei ole ongelma, sillä Cloudflare toimii nimenomaan ohjaamalla liikenteen omille edustapalvelimilleen nimipalvelun avulla. Verkko-osoitteen rekisteröinnin yhteydessä sen nimipalvelimeksi siis Cloudflalren palveluun kuuluvat nimipalvelimet.

Edellisestä siis seuraa, että julkaisijan on luotettava paitsi Cloudflaren edustapalveluun, mutta myös sen nimipalveluun. Tässä kotisivun julkaisun tapauksessa kysymys on kuitenkin epärelevantti, sillä jos käytettiin mainittua Github Pages -palvelua, ollaan jo luotettu suureen yhdysvaltalaiseen yritykseen. Tämä toteutus ei siis ehkä sovellu sellaisen sivuston julkaisuun, jolla käsitellään henkilötietoja.

Eurooppalainen lainsäädäntö ja suomalainen toteutus siitä kieltää henkilötietojen luovuttamisen ETA-alueen ulkopuolelle (ellei tietyt reunaehdot täyty). Toisaalta, jos sivusto hyödyntää esimerkiksi Facebookia sosiaalisen median toimintojen toteuttamiseen, henkilötiedot tulevat jo käsitellyksi ETA-alueen ulkopuolella.

Verkko-osoitteen hallinnassa on vielä eräs tärkeä yksityiskohta, johon on syytä kiinnittää huomiota. Käyttäjät ovat tottuneet pääsemään sivustoille jättäen perinteisen www-etuliitteen pois. Siispä sivustolle <http://www.karilaalo.fi> odotetaan päästävän kirjoittamalla selaimen osoitekenttään vain <http://karilaalo.fi>. On tietty tekninen yksityiskohta sille, että molemmat annetut osoitteet toimivat.

Kun Cloudflaren avulla julkaistaan web-sivusto, se on nimipalvelun rajoituksien johdosta käytännössä mahdollista tehdä vain verkkotunnuksen aliosoitteella. Github Pages yhdessä Cloudflaren kanssa perustuu siihen, että liikenne ohjataan DNS-järjestelmän CNAME-tietueella. Verkko-osoitteen päätasolle ei voi rekisteröidä samaan CNAME-tietuetta, jos samaan aikaan on tarve julkaista jokin muu tietue. Jokin muu tietue on julkaistava, jos halutaan, että verkkotunnukselle voi lähettää sähköpostia. On siis julkaistava myös MX-tietue.

Ylätason osoitteelle on siis julkaistava A-tietue, mutta Cloudflare- ja Github Pages -yhdistelmä ei tue tällaista yhdistelmää. On siis löydettävä jostain palvelin, johon verkko-osoitteen A-tietue on osoitettava ja joka suostuu välittämään osoitteeseen tulleet pyynnöt edelleen www-etuliitteellä toimivaan kotisivuun.

Minulla tällainen palvelin on joka tapauksessa, joten asia ei ole ongelma. Vaatimattomassa käyttötarkoituksessa on varmasti mahdollista kysyä joltakin teknisesti orientoituneelta ystävältä, voisikon hän tarjota tällaista palvelua. Kokonaisuus vaatii joka tapauksessa sen tason teknistä kikkailua ja klikkailua, että teknisesti orientoituneen ystävän apu saattaa muutenkin tulla tarpeeseen.

## Julkaisu, eli markdown

Nyt meillä on siis kokonaisuus, jossa voidaan julkaista sivusto ilman omaa www-palvelinta, tukeutuen joissain yksityiskohdissa esimerkiksi kaverin apuun. Miten sivuille julkaistaan uutta materiaalia?

Kokonaisuushan on jossain määrin staattinen. Jos on esimerkiksi tarkoitus julkaista blogi, artikkelit kirjoitetaan markdown-notaatiolla, jonka perusteella Githubin Jekyll muodostaa sivut. Muista, että kun artikkeli on yhtä, kuin markdown-notaatiolla kirjoitettu tekstitiedosto, sinun on tarvittaessa helppo siirtää blogisi jonnekin aivan muualle, jos Jekyll-ohjelmisto lakkaa olemasta tai Github lakkaa tukemasta sitä.

Uuden artikkelin julkaisu on siis niinkin yksinkertaista, kuin kirjoittaa se ja julkaista Githubin säilöön, joka edustaa sivustoa. Github ja Jekyll hoitaa loput.

Vaikka toteutus siinä määrin staattinen, että artikkelit ovat yksittäisi julkaistavia tiedostoja, ei dynaamiset toiminnot, tai vaikkapa sosiaalisen median ominaisuudet ole poissuljettuja.

## Facebook Comments

Facebookin [toteutus](https://developers.facebook.com/products/social-plugins/comments/) on vain yksi esimerkki tavasta liittää mille tahansa sivulle kommentointimahdollisuus. Toisen perinteisen vaihtoehdon vastaavasta toiminnallisuudesta tarjoaa myös esim. [Discus](https://disqus.com).

Nämä siis ovat jokseenkin uudenaikaisia palveluja, jotka eivät vaadi kotisivulta juuri muuta, kuin mahdollisuuden liittää ulkopuolista Javascript-koodia sivulle.

Joku väittää tietysti nyt suoraan, että vieraan Javascript-koodin upottaminen ei ole tietoturvallista, koska meille on opetettu niin ja olemme tottuneet uskomaan opetusta. Tässä väitteessä on toki perää, mutta kuten kaikessa toiminnassa, pitää toiseen vaakakuppiin laittaa tarve ja toiseen riskit. Riski pitää suhteuttaa sen toteutumisen todennäköisyyteen sekä riskin toteutumisesta mahdollisesti aiheutuvaan haittaan.

Nythän puhutaan toteutuksessa, jossa on joka tapauksessa tarkoitus esittää kotisivulla julkista tietoa ja tarjota esim. artikkeleihin liittyvä keskustelumahdollisuus palvelussa, jota käyttäjät joka tapauksessa käyttävät päivittäiseen viestintäänsä. Riskin toteutumisen todennäköisyyskin on kohtuullisen pieni, kun ajattelee, minkälaiset tappiot yhtiölle syntyisi, jos se käsittelisi käyttäjien henkilötietoja laittomasti. 

Toisaalta, moni väittää, että esim. Facebookin käyttöehdot ovat jä lähtökohtaisesti kohtuuttomat. Nämä tietosuojaan liittyvät riskit ovat kuitenkin sellaisia, jotka julkaisijan on harkittava. Kaikenlaisia dynaamisia lisäpalveluja on mahdollista ja jopa helppoa liittää tässä kuvatulla tavalla toteutetulle kotisivustolle, mutta ne eivät tule siinä mielessä ilmaiseksi, että dynaamiset verkkopalvelut tarvitsevat jotakin toimintansa kulujen ja sijoittajien tuototavoitteen kattamiseen. Usein se jokin tuottomahdollisuus on käyttäjiltä tai heidän käytöstään seuraamalla saadun tiedon hyödyntäminen esimerkiksi markkinoinnissa.

## Paketti

Vielä yhteen kooten, paketti syntyy seuraavalla ketjulla: Verkko-osoitteen rekisteröinti -> Cloudflaren edustapalvelu -> Github Pages -> Jekyll -> Sivuston lähdekoodisäilö (repository) Githubissa .

Edellisellä kokoonpanolla on hyvin edullisesti saatu paljon liikennettä sietävä ja kohtuullisella varmuudella erittäin hyvin saavutettavissa oleva kotisivusto, jonka ylläpito ei vaadi pääkäyttäjältä suurta huomiota.