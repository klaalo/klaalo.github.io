---
layout: post
title: "Kuluttajalle ei ole hyvää sähköpostipalvelua"
date: "2017-10-05 00:03:00 +0300"
---
Jokunen aika sitten kirjoitin, kuinka suomalaiset teleoperaattorit eivät [suojaa sähköpostipalvelujaan](suomalaisoperaattorit-eivat-suojaa-sahkoposteja) salauksella. Salauksen toteuttaminen olisi helppoa, mutta operaattorit eivät silti tue salausta. Näinpä suomalaisen internetoperaattorin sähköpostipalvelua ei voi suositella. Kun vaihtoehtoja alkaa etsiä, hyviä on vaikea löytää.

Tästä artikkelista tuli pitkä ja polveileva. Suosittelen ensin silmäilemään otsikot. Varsinaista tldr; osiota ei ole, mutta lopussa on yhteenvetokappale, jossa kerron, kuinka olen toteuttanut oman sähköpostin käyttöni.

Kuluttajien välinen viestintä on siirtymässä sähköpostista pikaviestivälineisiin. Esimerkiksi [WhatsApp](https://www.whatsapp.com), [Signal](https://signal.org) ja [Telegram](https://telegram.org) ovat hyviä, helppoja ja maksuttomia jopa sähköpostia monipuolisempia palveluja kuluttajien viestintään.

Pikaviestimien yleistyessä sähköpostilla on edelleen tärkeä jalansija. Kaikilla ei vielä ole käytössään pikaviestintä ja pikaviestimien välillä viestit ei kulje ristiin. Jos yksi kuluttaja käyttää Signalia ja toinen WhatsAppia, nämä eivät voi viestiä keskenään.

Sähköpostin voima on juuri sen yleisyydessä. Voisi verrata, että lähes kaikille maailman ihmisille voi lähettää paperisen kirjeen perinteisessä postissa. Lähes kaikille länsimaiden ihmisille voi lähettää sähköpostia. Vain harvalle länsimaiselle ihmiselle voi lähettää pikaviestin. Koko maailman populaatiossa pikaviestin on käytettävissä vain pienellä marginaalilla.

Sama pätee kaupalliseen toimintaan. Vain hyvin harvan kaupallisen yrityksen tai julkisen viranomaisen tavoittaa pikaviestimellä, mutta lähes kaikkiin saa yhteyden sähköpostilla.

## Minkälainen on hyvä sähköpostipalvelu - valintakriteerejä ja ominaisuuksia

Jotta voi valita hyvän sähköpostipalvelun, on pohdittava valitakriteerejä. Sähköposti on vanha ja vakiintunut palvelu ja on helppo erottaa tärkeitä ominaisuuksia, joilla palvelujen vertailu käy.

### Maksuttomuus vs. yksityisyys

Sähköpostin on ajateltu kuuluvan olennaisena osana internet-liittymän palveluihin. Jo aikaisessa vaiheessa, kun Suomessa alettiin tarjota kuluttajalle internet-liittymiä, hyvin nopeasti sähköpostipalvelu oli osa liittymän palvelutarjontaa.

Sähköpostin kiinteä suhde operaattorin internet-liittymään tuotti nopeasti kuluttajille hankaluuksia, kun operaattoria haluttiin vaihtaa. Sähköpostiosoitetta ei saanutkaan mukaan uudelle operaattorille ja kulkuttaja oli äkkiä lukittuna nykyiseen operaattoriinsa.

90-luvun puolivälin jälkeen lanseerattiin maksuton hotmail.com sähköpostipalvelu. Sitä markkinoitiin mm. ratkaisuna toimittajalukkoon, jossa kuluttaja on sähköpostiosoitteen takia sidoksissa internet-operaattoriinsa.

Ennen kuin tietosuojasta alettiin 2000-luvulla puhua kasvavassa määrin, harva tuli edes ajatelleeksi sähköpostipalvelun yksityisyyttä. Vielä tänä päivänäkin suuri osa kuluttajista tuntuu elävän kummallisessa kuplassa, jossa oletetaan kaiken internetistä saatavan palvelun ja sisällön olevan jollain tavalla ilmaista. Kuluttajat eivät suo ajatusta sille, miten palvelun tuottaminen kustannetaan. Näin myös sähköpostipalvelun oletetaan olevan maksutonta, se halutaan ilmaiseksi.

Kurja tosiasia on, että maailmassa ei ole ilmaisia lounaita, ei myöskään ilmaista sähköpostia. Palvelun tuottaminen kustannetaan aina jollakin. Maksuttoman sähköpostipalvelun hinta on vaikkapa käyttäjän yksityisyys, kun palvelun tuottaja kerää tietoa käyttäjästä ja myy sitä mainostajille. Toinen hyvin luonteenomainen tapa kustantaa palvelun tarjoaminen on käyttäjälle näytettävät mainokset.

Yleisesti ottaen on helppo todeta, että sähköpostipalvelu on joko maksuton tai käyttäjän yksityisyyttä suojaava. On erittäin epätodennäköistä, että se olisi molempia.

Mainostajat kilpailevat raa'asti tilaajista, joten se mainostaja, joka osaa parhaiten kohdentaa mainoksensa, tuottaa parhaiten. Tästä syystä käyttäjän profilointi on olennaisen tärkeää palvelun elinvoimalle. Tarvitaan paljon yksityiskohtaista dataa käyttäjästä. Käyttäjän data on internetissä arvokasta valuuttaa.

Maksuttoman sähköpostipalvelun käyttäjä joutuu paitsi katselemaan mainoksia, tulee efektiivisesti myyneeksi yksityisyytensä hintana palvelun käytöstä. Ei ole aivan päivän selvää päättää olla käsittelemättä henkilökohtaisia asioita sähköpostilla. Yksityisyys ei ole pelkästään viestien sisällön pysymistä suojassa.

Vaikka käyttäisi sähköpostia vain esimerkiksi verkosta ostettavien palvelujen viestintään, sähköpostipalvelun tarjoaja saa silti hyvin paljon henkilökohtaista tieto käyttäjästä. Minkälaisista verkkokaupoista käyttäjä hankkii tavaroita ja palveluja? Kenen kanssa käyttäjä viestii, keihin ihmisiin hän on yhteydessä? Minkälaisia matkoja käyttäjä tekee, mistä lentoyhtiöstä varaa matkansa ja minkälaisista hotelleista hän pitää. Käyttäjästä voi tehdä hyvin pitkälle meneviä päätelmiä pelkästään kulutustottumusten perusteella (lue lisää aiemmasta [artikkelista](mita-haittaa-on-henkilotiedon-keraamisesta)).

### Tietoturva

Jo todettiin, että kotimaiset internet-operaattorit eivät salaa sähköpostiviestejä, kun ne liikkuvat palvelimien välillä. Varsinaisen sähköpostiviestin salaaminen ei ole yksinkertaista, joten liikenteen salauksella on suuri merkitys. Palvelimien ja tietoliikennelaitteiden välillä siirrettävää sähköpostiviestiä voi verrata postikorttiin. Kuka tahansa viestin varrelle osuva henkilö voi lukea viestin sisällön ja selvittää, kuka viestin on lähettänyt ja kenelle se on menossa.

Tietosuoja ja yksityisyys eivät ole ainoita perusteita palvelun tietoturvalle. Aivan liian moneen internet-palveluun kirjaudutaan käyttäjätunnuksella ja salasanalla. Kertakirjautuminen esimerkiksi sosiaalisen median tunnuksilla on yleistymässä, mutta niin moniin palveluihin on vielä erillinen salasana. Lähes kaikissa salasanaan tukeutuvissa palveluissa unohtuneen salasanan voi palauttaa sähköpostiosoitteen avulla.

Käytännössä sähköposti on avain kaikkiin palveluihin, joissa käyttäjä on asiakkaana. Kun pahantahtoinen hyökkääjä saa haltuunsa käyttäjän sähköpostin, hän on saanut pääsyn laajalti käyttäjän elämään tietoverkoissa. Toimiva oikean käyttäjän sähköpostitili on erittäin arvokasta valuuttaa tietoverkkojen alamaailmassa. Hyökkääminen käyttäjän sähköpostiin on ehkä yksi helpoimpia tapoja toteuttaa identiteettivarkaus ja esimerkiksi tilata verkkokaupoista tavaraa toisen henkilön luottotiedoilla.

On siis selvää, että sähköpostin tietoturvan taso on ensiarvoisen tärkeä valintakriteeri. Palvelussa pitäisi olla kaksivaiheinen tunnistus. Pelkästään salasanaan ja käyttäjätunnukseen perustuva tunnistaminen ei ole riittävä hyvälle sähköpostipalvelulle.

Sähköpostipalvelun ylläpito on oltava hyvällä tasolla. Palvelun käyttöjärjestelmät ja ohjelmistot on päivitettävä säännöllisesti. Palvelun tarjoajalla pitäisi olla hyvät menetelmät hyökkäyksien tunnistamiseen ja ehkäisyyn. Käyttäjätietojen pitäisi olla luotettavasti suojattu urkinnalta. Kaikki liikenne käyttäjän ja palvelun välillä pitäisi olla luotettavasti salattu.

### Roskapostin ja haittaohjelmien tunnistaminen ja suodattaminen

On tarpeetonta korostaa, kuinka suuri haitta roskaposti on sähköpostin käyttäjälle. Aivan yhtä tärkeää on, että sähköpostipalvelu ehkäisee haittaohjelmien leviämistä. Vaikka verkkosivuilta ja selaimien lisäosien kautta tarttuvat haittaohjelmat ovat nykyään tiedostoliitteiden mukana tulevia viruksia yleisempiä, sähköposti on edelleen tehokas kanava haittaohjelmien levittämiseen ja kalasteluhyökkäyksiin.

Hyvä sähköpostipalvelu suodattaa haittaviestejä molempiin suuntiin. Sen lisäksi, että se suodattaa erilliseen kansioon käyttäjälle saapuvat haittaviestit, se kieltäytyy välittämästä käyttäjän suunnasta lähteviä haittaviestejä. Käyttäjän päätelaitteessa piilottelevat haittaohjelmat saattavat käyttää sähköpostipalvelua keinona levittäytyä muille käyttäjille. On parasta ja etenkin käyttäjän uskottavuuden kannalta olennaista, että haittaohjelmat eivät pääse lähettämään viestejä käyttäjän nimissä.

Sähköpostin suodattamiseen on useita menetelmiä, kuten viestin sisällön heuristinen analysointi tai lähettäjän ja viestin välittävien palvelimien maineen analysointi. Parasta on kuitenkin estää haittapostin pääsy palvelimelle jo ennen, kuin sitä ollaan vastaanotettu.

Mustalistaus (blacklisting) on erittäin tehokas menetelmä estää haittapostia. Internetissä on valmiita mustia listoja tunntetuista haittaviestien lähettäjistä, avoimista releistä (open relays) ja erilaisia osoite-blokkeja kuvaavia listoja.

Drop-listalla voi esimerkiksi olla kuluttajaliittymien IP-osoitteet, joista ei ole tarkoituskaan lähettää sähköpostia. On yleinen konsensus ja Suomessa jopa säädös, että sähköpostia ei lähtetettäisi yksittäisistä liittymistä, vaan aina palvelimen kautta. Oletetaan tämän vähentävän haittapostin määrää, kun postia välitetään hallitummin ylläpidetyiltä palvelimilta.

Mainitsin jo, että haittaviestejä voidaan suodattaa lähettäjän maineen perusteella. Tällä on vastaanotettavien viestien suodattamisen lisäksi erityisestä merkitystä myös lähetettävien viestien osalta. Lähetettäessä viestejä huonomaineisesta palvelusta viestit jäävät helposti vaille huomiota päädyttyään herkästi vastaanottajan roskapostiin.

Internet-operaattoreiden sähköpostipalveluilla on paljon käyttäjiä, joista monella voi olla päätelaitteissan haittaohjelmia. Niinpä operaattorin sähköpostipalvelimien kautta lähetetään paljon haittapostia. Tämä heikentää palvelimien mainetta. Onkin hyvin yleistä, että operaattorinsa sähköpostipalvelimelta lähettävän käyttäjän viesti päätyy suoraan vastaanottajan roskapostiin ja jää vastaanottajalta huomaamatta.

### Kotimaisuus

Joillekin kuluttajille palvelujen kotimaisuus voi olla tärkeää. Panostamalla kotimaiseen palveluun kuluttaja on valinnallaan osoittamassa mieltään siitä, miten palvelujen pitäisi yleisesti kehittyä. Jos vain harvat ovat halukkaita ostamaan kotimaista palvelua, ei sellaista tule tarjollekaan.

Ihminen viestii todennäköisen paljon lähipiirillensä, jolloin voisi olettaa matkan viestin lähettäjän ja vastaanottajan välillä olevan lyhyt, jos sähköpostipalvelin on kotimaassa. Tämä on kuitenkin illuusio, kun suurin osa käyttäjistä käyttää ulkomaista sähköpostipalvelua.

Suomessa nousi pienimuotoinen häly, kun aiemmin kotimainen Sonera, nykyään Telia, siirsi suomalaisten internet-liittymätilaajien sähköpostipalvelun Ruotsiin (vrt. esim. Ilta-Sanomien [artikkeli](https://www.is.fi/digitoday/tietoturva/art-2000001574810.html)). Telian tavoite oli saavuttaa säästöjä konsolidoimalla pohjoismaisia palveluja.

Häly Telian suunnitelmasta nousi muutamasta hyvästä syystä. Tärkeimpänä oltiin huolissaan viestiliikenteen yksityisyydestä, kun viestit kulkevat joka tapauksessa rajan yli Ruotsin puolelle.

Hieman ennen hälyn syntymistä Ruotsin Valtio teki muutoksen lainsäädäntöönsä, joka salli Ruotsin Signaalitiedustelulaitoksen [(FRA)](https://fi.wikipedia.org/wiki/Försvarets_radioanstalt) kaapata ja analysoida valtion rajat ylittävää tietoliikennettä. Telian sähköpostipalvelun siirto ja Ruotsin signaalitiedustelulaki sallisi suomalaisten Telian internet-asiakkaiden sähköpostin massavalvonnan.

### Sähköpostiosoite ja sähköpostilaatikko

Tässä artikkelissa käytän yleisesti termiä sähköpostipalvelu, mutta on ymmärrettävä erottaa toisistaan sähköpostiosoite ja sähköpostilaatikko. Virtuaalisessa tietoverkkomaailmassa tapahtuvasta viestinvälityksestä löytyy helppo analogia reaalimaailman postin kulkuun.

Reaalimaailmassa kuluttajalla on postilaatikko tai kerrostalossa postiluukku, johon posti toimitetaan. Postilaitos osaa toimittaa postin perille kuluttajan osoitteen perusteella. Yleensä postiosoite viittaa suoraan tiettyyn maantieteelliseen ja fyysiseen sijaintiin, mutta ei aina. Postin vastaanottajalla on mahdollisuus hankkia postilokero, jolloin osoite ei ole sidoksissa esimerkiksi vastaanottajan kodin sijaintiin. Toisaalta muuttoilmoituksen yhteydessä tilataan postin edelleenvälityspalvelu, jossa postilaitos määräaikaisesti jakelun yhteydessä ohjaa vanhaan osoitteeseen osoitetun postin muuttajan uuteen osoitteeseen.

Sama mekanismi toimii tietoverkkojen virtuaalisessa vastineessa, eli sähköpostissa, mutta vieläkin helpommin. Postilaatikolla on aina postiosoite, mutta kuluttajan henkilökohtaisen sähköpostiosoitteen ei tarvitse olla sidottu postilaatikkoon. On lukuisia palveluja, joista kuluttaja voi tilata sähköpostiosoitteen, johon ei liity varsinaista postilaatikkoa, vaan kuluttaja voi edelleenohjata osoitteeseen lähetetyn postin määrittämäänsä vastaanottopaikkaan.

[Iki ry](http://www.iki.fi/index.html):n tuottama ikiosoite tavoittelee yhdistyksen jäsenelle ikuista osoitetta internetverkossa. Yhdistyksen toiminta kustannetaan uusien jäsenien liittymismaksuilla. Maksamalla liittymismaksun kerran jäsen saa todennäköisesti koko elämänsä ajaksi pysyvän osoitteen, josta viestit välitetään edelleen sähköpostilaatikkoon, jonka sijaintia jäsen voi muuttaa niin usein, kun on tarpeen.

Sähköpostin välittämisessäkin on pidettävä mielessä yksityisyys. Kun muistetaan, että kaikki viestin matkalla olevat toimijat voivat lukea viestin, on käyttäjän luotettava vahvasti välityspalvelun tarjoajaan.

Aikanaan Suomessakin keskusteltiin lainsäädännöstä, joka velvoittaisi internet-liittymiä toimittavat operaattorit välittämään sähköpostipalvelujensa viestit edelleen käyttäjän vaihtaessa toimittajaa samoin, kuin nykyään matkapuhelinnumero on siirrettävissä operaattorilta toiselle. Sähköpostin siirrettävyys olisi periaatteessa jopa helpompaa, kuin matkapuhelinnumeron siirrettävyys. Keskustelu ei koskaan kuitenkaan edennyt pidemmälle ja edelleenkin operaattorin sähköpostiosoitetta käyttävät kuluttajat ovat lukossa vanhaan operaattoriinsa.

Maksuttomissa sähköpostipalveluissa on usein mahdollisuus paitsi viestien välittämiseen, myös niiden noutamiseen toisesta sähköpostipalvelusta. Halutessaaan pois maksuttomasta sähköpostipalvelusta käyttäjällä usein on mahdollisuus välittää viestit edelleen ainakin määräajaksi. Jos tämä ei onnistu, uuden palvelun voi yleensä määrittää noutamaan viestit vanhasta. Internet-operaattorin sähköpostin tapauksessa palvelun jatkumiseen ei voi luottaa sen jälkeen kun liittymän tilaaminen ja maksaminen lakkaa.

Samoin, kuin on tehtävä ero sähköpostiosoitteen ja laatikon välille, on tehtävä ero lähettämisen ja vastaanottamisen välille. Näiden kahden toiminnon ei tarvitse tapahtua symmetrisesti samasta paikasta.

### Viestien allekirjoittaminen ja lähettämisen rajaaminen

Sähköpostiosoitteelle voidaan määritellä, mistä verkon IP-osoitteista on luvallista lähettää kyseiselle verkkotunnukselle kuuluvia viestejä. Tämä on eräs tapa vähentää roskapostia, kun väärennetyllä lähettäjän osoitteella varustetut viestit voidaan suodattaa pois.

Toinen erittäin tehokas tapa vähentää väärennetyn lähettäjäosoitteen haittoja, on edellyttää viestien digitaalista allekirjoittamista. En tarkoita tässä allekirjoitusta, jonka viestin kirjoittaja lisää viestin loppuun allekirjoituksensa sen vakuudeksi, että viesti on juuri häneltä henkilökohtaisesti. Viestiä välittävä sähköpostipalvelin voi lisätä viestiin allekirjoituksen, jolla voidaan todentaa, että viesti on lähtenyt täsmälleen ja ainoastaan siltä palvelimelta, jolla on lupa välittää tietyn sähköpostiosoitteen viestejä.

Kun viestissä on allekirjoitus, vastaanottaja voi luottaa siihen paremmin ja se ei päädy roskapostin joukkoon. Vastaanottaja saa varmuuden, että lähettäjän osoitetta ei ole väärennetty. Tämä vähentää tiedonkalastelun riskiä kun pahantahtoinen hyökkääjä ei pysty esiintymään Poliisina tai muuna viranomaisena.

Viestien allekirjoittamisen vaatiminen ja lähettävän palvelimen rajaaminen ei ole yksinkertaista. Jotta rajaaminen voi toimia, on sähköpostiosoitteen verkkotunnus sidottava lähettäjälle varattuun erilliseen sähköpostipalvelimeen tai lähettäjän on käytettävä osoitteenaan palvelun verkkotunnusta.

Esimerkiksi yritys voi allekirjoittaa työntekijöidensä lähettämät viestit omalla palvelimellaan ja vastaanottaja voi olla varma, että viesti on lähetetty yrityksestä, johon sähköpostiosoite viittaa. Toisaalta, esimerkiksi Gmail allekirjoittaa lähettämänsä viestit ja on rajoittanut palvelimia, joilta Gmail-osoitteella varustettuja viestejä voi lähettää.

Jos kuluttaja yrittää lähettää operaattorinsa sähköpostipalvelinta käyttäen viestin, jossa lähettäjäosoitteena on Gmail-osoite, viestin välittäminen joko estyy kokonaan tai se päätyy suurella todennäköisyydellä vastaanottajan roskapostilaatikkoon.

Allekirjoittamiseen ja rajaamiseen liittyvien epävarmuustekijöiden johdosta käytänteet eivät ole yleistyneet laajalti.

### Verkkotunnus

Verkkotunnus, eli domain on palvelujen osoite verkossa. Peruskäyttäjä ymmärtää verkkotunnuksen www-palvelun osoitteeksi. Verkkotunnuksella kerrotaan selaimen osoitekentässä, mihin palveluun halutaan päästä.

Sähköpostiosoite perustuu aivan samalla tavalla verkkotunnukseen. Www-palvelun tarjoaminen ei ole verkkotunnukselle pakollista. Käyttäjä voi ottaa omaan nimeensä perustuvan verkkotunnuksen vain sähköpostia varten. Tällä tavoin kuluttajan sähköpostiosoite voi olla esimerkiksi muotoa: etunimi@sukunimi.fi .

Suomalaisen .fi-päätteisen verkkotunnuksen saa Viestintävirastolta rekisteröidä käytännössä kuka tahansa. Nykyään rekisteröinti ei enää onnistu suoraan virastolta, vaan tarvitaan verkkotunnusvälittäjä. Kaupallisia palveluntarjoajia löytyy helposti internetin hakukoneilla. Myös yksityishenkilöllä on mahdollisuus rekisteröityä verkkotunnusvälittäjäksi edellyttäen, että pystyy tarjoamaan verkkotunnuksen vaatimat palvelut.

Kun verkkotunnus on rekisteröity, tarvitaan nimipalvelu, joka ohjaa verkkotunnuksen liikenteen sellaiselle palvelimelle, joka pystyy palvelemaan verkkotunnusta. Sähköpostiosoitteen tapauksessa viestiä lähettävän osapuolen palvelin kysyy nimipalvelusta, mikä sähköpostipalvelin pystyy vastaanottamaan verkkotunnukselle tarkoitetun viestin.

Verkkotunnuksen sähköpostipalvelin voi sisältää sähköpostilaatikon, johon viestit välitetään suoraan. On kuitenkin yksinkertaista toteuttaa myös sähköpostipalvelu, joka välittää viestit edelleen varsinaiseen sähköpostilaatikkoon. Verkkotunnuksen sähköpostiosoitteen ei siis tarvitse olla sidoksissa sähköpostilaatikkoon, johon viesti lopulta toimitetaan.

Rajtulle joukolle varattu verkkotunnus helpottaa edellisessä kappaleessa mainittujen suojaominaisuuksien käyttöä viestien lähettämisen rajaamisessa ja allekirjoittamisessa.

## Vaihtoehtoja arvioimassa

### Tee itse

Toteuttamalla sähköpostipalvelun itse saa täsmälleen sellaista, jota haluaa. Rajat palvelun toteutukselle asettaa oma osaaminen. Itse tekeminen ei tietenkään ole vaihtoehto kovin monelle. Sähköpostipalvelun asentaminen, toimintaan saattaminen ja jatkuva ylläpito vaativat vahvaa osaamista, jotta palvelu voi toimia luotettavasti ja että siitä ei olisi haittaa muille verkon käyttäjille.

Internetin hakukoneilla löytää paljon ohjeita sähköpostipalvelun perustamiseen ja ylläpitoon. Nykyään on myös paljon kohtuullisen helppojakin automaatiotyökaluja ja malleja, jolla yksitoikkoiset perustamis- ja ylläpitotoimet onnistuvat helposti.

On myös saatavilla helppoja paketteja, joihin sisältyy kaikki tarvittavat komponentit kuten käyttöjärjestelmä, sähköpostopalvelin ja muu väliohjelmisto. Käyttäjän tarvitsee vain asentaa ja määritellä palvelin tarpeeseensa sopivaksi. Tällaisia paketteja on esimerkiksi [iRedMail](http://www.iredmail.org) ja [Mail-in-a-Box](https://mailinabox.email).

Sähköpostipalvelun tuottamisen rajoituksena kotona kuluttajaliittymässä on Viestintäviraston määräys, jonka tarkoituksena on vähentää haittapostin määrää. Suomalaisista kuluttajaliittymistä on teknisesti estetty viestien lähettäminen. Joissakin liittymissä on estetty myös viestien vastaanottaminen, vaikka tätä ei määräyksellä rajoiteta.

Kotona toimivan sähköpostipalvelimen toimintaa haittaa myös se, että vähiin käyneet IPv4-osoitteet ovat kuluttajaliittymässä vaihtuvia. On toteutettava nimipalvelu, joka sopeutuu kuluttajaliittymän vaihtuvaan IP-osoitteeseen.

Kotiliittymään on mahdollista perustaa sähköpostipalvelin, joka vastaanottaa viestejä. Kuluttajan on mahdollista esimerkiksi rekisteröidä henkilökohtainen verkkotunnus ja perustaa sitä varten kotonaan tavanomaisessa internet-liittymässä toimiva palvelin, jossa on sähköpostin vastaanottamiseen tarpeelliset palvelut.

Lähettämistä varten kotikäyttäjä tarvitsee erillisen palvelimen, jolta viestien lähettäminen on mahdollista. Viestien lähettämiseen on kaupallisia palveluja, esimerkiksi: [Sendgrid](https://sendgrid.com) tai [Mailjet](https://www.mailjet.com). Molemmat ovat ulkomaalaisia palveluja, joiden pääkäyttötarkoitus on massapostitus, ei kuluttajakäyttö. Massapostitukseen käytettävien palvelujen maine voi toisinaan olla huono. Suomessa ei ole kuluttajalle soveltuvasti pelkästään lähettämiseen sopivaa palvelua.

Nykyään on helposti ja edullisesti hankittavissa virtuaalipalvelinkapasiteettia etenkin ulkomailta, mutta myös kotimaasta. Palvelinkapasiteetin hankkimisessa on pohdittava alustapalvelun luotettavuutta. Voiko palvelimen toimittajaan luottaa niin paljon, että uskaltaa välittää sähköpostinsa sen kautta? Onko palveluntarjoajalla rajoituksia sähköpostin välittämisessä? Alustapalvelun kotimaisuuteen luonnollisesti pätee, mitä aiemmassa kappaleessa pohdittiin sähköpostipalvelun kotimaisuudesta.

## Web-hotellit ja hosting-yritykset

Perinteisesti, kun haluttiin oma verkkotunnus tai omat verkkosivut, hankittiin web-hotellipaketti. Pakettiin kuului tietty määrä tietoliikennettä ja levytilaa kotisivuille. Niiden ohessa sai sähköpostipalvelun. Paketit ovat parhaimmillaan hyvin edullisia. Jopa 5 €:lla kuukaudessa voi saada kotisivupaketin, johon kuuluu sähköpostiosoitteita ja -laatikoita. Web-hotellipakettien yhteydessä on tietenkin mahdollista käyttää myös omia verkkotunnuksia.

Samoin, kuin verkkotunnuksen rekisteröinnissä, ei www-palvelu ole pakollinen. Web-hotellipaketin voi hankkia pelkästään sähköpostipalvelua varten. On myös aivan kotimaisia palveluoperaattoreita, jotka tuottavat yrityksille pelkästään sähköpostipalvelua. Pienen yrityksen ei ole kustannustehokasta käydä läpi kaikkia tässä artikkelissa mainittuja ja artikkelista unohtuneita yksityiskohtia, joita sähköpostipalvelun jatkuvassa ylläpidossa on huomioitava. Tilausta kotimaisellekin sähköpostipalvelulle selvästi on.

Palvelupakettien tietosuoja ja tietoturva on yleensä kohtuullisella tai ainakin riittävällä tasolla, sillä huonoa palvelua tarjoava yritys ei pitkään pysyisi markkinoilla.

Palvelupaketit on yleensä kohdennettu nimenomaan yrityksille. Niiden käyttäminen ja käyttöön määrittäminen vaatii jonkin verran asiantuntemusta. Ne eivät siis suoraan sovellu tyypilliselle kuluttajalle arkiseksi sähköpostipalveluksi. Jos osaamista hieman on tai voi pyytää apua asiantuntijalta ja on valmis maksamaan sähköpostipalvelusta, on palvelupaketti hyvä vaihtoehto sähköpostipalveluksi kuluttajalle.

Artikkelin kirjoittajalla ei ole tuoretta kokemusta palvelupaketin tilaamisesta ja tämä onkin mielenkiintoinen haaste artikkelin väitteelle, että suomalaiselle kuluttajalle ei ole hyvää vaihtoehtoa sähköpostipalveluksi. Palvelupaketti voisi sellainen mahdollisesti olla, mutta asiaa pitäisi selvittää ja tarjontaa vertailla perusteellisemmin.

Tunnettuja kotimaisia palveluja on esimerkiksi: [Sigmatic](https://www.sigmatic.fi), [Nebula](http://www.nebula.fi) ja [Planeetta](https://www.planeetta.net).

### Internetoperaattorin sähköpostipalvelu

Artikkelissa on useasti viitattu ongelmiin internet-operaattorin tarjoamassa sähköpostipalvelussa, joten kerrataan ne tähän lyhyesti listan muodossa:

* sähköpostiviestejä ei salata siirrettäessä palvelimien välillä
* sähköpostipalvelimien maine on huono ja viestit päätyvät herkästi vastaanottajan roskapostiin
* käytettäessä operaattorin tarjoamaa sähköpostiosoitetta, siirtyminen toisen operaattorin asiakkaaksi on työlästä
* ei ole mahdollista (ainakaan helposti) käyttää lähettäjän osoitteena sellaista osoitetta, jossa rajoitetaan sallittuja lähettäviä palvelimia

Operaattorin tarjoamaa sähköpostia ei siis kannata käyttää viestien lähettämiseen tai myöskään vastaanottamiseen.

### Googlen Gmail

Ei ole mahdollista kirjoittaa artikkelia sähköpostipalvelusta mainitsematta Googlen maksutonta [Gmail](https://gmail.com)-sähköpostipalvelua. Erityisen tunnettu Googlen sähköpostipalvelu on käytännöstään skannata käyttäjän sähköpostit ja tarjota viestiin liittyviä mainoksia.

Googlen sähköposti onkin ensimmäisiä palveluja, joiden tarjoaminen perustuu nimenomaan käyttäjän profilointiin. Aluksi profilointi tehtiin nimenomaan sähköpostiviestien perusteella. Nykypäivänä Googlella on käyttäjästä niin paljon tietoa myös muista lähteistä, että sähköpostiviestien skannaaminen menettää merkitystään varsinkin, kun siitä on kohuttu niin paljon.

Googlen maksuttomat palvelut hakukoneesta puhumattakaan ovat niin kattava paketti, että ne kokonaisuudessan herkästi lukitsee käyttäjän pysyväksi asiakkaaksi. Gmail:ssa on ominaisuuksia, joiden perusteella palvelua voisi arvioida maksuttomien sähköpostipalvelujen parhaimmistoon, ellei parhaaksi.

En pysty kuvailemaan tässä artikkelissa kaikkia Gmailin ominaisuuksia, eikä siihen ole syytäkään, sillä Googlella on kattava helppolukuinen ohjeistus myös suomen kielellä.

Gmail käyttää edellä mainittuja viestin allekirjoittamista ja lähettävien palvelimien rajaamista. Palvelussa on erittäin hyvin toimiva haittaviestien suodatus. Gmail täyttää tässäkin artikkelissa esitetyn toiveen estämällä valtaosan haittaviesteistä vastaanottovaiheessa ennen kuin ne pääsevät eteenpäin vastaanottoprosessissa.

Gmail on jopa tunnettu siitä, miten ärhäkästi se kieltäytyy vastaanottamasta joitakin viestejä. On yleinen tukipyyntö tai keskustelupalstan aihe kysyä, miksi Gmail ei suostu ottamaan vastaan viestiä. Usein syynä on väärin konfiguroitu palvelin tai yksinkertaisesti palvelin, jonka Google on havainnut lähettävän massaviestejä tai runsaita määriä haittaviestejä. Googlella on hyvät mahdollisuudet havaita tällaise haitalliset palvelimet, kun se vastaanottaa niin valtavia massoja viestejä ja sillä on käyttäjiä kaikkialta maailmasta.

Gmailista on mahdollista välittää viestejä edelleen toiseen postilaatikkoon vaikkapa suodattamalla vain halutunlaiset viestit. Se myös osaa hakea viestejä muista laatikoista. Gmailin voi siis määrittää hakemaan viestejä vaikkapa vanhasta sähköpostiosoitteesta, jolloin käyttäjä saa yhdellä käyttöliittymällä nähtävilleen useisiin eri osoitteisiin tai laatikoihin lähetetyt viestit, vaikka niitä ei alkuperäisestä palvelusta saisikaan ohjattua edelleen.

Gmailin avulla on mahdollista käyttää omaa verkkotunnusta. Gmailiin voi ohjata omaan verkkotunnukseen saapuvat viestit ja sen voi määritellä lähettämään viestejä oman verkkotunnuksen osoitteella jopa täysin läpinäkyvästi jos verkkotunnuksella on lähettämiseen sopiva palvelin.

Googlen palveluissa on mahdollista käyttää kaksivaiheusta tunnistamista. Se vähentää käyttäjätilin kaappaamisen riskiä.

Ominaisuuslista kasvaa helposti pitkäksi ja tietenkin samoja ominaisuuksia löytyy muistakin palveluista. Edelleen, Google on onnistunut tekemään palveluista kokonaisvaltaisen paketin, jota on vaikea sivuuttaa.

Ettei osio menisi pelkäksi suitsutukseksi, on muistutettava Gmailin käyttöön liittyvistä haitoista, vaikka ne ovatkin ilmeisiä. Googlen sähköpostipalvelun yksityisyys on vahvasti kyseenalaistettu. Google tietää käyttäjästä valtavasti ja saadessaan käyttäjän yksityisen viestinnän haltuunsa, kokonaisuus on suorastaan pelottava.

Google on yhdysvaltalaisena yrityksenä alistettu viranomaisten salaisiin pakkokeinoihin, joiden toteutumisesta se ei edes saa ilmaista. On väitetty, että Googlen palvelut olisivat mukana yhdysvaltalaisessa massavalvonnassa siten, että viranomaisilla on suora pääsy Googlen käyttämiin henkilötietoihin ja käyttäjädataan. Viranomaisilla olisi väitteiden perusteella mahdollisuus penkoa käyttäjien tietoja kertomatta asiasta tutkinnan kohteelle.

Ennen Googlen Haminan konesalin käyttöönottoa ja todennäköisesti vielä sen jälkeenkin suomalaisten käyttäjien liikenne Gmailia tuottaville palvelimille kulkee ulkomaisissa verkoissa. Ennen, kuin Ruotsin ohittava valokaapeliyhteys Saksaan otetaan kattavasti käyttöön, liikenne on alttiina Ruotsin signaalitiedustelulaitoksen massavalvonnalle.

Googlen sähköpostipalvelusta on tullut maksuttomuudessaan niin suosittu, että se on pyyhkinyt kilpailijansa maailmankartalta. Kuluttajan on vaikea löytää edes maksullista käyttäjän yksityisyyttä turvaavaa viestivälinettä pitkälti mm. sen seurauksena, että Gmail on vallannut markkinat. Asetelmaan pätee myös muut monopoliaseman tai ainakin määrävän markkina-aseman haitat.

Aina toisinaan kysytään tai haastetaan esim. EU:n toimielimiä selittämään, miksi EU:ssa ei ole kotiperäistä tarjontaa tietotekniikkapalveluille. Eurooppalaiset markkinat eivät ole pystyneet tuottamaan käyttöjärjestelmää, päätelaitetta tai digitaalista palvelua, joka olisi saavuttanut edes sisämarkkinoilla edes merkittävää asemaa. EU:lla olisi sisämarkkinassaan mahdollisuus tukea paikallisia palveluja. Eurooppalaisten palvelujen vähyys lienee merkki siitä, että poliittisesti olisi liian uhkarohkeaa ehdotaakaan tällaista sisämarkkinoiden protektionismia.

Eurooppalaisen kansalaisen korvissa soi kysymys, miten voi olla, että kotoperäiset palvelumme jatkuvasti polkevat altavastaajan asemassa. Tätä kysymystä ei pidä kohdentaa pelkästää poliitikoille, vaan katsoa peiliin jakaessaan Gmail-osoitetta yhteystietonaan.

### Microsoftin Outlook

Aiemmin artikkelissa mainittiin ensimmäisten ilmaispalvelujen joukossa noussut hotmail.com, joka on nykyään osa Microsoftin [outlook.com](http://outlook.com)-palveluja. Erinäisten vaiheiden kautta osoite ja sähköpostipalvelu päätyi Microsoftin omistukseen ja nyt se on osana Microsoftin webissä tarjoamaa toimisto-ohjelmapakettia.

Siinä, missä Hotmail oli tarjolla yksityisille kuluttajille, Outlook on tunnettu myös sähköpostin asiakasohjelmana, joka toimi yhdessä Microsoftin Exchange -sähköpostipalvelinohjelmiston kanssa. Yrityksellä on edelleen paikallisia omissa tiloissa toimivia sähköpostipalvelimia, mutta yhä useampi ulkoistaa palveluja Microsoftin pilvipalveluihin todetessaan, että palvelimien ylläpito ei ole yrityksen ydintoiminta-aluetta.

Kuluttajille suunnatussa maksuttomassa sähköpostipalvelussa on pitkälti samoja ominaisuuksia, kuin Gmail:lla.

Outlook onkin eräs merkittävimmistä kilpailemassa Gmailille. Outlook ei ole saanut lainkaan merkittävää jalansijaa kuluttajien piirissä. [Erään](https://litmus.com/blog/email-client-market-share-trends-1h-2017) tilaston perusteella Outlookilla olisi sähköpostiasiakkaista 7%:n markkinaosuus, kun Gmailin hallussa olisi 21 %. Tässä tarkastelussa ensimmäisenä olisi Applen iPhone 31 %:n markkinaosuudella.

Outlook ei ole saanut kasvatettua sähköpostipalvelunsa markkinaosuutta edes Skype-palvelulla. Alun perin virolainen Skype menettää myös pikaviestinnässä merkitystään. Viimeisin mobiililaitteisiin suunnattu päivitys Skypen asiakasohjelmistosta teki pikaviestimen käytännössä käyttökelvottomaksi. Skype oli aikanaan kalliiden ulkomaanpuheluiden selättäjänä paljon huomiota ja asiakkaita kerännyt palvelu, mutta on tänään kuluttajakäytössä merkityksetön. Hyvästä integroinnistaan huolimatta sillä ei ole juuri käyttöä edes Outlook-sähköpostin yhteydessä.

Outlookin käyttöön pätee aivan samat haasteet ja hyödyt, kuin Gmailin käyttöön. Outlookin eduksi voi laskea, että se toimii saumattomasti yhteen Office toimisto-ohjelmiston kanssa. Googlen pilvestä tarjoamat työkalut eivät ole lainkaan yhtä tunnettuja.

Outlookista ja Gmailista on vaikea keksiä mitään sellaista ainutlaatuista näkökulmaa, jota ei olisi internetissä niin monesti sanottu. En halua suositella kumpaakaan hyvänä sähköpostipalveluna kuluttajalle ilmeisistä puutteista, erityisesti heikosta yksityisyyden tasosta ja palveluiden ulkomaisuudesta johtuen.

Jos käyttäjä hyväksyy palvelujen puutteet, ne ovat erinomaisia työkaluja. Kirjoittajana toivoisin, että kuluttajat olisivat valistuneempia ja ymmärtäisivät paremmin valintojensa seuraukset siitä huolimatta ja etenkin siksi, että palvelut ovat näennäisesti maksuttomia.

### Applen iCloud

Apple on huonosti tunnettu, mutta mielenkiintoinen toimija amerikkalaisten käytännössä maksuttomien sähköpostipalvelujen tarjoajana. Ollessaan yhdysvaltalainen, sillä on samat haasteet yksityisyyden osalta, kuin Googlella ja Microsoftilla. Apple on kuitenkin onnistunut pitämään paremman julkikuvan suhteessa käyttäjän henkilötietojen säilyttäjänä.

Kuluttajan saa käyttöönsä Applen iCloud pilvipalvelun hankkiessaan minkä tahansa Applen tuotteen (esim. Mac, iPhone tai iPad). Käytännössä pilvipalvelun käyttäjätilin rekisteröiminen on pakollista IOS-laitteiden käyttöönottamiseksi. Pilvipalvelusta on saatavilla ilman erillistä maksua myös sähköpostilaatikko ja siihen liittyvä sähköpostiosoite. Sähköpostiosoite on muotoa valittavissa@icloud.com .

Erillismaksuton laitteen hintaan sisältyvä tili sisältää 5 Gt tallennustilaa, joka on jaettu palvelujen kesken. Jos käyttäjällä on 3 Gt edestä valokvuia, muulle käytölle jää 2 Gt tilaa. Sähköposti kuluttaa tätä tilaa samoin, kuin muutkin iCloud-palvelut. Tilaa saa ostaa kuukausimaksulla lisää erikokoisissa paketeissa aina yhteen teratavuun asti. Tavanomaiselle kotikäyttäjälle 5 Gt käy nopeasti pieneksi, jos on tapana ottaa lainkaan valokuvia puhelimella.

Applen iCloud-saähköpostissa on vähemmän ominaisuuksia, kuin Gmailissa tai Outlookissa. Viestejä voi lähettää vain icloud.com -osoitteella. Tietysti omasta verkkotunnuksesta voi välittää sähköpostit edelleen iCloud-postilaatikkoon, mutta omalla osoitteella lähettäminen on hoidettava jotenkin muutoin.

iCloud-sähköpostissa on haittaviestien suodatus. Apple on vähemmän tunnettu ominaisuudesta, että se hiljakseen hylkää käyttäjälle saapuneita viestejä tunnistaessaan ne haitalliseksi. Tällä tavoin käyttäjä saattaa menettää myös aitoja viestejä, jotka Apple tulkitsee haitalliseksi. Tällaisia saattavat olla viestie, joiden tekstissä on joitakin fraaseja tai sanoja, jotka koetaan uhkaavaksi tai haitalliseksi (esimerkiksi lapsipornoon viittaavia asioita).

Viestien hävittämisestä ei ole syntynyt varsinaista kohua, mutta toimintoa on väitetty ennakkosensuuriksi, eli ihmisoikeuksiin kuuluvan sananvapauden rajoittamiseksi. Toiminto on hankala siksi, että palvelu vastaanottaa viestin toimittamatta sitä perille tai kertomatta loppukäyttäjälle, että viesti on hävitetty. Sen enempää viestin lähettäjä, kuin vastaanottaja ei saa tietoa viestin välittämisen epäonnistumisesta, vaan viesti vain hiljaa katoaa.

Apple väittää ja alan asiantuntijat vaikuttavat olevan vakuuttuneita, että iCloud-palvelujen yksityisyys on yleisesti aivan merkittävästi paremmalla tasolla, kuin muilla toimijoilla siitä huolimatta, että palvelu sijaitsee Yhdysvalloissa.

Viestit salataan palvelimien välillä siirrettäessä TLS-salauksella silloin, kun toisen osapuolen palvelimella on tuki salaukseklle. Voidaan kuitenkin väittää, että viranomaisilla olisi keinot seurata tietoliikennettä ja tarvittaessa valtavalla laskentateholla purkaa salaus niin halutessaan.

Apple väittää, että kaikki käyttäjän iCloudiin tallentama data sähköposti mukaan lukien olisi salattu ja että salaukseen tarvittava salainen avain olisi vain käyttäjän hallussa päätelaitteeseen tätä varten erikseen toteutetulla suojatulla enklaavilla. Apple on ollut Yhdysvaltain viranomaisten pakkokeinojen kohteena jopa niinkin tiukassa tilanteessa, että julkisuuteen asti on päässyt riita valtion ja Applen välillä tapauksista, joissa viranomaiset ovat vaatineet Applelta oikeuden päätöksen nojalla käyttäjän tietoja, mutta Apple ei ole pystynyt toimittamaan tietoja sillä perusteella, että sillä ei ole keinoa löytää tietoa palvelusta ja vaikka tieto löytyisi, sen salausta ei olisi mahdollista purkaa ilman käyttäjän omia toimenpiteitä (salaisen avaimen luovuttamista).

On tiedossa tapauksia, joissa viranomaiset ovat rikostutkinnassa mielummin hyödyntäneet päätelaitteiden heikkouksia tietojen saamiseksi, kuin yrittäneet urkkia tietoja Applen pilvipalvelusta.

Voi siis olettaa, että Applen pilvipalvelujen yksityisyydensuoja on monta kertaluokkaa paremmalla tasolla, kuin Gmail:n tai Outlookin.

Vaikka viranomainen ei pääse käsiksi varsinaiseen selväkieliseen tietoon, sillä on pääsy viestinnän metatietoon. Viranomainen voi joissain tapauksissa selvittää, keiden kanssa käyttäjä on viestinyt ja koska sekä jopa mahdollisesi missä.

Kun kaksivaiheinen tunnistaminen on ollut muiden palvelujen osalta käsillä, mainittakoon, että Apple nykyään käytännössä pakottaa kaksivaiheisen tunnistamisen käyttöön. Muilla palveluilla kaksivaiheinen tunnistaminen on erikseen päälle kytkettävä ominaisuus.

Jos käyttäjä on valmis tinkimään sähköpostipalvelun kotimaisuuden asteesta, Applen iCloud-sähköpostipalvelua voi suositella. Käytän sitä itse sillä perusteella, että se on huonoista vaihtoehdoista paras.

### Muut maksuttomat

Luetteloa sähköpostipalveluista voisi jatkaa loputtomiin. Artikkelia on mahdoton kirjoittaa täydelliseksi, mutta pyrittäköön kattavuuteen mainitsemalla kotimainen maksuton sähköpostipalvelu [luukku.com](https://www.luukku.com/). Se on MTV3:n ylläpitämä maksuton sähköpostipalvelu, johon sisältyy rajattu tila viesteille. Luukku-sähköpostin ongelmaksi muodostuukin hyvin nopeasti tilan puute. Viestejä on säännöllisesti poistettava tai panostettava maksulliseen lisälevytilaan. Äkkiä käy turhauttavaksi maksaa lisälevytilasta, kun lisämaksu ei poista mainoksia palvelun käyttöliittymästä. Luukku-sähköpostia ei voi käyttää erillisellä sähköpostiohjelmalla, vaan ainoastaan web-käyttöliittymällä. Palvelun yksityisyyden suoja on myös kyseenalainen.

Säännöllisesti maksuttoman sähköpostin markkinoille ilmaantuu uusia yrittäjiä, kuten viimeisimpänä vaikkapa [meiliboxi.fi](https://meiliboxi.fi). Nämä ovat innostuneiden harrastajien pystyttämiä palveluja, mutta uskaltaako käyttäjä luottaa niiden pysyvyyteen? Etenkin, jos palvelussa on rajoitettu käytettävää sähköpostiosoitetta, voi kuluttaja äkkiä olla kummallisessa tilanteessa, kun hänen sähköpostiosoitteensa ei yhtäkkiä olekaan saavutettavissa. Harrastaja ei ehkä enää jaksakaan ylläpitää maksutonta palveluaan tai lahjoittaja kyllästyy kustantamaan palvelun vaatimia palvelimia tai tietoliikennettä. Heikosti ylläpidetty palvelu saattaa osoittautua palvelinresurssia lahjoittavalle yritykselle huonoa mainetta tuottavaksi rasitteeksi.

### Kertakäyttöosoitteet

Toisinaan sähköpostia tarvitsee vain yhteen tarkoitukseen ja lyhyen aikaa. Kaikissa määritysten mukaan toimivissa sähköpostipalveluissa on mahdollisuus ohjata viestejä paikallisella osalla. Esimerkiksi viestien pitäisi kulkeutua perille molemmilla osoitteilla: nimi@posti.not ja nimi+erote@posti.not .

Jälkimäisen osoitteen erotteen avulla on mahdollista esimerkiksi ohjata sähköpostipalvelun suodattimien avulla viestit erilliseen kansioon tai suoraan roskakoriin. Näin voi antaa vaikkapa kaupallisille toimijoille erinäköisiä osoitteita ja ohjata viestit niin, että ne eivät täytä varsinaista saapuneet-viestien kansiota.

Aivan lyhyitä yksittäisiä tarpeita ja etenkin testaamista varten on myös palveluja, joista saa kertakäyttöisen, pois heitettävän sähköpostiosoitteen. Tällaisia ovat esimerkiksi: [Mailinator](https://www.mailinator.com) tai [Guerillamail](https://www.guerrillamail.com).

### Yksityisyyttä suojaavat palvelut

Verkossa on saatavilla myös sähköpostipalveluja, joita markkinoidaan erityisesti yksityisyysaspektilla. Palveluista voi olla saatavilla maksuton osoite ja laatikko, mutta yleensä laajempi käyttä vaatii maksullisen tilauksen hankkimista.

Suomessa tällaista erityisesti yksityisyyttä suojaavaa sähköpostipalvelua ei ole saatavilla, joten jos kotimaisuus on tärkeä valintakriteeri, tällaista vaihtoehtoa ei ole. Lyhyellä verkkohaulla löytyy muutamakin vaihtoehto, eräs pohjoismaasta Norjasta: [Runbox](https://runbox.com).

Runbox mainostaa yksityisyydensuojaa nimenomaan sijainnillaan Norjassa, norjalaisen lainsäädännön alla. Norja ei salli massavalvontaa, mutta koska tietoliikenne Suomesta väistämättä kulkee Ruotsin kautta, liikenne on silti alttiina Ruotsin signaalitiedustelulle.

Pankkisalaisuudestaan tunnetussa Sveitsissä on tarjolla [Protonmail](https://protonmail.com). Se on tunnettu päästä-päähän salauksestaan. Olen muistelevani, että Protonmail olisi väittänyt salaavansa käyttäjän tiedot myös tallennusvaiheessa, joten Applen palvelun tavoin ainoastaan käyttäjällä on pääsy tietoihin salaisen avaimensa turvin.

Olen ollut enemmän kiinnostunut oman sähköpostipalvelun ylläpidosta ja en ole erityisesti tutustunut yksityisyyttä säilyttävien sähköpostipalvelujen tarjontaan. Niistä ei ole helposti löydettävissä luotettavaa vertaisarviointia, joten palvelujen vertailu ei ole helppoa. Palvelujen perusteellinen testaaminen vaatisi rahallista panostusta, sillä maksuttomassa yksityisyyttä suojaavassa sähköpostipalvelussa on ilmeinen ristiriita. Yksityisyyttä suojaavat sähköpostipalvelut ovat myös markkinassa uuusia.

## Kokonaisuus syntyy yhdistelemällä

Artikkeli lähestyy loppuaan ja tässä vaiheessa on todettava, että sen nimeksi olisi paremmin sopinut: Kuluttajalle ei ole yhtä hyvää sähköpostipalvelua. Valistunut kuluttaja voi saada tyydyttävän sähköpostipalvelun yhdistelemällä parhaita osia huonoista vaihtoehdoista.

Moni käyttääkin useita palveluja, mutta harva kuluttaja varmastikaan pystyy kokoamaan edes tyydyttävää kokonaisuutta, vaan joutuu väistämättä tyytymään sähköpostiasiakkaana kompromisseihin.

Minulla on pääsy luotettavaan ja edulliseen palvelinkapasiteettiin, mikä mahdollistaa tuottaa omaa sähköpostipalvelua. Toimin .fi-verkkotunnusvälittäjänä, joten voin käyttää omaan sukunimeeni perustuvaa sähköpostiosoitteen verkkotunnusta.

Oman palvelimen ylläpidosta huolimatta, tai ehkä juuri siitä syystä olen päättänyt ulkoistaa sähköpostilaatikon iCloud.com -palveluun. Otan vastaan sähköpostiviestit omalla palvelimellani, mutta välitän ne edelleen Applen pilvisähköpostiin.

En halua säilyttää viestejä omalla palvelimella, sillä luotan itseäni enemmän Appleen palvelun saatavuuden osalta. Oma palvelimeni saattaa kaatua tai olla muutoin saavuttamattomissa koska tahansa, joten Applen pilvessä viestit ovat todennäköisemmin saatavilla.

Olen säätänyt sähköpostiohjelmat niin, että lähtevät viestit ohjataan oman palvelimeni kautta. iCloud-sähköpostia ei saa asetettua näyttämään omaan verkkotunnukseen perustuvaa osoitetta lähettäjän osoitteena. En käytä iCloud-sähköpostia lähettämiseen paitsi toisinaan mobiilipäätelaitteilla, joiden ohjelmia on hankalampi määrittää käyttämään omaa palvelinta iCloud:n sijasta. Oma kopioni lähetetyistä viesteistä kuitenkin tallennetaan iCloud-laatikkoon saapuvien viestien tapaan.

Sähköpostin asiakasohjelmat käyttävät omalle sähköpostipalvelimelle tunnistamisessa Googlen sovelluskohtaista salasanaa. Jokaisella asiakasohjelmalla on erillinen salasana. Jos yhden päätelaitteen salasana päätyisi vääriin käsiin, se on helppo poistaa käytöstä. Vaikka yhden salasanan sulkee, muut säilyvät käytössä. Tämä järjestely vähentää tilin kaappaamisen riskiä, joskin parantaa merkittävästi Googlen mahdollisuuksia lähettää sähköpostia minun nimissäni. Lisää järjestelystä toisessa [artikkelissa](google-on-nappara-idm-jarjestelma).

Omalla palvelimella pystyn rajoittamaan sähköpostiviestien lähettämistä minun nimissäni ja allekirjoittamaan lähetetyt viestit. Koska yksi ja sama IP-osoite on vain minun käytössäni, vastaanottavat sähköpostipalvelimet harvoin tulkitsevat sitä haitallisten viestien lähettäjäksi, eli sillä on hyvä maine. Tämä parantaa viestien toimittamisen luotettavuutta.

Tämän varsinaisen oma palvelin, iCloud -yhdistelmän lisäksi käytän toki myös Gmail- ja Outlook-palveluja. Outlookin sähköposti on käytössäni vain satunnaista kokeilua ja selvittelyä varten. Gmailia käytän mainoksille. Se on eräänlainen roskalaatikko-osoite, jonka voin herkästi luovuttaa, jos haluan suojella varsinaista osoitetta. Myös Gmail on tarpeen erilaisessa sähköpostin käyttöön liittyvässä testaamisessa.
