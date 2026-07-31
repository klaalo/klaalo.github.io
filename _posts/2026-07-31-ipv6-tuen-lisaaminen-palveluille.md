---
layout: post
title: IPv6-siirtymä olisi pitänyt tehdä jo
date: "2026-07-31 14:18:00 +0300"
---

## Tekoälyn avustuksella kirjoitettu

Jos tämä artikkeli kuulostaa tekoälyn tekstiltä, se todennäköisesti johtuu siitä, että artikkelin luomisessa on käytetty tekoälyä.

Tein IPv6-muutoksen pitkälti tekoälyavusteisesti. Koska projekti vaati kuitenkin merkittävän määrän aivan perinteistä "käsityötä", ajattelin kirjoittaa olennaiset asiat muistiin. Ehkä näistä on iloa jollekin toiselle – vaikkapa tekoälylle, joka haravoi blogeista tietoa, tai ihmiselle, joka painii samojen kysymysten kanssa.

Olen tietenkin tarkistanut ja viimeistellyt tekstin itse.

## Miksi juuri nyt?

[Viimeisimmässä](/notes/digitaalinen-itsenaisyys-muodostuu-pienista-asioista) kirjoituksessani kerroin, miksi päätimme siirtyä itse ylläpidettävään Mailcow-sähköpostipalvelimeen. Se oli yksi askel kohti parempaa digitaalista itsenäisyyttä ja omaa palveluiden hallintaa.

Tässä jatkan samaa polkua: kuinka lisäsimme palveluihin IPv6-valmiuden. Projekti ei rajoittunut vain palvelimiin, vaan jouduin tuomaan IPv6-tuen myös toimistolleni.

En ole aiemmin kiirehtinyt toimiston verkon IPv6-päivitystä, koska se ei ole tuntunut välttämättömältä. Nykytilanteessa IPv4-osoitteet ovat kuitenkin muuttuneet niukkuushyödykkeeksi, josta joutuu maksamaan erikseen. Urakka oli siis myös taloudellisesti kannattava.

IPv6 ei ole mikään uusi keksintö – se on suunniteltu jo 1990-luvulla. Siirtymän olisi pitänyt tapahtua jo aikoja sitten, sillä IPv4-osoitteet ovat loppumassa. Alkuperäinen 4,3 miljardin osoitteen avaruus ei riitä nyky-internetille, jossa [miljardeilla laitteilla on oma tarpeensa](https://www.internetsociety.org/resources/2018/state-of-ipv6-deployment-2018/). IPv6:n 128-bittinen osoiteavaruus ratkaisee tämän perusongelman käytännössä lopullisesti.

Suomessa teleoperaattorit ovat edenneet vaihtelevasti:
- DNA oli edelläkävijä ja toi laajan IPv6-tuen jo 2014–2015 ([DNA Oyj, 2015](https://www.sttinfo.fi/tiedote/27522180/dna-is-leading-the-way-in-ipv6-adoption-in-finland)).
- Elisa ja Telia seurasivat perässä, ja vuonna 2024 kaikkien suurten operaattorien kattavuus oli jo yli 90 prosenttia ([Wikipedia](https://en.wikipedia.org/wiki/IPv6_deployment)).

Konsultti ei aina työskentele samassa toimistossa. Myös matkapuhelinoperaattorin 5G-liittymän täytyy tarjota IPv6-tuki, jotta työt sujuvat.

Nykyään suuret sähköpostipalvelut (Gmail, Yahoo, Outlook) tukevat molempia protokollia. IPv6 on usein suoraviivaisempi vaihtoehto ilman NAT-välityksen aiheuttamia viiveitä.

Tässä projektissa tavoitteenani oli:
- Vähentää turhia kustannuksia poistamalla IPv4-osoitteet palvelimilta, joilla niitä ei tarvita (kuten toimiston ja palvelinalustan väliset yhteydet).
- Varmistaa sähköpostin toimitusvarmuuden tulevaisuudessakin.
- Parantaa palvelujen saavutettavuutta ja varautua aikaan, jolloin IPv6 on oletusarvo.
- Päästä eroon kikkailuista, kuten porttiohjauksista tai [Hairpin NAT:sta](https://help.ui.com/hc/en-us/articles/30202160464023-Hairpin-NAT-in-UniFi), hyödyntämällä suoria IPv6-yhteyksiä.

Vaikka kyseessä oli Karidea Oy:n työprojekti, kirjoitan tästä täällä henkilökohtaisessa blogissani. Ehkä myöhemmin näistä tulee asiaa uutiskirjeeseen, mutta se on sitten toisen kerran aiheena.


## Sähköpostin erityisvaatimukset

Sähköpostipalvelimen IPv6-lisäys on vaativampi tehtävä, kuin vaikka tavanomaisen web-palvelun ostalta.

### 1. FCrDNS ([Forward-confirmed Reverse DNS](https://en.wikipedia.org/wiki/Forward-confirmed_reverse_DNS))

Kaikki kolme täytyvät täsmätä:
- Forward DNS (AAAA-tietue)
- Reverse DNS (PTR-tietue)
- SMTP-banneri: postipalvelin ilmoittaa vastauksessaan nimensä oikein

Jos yksi näistä puuttuu tai ei täsmää, sähköpostit menevät roskapostiin tai
hylätään kokonaan.

PTR-tietueita eli IP-osoitteen [käänteistä nimeä](https://en.wikipedia.org/wiki/Reverse_DNS_lookup), jolla tiettyä IP-osoitetta vastaava nimi voidaan selvittää, ei määritellä verkkotunnuksen DNS-palvelussa. Se täytyy muuttaa kyseisen verkon operoinnin toimesta, eli yleensä sillä alustalla, missä itse palvelin toimii (hosting provider).

### 2. SPF (Sender Policy Framework)

SPF on kuvaus siitä, ketkä saavat lähettää sähköpostia meidän nimissämme.

Ratkaisumme:

    v=spf1 mx a -all

Hyvä puoli tässä konfiguraatiossa: `mx`- ja `a`-mekanismit kattavat automaattisesti sekä A- että AAAA-tietueet. Ei tarvinnut lisätä erillistä
IPv6-mekanismia. AAAA-tietueen lisääminen sähköpostipalvelimen osoitteelle riitti.

### 3. DKIM ja DMARC

Nämä ovat protokollariippumattomia, joten niissä ei tarvittu muutoksia:
- DKIM: Avain varmistaa viestin eheyden (ei liity IP-versioon)
- DMARC: Ohjeistus vastaanottajille, miten käsitellä epäonnistuneet autentikoinnit

### 4. Gmail ja Yahoo 2024-vaatimukset

Vuoden 2024 helmikuusta lähtien suurten sähköpostipalveluiden vaatimukset:
- Paikkansa pitävät forward/reverse DNS-parit (sekä IPv4 että IPv6)
- SPF TAI DKIM vähintään (molemmat suositeltu)
- Spam-prosentti alle 0,3 %
- Suurten lähettäjien (>5000 viestiä/päivä): kaikki kolme (SPF+DKIM+DMARC)

## IPv4 vs. IPv6 -käyttäytyminen: liikkuvat osoitteet ja kustannukset

Meidän urakassamme jäi (ainakin) yksi ero IPv4- ja IPv6-maailmojen välille. Se liittyy osoitteiden hallintaan. Ja johtuu oikeastaan laiskuudesta, sillä emme nyt halunneet käyttää tähän aikaa.

### Liikkuva IPv4 (floating IP)

Sähköpostipalvelinta pystytettäessä otimme alusta alkaen käyttöön [liikkuvan IPv4-osoitteen](https://docs.hetzner.com/cloud/floating-ips/getting-started/adding-a-floating-ip/) (Floating IP). Tämä mahdollistaa IP-osoitteen siirtämisen palvelimelta toiselle ilman, että DNS-tietueita tarvitsee muuttaa. Se on eräänlainen vakuutus vikatilanteita varten, jolloin palvelu voidaan siirtää nopeasti uudelle instanssille. Tästä lystistä joutuu maksamaan noin 1–2 €/kk.

### IPv6 – kiinteä osoite vai liikkuva aliverkko?

IPv6:lle emme aluksi tehneet samaa. Oletuksena IPv6-osoite on sidottu tiettyyn instanssiin. Jos palvelinta joutuu siirtämään:
1. Uusi palvelin saa uuden IPv6-osoitteen.
2. DNS:n AAAA-tietue on päivitettävä manuaalisesti.
3. On odotettava TTL-ajan (Time to Live) umpeutumista (oletuksena jopa 12 tuntia), jotta uusi osoite päivittyy kaikkialle.

Toki Hetzner tarjoaa myös liikkuvia IPv6-aliverkkoja (esim. /112), mutta se nostaisi kustannuksia noin 2–5 €/kk lisää. Koska sähköpostipalvelimen siirrot ovat harvinaisia ja liikkuva IPv4 takaa joka tapauksessa viestien kulun, tein taloudellisen päätöksen:
> älä osta liikkuvaa IPv6-osoitetta

Sen sijaan dokumentoin migraatioprosessin tarkasti (tähän blogiin 😉) ja lyhennän DNS:n TTL-ajat hyvissä ajoin, jos tiedossa on suunniteltu muutos.

## Konfiguraatio

### Mailcow-puoli

Varmistimme, että:
- Postfix: `inet_protocols = all`
- Dovecot: `listen = *, [::]`
- SMTP-bannerit osoittavat oikeaan nimeen ([FQDN](https://en.wikipedia.org/wiki/Fully_qualified_domain_name))

### DNS-puoli

Lisättiin:
- AAAA-tietue
- MX-tietue (tätä ei tarvittu, koska MX osoittaa samaan nimeen)
- SPF pysyi ennallaan (mx + a kattaa automaattisesti)

### Reverse DNS

Pyysimme palveluntarjoajalta PTR-tietueen asetuksen:
- IPv4 PTR: Jo olemassa
- IPv6 PTR: Pyydetty ja asetettu

## Testaus

Käytimme `nc` ([netcat](https://en.wikipedia.org/wiki/Netcat)) telnetin sijaan kokeillaksemme, että IPv6-osoitteella yhteys palvelimeen saadaan.
Varmistettiin myös:
- Forward lookup: `dig AAAA email.example.com +short`
- Reverse lookup: `dig -x [IPv6-osoite] +short`
- Molempien täytyi palauttaa sama FQDN

## Suorituskykyhavainto: huomasinko eron?

Projektin aikana tein mielenkiintoisen havainnon: palvelut tuntuivat toimivan nopeammin ja sujuvammin kuin ennen. Epäilin ensin [vahvistusharhaa](https://fi.wikipedia.org/wiki/Vahvistusharha), mutta yhdessä tekoälyn kanssa löysimme useita teknisiä syitä, jotka puoltavat tätä kokemusta.

IPv6 voi todellakin vähentää viivettä, mikä on kriittistä nykyisissä web-toteutuksissa, joissa yksi sivulataus vaatii lukuisia pieniä pyyntöjä.

**Mahdolliset syyt nopeutumiselle:**
- **Ei NAT-viivettä:** IPv4 vaatii usein CGNAT-välityksen (carrier-grade NAT). Jos ei mitään muuta, niin ainakin edullinen ja hidas toimistoreitittimemme käyttää NAT-välitystä.
- **Parempi infra ja reititys:** IPv6-liikenne kulkee usein uudemmilla laitteilla ja suorempia peering-yhteyksiä pitkin.
- **Optimoitu [MTU](https://en.wikipedia.org/wiki/Maximum_transmission_unit):** IPv6 sallii suuremmat paketit ja vähentää pakettien jakautumista (fragmentaatiota).
   - myös [suuret paketit](https://en.wikipedia.org/wiki/Jumbo_frame) otettiin samassa yhteydessä käyttöön

Vaikka tämä on enemmän havainto kuin lupaus, moni muukin on raportoinut vastaavasta suorituskyvyn parantumisesta siirtyessään IPv6:n käyttöön. Esimerkiksi Akamai ja LinkedIn ovat havainneet, että IPv6-yhteydet voivat olla merkittävästi nopeampia vähentämällä NAT-välityksen ja muiden välivaiheiden tarvetta ([Internet Society, 2017](https://www.internetsociety.org/resources/doc/2017/state-of-ipv6-deployment-2017)). Myös Apple raportoi WWDC 2020 -tapahtumassa, että yhteyden muodostus on keskimäärin 1,4 kertaa nopeampaa IPv6-verkossa. On hyvä huomata, että vaikka IPv6 otetaan käyttöön, IPv4 jää tietysti edelleen rinnalle varmistamaan saavutettavuuden kaikkialta.

## Migraatiosuunnitelma: jos palvelinta joudutaan siirtämään

Vaikka emme ostaneet liikkuvaa IPv6:tta, on prosessi dokumentoitu (tähän blogiin 😉). Tämä kappale pysyy nyt mukana artikkelissa, mutta rehellisyyden nimissä, tätä yksityiskohtaa ei ole dokumentoitu muualle.

Suuremmassa yrityksessä tietysti tällainen poikkeama ei jäisi voimaan, vaan korjattaisiin heti. Me pystymme tämän muistamaan ja huomaamme kyllä, jos asia tulee eteen. Asia ei ole myöskään mitään rakettitiedettä kokeneelle asiantuntijalle, vaikka tekoäly näyttää sen kovin suureksi asiaksi nostavan.

Jätän siis tämän osion nyt tänne teidän luettavaksenne ihan vaikka anekdoottina.

### Ennen migraatiota (48 tuntia etukäteen)
- Laske AAAA-tietueen TTL arvosta ~12h arvoon ~5min
- Varoita tiimiä suunnitellusta ylläpidosta

### Migraation aikana
- Siirrä palvelin uudelle instanssille
- Floating IPv4 siirtyy automaattisesti
- Uusi palvelin saa uuden IPv6-osoitteen
- Päivitä DNS-AAAA-tietue viipymättä
- Odota 5-10 minuuttia TTL:n vanhentumiseksi
- Verifioi yhteys (`nc -6 email.example.com 587`)
- Testaa sähköpostien toimivuus

### Jälkeen
- Palauta TTL alkuperäiseen arvoon
- Päivitä dokumenttiin uusi IPv6-osoite

**Toiminta-aika:** 5-10 minuuttia IPv6-keskeytystä (IPv4 toimii koko ajan)

## Tärkeimmät opit

### Ennen kuin aloitat
* Ymmärrä FCrDNS-vaatimusten kriittisyys.
* Varmista, kuka hallitsee PTR-tietueita (yleensä palveluntarjoaja).
* Tutustu suurten sähköpostipalveluiden vaatimuksiin (Gmail/Yahoo 2024).
* Varmista, että koko pinosi – mukaan lukien Docker-kontit – tukee IPv6:ta.

### Huomioitavaa
* IPv6-osoitteen PTR-tietuetta ei voi hallita itse DNS-paneelista.
* Migraatiossa IPv6 vaatii manuaalisen DNS-päivityksen, ellet maksa liikkuvasta aliverkosta.
* TTL-arvojen hallinta on avainasemassa keskeytysten minimoimiseksi.

### Oivallukset
* `v=spf1 mx a -all` on nerokas: se kattaa automaattisesti molemmat IP-versiot ilman lisämääreitä.
* IPv6 ei ole vain tulevaisuutta, se on usein jo nyt suorituskykyisempi.
* Aina ei kannata maksaa "liikkuvuudesta", jos hyvä dokumentaatio ja valmistautuminen riittää.

## Hyödyllisiä linkkejä ja materiaaleja
* [Mailcow-dokumentaatio](https://docs.mailcow.email)
* [Gmail-sähköpostilähettäjän ohjeet](https://support.google.com/mail/answer/81126)
* [RFC 7208 (SPF)](https://datatracker.ietf.org/doc/html/rfc7208)
