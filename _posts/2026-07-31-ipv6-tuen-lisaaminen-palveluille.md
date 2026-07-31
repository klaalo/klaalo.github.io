---
layout: post
title: IPv6 siirtymä olisi pitänyt tehdä jo
date: "2026-07-31 13:32:00 +0300"
---

## Tekoälyn avustuksella kirjoitettu

Jos tämä artikkeli kuulostaa tekoälyn tekstiltä, se todennäköisesti johtuu siitä, että artikkelin luomisessa on käytetty tekoälyä.

Tein IPv6-muutosta pitkälti tekoälyavusteisesti. Mutta koska projekti oli ihan merkittävässä määrin aivan totista ihmistyötä, ajattelin kirjoittaa olennaiset asiat muistiin tänne blogiin, jos niistä olisi iloa jollekin. Vaikkapa jollekin tekoälylle, joka haravoi blogeista tietoa.

Olen luonnollisesti tarkistanut tekstin ennen julkaisua.

## Miksi juuri nyt?

Viimeisimmässä kirjoituksessani kerroin siitä, miksi päätimme siirtyä itse ylläpidettävään sähköpostipalvelimeen Mailcow-ympäristössä. Se oli ensimmäinen askel kohti parempaa hallintaa palveluista, joita käytän - etenkin työssäni.

Tässä kirjoituksessa jatkan edelliselle aiheelle läheisesti: kuinka lisäsimme palveluihin IPv6-valmiuden. Projektiin sisältyi myös se, että jouduin lisäämään IPv6-tuen myös toimistolle, josta työtäni teen.

En ole tätä ennen kiirehtinyt toimiston verkon IPv6-valmiudella, koska se ei ole tuntunut välttämättömältä. IPv4-osoitteet kuitenkin maksavat rahaa - enemmän, kuin IPv4-osoitteet, joten urakka oli nyt myös kustannusnäkökulmasta kannattava.

IPv6 ei ole mitenkään uusi asia – se on suunniteltu jo 1990-luvulla. Siirtyä pitäisi jo, koska IPv4-osoitteet loppuvat. Alkuperäinen IPv4-osoiteavaruus sisältää vain noin 4,3 miljardia osoitetta, mikä ei riitä enää nykyaikaiselle internetille, jossa [miljardeilla laitteilla on oma IP-osoitteensa](https://www.internetsociety.org/resources/2018/state-of-ipv6-deployment-2018/). IPv6:n 128-bittinen osoiteavaruus tarjoaa likimain loputtomasti osoitteita ja ratkaisee tämän perimmäisen pulman.

Eipä muutos ole järin vilkkaasti edennyt myöskään teleoperaattoreilla:

- DNA oli Suomen edelläkävijöitä IPv6:n käyttöönotossa. Vuonna 2014 DNA otti käyttöön laajamittaisen IPv6-tuen mobiililiittymiin, ja vuonna 2015 se oli jo Suomen suurin IPv6-operaattori ([DNA Oyj, 2015](https://www.sttinfo.fi/tiedote/27522180/dna-is-leading-the-way-in-ipv6-adoption-in-finland) [RIPE 71 Conference: DNA Finland IPv6](https://ripe71.ripe.net/presentations/163-RIPE71-IPv6-deployment-experiences-from-DNA.pdf)).

- Elisa ja Telia tulivat mukaan myöhempänä, mutta nykytilanteessa molemmat tukevat IPv6:a laajasti. Vuonna 2024 kaikkien kolmen suuren operaattorin IPv6-kattavuus oli yli 90 prosenttia ([Wikipedia: IPv6 deployment - Finland](https://en.wikipedia.org/wiki/IPv6_deployment)).

- Elisan 5G-liittymät tukevat IPv6:a – tämä on olennaista liikkuvassa työssä. Konsultti ei työskentele päivittäin samassa toimistossa.

Nykytilanteessa palveluntarjoajat tarjoavat IPv6:n oletuksena, asiakkaat ovat yhä useammin dual-stack-yhteystekniikoilla, ja suuret sähköpostipalvelut (Gmail, Yahoo, Outlook) tukevat molempia protokollia. Viiveet IPv4:ssä voivat johtua CGNAT-ongelmista, kun taas IPv6 on usein suoraviivaisempi ilman NAT-välitystä.

Tämä ei ollut pelkästään sähköpostipalvelimen IPv6-lisäys. Samassa yhteydessä
lisättiin IPv6-tuki muihinkin [Karidea Oy](https://www.karidea.fi):n ylläpitämiin palveluihin.

Vaikka kyseessä oli työprojekti, kerron nyt aiheesta täällä henkilökohtaisessa blogissa. Ehkä jatkossa saatte kuulla näistä asioista uutiskirjeessä tms. Mutta se on sitten toisen projektin aihe.

Tiivistettynä tavoitteet tässä projektissa:

- Ensisijaisesti: pelkästään IPv6 palvelimille, joille yleistä pääsyä IPv4-osoitteilla ei tarvita (mm. toimiston ja palvelinalustan välinen yhteys)
   - kalliista IPv4-osoitteesta ei tarvitse maksaa turhaan 
- Sähköpostin toiminta- ja toimitusvarmuus myös tulevaisuudessa (IPv4 osoitteet harvinaistuvat)
- Palvelujen saavutettavuus kaikilta verkkoilta (jotka käyttävät IPv6:sta)
- Valmistautuminen tulevaisuuteen, jossa IPv6 on oletus eikä poikkeus
- Samalla suorituskykypotentiaali paranee (ei NAT-kulun kautta)
   - Suora yhteys tietyille laitteille IPv6-osoitteella - ei enää tarvetta [porttiohjauksille](https://en.wikipedia.org/wiki/Port_forwarding) tai [Hairpin NAT:lle](https://help.ui.com/hc/en-us/articles/30202160464023-Hairpin-NAT-in-UniFi)


## Sähköpostin Erityisvaatimukset

Sähköpostipalvelimen IPv6-lisäys on monimutkaisempaa kuin tavallinen
web-palvelin:

### 1. FCrDNS ([Forward-confirmed Reverse DNS](https://en.wikipedia.org/wiki/Forward-confirmed_reverse_DNS)) - Kriittisin Vaatimus

Kaikki kolme täytyvät täsmätä:
- Forward DNS (AAAA-tietue)
- Reverse DNS (PTR-tietue)
- SMTP-banneri: postipalvelin ilmoittaa vastauksessaan nimensä oikein

Jos yksi näistä puuttuu tai ei täsmää, sähköpostit menevät roskapostiin tai
hylätään kokonaan.

PTR-tietueita eli IP-osoitteen käänteistä nimeä, jolla tiettyä IP-osoitetta vastaava nimi voidaan selvittää, ei määritellä verkkotunnuksen DNS-palvelussa. Se täytyy muuttaa kyseisen verkon operoinnin toimesta, eli yleensä sillä alustalla, missä itse palvelun toteutetaan (hosting provider).

### 2. SPF (Sender Policy Framework)

SPF on kuvaus siitä, ketkä saavat lähettää sähköpostia meidän nimissämme.

Meidän ratkaisu:

    v=spf1 mx a -all

Hyvä puoli tässä konfiguraatiossa: `mx`- ja `a`-mekanismit kohdentavat sallitut lähettäjät automaattisesti sekä A-että AAAA-tietueet. Ei tarvinnut lisätä erillistä
`ip6:`-mekanismia – AAAA-tietueen lisääminen riitti.

### 3. DKIM ja DMARC

Nämä ovat protokollariippumattomia, joten niissä ei tarvittu muutoksia:
- DKIM: Avaimena varmistaa viestin eheyden (ei liity IP-versioon)
- DMARC: Ohjeistus vastaanottajille, miten käsitellä epäonnistuneet autentikoinnit

### 4. Gmail ja Yahoo 2024-vaatimukset

Vuoden 2024 helmikuusta lähtien suurten sähköpostipalveluiden vaatimukset:
- Paikkansa pitävät forward/reverse DNS-parit (sekä IPv4 että IPv6)
- SPF TAI DKIM vähintään (molemmat suositeltu)
- Spam-prosentti alle 0,3 %
- Suurten lähettäjien (>5000 viestiä/päivä): kaikki kolme (SPF+DKIM+DMARC)

## IPv4 vs. IPv6 Käyttäytyminen

### Nopeutunut käyttökokemus

Muutossa tehdessä tein havainnon, että palvelut tuntuivat toimivan nopeammin ja sujuvammin, kuin ennen. En pitänyt tätä kovin mahdollisena todellisuutena, vaan enemmänkin ajattelin, että kyseessä on vahvistusharha.

Kysyin asiaa tietysti tekoälyllä ja yhdessä löysimmekin vahvistuksen sille, että IPv6-osoitteeseen siirtyminen voi nopeuttaa liikennettä ja ennen kaikkea vähentää viivettä, joka pakettiliikenteessä on harmillisen haitallista. Nykyisissä moderneissa web-toteutuksissa se korostuu, kun yksittäiseen sivulataukseen saattaa sisältyä lukematon määrä erilaisten yksittäisten tiedostojen lataamista.

### IPv4 – Liikkuva IP (Floating IP)

Shäköpostipalvelimen toteuttamisen yhteydessä otimme alusta lähtien käyttöön [liikkuvan](https://docs.hetzner.com/cloud/floating-ips/getting-started/adding-a-floating-ip/) IPv4-osoitteen. IPv6:lle emme tätä aluksi tehneet. Liikkuva osoite mahdollistaa IP-osoitteen siirtämisen palvelimelta toiselle jos palvelimen vaihto joskus tulee aiheelliseksi.

- Voidaan siirtää toiseen palvelimeen ilman DNS-muutoksia
- Maksaa noin 1-2 €/kk
- Mahdollistaa nopean vikatilanteesta toipumisen

### IPv6 – Kiinteä osoite
- Sidottu tiettyyn instanssiin (palvelimeen)
- Siirrettäessä uusi palvelin saa UUDEN IPv6-osoitteen
- DNS:n AAAA-tietue pitää päivittää manuaalisesti
- Toiminta-ajaksi: TTL-ajan odotus (≈ 12 tuntia)
- Voidaan ennalta lyhentää 300 sekuntiin (5 minuuttia) ennen migraatiota

Eli palvelimen yllättävässä virhetilanteessa, johon ei voida ennalta varautua, IPv6-osoite vaihtuu. Vaihtumisen yhteydessä voi kestää jopa vuorokausi ennen kuin kaikki päätelaitteet oppivat uuden muuttuneen osoitteen.

Jos muutokseen voidaan varautua etukäteen, voidaan ennalta lyhentää osoitteen välimuistuaikaa ([TTL - Time to Live](https://en.wikipedia.org/wiki/Time_to_live))

### Taloudellinen Päätös: Ostetaanko Floating IPv6?

Hetzner tarjoaa IPv6-aliverkkoja (esim. /112), joita voidaan liikkuttaa.
Mutta:
- Lisäkustannus: noin 2-5 €/kk
- Yksittäinen IPv6-osoite ei liiku, vain aliverkot
- Sähköpostipalvelimen siirrot tapahtuvat harvoin (vuosia välein)
- IPv4 floating IP jo takaa sähköpostin jatkuvuuden

**Päätös:** Älä osta floating IPv6:tta. Dokumentoi migraatioprosessi sen sijaan.

## Konfiguraatio

### Mailcow-puoli

Varmistimme, että:
- Postfix: `inet_protocols = all`
- Dovecot: `listen = *, [::]`
- SMTP-bannerit osoittavat oikeaan [FQDN](https://en.wikipedia.org/wiki/Fully_qualified_domain_name):hen

### DNS-puoli

Lisättiin:
- AAAA-tietue
- Päivitettiin MX-tietue (ei tarvinnut, MX osoittaa saman nimen)
- SPF pysyi ennallaan (mx + a kattaa automaattisesti)

### Reverse DNS

Pyysimme palveluntarjoajalta PTR-tietueen asetuksen:
- IPv4 PTR: Jo olemassa
- IPv6 PTR: Pyydetty ja asetettu

## Testaus

Käytimme `nc` (netcat) telnetin sijaan kokeillaksemme, että IPv6-osoitteella yhteys palvelimeen saadaan.
Varmistettiin myös:
- Forward lookup: `dig AAAA email.karidea.fi +short`
- Reverse lookup: `dig -x [IPv6-osoite] +short`
- Molempien täytyi palauttaa sama FQDN

## Suorituskykyhavainto

Palveluiden siirtäminen IPv6:een toi mukanaan odottamattoman hyödyn:

**Havainto:** Palvelinten käyttö tuntuu suoremmalta ja nopeammalta.

**Mahdolliset syyt:**
- **Ei NAT:** IPv4 vaatii usein CGNAT-kulun (carrier-grade NAT), joka lisää viiveitä
- **Uudempi infra:** IPv6-reititys kulkee useimmiten uudemmilla laitteistoilla
- **Suorempi peering:** IPv6-verkkojen välillä on usein suorampia yhteyksiä
- **Parempi MTU:** IPv6 sallii suurempia paketteja, vähemmän jakautumista

Tämä on havainto, ei take. Mutta monet muutkin ovat raportoineet samanlaisia
kokemuksia siirryttäessä IPv4 → IPv6.

## Migraatiosuunnitelma: Jos Palvelinta Joudutaan Siirtämään

Vaikka emme ostaneet floating IPv6:tta, on prosessi dokumentoitu:

### Ennen migraatiota (48 tuntia etukäteen)
- Laske AAAA-tietueen TTL arvosta ~12h arvoon ~5min
- Varoita tiimiä suunnitellusta ylläpidosta

### Migraation aikana
- Siirrä palvelin uusille instanssille
- Floating IPv4 siirtyy automaattisesti
- Uusi palvelin saa uuden IPv6-osoitteen
- Päivitä DNS-AAAA-tietue viipymättä
- Odota 5-10 minuuttia TTL:n vanhentumiseksi
- Verifioi yhteys (`nc -6 email.karidea.fi 587`)
- Testaa sähköpostien toiminta

### Jälkeen
- Palauta TTL alkuperäiseen arvoon
- Päivitä dokumentti uudeksi IPv6-osoitteeksi

**Toiminta-aika:** 5-10 minuuttia IPv6-keskeytystä (IPv4 toimii koko ajan)

## Tärkeimmät opit

✅ **Ennen kuin aloitat:**
- Ymmärrä FCrDNS-vaatimuksien kriittisyys
- Tiedä, kenellä PTR-tietueiden hallinta on (palveluntarjoaja)
- Lue Gmail/Yahoo vaatimukset (2024)
- Varmista, että alustapalveluntarjoasi tukee IPv6-osoitteistoa
- Tarkista, että käyttämäsi mahdollinen konttitoteutuksesi (esim. [Docker](https://docs.docker.com/engine/daemon/ipv6/)) on IPv6-yhteensopiva

⚠️ **Huomioitavaa:**
- IPv4 ja IPv6 käyttäytyvät eri tavoin palveluntarjoajalla
- IPv6 PTR:tä ei voi itse hallita
- Migraatiossa IPv6 vaatii manuaalisen DNS-päivityksen
- TTL-ajoitus vaikuttaa keskeytyksen kestoon

💡 **Mielenkiintoiset havainnot:**
- `v=spf1 mx a -all` kattaa automaattisesti sekä IPv4 että IPv6
- IPv6 voi todellisuudessa olla nopeampaa (ei NAT)
- Floating IPv6 on kallis vakuutus harvinaista tapahtumaa vastaan

📚 **Materiaalit:**
- Mailcow-dokumentaatio: https://docs.mailcow.email
- Gmail-sähköpostilähettäjän ohjeet: https://support.google.com/mail/answer/81126
- RFC 7208 (SPF): https://datatracker.ietf.org/doc/html/rfc7208

## Loppusanat

Tämä IPv6-migraatio oli enemmän kuin pelkkä tekninen päivitys. Se oli
valmistautuminen tulevaisuuteen, jossa IPv6 on oletus, ja IPv4 jää
taaksepäin yhteensopivuuden vuoksi.

Erityisen tärkeää oli ymmärtää, että sähköpostipalvelimilla ei ole
varaa virheisiin. FCrDNS, SPF, DKIM ja DMARC ovat vaatimuksia, ei
valinnaisia ominaisuuksia.

Jos teet samanlaisia ratkaisuja, muista:
- Testaa perusteellisesti ennen tuotantoon vientiä
- Dokumentoi prosessi, jos tulee siirtoja
- Tee kokeellisia havaintoja (kuten suorituskyky)
- Pidä taloudelliset harkintasi mielessä (floating IPv6 vs. dokumentaatio)
