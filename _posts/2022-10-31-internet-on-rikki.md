---
layout: post
title: "Internet on rikki"
date: "2022-10-31 20:12:00 +0300"
published: false
---

Kun Internet-verkkoa aikanaan alettiin kehittää Yhdysvalloissa, se suunniteltiin hajautetuksi. Verkon jokainen tekninen kerros perustuu siihen, että verkko koostuu lukemattomista päätteistä, joilla jokaisella on oma, muista erillinen osoite. 

Verkon rakenne, protokollat ja palvelut suunniteltiin niin, että siinä olevat laitteet ovat hajallaan ympäri maailmaa. Laitteiden ja palveluiden, osoitteiden ja liikennettä välittävien reitittimien määrä voi teoriassa olla lähes ääretön.

Viime aikoina Internet on kehittynyt aivan toiseen suuntaan. Palvelut ja verkon toteuttamisen teknologia keskittyy yhä harvemmalle taholle. GAFAM (Google \[Alphabet\], Apple, Facebook \[Meta\], Amazon, Microsoft), [viiden suuren ryhmä](https://en.wikipedia.org/wiki/Big_Tech) hallitsee Internetin käyttöä ja kehittämistä.

Suuren viiden hallussa on paitsi palvelut, joita ihmiset käyttävät laajasti, myös alustat, joilla palvelut tuotetaan. Alustoissa on näiden viiden lisäksi tapahtunut myös muuta keskittymistä. Esimerkiksi [CloudFlare](https://www.cloudflare.com/en-gb/) ja [Akamai](https://www.akamai.com) ovat nykyään yhtä, kuin sisällön jakelu.

![Klaalo Twitter front page after Elon Musk bought Twitter](https://misc.karilaalo.fi/pics/2022-10-28-musk-bought-twitter.png)

Muutos ei ole tapahtunut yhtäkkiä vaan hiljakseen. Alla on avattu muutamia isompia muutoksia Internetin keskittymisen taustalla. Hidas muutos havaitaan heikosti, mutta juuri nyt tämä aihe nousee ajankohtaiseksi, kun Elon Musk pitkän ja likaisen kaupankäynnin jälkeen muuttui Twitterin omistajaksi([TheVerge](https://www.theverge.com/2022/10/27/23184519/elon-musk-twitter-acquisition-deal-complete-agreement), [TechCrunch](https://techcrunch.com/2022/10/27/elon-musk-bought-twitter/?guccounter=1)).

## Spam rikkoi sähköpostin

Sähköpostipalvelu on internet-verkon tietoliikenteen välittämiseen osallistuvien reitittimien ja verkon nimipalvelun rinnalla mainio esimerkki palvelun toteuttamiseen osallistuvien laitteiden hajauttamisesta.

Sähköpostin välittämiseen käytetyn protokollan (SMTP - Simple Mail Transfer Protocol) perusajatuksena on, että organisaatiot ovat jakautuneet verkkoalueisiin (Domain) ja verkkoalueella on omalla alueellaan postia välittämä palvelin. Yritys tai muu organisaatio muodostaa verkkoalueen ja sillä on oma sähköpostipalvelin.

Verkon nimipalvelun avulla erilliset sähköpostipalvelimet osaavat vastaanottajan osoitteeseen perustuen selvittää, mikä postipalvelin välittää vastaanottajan sähköpostia. Lukemattomat sähköpostipalvelimet muodostavat toisistaan riippumattoman, mutta saumattomasti toimivan verkoston. Jos yksi palvelin on epäkunnossa, vain sen palvelimen alueella olevien käyttäjien sähköposti ei toimi.

Sähköposti on alusta asti ollut maksuton siten, että viestien perille välittämisestä ei peritä maksua palvelimien välillä. Luonnollisesti verkon ja sen palvelimien ylläpidosta, verkkoliikenteen välittämisestä ja yhdysliikenteestä ja muusta sellaisesta muodostuu kulua. Kulu on käyttäjälle näkymätön. Käyttäjän näkökulmasta sähköpostin lähettäminen on ilmaista.

Niinpä sähköpostia voitiin lähettää myös turhaan. Sähköpostista tuli roskapostittajien valtakuntaa. Mainosten, huijausviestien ja suorastaan haitallisten ja vahingollisten viestien lähettäminen oli paitsi helppoa, myös erittäin edullista. Toimivien sähköpostiosoitteiden listat olivat kauppatavaraa.

Piti kehittää vastatoimia. Kehitettiin roskapostin suodatuspalveluja ja sähköpostiprotokollan laajennoksia, joilla viestien lähettäjät pystyttiin tunnistamaan. Kerättiin mustia listoja, joiden perusteella evättiin viestien välittäminen epäluotettavaksi luokitelluilta lähettäjiltä.

Suodatuspalvelujen asentaminen ja ylläpito tai toisaalta roskapostisuodatuksen aiheuttamien ongelmien selvittäminen muuttui niin työlääksi, että [moni luopui oman sähköpostipalvelun ylläpidosta](https://cfenollosa.com/blog/after-self-hosting-my-email-for-twenty-three-years-i-have-thrown-in-the-towel-the-oligopoly-has-won.html) ja siirtyi palveluna tarjottavan sähköpostin käyttäjäksi. Yritykset ostivat sähköpostin palveluna sen sijaan, että olisivat ylläpitäneet omaa palvelintaan.

Myös kuluttajat halusivat internetoperaattorin tarjoamaa sähköpostipalvelua paremman. Kuluttajat siirtyivät maksuttomien mainoksin kustannettujen palvelujen käyttöön. Niissä oli internetoperaattorin sähköpostipalvelua paremmat suodatusominaisuudet ja enemmän tilaa alati kasvaville liitetiedostoille.

Nykyään sähköpostipalvelun tuottaminen on muutaman suuren toimijan varassa. Googlen Gmail, Microsoftin Outlook ja Apple Mail voivat sanella, millä periaatteilla sähköpostia välitetään, millaiset viestit luokitellaan roskapostiksi ja millaiset viestit jätetään kokonaan välittämättä.

Pienen sähköpostipalvelun ylläpitäjän on aivan turhaa yrittää vedota protokollan sääntöihin, jos suuri sähköpostipalvelun tuottaja ei suostu välittämään hänen viestejään. Suuren sähköpostipalvelun tuottajan kanssa ei voi keskustella, sillä niillä ei ole asiakaspalvelua tai kontaktipistettä, johon ottaa yhteyttä ongelmissa.

Voi siis sanoa, että roskaposti ja kuluttajien siirtyminen käyttämään muutamia suuria sähköpostipalveluja paitsi rikkoi hajautetun sähköpostipalvelun, myös siirsi vallan sähköpostipalvelusta muutamalle suurelle yritykselle. Muutama yritys päättää, miten ja millä ehdoilla sähköpostia välitetään. Pienillä ei ole asiassa sanan valtaa.

## Hakukoneoptimointi rikkoi verkkohaut

Kun Google aloitti hakukoneensa kehittämisen, eräs sen toimintaperiaatteista oli: "[Don't be Evil](https://en.wikipedia.org/wiki/Don't_be_evil)". Hiljakseen tavoite muuttui. 2015 motto muuttui muotoon: "Do the right thing". Kaikesta päätellen sittemin motto on unohtunut kokonaan.

Googlen hakukoneen periaate oli olla mahdollisimman yksinkertainen. Aluksi se oli vain hakukenttä, johon syötettiin hakuehto ja painike, jolla haku käynnistyi. Ei mitään muuta.

Hakutulokset esitettiin yksinkertaisena listana, joka oli järjestetty hakukoneen tilastollisen analyysin perusteella osuvimpaan järjestykseen. Järjestys perustui siihen, kuinka hyvin tulos osuu hakusanoihin. Enemmän linkitetyt sivut nousivat ylemmäs, kuin sellaiset, joihin oli linkkejä vähemmän.

Ajan kuluessa, kun hakukoneesta tuli suositumpi, siihen tuli lisää ominaisuuksia. Yksinkertaisen hakukentän lisäksi oli mahdollista valita, haetaanko tietoa uutisista, valokuvista tai videoista.

Koska hakukoneen ylläpito ei ole ilmaista, kulut keksittiin kattaa mainoksilla. Hakutulosten yhteydessä alettiin näyttää hakuun liittyviä mainoksia. Pitkään oli periaate, että mainoksin kustannetut hakutulokset erottuvat tuloslistassa selkeästi. Myöhemmin tämä periaate on hämärtynyt.

Hakutuloksien osuvuuteen liittyvät algoritmit on aina olleet salaisuuksia. Niissä on kuitenkin tapahtunut muutos. Osuvuus ei perustu pelkästään siihen, mitä käyttäjä hakee, vaan myös siihen, mitä käyttäjä on hakenut aiemmin, eli käyttäjäkohtainen konteksti. Hakukone alkoi kerätä tietoa käyttäjästä ja muodostaa tästä profiilia. Hakutulosten osuvuus perustuikin nyt siihen, minkälainen käyttäjä on, ei pelkästään siihen, mitä hän hakee.

Samaan aikaan kun hakukonepalvelut yrittivät keksiä, miten kustantaa palvelunsa kulut, myös sivustojen julkaisijat tarvitsivat tulon teon välineen. Hekin ratkaisivat asian näyttämällä käyttäjille mainoksia. Kävikin niin, että hakukonetoimittaja loi mainosverkoston, joka näytti mainoksia paitsi hakutulosten yhteydessä, myös verkkosivustoilla.

Yritysten on tarve saada palvelunsa ja tuotteensa näkyville, joten ne mainostivat näiden mainosverkostojen kautta. Lisäksi tuottavaksi kaupalliseksi palveluksi muodostui hakukoneoptimointi. Hakukoneoptimoinnin tarkoitus on toteuttaa verkkosivujen julkaisut siten, että ne saisivat paitsi paljon linkutyksiä, että hakukoneiden algoritmit nostaisivat sivuston julkaisut tuloslistan kärkeen.

Koska mainoksia verkkoon myyvät hakukonetoimittajat, ne näkevät paitsi mitä käyttäjä hakee, myös millä sivuilla käyttäjät vierailevat. Niinpä enää pelkästään linkkien määrä ei vaikuta hakutulosten osuvuuteen, vaan se, kuinka paljon linkkejä klikataan ja paljonko sivuja luetaan.

Syntyi ilmiö: klikkien kalastelu. Paitsi, että sivustoista piti tehdä sellaisia, että hakukone nostaa ne tuloslistan kärkeen, sivustojen piti saada mahdollisimman paljon klikkauksia käyttäjiltä, eli niiden piti näkyä mahdollisimman monelle silmäparille lukumääräisesti mitattuna.

Syntyi myös lieveilmiö. Haitallisten sivujen piti saada näkyvyyttä myös, jotta esimerkiksi huijauksiin käytetyt sivustot pääsisivtä hakukonetuloksissa esiin ja saisivat klikkauksia käyttäjiltä. Niinpä haitalliset sivustot alkoivat kopioida sivuillensa materiaalia suosituilta uutis- ja tietosivuilta. Näin ne näyttäytyivät hakukoneille asiallisilta sivustoilta, vaikka tosiasiassa yrittivät esimerkiksi harhauttaa käyttäjää asentamaan haitta- tai kiristysohjelman laitteellensa.

Motivaatiot käyttäjien huomiolle on moninaisia aina hyvässä tarkoituksessa tehdyn markkinoinnin ja pahassa tarkoituksessa tehdyn harhauttamisen välillä. Hakukoneptimoinnin seuraus hyvässä ja pahassa on se, missä olemme nyt.

Käyttäjien on vaikea löytää internetin informaatiotulvan joukosta asiallista tietoa. Jopa hakukoneille on vaikeaa erottaa haitallinen tai tarpeeton tieto hyödyllisestä ja aiheellisesta. Hakutulosten joukossa, jopa aivan hakutulosten kärjessä on automatisoidun hakukoneoptimoinnin tuottamaa materiaalia, jonka ainoa tarkoitus on saada käyttäjä vierailemaan sivustolla.

Haitallisen informaation sivusto ei todellisuudessa tarjoa hyödyllistä ja ajantasaista tietoa, vaan se on vanhentunut kopio hyötysivuston datasta. Sen ainoa tarkoitus on harhauttaa hakukoneen algoritmia. Haitallisen informaation sivustoja on helppoa ja edullista toteuttaa aina uusia, aina uusiin erilaisiin aidon näköisiin osoitteisiin.

Hakukoneet eivät enää toimi. Hyödyllistä informaatiota on vaikea löytää haitallisen seasta. Käyttäjän on tiedettävä, mistä hyödyllinen tieto löytyy ja osattava erottaa haitallinen tieto hyödyllisestä.

## Zuckerbergin ahneus rikkoi Facebookin

Facebook oli aikanaan mukavan tuntuinen yhteisö, jossa oli mahdollista viestiä tuttavien ja heidän tuttavien kanssa. Facebookiin muodostui eri asioiden harrastajien yhteisöjä ja ryhmiä erilaisten aihepiirien ympärille.

Facebookiin modostui nk. puskaradioita, paikallisia kaupunginosaryhmiä, joissa alueen asukkaat pystyivät vaihtaa tietoa ja keskustella alueen asioista tuntematta toisiaan henkilökohtaisesti. Ryhmät olivat hyödyllisiä toimiessaan ajankohtaisena alueen ilmoitustauluna.

Hellyttävien kissakuvien lisäksi Facebook mahdollisti kaverien jakaa kavereilleen kuvia lomamatkoistaan tai harrastuksistaan. Hakukoneiden algoritmien tapaan Facebook alkoi järjestellä käyttäjien syötteen virtaa sen mukaan, mitkä julkaisut saivat eniten tykkäyksiä ja huomiota. Hakukoneiden algoritmien tapaan, mitä useampi silmäpari vietti aikaa julkaisun parissa, sitä todennöisemmin julkaisua näytettiin myös muille.

Kuten hakukoneet, myös Facebook tuskaili tulon tekemisen periaatteiden kanssa. Kuinka ollakaan, myös Facebook keksi tulon tekijäksi mainokset. Käyttäjien julkaisuvirrassa alettiin näyttää mainoksia. Käyttäjien huomiosta ei kilpaillut ainoastaan selfiet ja kissakuvat, vaan mainostajien materiaali. Mitä enemmän mainostaja oli valmis käyttämään rahaa, sitä enemmän hänen sisältöään näytettiin.

Yritykset löysivät myös harrasteryhmät. Koska varsinainen mainostaminen Facebookin alustalla maksoi rahaa, yritykset alkoivat luoda tavallisia käyttäjätilejä mainostaakseen puskaradiossa vertaisena käyttäjänä muiden joukossa. Kaupunginosaryhmissäkin alkoi näkyä yhä enemmän julkaisuja, joiden ainoa tarkoitus oli saada yrityksille näkyvyyttä ja asiakkaita. Kaupunginosaryhmät eivät enää olleetkaan niin hyödyllisiä kuin aiemmin.

Kun mainokset tulvivat kissakuvien joukossa ja kaupunginosaryhmien julkaisujen seassa käyttäjien silmille yhä useammin, he alkoivat kokea Facebookin enemmän rasitteeksi kuin hyödylliseksi.

Facebook oli kasvanut maailmanlaajuiseksi valtavaksi mainosverkostoksi. Mainostulojen lisäksi Facebook tarvitsi tuloja levittääkseen lonkerojaan yhä laajemmalle. Facebook osti WhatsApp pikaviestialustan ja kuvien jakamiseen tarkoitetun Instagramin.

Facebook ja ostetut sosiaalisen median palvelut erotettiin omiksi yhtiökseen. Niiden omistajaksi tuli emoyhtiö Meta. Metalle tuli mahdolliseksi yhdistellä eri välineistä kerättävää tietoa ja muodostaa käyttäjistä ja heidän verkostoistaan yhä tarkempia profiileja, joiden avulla mainoksia ja informaatiosyötettä voitiin paremmin kohdentaa.

Facebookin ja Metan perustaja Mark Zuckerberg haaveili Metaversesta, digitaalisesta virtuaalisesta ympäristöstä, jossa ihmiset eläisivät digitaalisena olentoina. Metaversessä tapahtuisi kaikki digitaalinen asiointi ja viestintä, jopa digitaalinen työ kokouksineen siirtyisi Metaverseen.

Kasvun ja laajenemisen mahdollistajaksi tarvittiin lisää tulon tekijöitä. Kävi ilmeiseksi, että rahaa voi tehdä myös myymällä käyttäjistä kertyvää tietoa. Metan omistamien välindeiden tuottama tarkka profiili käyttäjistä voitiin myydä mainostajille "nimettömänä".

Vakavin episodi käyttäjien tietojen myymisessä tapahtui 2010-luvulla, kun [Cambridge Analytica -skandaali](https://en.wikipedia.org/wiki/Facebook–Cambridge_Analytica_data_scandal) tuli julkisuuteen. Facebookista kerättyjä käyttäjien tietoja yhdisteltiin muista lähteistä ja suoraan käyttäjille tehdyistä kyselyistä saatuihin tietoihin, joista muodostettiin tarkkoja psykologisia profiileja.

Tuli mahdolliseksi vahvistaa ihmisten ennakkoasenteita näyttämällä ja korostamalla mm. Facebookin syötteissä tietynlaisia julkaisuja. Cambridge Analytica -tietoa käytettiin hyödyksi Ted Cruzin ja Donald Trumpin vaalikampanjoissa.

Lopputulos tunnetaan. Donald Trumpista tuli presidentti ja Yhdysvaltojen poliittinen kenttä jakaantui vahvasti. Lopulta, kun Donald Trump hävisi presidenttikisan Joe Bidenille, vihainen väkijoukko ryntäsi väkivaltaisesti vallaten Yhdysvaltojen senaatin Washingtonissa. Mellakassa aiheutui kuolemia ja loukkaantumisia. Eturivin poliitikot avustajineen, mm. Trumpin oma varapresidentti Mike Pence onnistui väistämään vihaista väkijoukkoa vain täpärästi.

Mainokset eivät enää olleet Facebookin ainoa haitta. Ennakkoluulojen kasvu ja silkka usko salaliittoteorioihin alkoi hajoittaa yhteiskuntia. Väitetään, että Facebook on ollut osallisena jopa [rohinga-kansan murhaan Myanmarissa](https://en.wikipedia.org/wiki/Rohingya_genocide#Facebook_controversy).

Useita "lopeta Facebookin käyttö" -kampanjoita on käynnistynyt ei ainoastaan Cambridge Analytica -skandaalin, Yhdysvaltain senaatin valtauksen tai Myanmarissa tapahtuneen kansanmurhan myötä. Edelleen Facebook myy mainoksia ja alustalla julkaistaan paitsi kissakuvia ja -videoita, myös käyttäjien omia tarinoita. Edelleen Zuckerbergin suunnitelmissa on Metaverse.

Facebookin voidaan sanoa olevan suorastaan haitallinen. Voidaan väittää, että Zuckergerin ahneus laajentaa Facebookista ja sen sisarpalveluista alusta digitaaliseen elämään, eli Zuckerbergin suuruudenhullut Metaverse-suunnitelmat ovat tuhoneet hänen luomansa alustan.

## Evästeiloitukset rikkoivat webin

Ylenmääräinen käyttäjien henkilötietojen kerääminen ja käyttäjien henkilöprofiilien luominen huolestutti lainsäätäjiä. Edward Snowdenin paljastukset [maailmanlaajuisesta joukkovalvonnasta](https://fi.wikipedia.org/wiki/Maailmanlaajuista_joukkovalvontaa_koskevat_paljastukset_(2013_alkaen)) ja itävaltalaisen [Max Schremsin oikeustapaus](https://en.wikipedia.org/wiki/Max_Schrems#Schrems_I) aiheutti mm. [sopimuksien purkautumisen](https://en.wikipedia.org/wiki/International_Safe_Harbor_Privacy_Principles), joiden perusteella voitiin välittää henkilötietoja Euroopan ja Yhdysvaltain välillä.

Euroopassa tuli voimaan henkilötietoja suojaava [yleinen tietosuoja-asetus](https://fi.wikipedia.org/wiki/Yleinen_tietosuoja-asetus) (GDPR). Eräänä tietosuoja-asetuksen epäonnistumisena pidetään evästesuostumuskyselyjä, joita verkkosivustoilla lain mukaan joudutaan esittämään, mikäli evästeitä käytetään.

Mainosverkoston käyttivät evästeitä käyttäjien tunnistamiseksi yhdistääkseen käyttäjien klikkailut heidän profiiliinsa ja kerätäkseen tällä tavalla vieläkin tarkempaa tietoa käyttäjistä.

Lainsäätäjät kokivat evästeet ongelman ytimeksi ja etenkin suurten teknologiajättien lobbaamisen ansiosta asiassa päädyttiin säätämään kehnosti. Syntyi sekamelskainen direktiivi sähköisen viestinnän palveluista (ePrivacy), jota Suomessa toteutetaan vastaavalla [lailla](https://www.finlex.fi/fi/laki/ajantasa/2014/20140917#O7L24).

Ihmiset siis erehtyvät osoittamaan väärää puuta kritisoidessa tietosuoja-asetusta (GDPR) evästesuostumusviidakosta.

Sekava sääntely aiheutti valtavaa hankaluutta aivan päivittäisessä internetin käytössä. Jokaisella sivustolla käytetään evästeitä ja kun evästeitä käytetään, laki vaatii nykyään pyytämään evästeiden käytölle suostumuksen. Suostumuspyynnöt ovat hyvin kirjavia.

Vaikka laki edellyttää, että suostumuksen perumisen ja sen antamatta jättämisen pitäisi olla yhtä helppoa, kuin suostumuksen antamisen, suostumuksen antamiseen käytettävät palvelut yrittävät tehdä kieltäytymisestä hyvin vaikeaa.

Internetin selailu ja sivujen lukeminen on rikki. Mainosverkostojen tiedonkeruu ja maailmanlaajuinen joukkovalvonta käynnisti huonon lainsäädännön, jolla yritetään suojella ihmisten oikeutta yksityisyyteen ja kitkeä massavalvontaa -seurantaa. Suostumuspyynnöt aiheuttavat erillisen lisärasitteen ja klikkauksen jokaisella sivulla erikseen. Internetin sivujen selailu on raivostuttavaa evästesuostumuspyyntöjen väistelyä.

## Klikkiotsikot rikkovat journalismia

Huomio käyttäjien silmäpareista on veristä kilpailua. Ilmiö on heijastunut myös journalismiin. Sanomalehtien tilaaminen digitaalisena versiona lienee jo yleisempää, kuin paperilehden tilaaminen.

Sanomalehtien julkaisijoiden on tuotettava sama uutinen monessa mediassa. Edelleen julkaistaan perinteinen paperinen päivälehti, mutta sen rinnalla on digilehti ja vielä erikseen verkkosivusto, jolla uutiset julkaistaan heti niiden ilmestyttyä.

Paperinen lehti, sen näköisversio ja digilehti edellyttää tilaamista. Niitä julkaistaan myytävien mainosten ja tilausmaksujen tuloilla. Tilaajamaksuissa osaltaan maksetaan myös verkkosivujen tuottamisesta, mutta verkkosivuista saadaaan tuloja myös mainoksia näyttämällä.

Ja kuten jo tähän mennessä olemme oppineet, verkkosivustoilla joudutaan kilpailemaan silmäpareista. Niinpä myös sanomalehtien verkkosivustot joutuvat tekemään sivustoistaan, eli julkaistavista uutisotsikoista mahdollisimman houkuttelevia.

Tämä ilmiö on johtanut jopa uudissanan merkityksen avaamista sanakirjaan. [Klikkijournalismilla](https://www.kielikello.fi/-/klikkausjournalismi-ja-muita-vuoden-sanoja) tarkoitetaan julkaistavien uutisten ja niiden otsikoiden muokkaamista mahdollisimman uteliaisuutta herättäväksi, jotta klikkauksia kertyisi paljon. 

Uutisten otsikot ovat erilaisia eri medioissa. Perinteisessä paperilehdessä julkaistavat otsikot ovat lähempänä uutisen aiheetta, kun paperilehden ei tarvitse kilpailla silmäpareista. Verkkosivulla julkaistavan uutisen otsikon on oltava räväkkä ja huomiota herättävä.

Uutisia lukevan on vaikea yhdistää verkkosivulla julkaistavaan nopeaan uutisointiin tarkoitettua otsikkoa perinteisessä muodossa julkaistuihin uutisiin.

Journalismi on rikki. Journalistisiin ratkaisuihin vaikuttaa tarve kilpailla lukijoiden huomiosta.

| <small>_Tämän kappaleen otsikko on tarkoituksella preesensissä, kun muut otsikot ovat imperfektissä sen ilmaisemiseksi, että journalismilla on vielä toivoa ja muun väittäminen olisi vaatinut väkevämpää perustelua._</small> |

## Elon Muskin pompöösiys rikkoi Twitterin

Internetin ongelmat kärjistyivät lokakuussa 2022, kun Elon Musk pitkän ja likaisen kaupankäynnin myötä [päätyi Twitterin omistajaksi](https://www.theverge.com/2022/4/11/23019836/elon-musk-twitter-board-of-directors-news-updates).

Koko Elon Muskin uraa aina Paypalin kautta autojen ja rakettien valmistajaksi voi yhdellä sanalla luonnehtia pompöösiksi. Zuckerbergin Metaversetavoitteiden tavoin Musk tavoittelee kaiken kattavaa alustaa X.

Nyt Musk omistaa Twitterin ja on jo tehnyt paljon suuria muutoksia. Hän aloitti erottamalla joukon johtajia. Donald Trumpin aikaansaama Yhdysvaltain senaatin valtaaminen johti elinikäiseen porttikieltoon Twitteristä. Nyt, Muskin tultua Twitterin vallan kahvaan, [aprikoidaan](https://www.cnbc.com/2022/10/28/trump-says-twitter-is-now-in-sane-hands-with-musk.html), palauttaako Musk Trumpin pääsyn Twitteriin.

Mainostajat ovat jo alkaneet peräytyä Twitteristä. Samoin on perääntymässä käyttäjät, jotka pelkäävät, että Twitter muuttuu vihapuheen, virheellisten väittämien ja tarkoituksella valheellisen harhaanjohtavan tiedon alustaksi.

## Internetin keskittymisestä harvoille on haittaa

Samoin, kuin vallan keskittymisessä ylipäätään, myös Internetin keskittymisestä on haittaa. Internetistä on tullut oligopoli, harvojen valta.

Jättien kiistely vallasta internetissä näkyy jo internetin keskeisten protokollien kehittämisessä. Googlella ja Applella on avoin riita lyhytviestien, eli SMS:ien korvaajaprotokollasta [RCS](https://en.wikipedia.org/wiki/Rich_Communication_Services):stä.

Google on kehittänyt RCS:stä korvaajan vanhalle rajoittuneelle SMS:lle ja haluaisi myös Applen ottavan sen laitteissaan käyttöön. Applella on vain omissa laitteissaan iCloudin välityksellä toimiva iMessage-palvelu, joka sulkee käytäjät Applen ekosysteemiin. Sillä on vähän syitä ja tahtoa ottaa käyttöön Googlen suunnitteleman viestiprotokolla, vaikka se olisikin lähtökohdiltaan avoin.

Applen johtaja Tim Cook on vielä syksyllä 2022 ilmaissut selkeästi, että Applella ei ole suunnitelmia Googlen suunnitteleman protokollan käyttöönotosta.

Suomessa ja euroopassa ei vielä kovin paljon puhuta [nettineutraliteetusta](https://fi.wikipedia.org/wiki/Nettineutraliteetti). Yhdysvalloissa keskustelu on vilkasta, kun internetverkon operaattorit rajoittavat tai hidastavat tietynlaista liikennettä verkossaan.

Voidaan siis sanoa, että Internet on rikki. Se on ajautunut harvojen valtaan ja ei enää toimi hajautetusti siten, kuin se alun perin suunniteltiin.