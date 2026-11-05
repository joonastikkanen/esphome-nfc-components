# Vesimittarin NFC-kotelo v1.3 – napsautuskansi ja ESP32-lukitus

## Tulosta päivitykseen kaksi osaa

| Tiedosto | Määrä | Toiminto |
|---|---:|---|
| `stl/03_NFC_kelkka.stl` | 1 | NFC-korttipaikka ja neljä integroitua kannen joustokynttä |
| `stl/10_NFC_kansi_ESP_pidike.stl` | 1 | Napsautuskansi ja ESP32:n integroitu joustopidike |

Nämä korvaavat v1.2:n NFC-kelkan ja sen kannen. Lukitukset sisältyvät näihin kahteen osaan. Päivitys on mitoitettu v1.2:n poikittaiskelkkaan, jossa NFC-kortin X-mitta on 42,6 mm ja Y-mitta 40,5 mm.

## Kiinnityksen toiminta

### NFC-kansi

- Kelkassa on neljä leveää, ulospäin joustavaa kynttä. Niiden viistot nokat ohjaavat kannen paikalleen.
- Kannen neljä sivukorvaa napsahtavat kynsien alle. Pystysuorat ohjaimet kohdistavat kannen Y-suunnassa.
- Sivuvälys on 0,4 mm, kynnen limitys kannen reunaan 0,45 mm ja pystysuuntainen asennusvälys 0,25 mm.
- Aseta NFC-kortti kelkkaan, ohjaa johdot lovista ja kohdista kansi. Paina kannen reunoja tasaisesti, kunnes kaikki neljä kynttä lukittuvat.
- Irrota kansi vapauttamalla yhden sivun kaksi kynttä ulospäin ja nostamalla kyseistä reunaa hieman. Vapauta sitten vastakkainen sivu.

### ESP32-C3

- USB-pään kaksi kiinteää kynttä ja vastakkaisen pään kaksi joustavaa kynttä pidättävät korttia ylöspäin.
- Pitkät joustovarret on erotettu kansilevystä 0,8 mm U-raoilla. Varsi ja sen alla oleva kapea pohjakaistale voivat joustaa sivusuunnassa yhdessä.
- Kortin sivuvälys on 0,4 mm per sivu. Kynnet ulottuvat 0,45 mm kortin reunojen päälle; nimellinen pystysuuntainen välys on 0,35 mm.
- Irrota USB-johto asennuksen ajaksi. Pujota kortin USB-pää ensin kiinteiden kynsien alle noin 20–22° kulmassa. Laske vastakkainen pää alas ja levitä tarvittaessa joustovarsia kevyesti, kunnes kortti napsahtaa paikalleen.
- Irrotettaessa levitä joustovarsia sivuille, nosta USB-liitintä vastapäätä oleva pää ylös ja vedä USB-pää pois kiinteiden kynsien alta.
- Kynnet on mitoitettu annetulle 17,8 × 21 × 3,5 mm kokonaiselle kortin tilavaraukselle. Sovita todelliset komponentit ja juotetut johdot niin, että kynnet tukeutuvat kortin reunoihin eivätkä johtoihin.

## Tulostus

**Suositus: PETG**, 0,4 mm suutin, 0,2 mm kerros ja vähintään 3 seinämälinjaa. Käytä 100 % mittakaavaa.

- Molemmat päivityksen STL:t ovat oikein päin: tasainen pohja alustalle, kynnet ja ESP32-pidike ylöspäin.
- Tukimateriaalia ei ole tarkoitettu käytettäväksi. Kynsien alapinnoissa on 45° nousut; kannen ja kelkan pohjat ovat tasaiset.
- Joustovarsien U-raot pitää jättää auki. Poista mahdolliset ensimmäisen kerroksen purseet ja raon yli kulkevat langat ennen sovitusta.
- Suunniteltu joustovarren paksuus on 1,2 mm. Joustokohtien tulisi muodostua yhtenäisistä seinämälinjoista.

## Mitat

| Kohde | Mitta |
|---|---|
| NFC-kortin mitoitus | X42,6 × Y40,5 mm |
| NFC-taskun vapaat sisämitat | X43,8 × Y41,7 mm |
| NFC-piirilevyn alapinnan etäisyys mittarista | 3,6 mm |
| NFC-komponenttivaraus | 6 mm piirilevyn alapinnasta; 0,8 mm tilaa kannen alle |
| Kannen peruslevy | 47 × 44,9 × 1,2 mm; sivukorvien kohdalla leveys 48 mm |
| ESP32-C3 | 17,8 × 21 × 3,5 mm |
| ESP32:n sivuohjainten vapaa leveys | 18,6 mm |
| Korkeus ESP32-pidikkeen yläreunasta ulkokannen sisäpintaan | 8 mm |
| Suositeltu säätöalue | X ±20 mm, Y ±16 mm |
| Ulkokotelo | 128 × 110 mm, 28 mm mittarin näyttötason yläpuolella |

## Johdot ja lukeminen

NFC-kortin antennipuoli osoittaa mittariin. Vie johdot kelkan ja kannen etu- tai sivulovesta liukuohjainten yläpuolelle. Jätä USB-virtajohtoon ja 550 mm NFC-johtoon löysää liikettä varten.

ESP32:n 40 × 20 mm liima-antennille on paikka ulkokannen sisällä. Mallinnettu koaksiaalikaapelin reitti on keskiasennossa noin 36 mm ja tarkistetuissa ääriasennoissa enintään 57,3 mm. 70 mm kaapeliin jää vähintään 12,7 mm pituusvaraa. Reitti on tilavaraus: lopulliset loivat mutkat ja liittimen paikka sovitetaan oikeaan korttiin.

Käyttäjä on saanut aiemman telineen lukemaan mittaria ilman kantta. Tämän version napsautuskynsien käytännön jousto, pitovoima ja NFC-luku uudessa kokoonpanossa tarvitsevat vielä fyysisen sovituksen. Kokeile lukeminen uudelleen ESP32:n ja johtojen ollessa paikoillaan.

## Tarkistukset

- Kaikki 9 tulostettavaa osatyyppiä ovat ehjiä yksittäisiä solideja ja STL-verkot suljettuja.
- NFC-kansi ja ESP32 mahtuvat paikoilleen ilman nimellistä tilavuusleikkausta.
- Kannen nostaminen 0,7 mm ja ESP32:n nostaminen 0,8 mm törmäävät mallissa pidätyskynsiin: muotolukitus pidättää suoraa nostoa.
- ESP32:n 22° pujotusasento tarkistettiin ilman USB-pistoketta; kortin tilavaraus ei leikkaa pidikettä.
- Koko kelkan liikealue, piirilevyjen ja USB-pistokkeen tilavaraukset tarkistettiin yhdeksässä kohdassa: X −20 / 0 / +20 mm ja Y −16 / 0 / +16 mm.
- Koaksiaalikaapelin pituus ja muoviosiin osuminen tarkistettiin samoissa yhdeksässä kohdassa.
- Tarkistukset ovat geometrisia. Joustovoimaa, materiaalin väsymistä tai tulosteen lujuutta ei ole mitattu.

## Tiedostot

- `Vesimittari_NFC.FCStd`: kokoonpano; ulkokansi on aluksi piilossa. Valitse osa puusta ja paina välilyöntiä näyttääksesi sen.
- `Tulostusosat.FCStd`: koko kotelon kaikki 14 tulostettavaa kappaletta tulostusasennossa. Asettelu ei vastaa tiettyä tulostuslevyä.
- `Havainne.FCStd`: kansi ja ESP32 nostettuina kelkan yläpuolelle, ulkokansi vieressä.
- `Vesimittari_NFC.step`: tulostettavien osien kokoonpano.
- `nfc_kansi_esp32.png`: lähikuva napsautuskiinnityksistä.
- `mekanismi.png`, `kotelo_suljettu.png`, `kokonaisuus.png`, `tulostusosat.png`: muut havainnekuvat.
- `tarkistus.json`: lähtömitat ja tarkistustulokset.
- `../vesimittari_kotelo.FCMacro`: mallin lähde. Muuta `P`-sanakirjan parametreja ja suorita FreeCADin Makrot-valikosta. FCStd:n mittataulukko dokumentoi lähtöarvot, mutta ei itsessään ohjaa geometriaa.

### Koko kotelon tulostusluettelo

| Osa | Määrä |
|---|---:|
| 01 Satula | 1 |
| 02 Poikittaiskelkka | 1 |
| 03 NFC-kelkka, joustokynnet | 1 |
| 04 X-kiila | 1 |
| 05 C-puristin | 2 |
| 06 Y-kiila | 2 |
| 07 Sovituskiila | 4 |
| 08 Ulkokansi | 1 |
| 10 NFC-kansi ja ESP32-joustopidike | 1 |
