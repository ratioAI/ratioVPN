# Ratio VPN 2.0 – Design

Stand: 24.11.2026 · Grundlage: Branch `automatik` (Commit 8256966, Automatik aus der laufenden exe wiederhergestellt)

## Absicht

Ratio VPN läuft täglich unbeaufsichtigt: mehrere Minecraft-26.2-Fenster (auch NRC-Client, alle als
`…\RatioLauncher\meta\java\zulu_25\bin\javaw.exe`) bekommen über die Automatik je eine eigene von 11
Proton-DE-WireGuard-Verbindungen. Auftrag: Programm komplett visuell und in der Leistung überarbeiten, neue
Funktionen, „überrasch mich“. Ausdrücklich: **jedes Programm** muss weiterhin über das VPN laufen können, nicht nur
Minecraft; die Automatik soll für beliebige Programme funktionieren.

## Befunde (aus Protokoll seit 19.10. und Code)

- 122× „antwortet nicht mehr“, 134× „wieder da“; allein 28.10.: 47 Ausfälle → wohl Internet weg, nicht Server. Die
  Automatik behandelt das wie Einzelausfälle (Meldungsflut, unnötige Wechsel).
- Falsch erkannt: YouTube-Fenster „How to get UNLIMITED Dried Kelp Blocks …“ bekam eine Verbindung (Titel passte).
- Leistung: Ratio VPN fängt **alle** ausgehenden TCP/UDP-Pakete des PCs ab, auch wenn keine einzige Regel aktiv ist.
  Jede neue Verbindung irgendeines Programms liest die Windows-Verbindungstabelle (v4 **und** v6) neu ein, unter einer
  globalen Sperre, mit neuem Speicher pro Lesen. Pro verschlüsseltem Paket ein neues Byte-Array, pro eingehendem Paket
  eine Kopie, Tunnel-Adresse wird pro Paket neu geparst.
- Startet man eine neue Build, beendet sie automatisch die ältere laufende Instanz (`OtherInstanceIsOlderBuild`).
  Der Autostart-Task zeigt fest auf `Downloads\RatioVPN2\…\RatioVPN.exe`.

## Ziele

1. **Tempo** messbar verbessern, ohne Risiko für den Paketweg.
2. **Automatik für alle Programme**: Regeln statt festem Minecraft-Muster; mit Fenster- oder Prozess-Erkennung.
3. **Schlauere Automatik**: Internet-Ausfall erkennen, unzuverlässige Server als Reserve zuletzt, Doppel-IP-Schutz,
   Kick-Erkennung.
4. **Neue Oberfläche**: Cockpit als Start, klare Navigation, Live-Werte, Statistik.
5. Umstieg in einem Klick, Einstellungen bleiben vollständig erhalten.

## Nicht-Ziele

- Kein Wechsel des UI-Frameworks (bleibt WPF/.NET 8), keine neuen NuGet-Abhängigkeiten in der App.
- Kein Batch-Empfang/-Senden über WinDivert (RecvEx/SendEx): Verhalten bei Teil-Batches ist laut Doku offen und hier
  ohne Adminrechte nicht testbar → später, mit Messung.
- Keine Server-Auswahl nach Land/Pool in den Regeln (JSON so anlegen, dass es später ergänzt werden kann).

## Anti-Ziele (wäre ein Fehlschlag, selbst wenn es „funktioniert“)

- Die echte IP leakt für ein verwaltetes Programm (auch kurzzeitig durch Umbau).
- Die laufende VPN-Instanz wird während der Arbeit gestört (beenden, überschreiben, zweite Instanz, Treiber,
  echte `settings.json`).
- Bestehende Einstellungen/Regeln/Automatik-Einstellungen gehen beim Umstieg verloren.
- Die Oberfläche wird langsamer oder schwerer (RAM/CPU im Leerlauf).

## Rahmenbedingungen

- Neue App niemals starten, solange die alte läuft (sie würde sie beenden). Optik wird über ein eigenes
  Vorschau-Werkzeug geprüft, das Fenster mit Demo-Daten in PNG rendert (kein Treiber, keine echten Einstellungen).
- Tests verwenden ausschließlich temporäre Einstellungsdateien.
- Build-Ausgabe in eigenen Ordner `publish-2.0` (gitignored). Kein Push ohne Auftrag.
- Einstellungen bleiben abwärtskompatibel: alte exe ignoriert neue Felder; `AutoPilot`-Objekt (inkl. `TitlePattern`)
  bleibt bestehen.

## Ansätze (entschieden)

| Ansatz | Bewertung |
|---|---|
| **WPF behalten, komplett neu gestalten** (gewählt) | Automatik/Code bleiben, kleine exe, kein neues Risiko für den Paketweg |
| WinUI 3 | Natives Win-11-Aussehen, aber ganze Oberfläche neu, größere Verteilung (Windows App SDK) |
| Web-Oberfläche (WebView2) | Maximale Gestaltungsfreiheit, aber deutlich mehr RAM, zweite Technologie |

Der Nutzer hat das „Wie“ abgegeben („vollste Kreativität“); gewählt wurde WPF.

## Design

### 1. Tempo (nur sichere, testbare Änderungen)

- **Umleitung aus, wenn keine Regel existiert**: Gibt es weder Programm- noch Fenster-/Prozessregeln (z. B. Minecraft
  läuft nicht), wird der WinDivert-Handle geschlossen → PC läuft mit voller Geschwindigkeit. Sobald eine Regel
  entsteht, wird er synchron vor dem Rückkehren von `ApplyRules` geöffnet (gleicher Code wie beim Start).
  `VpnController` entscheidet, `IPacketCapture` bekommt `IsRunning`; testbar mit Fake-Capture.
- **Verbindungstabelle**: nur die benötigte Adressfamilie (v4/v6) lesen, nativen Puffer wiederverwenden, direkt aus
  dem nativen Speicher parsen, Wörterbücher wiederverwenden.
- **Routing**: Tunnel-Adresse als `uint` am Tunnel zwischenspeichern; NAT-Schlüssel ohne String-Hashing; eingehende
  Pakete ohne Kopie (in-place im Empfangspuffer des Tunnels, Einspeisen ist synchron).
- **WireGuard senden**: ohne Allokation pro Paket (gepoolter/threadlokaler Puffer, `SendTo(ReadOnlySpan, SocketFlags,
  SocketAddress)` mit zwischengespeicherter Adresse).
- **Oberfläche**: ein gemeinsamer Fenster-/Prozess-Scan alle 2 s für Automatik und Programmliste statt zwei getrennter.
- **Messen**: `tests/RatioVPN.Bench` (Stopwatch + allokierte Bytes): Durchleiten, Tunneln, Eingang, Tabellenlesen,
  Automatik-Schritt; Werte vorher (Branch `automatik`) und nachher im Abschlussbericht.

### 2. Automatik-Regeln (für alle Programme)

`AppSettings.AutoRules: List<AutoRuleEntry>`:

| Feld | Bedeutung |
|---|---|
| `Id`, `Name`, `Enabled` | |
| `ExeNames` | Dateinamen, kommagetrennt (`javaw.exe, java.exe`); leer = jedes Programm (dann Titel nötig) |
| `TitlePattern` | Regex auf Fenstertitel; **leer = Prozess-Erkennung** (auch ohne Fenster, z. B. Skripte/Bots) |
| `Mode` | `Separate` = jede laufende Kopie eigene Verbindung · `Shared` = alle Kopien eine gemeinsame (mit Wechsel bei Ausfall) |
| `WatchTraffic` | Kick-Erkennung an/aus |

- Ein Prozess gehört zur ersten passenden aktiven Regel. Instanz = Prozess-ID.
- **Migration** (einmalig, wenn `AutoRules` fehlt): Regel „Minecraft 26.2“ aus `AutoPilot.TitlePattern`, `ExeNames =
  javaw.exe, java.exe`, `Separate`, `WatchTraffic = true`, `Enabled = true` (der Hauptschalter
  `AutoPilot.Enabled` bleibt unverändert und entscheidet allein). Damit ist der
  YouTube-Fehlgriff behoben (Titel **und** Programmdatei müssen passen).
- `AutoPilot.Enabled` bleibt Hauptschalter; `FailAfterSeconds`, Discord bleiben dort.
- Zuordnung wie bisher (bestehende funktionierende Verbindung behalten, sonst freie, nie doppelt, sonst blockiert
  „!“), erweitert um `Shared`: alle Instanzen einer Regel bekommen dieselbe Verbindung, die als belegt zählt.

### 3. Schlauere Automatik

- **Internet-Ausfall**: Fallen ≥ 75 % der laufenden aktivierten Verbindungen (mind. 2) gleichzeitig aus → Zustand
  „Internet weg“: keine Wechsel, keine Einzelmeldungen, eine wichtige Meldung „Internet weg“ und später „wieder da“.
  Neue Instanzen werden in dieser Zeit blockiert.
- **Zuverlässigkeit**: Ausfälle je Verbindung der letzten 24 h; freie Verbindungen werden nach Stufe (0 / 1–2 / 3+
  Ausfälle) und dann alphabetisch vergeben – im Normalfall bleibt die bisherige Reihenfolge.
- **Doppel-IP-Schutz**: Öffentliche IPs werden je Verbindung gemerkt (Knopf „Alle IPs prüfen“ + automatisch einmal
  nach dem ersten Verbinden pro Sitzung, max. 2 gleichzeitig, über die bestehende curl-Kopie-Methode). Verbindungen mit
  gleicher IP gelten als eine Gruppe: `Separate`-Instanzen bekommen nie zwei aus derselben Gruppe. Wichtige Meldung
  bei Fund.
- **Kick-Erkennung**: Routing zählt pro Prozess-ID getunnelte Pakete/Bytes (Zeiger am Port-/NAT-Eintrag, keine
  Zusatzsuche). Hatte eine überwachte Instanz Verkehr und seit 60 s keinen mehr → wichtige Meldung „keine Verbindung
  mehr zum Server (gekickt?)“; bei neuem Verkehr „wieder verbunden“. Dieselben Zähler liefern die Live-Kurven im Cockpit.
- Ereignisse bekommen eine Art (`Kind`) plus Tunnel/Prozess, damit Statistik und Oberfläche sie auswerten können.

### 4. Oberfläche

- Eigenes Fenster-Design (WindowChrome), dunkel, auf Windows 11 mit Mica-Hintergrund (Fallback: einfarbig),
  Segoe-Fluent-Icons, abgerundete Karten, dezente Animationen (Status-Puls beim Verbinden, weiche Übergänge).
- Navigation links: **Cockpit · Programme · Automatik · Verbindungen · Statistik · Einstellungen**.
- **Cockpit**: Statuszeile (geschützt / Anzahl Fenster / Reserven bereit / Internet ok), je verwaltete Instanz eine
  Kachel: Icon, Titel, Verbindung, Status, Latenz (Handshake-Laufzeit), öffentliche IP, Laufzeit, Live-Kurve; darunter
  der Verlauf.
- **Programme**: wie bisher (jedes Programm zuweisbar, einzelne Prozesse), aufgeräumter.
- **Automatik**: Hauptschalter, Regel-Liste und Editor mit Live-Test („passt gerade auf 2 offene Fenster“), Discord.
- **Verbindungen**: kompakte Karten mit Status, Latenz, IP, Zuverlässigkeit (Ausfälle 24 h), Datenmenge,
  „Alle IPs prüfen“, Import per Knopf/Drag & Drop.
- **Statistik**: Ausfälle pro Tag (30 Tage), Ranking der Verbindungen, Kicks, Datenmenge pro Tag.
- **Infobereich**: Symbol mit Statusfarbe, Tooltip-Zusammenfassung, Menü mit Automatik an/aus; optional Hinweise
  für wichtige Ereignisse.
- Vorschau-Werkzeug `tools/RatioVPN.Preview` rendert jede Seite mit Demo-Daten als PNG (zur Prüfung).

### 5. Statistik

- `StatsStore` (Core): Ereignisse als JSON-Zeilen in `%APPDATA%\RatioVPN\statistik.jsonl` (Pfad injizierbar, rotiert ab
  5 MB), Datenmenge je Tag aus Tunnel-Zählern alle 5 min.
- **Rückwirkend ab 19.10.**: beim ersten Start einmalig aus `fehler.log` („Automatik: …“-Zeilen) befüllt.

### 6. Umstieg

- Neue exe starten → beendet die alte automatisch (bestehender Mechanismus) → übernimmt Einstellungen.
- **Autostart-Selbstheilung**: Ist Autostart an und zeigt der Task auf eine andere exe, wird er auf die neue gesetzt.
- Version 2.0.0.

## Dem Umsetzer überlassen

Konkrete Farben/Abstände/Animationen, Aufteilung in Dateien, Namen interner Typen, genaue Schwellen (solange
dokumentiert und getestet), Reihenfolge der Umsetzung innerhalb einer Etappe.

## Eigene Entscheidungen (zum Gegenlesen)

- WPF statt WinUI/WebView2; kein WinDivert-Batching in dieser Runde.
- Minecraft-Regel prüft zusätzlich `javaw.exe`/`java.exe` (NRC läuft ebenfalls als `javaw.exe`).
- Schwellen: Internet-Ausfall ≥ 75 %, Kick nach 60 s ohne Verkehr, Zuverlässigkeit über 24 h.
- IP-Prüfung automatisch einmal pro Sitzung je Verbindung über api.ipify.org (wie der bestehende Knopf).
