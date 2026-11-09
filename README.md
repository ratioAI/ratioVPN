<div align="center">

# Ratio VPN

**Split-Tunneling-VPN für Windows: pro Programm und sogar pro Fenster wählen, über welche VPN-Verbindung es ins Internet geht.**

[![CI](https://github.com/ratioAI/ratioVPN/actions/workflows/ci.yml/badge.svg)](https://github.com/ratioAI/ratioVPN/actions/workflows/ci.yml)
![.NET](https://img.shields.io/badge/.NET-8-512BD4?logo=dotnet&logoColor=white)
![C#](https://img.shields.io/badge/C%23-WPF-239120)
![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D6?logo=windows&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

</div>

---

## Highlights

- **Eigene WireGuard-Implementierung in C#**, ohne Fremdbibliotheken: Noise-IKpsk2-Handshake, X25519, BLAKE2s, ChaCha20-Poly1305, Rekeying, Keepalive und Replay-Schutz. Kein WireGuard-Client und kein virtueller Netzwerkadapter nötig.
- **Paketumleitung mit WinDivert**: ausgehende TCP/UDP-Pakete werden über die Windows-Verbindungstabelle dem Prozess zugeordnet und per NAT in den passenden Tunnel geschickt.
- **Regeln pro Programm und pro Fenster**: zwei Instanzen desselben Programms (z. B. zwei Java-Fenster) bekommen eigene Verbindungen.
- **Kill-Switch, IPv6-Leckschutz, MSS-Clamping**, Schlüssel DPAPI-verschlüsselt, Autostart ohne UAC-Abfrage.
- **Getestet** mit Referenzvektoren (RFC 7748, RFC 8439) und Routing-Tests; End-to-End-Test gegen einen echten WireGuard-Server optional.

Eigenes Split-Tunneling-VPN für Windows: Du entscheidest **pro Programm**, über welche VPN-Verbindung es ins Internet geht. Chrome kann über Frankfurt laufen, Discord über Amsterdam und alles andere direkt. Bis zu 10 Verbindungen (oder mehr) laufen gleichzeitig, jede mit eigener IP.

## So funktioniert es

```
Programm (z. B. Discord.exe)
   │  ausgehendes Paket
   ▼
WinDivert fängt TCP/UDP ab ──► Wem gehört der Port? (Windows-Verbindungstabelle → PID → .exe)
   │                                   │
   │ keine Regel                       │ Regel: "Discord → NL"
   ▼                                   ▼
normal ins Internet          Absenderadresse umschreiben, verschlüsseln (WireGuard)
                              und per UDP an den VPN-Server senden
                                       │
                              Antwort entschlüsseln, Adresse zurückübersetzen
                              und als eingehendes Paket an Discord zurückgeben
```

- **WireGuard läuft komplett in der App** (eigene Implementierung in C#: Noise-Handshake, ChaCha20-Poly1305, Rekeying, Keepalive). Dafür ist kein WireGuard-Programm und kein virtueller Netzwerkadapter nötig.
- **WinDivert** (signierter Treiber, liegt bei) leitet die Pakete um. Deshalb braucht die App Administratorrechte.
- Jede importierte `.conf`-Datei ist eine eigene Verbindung mit eigenem Server und damit eigener öffentlicher IP.

## VPN-Anbieter

Getestet mit **Proton VPN Plus**, das 10 gleichzeitige Verbindungen erlaubt. WireGuard-Dateien gibt es direkt im Konto:

1. Auf account.protonvpn.com anmelden → **Downloads** → **WireGuard-Konfiguration**.
2. Der Datei einen Namen geben (z. B. `DE-1`), Plattform **Windows** wählen, einen Server auswählen und **Create** → **Download** klicken.
3. Für 10 verschiedene Adressen 10 Dateien mit 10 verschiedenen Servern erzeugen. Proton erlaubt 10 gleichzeitige Verbindungen, also können bis zu 10 Dateien gleichzeitig aktiv sein.

Die App funktioniert genauso mit Mullvad, Surfshark, AirVPN oder einem eigenen WireGuard-Server.

## Bauen

Voraussetzung: [.NET SDK 8](https://dotnet.microsoft.com/download/dotnet/8.0) oder neuer.

```
build.bat
```

Danach liegt alles in `publish\`: `RatioVPN.exe`, `WinDivert.dll` und `WinDivert64.sys`. Die drei Dateien müssen zusammenbleiben. Alternativ öffnest du `RatioVPN.sln` in Visual Studio 2022 und startest `RatioVPN.App`.

## Benutzung

1. `RatioVPN.exe` starten und die UAC-Abfrage bestätigen.
2. **Verbindungen** → *WireGuard-Dateien importieren* (Mehrfachauswahl oder Drag & Drop). Ein Klick auf den Namen benennt eine Verbindung um.
3. **Programme**: Die Liste zeigt alle offenen Fenster. Im Auswahlfeld rechts wählst du die Verbindung. Die Änderung wirkt sofort und bleibt gespeichert.
4. Mit *IP prüfen* siehst du die öffentliche IP einer Verbindung.
5. Programme ohne Fenster (z. B. Hintergrund-Clients) fügst du über *+ Programm hinzufügen* hinzu.

Einstellungen: Kill-Switch, Autostart mit Windows (über die Aufgabenplanung, ohne UAC) und Weiterlaufen im Infobereich.

## Wichtig zu wissen

- **DNS**: Windows löst Namen über einen Systemdienst auf. Diese Anfragen gehen deshalb nicht durch den Tunnel. Schalte im Browser „Sicheres DNS“ (DoH) ein, dann läuft auch die Namensauflösung über das VPN.
- **IPv6** wird für zugewiesene Programme blockiert. Sie weichen dann auf IPv4 aus, und das läuft durch den Tunnel. So sickert keine echte Adresse durch.
- **Heimnetz** (192.168.x.x usw.) erreichen zugewiesene Programme weiter direkt.
- Beim Umstellen eines laufenden Programms brechen seine bestehenden Verbindungen einmal ab und bauen sich neu auf. Discord und Browser machen das automatisch.
- Manche Spiele mit Kernel-Anti-Cheat mögen Paket-Umleitung nicht. Weise diesen Spielen im Zweifel keine Verbindung zu.
- **Mehrere Fenster desselben Programms:** Läuft ein Programm mehrfach als eigener Prozess (z. B. zwei Minecraft-/Java-Instanzen, „Zulu Platform x64 Architecture“), zeigt die App unter dem Programm jedes Fenster einzeln. Dort wählst du pro Fenster eine eigene Verbindung, „Ohne VPN“ oder „Wie das Programm“. Diese Fenster-Regeln gelten, solange der Prozess läuft. Nach einem Neustart des Programms stellst du sie neu ein.
- Mehrere Fenster, die sich **einen** Prozess teilen (z. B. alle Chrome-Fenster), lassen sich technisch nicht trennen. Für zwei IPs im Browser nimmst du zwei Browser (z. B. Chrome und Firefox).
- Die Schlüssel liegen DPAPI-verschlüsselt in `%APPDATA%\RatioVPN\settings.json`. Fehlerprotokoll: `%APPDATA%\RatioVPN\fehler.log`.

## Fehlerbehebung

| Meldung | Lösung |
|---|---|
| WinDivert-Treiber nicht gefunden | `WinDivert64.sys` muss neben der `.exe` liegen |
| Zugriff verweigert | Als Administrator starten (passiert normalerweise automatisch) |
| Treiber blockiert | Antivirus-Ausnahme für den Ordner anlegen. Manche Virenscanner stufen WinDivert vorsorglich als verdächtig ein |
| Verbindung „Fehler“ / Handshake-Zeitüberschreitung | Server offline, Datei abgelaufen oder Gerätelimit beim Anbieter erreicht. Neue Datei erzeugen |
| Programm bekommt kein Internet | Kill-Switch aktiv und Verbindung getrennt? Unter *Verbindungen* auf *Verbinden* klicken |

## Projektaufbau

```
src/RatioVPN.Core/      Plattformunabhängiger Kern
  Crypto/               BLAKE2s, X25519, ChaCha20-Poly1305, XChaCha20 (ohne Fremdbibliotheken)
  WireGuard/            .conf-Parser, Noise-IKpsk2-Handshake, Tunnel (Timer, Rekey, Replay-Schutz)
  Net/                  IP/TCP/UDP: Prüfsummen, MSS-Clamping, Segmentierung großer Pakete
  Routing/              RoutingEngine: Programm → Tunnel, NAT hin und zurück, Kill-Switch
  Windows/              WinDivert-Anbindung, Port→Prozess-Zuordnung
  VpnController.cs      Verbindet alles, speichert Einstellungen
src/RatioVPN.App/       WPF-Oberfläche, Infobereich-Symbol, DPAPI, Autostart
tests/RatioVPN.Tests/   Testläufer (Krypto-Vektoren, Pakete, End-to-End gegen echten WireGuard-Server)
lib/WinDivert/          WinDivert 2.2.2 (LGPL v3), x64
```

Tests ausführen: `dotnet run --project tests/RatioVPN.Tests` (mit einer `client.conf` als Argument zusätzlich End-to-End).

---
WireGuard® ist eine eingetragene Marke von Jason A. Donenfeld. WinDivert © basil00, LGPL v3.
