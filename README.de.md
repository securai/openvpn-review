# OpenVPN-Review

**DISCLAIMER:** Dieses Tool befinden sich momentan noch in der Beta-Phase. Unerwartetes Verhalten, Fehler oder nicht unterstsütze Ciphersuites sind sehr wahrscheinlich noch enthalten. Für gemeldete Fehler bedanken wir uns ganz herzlich!

---

[[EN version]](README.md)

OpenVPN-Review ist ein in `python3` geschriebenes Tool das die Sicherheit einer [OpenVPN Community](https://openvpn.net/index.php/open-source.html) Konfiguration bewertet. 
Hauptsächlich ist das Script zur Bewertung von Serverkonfigurationsdateien konzipiert, aber Konfigurationsdateien von Clients können auch bewertet werden.

**Diese Bewertung dient jedoch nur der Orientierung und kann natürlich keine absolute Sicherheit versprechen!**

Bitte melden Sie jeden gefundenen Fehler, Vorschläge oder Kritik, indem Sie ein neues Issue auf [dem GitHub Repository](https://github.com/securai/openvpn-review) öffnen. Falls das nicht geht, können Sie uns auch gerne eine E-Mail senden.

Sollten Sie fehlende (diese werden als *unknown* in der Bewertung markiert) Daten- und/oder Kontrollkanal Ciphersuites oder Hashingfunktionen finden, würden wir Sie bitten ein Issue auf [dem GitHub Repository](https://github.com/securai/openvpn-review) zu erstellen, sodass diese so bald als möglich implementiert werden können.

Vielen Dank für Ihre Unterstützung!

[![Securai](/img/securai.png)](https://securai.de)

[![Contact](/img/mail.png)](https://www.securai.de/en/contact/)


## Installation

GitHub:

 * [![Clone oder Download](/img/cod.png)](https://github.com/securai/openvpn-review/archive/master.zip)
 * Extrahieren
 * `$ python3 openvpn-review.py`

PyPi:

 * Nach Abschluss der Beta-Phase verfügbar.

## Benutzung

```
  -h, --help            show this help message and exit
  -c CONFIG, --config CONFIG
                        The OpenVPN configuration file (default /etc/openvpn/server/server.conf)
  -s, --server          Flag to define that the script is running on the OpenVPN server. The default tls-cipher for the server can only be identified on the server itself.
                        If the script is executed on a differnt system and this flag is set, the results may be distorted.
                        If the default tls-cipher is configured and the script is not executed on the server, the results will be incomplete.
  -m, --mbedtls         Flag to define that mbedTLS is used for OpenVPN.
  -v, --verbose         Verbose mode
  -vv, --veryverbose    Very verbose mode
```


## Beispiel

Zur Demonstration des Tools wird die Beispiel-Serverkonfiguration aus dem [offiziellen OpenVPN GitHub](https://github.com/OpenVPN/openvpn/tree/master/sample/sample-config-files) (ohne Kommentare) verwendet.

```
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
keepalive 10 120
tls-auth ta.key 0
cipher AES-256-CBC
persist-key
persist-tun
status openvpn-status.log
verb 3
explicit-exit-notify 1
```


### OpenVPN Server Konfiguration Überprüfung (ohne -s/--server)

![OpenVPN Server Konfiguration Überprüfung (ohne -s/--server)](/img/wo.png)

Der `tls-cipher` ist *unknown*, da in der Konfigurationsdatei diese Option nicht spezifiziert wurde, deshalb wird der Standardwert verwendet. Dieser Standardwert ist von der eingesetzten SSL Bibliothek abhängig und das Script wurde nicht im Servermodus gestartet, somit ist es dem Script nicht möglich diese zu identifizieren und zu bewerten.

### OpenVPN Server Konfiguration Überprüfung (mit -s/--server)

![OpenVPN Server Konfiguration Überprüfung (mit -s/--server)](/img/w.png)

Wird das Script im Servermodus gestartet, benutzt dies die lokale SSL Bibliothek um die Standartwerte zu identifizieren und zu bewerten.

## To Do

 * Implementierung einer Warnung, wenn die OpenVPN Version des Benutzers aktueller ist, als die letzte OpenVPN Version die im Script betrachtet wurde. Somit sollten Probleme zwischen OpenVPN Updates und Updates dieses Scriptes vermieden werden.
 * Unterstützung für die `--reneg*` Optionen hinzufügen
 * Unterstützung für die `--keysize n` Option hinzufügen
 * Die Bewertung der `--prng` Option nachprüfen
 * :suspect:


## Vorschau

Dieses Script wird um ein zweites Tool ergänzt, das eine Sicherheitsprüfung aus der Clientperspektive ohne Einsicht auf die Severkonfiguration erlaubt (ähnlich zu Tools wie SSLScan).

---
[Mozilla Public License Version 2.0](https://www.mozilla.org/media/MPL/2.0/index.txt)