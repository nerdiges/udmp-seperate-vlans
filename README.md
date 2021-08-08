# UDM / UDM Pro VLAN Trennung

Werden auf der UDM/UDM Pro unterschiedliche VLANs verwendet, so kann innerhalb der Sicherheitszonen LAN und Guest zwischen den jeweiligen VLANs ungefiltert kommuniziert werden, da das Firewallregelwerk per Default keine strikte Trennung umsetzt (siehe auch https://nerdig.es/udm-pro-netzwerktrennung-1/). Damit zwischen den 

## Funktionsweise
Das Script `21-separate-vlans.sh` wird per [UDM / UDMPro Boot Script](https://github.com/boostchicken/udm-utilities/tree/master/on-boot-script) von [boostchicken](https://github.com/boostchicken) beim Systemstart ausgeführt. Da die vom Script erzeugten Firewall regeln bei Änderungen an der Firewall-Konfiguration gelöscht werden, wird beim initialen Ausführen des Scripts ein Cron-Job angelegt, der das Script alle 2 Minuten ausführt um sicherzustellen, dass die REgeln dauerhaft implementiert sind. 

## Voraussetzungen
Das [UDM / UDMPro Boot Script](https://github.com/boostchicken/udm-utilities/tree/master/on-boot-script) von [boostchicken](https://github.com/boostchicken) muss auf der Unifi Dream machine installiert sein.

## Installation des Scriptes
Nachdem eine Verbindung per SSH zur UDM/UDM Pro hergestellt wurde wird das Script folgendermaßen installiert

```
# 1. download file to directory /mnt/data/on_boot.d
curl -o /mnt/data/on_boot.d/21-separate-vlans.sh https://raw.githubusercontent.com/nerdiges/udmp-seperate-vlans/main/21-separate-vlans.sh

# 2. make script executable
chmod +x /mnt/data/on_boot.d/21-separate-vlans.sh

# 3. run script to add missing firewall rules and to create cron job
/mnt/data/on_boot.d/21-separate-vlans.sh
```

## Konfiguration
Im Script kann über die Variable *exclude* eine Liste von Interfaces angegeben werden, bei denen der ausgehende Datenverkehr grundsätzlich zugelassen wird.

**Beispiel:** Wurden in der *Unifi Network* Oberfläche beispielsweise zwei Corporate-Network VLANs mit den VLAN-IDs 20 und 21, so werden von Unifi die Interfaces *br20* und *br21* angelegt. Wird in der Variablen *exclude* das Interface br20 angegeben so wird der Traffic *br20* -> *br21* grundsätzlich zugelassen. Dazu wird auch eine entsprechende Firewall Regel eingetragen, die das Connection-Tracking aktiviert und Pakete mit dem Status `established`und `related` zulässt (siehe auch variablen `allow_related_lan`und `allow_related_guest`).



Siehe auch: https://nerdig.es/udm-pro-netzwerktrennung-2/
