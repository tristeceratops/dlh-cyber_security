### TShark — lecture et analyse d’un fichier PCAP

| Objectif                                                  | Commande                                                                          | À retenir                               |
| --------------------------------------------------------- | --------------------------------------------------------------------------------- | --------------------------------------- |
| Lire le PCAP                                              | `tshark -r capture.pcap`                                                          | Affiche les paquets                     |
| Afficher les détails complets                             | `tshark -r capture.pcap -V`                                                       | Tous les champs de chaque paquet        |
| Afficher uniquement les paquets correspondant à un filtre | `tshark -r capture.pcap -Y "dns"`                                                 | **Display filter**                      |
| Filtrer sur une IP                                        | `tshark -r capture.pcap -Y "ip.addr == 192.168.1.10"`                             | Source **ou** destination               |
| Filtrer source                                            | `tshark -r capture.pcap -Y "ip.src == 192.168.1.10"`                              | IP source                               |
| Filtrer destination                                       | `tshark -r capture.pcap -Y "ip.dst == 192.168.1.10"`                              | IP destination                          |
| Filtrer un port                                           | `tshark -r capture.pcap -Y "tcp.port == 443"`                                     | Source **ou** destination               |
| Filtrer un protocole                                      | `tshark -r capture.pcap -Y "http"`                                                | Ex. `dns`, `tls`, `icmp`, `ssh`         |
| Combiner des filtres                                      | `tshark -r capture.pcap -Y "dns && ip.src == 10.0.0.5"`                           | `&&` = ET                               |
| Alternative                                               | `tshark -r capture.pcap -Y "dns                                                   |                                         |
| Afficher certains champs                                  | `tshark -r capture.pcap -T fields -e ip.src -e ip.dst`                            | Très pratique pour extraire des données |
| Numéro + IPs                                              | `tshark -r capture.pcap -T fields -e frame.number -e ip.src -e ip.dst`            | Extraction ciblée                       |
| Format CSV                                                | `tshark -r capture.pcap -T fields -E header=y -E separator=, -e ip.src -e ip.dst` | Pour analyse/scripts                    |
| Afficher les octets                                       | `tshark -r capture.pcap -x`                                                       | Hexdump du paquet                       |
| Ne pas résoudre les noms                                  | `tshark -r capture.pcap -n`                                                       | Garde IP/ports numériques               |
| Conversations TCP                                         | `tshark -r capture.pcap -z conv,tcp`                                              | Qui communique avec qui                 |
| Conversations UDP                                         | `tshark -r capture.pcap -z conv,udp`                                              | Conversations UDP                       |
| Endpoints IP                                              | `tshark -r capture.pcap -z endpoints,ip`                                          | Liste des endpoints                     |
| Hiérarchie des protocoles                                 | `tshark -r capture.pcap -z io,phs`                                                | Répartition des protocoles              |
| Voir les champs disponibles                               | `tshark -G fields`                                                                | Utile avec `-e`                         |

**Les 5 options à retenir pour la lecture :**

```text
-r  → lire un PCAP
-Y  → filtrer
-T  → choisir le format de sortie
-e  → choisir les champs
-z  → statistiques
```

Exemple très courant :

```bash
tshark -r capture.pcap \
  -Y "http.request" \
  -T fields \
  -e frame.number \
  -e ip.src \
  -e http.host \
  -e http.request.uri
```

Cela permet de transformer un PCAP en une sortie exploitable plutôt que de parcourir tous les paquets manuellement.

