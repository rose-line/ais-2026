# Techniques défensives avec Python

## Intro

On va ici se concentrer sur l'utilisation de Python pour les contrôles de sécurité ainsi que l'identification des vulnérabilités et des surfaces d'attaque dans le cadre des techniques de sécurité défensive.

## 1. Contrôles de sécurité

Les contrôles de sécurité font référence aux contre-mesures et aux politiques mises en place pour protéger une organisation et minimiser le risque d'exposition involontaire (par les parties prenantes) et d'exposition intentionnelle (par un acteur malveillant). Ils sont conçus pour éviter les attaques sur les données et maintenir la confidentialité. Parfois, ils sont également traités comme des normes internes et sont appliqués par l'équipe cyber.

Il existe d'autres aspects qui peuvent être évalués à l'aide de divers contrôles de sécurité.

Ces contrôles peuvent être axés sur des aspects de sécurité qui peuvent couvrir un seul système cible, un ensemble de systèmes cibles ou même un réseau entier. Quelques-uns des domaines visés :

- Surveillance des fichiers pour les changements non autorisés
- Gestion des mots de passe
- Analyse du système pour les mots de passe faibles
- Contrôles des actifs sur cloud (Saas, Paas, Iaas)

### Création d'un contrôle de sécurité sur _login.defs_

Nous allons créer un simple contrôle de sécurité pour vérifier les valeurs par défaut définies pour le package de connexion utilisateur et si elles peuvent conduire à une sécurité faible. Ces paramètres sont définis dans `/etc/login.defs` sous Linux. Plus précisément, nous allons examiner les configurations suivantes et vérifier si elles sont conformes aux limites permises selon une politique spécifique :

| Paramètre      | Description |
|----------------|-------------|
| PASS_MAX_DAYS  | Le nombre maximum de jours pendant lesquels un mot de passe est valide |
| PASS_MIN_DAYS  | Le nombre minimum de jours pendant lesquels un mot de passe doit être utilisé avant de pouvoir être changé |
| PASS_WARN_AGE  | Le nombre de jours avant l'expiration du mot de passe pendant lesquels l'utilisateur reçoit un avertissement |

### Script

Voici un script qui lit `/etc/login.defs` et affiche les incohérences entre la configuration et une politique spécifiée. Ce script utilise le concept de « classe » que nous n'avons pas vu. Il s'agit d'une structure de données qui permet de regrouper des fonctions et des variables liées à un même concept. Ici on définit une classe `PasswordSecurityControl` qui contient les paramètres de la politique de sécurité et une méthode `check_config()` qui effectue les vérifications. Dans un système où les contrôles de sécurité sont nombreux, il est plus facile de les organiser en classes.

Compatibilité : la plupart des distributions Linux

```python
'''
Ce script vérifie la configuration d'expiration des mots de passe sur un système Linux via le fichier /etc/login.defs.
- Il compare les valeurs configurées avec une politique de sécurité définie dans la classe PasswordSecurityControl.
- Il affiche les métriques non conformes et le nombre total de non-conformités détectées.
'''

import platform
import subprocess


class PasswordSecurityControl:
    # Définition de la politique de sécurité pour l'expiration des mots de passe
    # (scénario réel : plutôt BDD ou fichier de config)
    PASS_MAX_DAYS_POLICY = 60
    PASS_MIN_DAYS_POLICY = 1
    PASS_WARN_AGE_POLICY = 7

    def check_config(self):
        if platform.system() == "Linux":
            output = subprocess.check_output("grep '^PASS' /etc/login.defs", shell=True)
            output_list = output.decode("utf-8").split("\n")

            print("Configuration de mot de passe depuis login.defs :")
            print(output_list, "\n")

            nb_failed = 0
            for config_item_line in output_list:
                config_item = config_item_line.split("\t")
                if len(config_item) != 2:
                    continue
                name = config_item[0]
                value = int(config_item[1])

                if (name == "PASS_MAX_DAYS") and value != self.PASS_MAX_DAYS_POLICY:
                    print(
                        "Métrique : ",
                        name,
                        "\tValeur spécifiée par politique : ",
                        self.PASS_MAX_DAYS_POLICY,
                        "\tValeur effective : ",
                        value,
                    )
                    nb_failed += 1
                elif (name == "PASS_MIN_DAYS") and value != self.PASS_MIN_DAYS_POLICY:
                    print(
                        "Métrique : ",
                        name,
                        "\tValeur spécifiée par politique : ",
                        self.PASS_MIN_DAYS_POLICY,
                        "\tValeur effective: ",
                        value,
                    )
                    nb_failed += 1
                elif (name == "PASS_WARN_AGE") and value != self.PASS_WARN_AGE_POLICY:
                    print(
                        "Métrique : ",
                        name,
                        "\tValeur spécifiée par politique : ",
                        self.PASS_WARN_AGE_POLICY,
                        "\tValeur effective : ",
                        value,
                    )
                    nb_failed += 1

            if nb_failed > 0:
                print("\nNombre de métriques non conformes : ", nb_failed)

        else:
            print("Ce script est conçu pour Linux.")


if __name__ == "__main__":
    pwd_sec_control = PasswordSecurityControl()
    pwd_sec_control.check_config()
```

### Modifications

- Si on vérifie de nombreux paramètres de configuration, ça va faire beaucoup de `if`. Comment faire pour éviter ça ?

- Journalisation de la sortie de ce script / exécution une fois par jour.

## 2. Monitoring de ports

Compatibilité : tout OS supportant Python et le module `psutil`

On veut vérifier si les ports 20 et/ou 21 sont ouverts ou non.

- Implémenter le script _sans IA_

  - le script est facile, il faut juste se documenter sur l'utilisation du module `psutil` et sa fonction `net_connections()` pour vérifier les ports ouverts.

  - utiliser la structure de classe comme précédemment.

- Modifier le script pour que la liste de ports à vérifier provienne d'un fichier externe (se documenter sur la lecture de fichier en Python via `open()`).

- Modifier le script pour qu'il puisse identifier les changements d'états par rapport au dernier lancement.

  - ex : port 21 était fermé hier, il est ouvert aujourd'hui.

  - cela va impliquer de garder une trace de l'état précédent des ports (exécution précédente du script)

  - loguer tous les changements d'état dans un fichier de log (pour loguer, utiliser le module `logging` de Python, cf cours).

  - tester en forçant l'ouverture/fermeture de ports.

## 3. Monitoring de logs

Compatibilité : Linux, mais les fichiers changent en fonction des distros ; adaptable pour Windows

### Analyse de logs

Il existe de nombreux logs dans Linux qui peuvent être monitorés. En voici quelques exemples notables (dépend des distros) :

- `/var/log/secure` (sur RedHat) ou `/var/log/auth.log` (Debian/Ubuntu) : logs d'authentification, y compris tentatives de connexion, changements de mot de passe, accès _sudo_, connexions SSH...

- `/var/log/faillog` : enregistre les tentatives de connexion échouées, y compris noms d'utilisateur, adresses IP source, horodatages (`faillog` pour afficher les échecs de connexion)

- `/var/log/wtmp` : enregistre les connexions et déconnexions des utilisateurs, y compris les connexions SSH

- `/var/log/messages` : nombreux messages systèmes et d'applications

- `/var/log/syslog` : messages système généraux

- `/var/log/audit/audit.log` : logs d'audit de sécurité, peut être configuré pour enregistrer des événements spécifiques liés à la sécurité (pour auditing)

- logs spécifiques de serveurs (web, bdd...), par exemple `/var/log/apache2/access.log` et `/var/log/apache2/error.log` pour Apache

- sur certaines distros, les logs sont gérés par `journald` et peuvent être consultés via la commande `journalctl` (logs centralisés) avec les options pour filtrer par service, par niveau de gravité, etc.

Voici, grossièrement, les étapes à suivre pour atteindre des objectifs de sécurité défensive en surveillant les journaux :

- script qui surveille en continu les fichiers de journalisation intéressants ;

- analyse pour obtenir des informations et des modèles pertinents ;

- prise de mesures en fonction des informations.

### Mise en place d'un monitoring de logs

Nous allons ici surveiller en temps réel un fichier de journalisation généré par nos soins.

- Utilisation du module Python `tailer` pour surveiller un fichier en temps réel (utiliser `pip/pip3` pour installer si nécessaire).

- Utilisation du module `os` (_built-in_) pour faciliter la gestion des chemins de fichiers.

- Créer un fichier `test_log.log` à côté du script avant exécution.

### Script

```python
import tailer
import os

# Définition de l'emplacement du script
dir = os.path.realpath(os.path.join(
    os.getcwd(), os.path.dirname(__file__)))


class LogMonitor:
    def monitor_log(self, logfile):
        logfile = os.path.join(dir, logfile)
        print('Surveillance de : ', logfile)

        for log_line in tailer.follow(open(logfile)):
            print(log_line)


if __name__ == "__main__":
    monitor = LogMonitor()
    monitor.monitor_log('test_log.log')
```

Ce script monitore le fichier `test_log.log` en temps réel, affiche les nouvelles lignes de journal au fur et à mesure qu'elles sont générées.

- Tester en ajoutant manuellement des lignes dans `test_log.log` pendant que le script est en cours d'exécution.

### Modifications

Imaginons maintenant que nous voulions détecter les lignes de journal qui contiennent les mots "ERROR" ou "CRITICAL" (on se rappelle que, en logging, ce sont les niveaux de gravité les plus élevés).

- Modifier le script pour qu'il puisse détecter ces mots-clés grâce au module `re` (expressions régulières, se renseigner sur son utilisation) et afficher un message d'alerte le cas échéant.

#### Expressions régulières (_RegEx_)

Les expressions régulières (_Regular Expressions_ ou _RegEx_) sont des séquences de caractères qui définissent un motif de recherche. Elles sont largement utilisées pour _rechercher_, _extraire_ ou _manipuler_ des chaînes de caractères en fonction de critères spécifiques. En Python, le module `re` fournit des fonctions pour travailler avec les expressions régulières.

Voici un exemple qui « valide » une adresse IPv4 :

```python
import re

def validate_ipv4_address(ip_address):
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    return re.match(pattern, ip_address):
```

## 4. Identifier une attaque brute-force

Compatibilité : Linux, mais les fichiers ou journaux à consulter changent en fonction des distros ; adaptable pour Windows

### Monitoring de logs d'authentification

En examinant les logs d'authentification, on peut identifier des tentatives de connexion par force brute.

- Examiner la structure du fichier de log d'authentification de votre système pour identifier les lignes et les champs pertinents.

### Script

- Écrire un script qui analyse les logs d'authentification en temps réel pour détecter les tentatives de connexion échouées.

  - Afficher le nom d'utilisateur lorsqu'une tentative de connexion échouée est détectée.

  - Pour tester le script, on peut simuler des tentatives de connexion (succès ou échec) en utilisant la commande `su - username`.w

### Modifications

- Modifier le script pour qu'il puisse détecter les tentatives de connexion échouées ciblant chaque nom d'utilisateur, et enregistrer le nombre de tentatives échouées pour chaque utilisateur dans un dictionnaire Python. Afficher une alerte lorsque le nombre de tentatives échouées pour un utilisateur dépasse un seuil spécifié.

- Modifier ce script pour faire un _reset_ du compteur dès qu'une authentification réussie est détectée pour un utilisateur donné.

- Les authentifications réussies d'un utilisateur légitime peuvent venir « masquer » les tentatives de connexion échouées d'un attaquant qui cible ce même utilisateur. Élaborer et implémenter une stratégie pour détecter les tentatives de connexion échouées même en présence d'authentifications réussies pour le même utilisateur.

## 5. Boite à outils pour surface d'attaque

Concevoir une classe avec ces fonctions :

1. `check_open_ports()` : utilise le module `nmap3` pour scanner les ports ouverts sur la machine locale et affiche les résultats.

    - Il faut que `nmap` soit installé sur la machine pour que le module fonctionne.

    - Puis installer le module `nmap3` via `pip/pip3` si nécessaire.

    - La fonction doit renvoyer un « dump » JSON (module `json`).

2. `check_listening_sockets` : utilise `psutil.net_connections()` pour récupérer les sockets d'écoute ouverts (`status == psutil.CONN_LISTEN`) ; la fonction renvoie une liste de sockets.

3. `list_members_privileged_groups()` : utilise le module `subprocess` pour exécuter des commandes système qui listent les membres des groupes privilégiés (disons `adm` et `sudo`) et affiche les résultats (commande `members` sur Debian/Ubuntu).

    - Utiliser `subprocess.check_output()` pour exécuter les commandes et récupérer les résultats.

> Notez que ces fonctions utilitaires n'affichent rien : elles _renvoient_ les données collectées. Le code appelant va ensuite décider de ce qui en est fait. Ce genre de construction permet de séparer la logique de collecte des données de leur traitement. Cela permet notamment de créer des « boîtes à outils » de fonctions qui pourront être utilisées dans des contrôles de sécurité plus vastes. Pour les tests, vous vous contenterez d'afficher le résultat des appels à ces fonctions.

## 6. Vérifier si les paquets installés sont vulnérables via les DB CVE

Compatibilité : distros _Debian-based_

Les CVE (_Common Vulnerabilities and Exposures_) sont une liste standardisée de vulnérabilités de sécurité publiquement divulguées dans les logiciels et les systèmes. Elle est maintenue par l'organisation MITRE et fournit un point de référence commun pour identifier et discuter des menaces de sécurité.

La gravité d'un CVE est généralement évaluée à l'aide du CVSS (_Common Vulnerability Scoring System_). Le CVSS fournit une méthode standardisée pour évaluer la gravité d'une vulnérabilité, en tenant compte de facteurs tels que l'impact potentiel d'une attaque, la facilité d'exploitation et la disponibilité de correctifs ou de techniques d'atténuation. Le score CVSS est représenté par une valeur numérique allant de 0 à 10 (10 = critique). Cela permet de prioriser la réponse aux vulnérabilités.

> Il est important de noter que le score CVSS n'est pas forcément objectif, et n'est qu'un des facteurs qui peuvent être pris en compte lors de l'évaluation de la gravité d'une vulnérabilité et de la planification d'une réponse.

Nous allons ici utiliser Python pour identifier les paquets et découvrir s'il existe une vulnérabilité connue dans la base de données CVE.

- Installer le paquet `debsecan` (_Debian-based_ seulement) : il permet de scanner les paquets installés et de vérifier s'ils sont vulnérables en se basant sur la base de données CVE.

- Utiliser le module `subprocess` dans un script (comme précédemment) pour exécuter la commande `debsecan` et récupérer la liste des CVE applicables au système.

- L'outil ne montre pas les scores CVSS ; rechercher une API Web d'informations CVE et modifier le script pour l'utiliser : récupérer les descriptions et scores CVSS des vulnérabilités identifiées et les afficher dans la sortie du script.

  - la récupération des données à partir de l'API peut être effectuée à l'aide du module `requests` de Python, qui permet d'envoyer des requêtes HTTP et de traiter les réponses.

  - les réponses seront sans doute au format JSON, il faudra donc utiliser le module `json` pour les analyser et extraire les informations pertinentes.

- Faites conclure le script en affichant une alerte pour les paquets qui ont des vulnérabilités avec un score CVSS supérieur à un seuil spécifié.
