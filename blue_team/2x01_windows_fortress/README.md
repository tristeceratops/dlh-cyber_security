# PowerShell Active Directory Baseline Audit - Cheat Sheet

Script: `0-domain_baseline.ps1`

Objectif :
- Inventorier un domaine Active Directory
- Récupérer les utilisateurs, groupes, GPO, politiques de sécurité
- Identifier des mauvaises configurations de sécurité

---

# 1. Commandes Active Directory utilisées

## Module Active Directory

| Commande | Description | Utilisation / Arguments |
|---|---|---|
| `Import-Module ActiveDirectory` | Charge les commandes Active Directory | Aucun argument |
| `Import-Module GroupPolicy` | Charge les commandes GPO | Aucun argument |

---

# Domaine / Forêt / Contrôleurs

| Commande | Description | Utilisation / Arguments |
|---|---|---|
| `Get-ADDomain` | Retourne les informations du domaine courant | `Get-ADDomain` ou `Get-ADDomain -Identity domaine.local` |
| `Get-ADForest` | Retourne les informations de la forêt AD | `Get-ADForest` |
| `Get-ADDomainController` | Liste les contrôleurs de domaine | `Get-ADDomainController -Filter *` |

Exemples :

```powershell
$domain = Get-ADDomain

$domain.DNSRoot
$domain.DomainMode
````

Résultat :

```
meddefense.local
Windows2016Domain
```

---

# Utilisateurs Active Directory

| Commande      | Description                              | Utilisation / Arguments             |
| ------------- | ---------------------------------------- | ----------------------------------- |
| `Get-ADUser`  | Récupère un ou plusieurs utilisateurs AD | `Get-ADUser utilisateur`            |
| `-Filter`     | Filtre LDAP simplifié                    | `Get-ADUser -Filter *`              |
| `-Properties` | Ajoute des propriétés supplémentaires    | `-Properties Enabled,LastLogonDate` |

Exemples :

Tous les utilisateurs :

```powershell
Get-ADUser -Filter *
```

Utilisateur précis :

```powershell
Get-ADUser administrator
```

Avec propriétés :

```powershell
Get-ADUser administrator -Properties *
```

Propriétés utilisées dans le script :

| Propriété                       | Description                        |
| ------------------------------- | ---------------------------------- |
| `Enabled`                       | Compte activé/désactivé            |
| `LastLogonDate`                 | Dernière connexion                 |
| `PasswordLastSet`               | Dernier changement de mot de passe |
| `PasswordNeverExpires`          | Mot de passe qui n'expire jamais   |
| `Description`                   | Description du compte              |
| `TrustedForDelegation`          | Délégation Kerberos non contrainte |
| `msDS-SupportedEncryptionTypes` | Types de chiffrement Kerberos      |

---

# Groupes Active Directory

| Commande            | Description                   | Utilisation / Arguments             |
| ------------------- | ----------------------------- | ----------------------------------- |
| `Get-ADGroup`       | Liste les groupes AD          | `Get-ADGroup -Filter *`             |
| `Get-ADGroupMember` | Liste les membres d'un groupe | `Get-ADGroupMember "Domain Admins"` |

Exemple :

```powershell
Get-ADGroupMember "Domain Admins"
```

Retour :

```
Administrator
analyst
```

---

# GPO (Group Policy Object)

| Commande  | Description      | Utilisation / Arguments |
| --------- | ---------------- | ----------------------- |
| `Get-GPO` | Récupère les GPO | `Get-GPO -All`          |

Exemple :

```powershell
Get-GPO -All
```

Retour :

```
Default Domain Policy
Default Domain Controllers Policy
```

---

# Politique de mot de passe

| Commande                            | Description                                   | Utilisation / Arguments |
| ----------------------------------- | --------------------------------------------- | ----------------------- |
| `Get-ADDefaultDomainPasswordPolicy` | Récupère la politique de mot de passe domaine | Aucun argument          |

Exemple :

```powershell
$policy = Get-ADDefaultDomainPasswordPolicy
```

Propriétés :

| Propriété              | Description                              |
| ---------------------- | ---------------------------------------- |
| `MinPasswordLength`    | Taille minimale                          |
| `ComplexityEnabled`    | Complexité activée                       |
| `PasswordHistoryCount` | Nombre d'anciens mots de passe conservés |
| `MaxPasswordAge`       | Expiration maximale                      |
| `LockoutThreshold`     | Nombre d'essais avant verrouillage       |

---

# Kerberos

| Commande     | Description                           | Utilisation / Arguments                     |
| ------------ | ------------------------------------- | ------------------------------------------- |
| `Get-ADUser` | Permet de lire les attributs Kerberos | `-Properties msDS-SupportedEncryptionTypes` |

Exemple :

```powershell
Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes
```

Valeurs :

| Valeur | Chiffrement |
| ------ | ----------- |
| 1      | DES         |
| 2      | RC4         |
| 4      | AES128      |
| 8      | AES256      |

---

# 2. Concepts PowerShell utilisés

---

# Variables

## Syntaxe

```powershell
$name = "admin"
```

Contrairement à Bash :

```bash
name="admin"
```

Utilisation :

```powershell
$name
```

---

# Objets

PowerShell manipule des objets, pas du texte.

Exemple :

```powershell
$user = Get-ADUser administrator
```

Voir les propriétés :

```powershell
$user | Get-Member
```

Afficher tout :

```powershell
$user | Format-List *
```

Accès :

```powershell
$user.Name
$user.Enabled
```

---

# Pipeline

Le pipeline transmet des objets.

Exemple :

```powershell
Get-ADUser -Filter * | Where-Object {$_.Enabled}
```

Lecture :

```
Get users
    |
    v
Garder uniquement les comptes actifs
```

---

# Where-Object

Filtrer des objets.

Syntaxe :

```powershell
Where-Object { condition }
```

Exemple :

```powershell
Where-Object {$_.Enabled -eq $true}
```

Comparateurs :

| PowerShell | Signification |
| ---------- | ------------- |
| `-eq`      | égal          |
| `-ne`      | différent     |
| `-gt`      | supérieur     |
| `-lt`      | inférieur     |
| `-like`    | wildcard      |

Exemple :

```powershell
$name -like "*svc*"
```

---

# Select-Object

Choisir des propriétés.

Exemple :

```powershell
Get-ADUser -Filter * |
Select-Object Name,Enabled
```

Equivalent d'un :

```bash
cut
```

mais sur des objets.

---

# Boucle foreach

Syntaxe :

```powershell
foreach ($item in $list)
{
    action
}
```

Exemple :

```powershell
foreach ($user in $users)
{
    $user.Name
}
```

---

# Conditions

Syntaxe :

```powershell
if(condition)
{

}
else
{

}
```

Exemple :

```powershell
if($user.Enabled)
{
    "Active"
}
```

---

# Tableaux

Créer un tableau :

```powershell
$array = @()
```

Ajouter :

```powershell
$array += "value"
```

Compter :

```powershell
$array.Count
```

---

# PSCustomObject

Créer un objet personnalisé.

Exemple :

```powershell
[PSCustomObject]@{

    Name = "admin"
    Enabled = $true

}
```

Résultat :

```
Name     Enabled
----     -------
admin    True
```

Très utilisé pour créer des rapports.

---

# Group-Object

Regrouper des objets.

Exemple :

```powershell
$findings | Group-Object Severity
```

Résultat :

```
Count Name
----- ----
3     Critical
5     High
2     Medium
```

---

# Fonctions

Créer une commande personnalisée :

```powershell
function Get-Test {

    Write-Host "test"

}
```

Exécution :

```powershell
Get-Test
```

---

# Return

Retourner une valeur :

```powershell
return $object
```

ou implicitement :

```powershell
$object
```

Exemple :

```powershell
function Get-Name {

    $domain = Get-ADDomain

    $domain.DNSRoot

}
```

---

# 3. Comparaison Bash vs PowerShell

| Concept          | Bash              | PowerShell                    |
| ---------------- | ----------------- | ----------------------------- |
| Shell            | Bash              | PowerShell                    |
| Variables        | `$var`            | `$var`                        |
| Export variable  | `export VAR=x`    | `$env:VAR="x"`                |
| Afficher         | `echo`            | `Write-Host` / `Write-Output` |
| Liste fichiers   | `ls`              | `Get-ChildItem`               |
| Processus        | `ps`              | `Get-Process`                 |
| Services         | `systemctl`       | `Get-Service`                 |
| Lire fichier     | `cat`             | `Get-Content`                 |
| Supprimer        | `rm`              | `Remove-Item`                 |
| Copier           | `cp`              | `Copy-Item`                   |
| Déplacer         | `mv`              | `Move-Item`                   |
| Recherche texte  | `grep`            | `Select-String`               |
| Filtrer          | `grep/awk`        | `Where-Object`                |
| Extraire colonne | `awk`             | `Select-Object`               |
| Boucle           | `for x in`        | `foreach ($x in)`             |
| Fonction         | `function name()` | `function Name {}`            |
| Pipeline         | texte             | objets                        |

---

# 4. Commandes PowerShell utiles pour apprendre

## Découvrir une commande

```powershell
Get-Command
```

Exemple :

```powershell
Get-Command Get-AD*
```

---

## Voir l'aide

```powershell
Get-Help Command
```

Exemple :

```powershell
Get-Help Get-ADUser -Examples
```

---

## Voir les propriétés d'un objet

```powershell
object | Get-Member
```

Exemple :

```powershell
Get-ADUser admin | Get-Member
```

---

## Voir tout un objet

```powershell
object | Format-List *
```

Exemple :

```powershell
Get-ADUser admin -Properties * | Format-List *
```

---

# 5. Workflow PowerShell pour l'AD

Toujours suivre cette méthode :

```
1. Trouver la commande
        |
        v
Get-Command

2. Voir l'aide
        |
        v
Get-Help

3. Exécuter
        |
        v
Get-ADUser

4. Explorer l'objet
        |
        v
Get-Member

5. Filtrer
        |
        v
Where-Object

6. Formater le résultat
        |
        v
Select-Object
```

---

# Résumé

Le script repose principalement sur :

* `Get-AD*` → récupérer les objets Active Directory
* `Where-Object` → filtrer
* `Select-Object` → sélectionner les propriétés
* `foreach` → parcourir
* `[PSCustomObject]` → créer un rapport
* `Group-Object` → faire des statistiques

La différence majeure avec Bash :

**Bash manipule du texte.
PowerShell manipule des objets.**