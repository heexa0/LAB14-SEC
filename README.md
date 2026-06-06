# LAB14-SEC
# Bypass Complet de Détection de Root Android
## Frida · Objection · Medusa · Magisk

**ÉCOLE NATIONALE DES SCIENCES APPLIQUÉES DE MARRAKECH — ENSA Marrakech**

| | |
|---|---|
| **Réalisé par** | Chaoulid Hafssa |
| **Filière** | Génie GCDSTE / Sécurité |
| **Établissement** | ENSA Marrakech |
| **Année universitaire** | 2025 – 2026 |

> Rapport de Travaux Pratiques — Module : Cybersécurité / SOC & Analyse Mobile

---

## Prérequis

| Composant | Détail |
|---|---|
| **Système** | PC Windows / macOS / Linux avec droits admin/sudo |
| **Python** | Python 3.8+ et pip |
| **ADB** | Android Platform Tools → [télécharger ici](https://developer.android.com/tools/releases/platform-tools) |
| **Appareil Android** | Android 8.0+ avec *Options développeur* + *Débogage USB* activés |
| **Frida** | Côté PC et `frida-server` côté appareil — versions **strictement** alignées |
| **APK cible** | Application faisant une root detection (ex : RootBeer Sample, DevAdvance RootChecker) |

### Vérifications rapides

```bash
python --version
pip --version
adb devices
frida --version
```

---

## Étape 1 — Installer Frida côté PC

```bash
pip install --upgrade frida frida-tools
frida --version
python -c "import frida; print(frida.__version__)"
```

---

## Étape 2 — Démarrer `frida-server` sur l'appareil

> **Indispensable pour Frida, Objection et Medusa.**

### 2.1 Identifier l'architecture CPU

```bash
adb shell getprop ro.product.cpu.abi
```

| Valeur | Appareils concernés |
|---|---|
| `arm64-v8a` | Téléphones récents (64-bit) |
| `armeabi-v7a` | Téléphones anciens (32-bit) |
| `x86_64` | Émulateurs |

### 2.2 Télécharger `frida-server`

Rendez-vous sur [https://github.com/frida/frida/releases](https://github.com/frida/frida/releases) et téléchargez :

```
frida-server-<même_version_que_frida_PC>-android-<arch>.xz
```

Décompression :

```bash
# macOS / Linux
tar xf frida-server-*.xz

# Windows : utiliser 7-Zip → clic droit > Extraire ici
```

> **Règle d'or :** `frida --version` (PC) doit être **identique** à la version du binaire téléchargé.

### 2.3 Pousser et lancer `frida-server`

```bash
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server

# Mode interactif (bloque le terminal)
adb shell "/data/local/tmp/frida-server -l 0.0.0.0"

# Mode arrière-plan (recommandé)
adb shell "nohup /data/local/tmp/frida-server -l 0.0.0.0 >/dev/null 2>&1 &"
```

### 2.4 Redirection de ports (si nécessaire)

```bash
adb forward tcp:27042 tcp:27042
adb forward tcp:27043 tcp:27043
```

### 2.5 Validation

```bash
frida-ps -Uai
```

> **Attendu :** une liste des applications installées sur l'appareil. Si vide → voir [Dépannage](#étape-8--dépannage-complet).

---

## Étape 3 — Comprendre Frida en 10 minutes

### Vocabulaire clé

| Flag / Terme | Signification |
|---|---|
| `-U` | Cible un appareil USB |
| `-f <package>` | **Spawn** : Frida démarre l'app et injecte au tout début |
| `-n <ProcessName>` | **Attach** : s'attache à un processus déjà lancé |
| `--no-pause` | Ne pas mettre en pause l'app après injection |
| `Java.perform(fn)` | Attendre que la VM Java soit prête pour installer les hooks |
| `Java.use('classe')` | Charger une classe Java pour la hooker |
| `implementation` | Remplacer le corps d'une méthode |
| `overload('sig')` | Cibler une surcharge précise d'une méthode |

### Test minimal — `hello.js`

Créez un fichier `hello.js` :

```javascript
Java.perform(function () {
  console.log("[+] Script injecté : Java.perform OK");
});
```

Exécution :

```bash
frida -U -f com.example.rootcheck -l hello.js --no-pause
```

> **Attendu :** l'app démarre et vous voyez `[+] Script injecté : Java.perform OK` dans le terminal.

### Spawn vs Attach

```bash
# Spawn : Frida démarre l'app (vérifications tôt dans le cycle de vie)
frida -U -f com.example.rootcheck -l monscript.js --no-pause

# Attach : l'app est déjà ouverte, on s'y attache
frida -U -n "NomDuProcessus" -l monscript.js
```

> Si l'app crashe en mode spawn, ouvrez-la d'abord manuellement puis utilisez `-n`.

---

## Étape 4 — Bypass Java avec Frida (bypass_root_basic.js)

### Les 4 vecteurs de détection Java ciblés

| Vecteur | Mécanisme | Action du hook |
|---|---|---|
| `android.os.Build.TAGS` | Retourne `test-keys` si rooté | Forcer `release-keys` |
| `java.io.File.exists()` | Retourne `true` pour `/system/xbin/su`, etc. | Retourner `false` pour les chemins suspects |
| `Runtime.getRuntime().exec()` | Tente d'exécuter `su` | Bloquer et remplacer par `echo` |
| `RootBeer.isRooted()` | Bibliothèque tierce de détection combinée | Forcer `false` |

### Script complet — `bypass_root_basic.js`

```javascript
// Hooks Java pour neutraliser les checks de root les plus courants
const suspiciousPaths = [
  "/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/su",
  "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
  "/system/bin/busybox", "/system/xbin/busybox"
];

function lc(s) { try { return ("" + s).toLowerCase(); } catch (_) { return ""; } }

Java.perform(function () {

  // 1) Build.TAGS → retourner une valeur propre
  try {
    const Build = Java.use('android.os.Build');
    Object.defineProperty(Build, 'TAGS', {
      get: function () { return 'release-keys'; }
    });
    console.log('[+] Build.TAGS -> release-keys');
  } catch (e) { console.log('[-] Build.TAGS hook failed:', e); }

  // 2) RootBeer (si présent dans l'app)
  try {
    const RB = Java.use('com.scottyab.rootbeer.RootBeer');
    RB.isRooted.implementation = function () {
      console.log('[+] RootBeer.isRooted -> false');
      return false;
    };
    if (RB.isRootedWithBusyBoxCheck)
      RB.isRootedWithBusyBoxCheck.implementation = function () {
        console.log('[+] RootBeer.isRootedWithBusyBoxCheck -> false');
        return false;
      };
  } catch (e) { console.log('[*] RootBeer non présent ou déjà neutralisé'); }

  // 3) File.exists() → refuser les chemins suspects
  try {
    const File = Java.use('java.io.File');
    File.exists.implementation = function () {
      const p = this.getAbsolutePath();
      if (suspiciousPaths.indexOf(p) !== -1) {
        console.log('[+] File.exists bypass:', p);
        return false;
      }
      return this.exists.call(this);
    };
  } catch (e) { console.log('[-] File.exists hook failed:', e); }

  // 4) Runtime.exec → bloquer su / which su / busybox
  try {
    const Runtime = Java.use('java.lang.Runtime');
    const JString  = Java.use('java.lang.String');
    const StringArray = Java.use('[Ljava.lang.String;');

    function suspicious(cmd) {
      const s = lc(Array.isArray(cmd) ? cmd.join(' ') : cmd);
      return s.startsWith('su') || s.includes(' which su') ||
             s.includes(' busybox') || s.includes(' su ');
    }

    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
      if (suspicious(cmd)) {
        console.log('[+] Blocked Runtime.exec:', cmd);
        return this.exec(JString.$new('echo'));
      }
      return this.exec(cmd);
    };
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function (arr) {
      const js = arr ? Array.from(arr) : [];
      if (suspicious(js)) {
        console.log('[+] Blocked Runtime.exec:', js.join(' '));
        const repl = StringArray.$new(1);
        repl[0] = JString.$new('echo');
        return this.exec(repl);
      }
      return this.exec(arr);
    };
    Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;').implementation = function (cmd, env) {
      if (suspicious(cmd)) {
        console.log('[+] Blocked Runtime.exec:', cmd);
        return this.exec(JString.$new('echo'), env);
      }
      return this.exec(cmd, env);
    };
    Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;').implementation = function (arr, env) {
      const js = arr ? Array.from(arr) : [];
      if (suspicious(js)) {
        console.log('[+] Blocked Runtime.exec:', js.join(' '));
        const repl = StringArray.$new(1);
        repl[0] = JString.$new('echo');
        return this.exec(repl, env);
      }
      return this.exec(arr, env);
    };

    console.log('[+] Runtime.exec hooks installés');
  } catch (e) { console.log('[-] Runtime.exec hooks failed:', e); }

  console.log('[+] Bypass Java installé avec succès');
});
```

### Exécution

```bash
frida -U -f com.example.rootcheck -l bypass_root_basic.js --no-pause
```

> **Attendu :** logs `[+]` dans le terminal, l'app ne détecte plus le root pour les checks Java.

---

## Étape 4.1 — Bypass Natif avec Frida (bypass_native.js)

Certaines applications effectuent leurs vérifications en **C/C++** en appelant directement la `libc` (`open`, `stat`, `access`…). Ces appels échappent aux hooks Java.

### Script — `bypass_native.js`

```javascript
// Bloquer les appels libc vers des chemins suspects
const SUS = [
  '/system/bin/su', '/system/xbin/su', '/sbin/su', '/system/su',
  '/system/bin/busybox', '/system/xbin/busybox'
];

function isSus(ptrPath) {
  try {
    const p = ptrPath.readCString();
    return !!p && (
      SUS.indexOf(p) !== -1 ||
      p.includes('/proc/mounts') ||
      p.includes('/proc/self/mounts')
    );
  } catch (_) { return false; }
}

function hookLibc(name, pathArgIndex) {
  const addr = Module.findExportByName('libc.so', name) ||
               Module.findExportByName(null, name);
  if (!addr) { console.log('[*] Export introuvable:', name); return; }

  Interceptor.attach(addr, {
    onEnter(args) {
      const pArg = pathArgIndex >= 0 ? args[pathArgIndex] : null;
      if (pArg && isSus(pArg)) {
        this.block = true;
        this.path  = pArg.readCString();
      }
    },
    onLeave(retval) {
      if (this.block) {
        console.log('[+] Blocked', name, 'on', this.path);
        retval.replace(ptr(-1));
      }
    }
  });
  console.log('[+] Hooked', name);
}

hookLibc('open',   0);
hookLibc('openat', 1);
hookLibc('access', 0);
hookLibc('stat',   0);
hookLibc('lstat',  0);
```

### Exécution combinée (Java + Natif)

```bash
frida -U -f com.example.rootcheck -l bypass_root_basic.js -l bypass_native.js --no-pause
```

### Découverte des chemins avec `frida-trace`

Avant d'écrire vos hooks, identifiez les chemins réellement consultés par l'app :

```bash
frida-trace -U -i open -i access -i stat -i openat -i fopen -i readlink com.example.rootcheck
```

Analysez les logs pour adapter la liste `SUS` à votre cible.

---

## Étape 5 — Bypass avec Objection (approche simplifiée)

Objection est une surcouche à Frida qui propose des commandes prêtes à l'emploi, sans écrire de scripts manuellement.

### Installation

```bash
# Méthode recommandée (isolation via pipx)
pip install --user pipx
pipx ensurepath
pipx install objection

# Ou via pip classique
pip install --upgrade objection

# Vérification
objection --version
```

### Lancement — Mode Spawn (recommandé)

```bash
objection -g com.example.rootcheck explore --startup-command "android root disable"
```

### Lancement — Mode Attach

```bash
# Ouvrez l'app d'abord, puis :
objection -g com.example.rootcheck explore

# Dans la console Objection :
android root disable
```

### Commandes utiles dans la console Objection

```bash
android root disable                                              # bypass root Java
android sslpinning disable                                        # bypass SSL pinning
android hooking search classes root                              # chercher des classes "root"
android hooking search methods isRoot                            # chercher des méthodes "isRoot"
android hooking watch class com.example.RootCheck                # observer une classe
android hooking set return_value com.example.RootCheck isRooted false   # forcer retour false
help android root                                                # aide sur les commandes root
help android hooking                                             # aide sur le hooking
```

### Plusieurs commandes au démarrage

```bash
objection -g com.example.rootcheck explore \
  --startup-command "android root disable" \
  --startup-command "android sslpinning disable" \
  --startup-command "android hooking search classes root"
```

---

## Étape 6 — Bypass avec Medusa

Medusa est un framework basé sur Frida qui propose des modules de bypass prêts à l'emploi via une CLI unifiée.

### Installation

```bash
git clone <URL_du_depot_Medusa>
cd Medusa
pip install -r requirements.txt
python medusa.py --help
```

### Exécution

```bash
# Mode Spawn
python medusa.py --usb --spawn com.example.rootcheck --module root-bypass

# Mode Attach
medusa --usb --attach "NomDuProcessus" --module root-bypass
```

> En cas d'échec avec Medusa, repassez en Frida pur (Étapes 4 & 4.1).

---

## Étape 7 — Quand Préférer Magisk

| Situation | Solution recommandée |
|---|---|
| Checks Java purs | Frida / Objection (Étapes 4 & 5) |
| Checks natifs C/C++ | Frida natif (Étape 4.1) |
| Détection Play Integrity / SafetyNet | **Magisk** |
| Propriétés système profondes | **Magisk** |
| Masquage global pour plusieurs apps | **Magisk** |

### Étapes résumées Magisk

1. Rooter avec Magisk (boot patché), activer **Zygisk**.
2. Configurer **DenyList** — inclure l'app cible + Play Services + Play Store.
3. Modules utiles : *Play Integrity Fix*, *MagiskHide Props Config*, *Shamiko*.
4. Nettoyer les données Play Store/Services → redémarrer → tester.

> **Limite :** la *Strong Integrity* (vérification matérielle) n'est généralement pas contournable sans vulnérabilité spécifique.

---

## Étape 8 — Dépannage Complet

| Problème | Cause probable | Solution |
|---|---|---|
| `frida: command not found` | PATH mal configuré | `pip install --upgrade frida frida-tools` ; ajouter Scripts Python au PATH |
| `objection: command not found` | PATH mal configuré | `pipx install objection` ; ajouter Scripts Python au PATH |
| `unable to connect to remote frida-server` | Serveur arrêté ou versions différentes | `adb shell ps \| grep frida` ; aligner versions ; `adb forward tcp:27042 tcp:27042` |
| L'app crashe à l'injection | Hook trop précoce ou bug | Utiliser `-n` (attach) ; injecter `hello.js` seul d'abord ; ajouter les hooks un à un |
| L'app détecte encore le root | Checks natifs non couverts | Ajouter `bypass_native.js` ; essayer mode Attach ; hooker la méthode Java passerelle |
| L'app détecte Frida lui-même | Anti-instrumentation présente | Passer en Attach (`-n`) ; réduire les logs ; ajouter un script anti-Frida |
| Noms de classes obfusqués | Obfuscation ProGuard/R8 | Énumérer les classes chargées (voir ci-dessous) |
| Permissions refusées sur processus système | Appareil non rooté | Hooker uniquement les apps utilisateur |

### Identifier les classes obfusquées

```javascript
Java.perform(function () {
  Java.enumerateLoadedClasses({
    onMatch: function (name) {
      if (name.toLowerCase().includes('root')) console.log(name);
    },
    onComplete: function () { console.log('[+] Énumération terminée'); }
  });
});
```

### Script anti-Frida basique

```javascript
Java.perform(function () {
  try {
    const Sys = Java.use('java.lang.System');
    Sys.getenv.overload('java.lang.String').implementation = function (name) {
      if (name && name.toLowerCase().includes('frida')) {
        console.log('[+] Hide env:', name);
        return null;
      }
      return this.getenv(name);
    };
  } catch (e) {}
});
```

---

## Étape 9 — Check-list Rapide

- [ ] `python` et `pip` OK ; version Frida notée
- [ ] `adb devices` → appareil en statut `device`
- [ ] `frida-server` lancé ; `frida-ps -Uai` liste des apps
- [ ] `hello.js` s'injecte sans erreur
- [ ] `bypass_root_basic.js` neutralise les checks Java
- [ ] Si checks natifs : `bypass_native.js` neutralise les appels `libc`
- [ ] Option Objection : `android root disable` fonctionne sur l'app cible
- [ ] Option Medusa : module `root-bypass` injecté et logs visibles
- [ ] Option Magisk : Zygisk + DenyList configurés si masquage système requis

---

## Exercices à Rendre

### Exercice 1 — Preuve d'installation et connexion *(20 pts)*

```bash
objection --version
frida --version
adb devices
```

**Attendu :** captures d'écran ou texte de console.

---

### Exercice 2 — Démarrage et visibilité *(20 pts)*

1. Lancer `frida-server` sur l'appareil.
2. Lancer Objection en `explore` sur le package cible.
3. Atteindre l'invite :

```
com.example.rootcheck on (Android: X.X) [usb] #
```

**Attendu :** capture de la console Objection active.

---

### Exercice 3 — Bypass Java avec Objection *(40 pts)*

1. Capture **avant** : message « Root detected » ou blocage.
2. Exécuter `android root disable`.
3. Capture **après** : l'app fonctionne normalement.
4. Logs Objection montrant les hooks activés.

**Attendu :** comparatif avant/après + logs console.

---

### Exercice 4 (Bonus) — Bypass natif *(20 pts)*

1. Utiliser `frida-trace` pour identifier un appel natif sur un chemin suspect.
2. Montrer un hook (`bypass_native.js` ou retour forcé au niveau Java) qui neutralise la détection.

**Attendu :** sortie `frida-trace` + hook fonctionnel documenté.

---

## Conclusion

Ce lab couvre l'ensemble de la chaîne de bypass de détection de root Android, des hooks Java les plus simples jusqu'aux vérifications natives C/C++, en passant par les outils d'automatisation Objection et Medusa.

La leçon fondamentale : **aucune vérification exécutée côté client ne peut être considérée comme fiable**. Dès lors qu'un attaquant contrôle l'environnement d'exécution, il peut intercepter, falsifier ou supprimer n'importe quelle réponse. La sécurité réelle repose sur la validation côté serveur, la cryptographie et une architecture de confiance zéro.

Les compétences acquises ici — chaîne ADB/Frida, écriture de hooks Java et natifs, utilisation d'Objection, analyse avec `frida-trace` — sont directement applicables dans des missions d'audit de sécurité mobile professionnelles.
