# insurance-soc-lab — résumé en français

**Un SOC complet pour une compagnie d'assurance, en une commande** : SIEM Wazuh,
quatre machines supervisées, un simulateur qui attaque l'entreprise toutes les
quelques minutes, et 16 règles de détection sur mesure, chacune testée contre
le vrai moteur Wazuh à chaque commit.

> **Conçu dans et pour une vraie entreprise.** Ce projet a été conçu et déployé
> une première fois pendant mon stage de cybersécurité (2026) au sein de
> l'équipe sécurité SI d'une **grande compagnie d'assurance algérienne**, pour
> répondre à un vrai besoin : une prévention solide (NGFW, IPS, XDR,
> segmentation), mais aucune corrélation centralisée des événements de sécurité.
> Par confidentialité, cette version publique utilise un assureur fictif,
> **InsurCo**, et uniquement des données synthétiques.

## Ce qui est détecté

- Brute force SSH, puis connexion réussie depuis la même IP (compromission).
- Connexions en dehors des heures de bureau.
- Escalade de privilèges via sudo (shell root, modification de `/etc/shadow`).
- Attaques web : injection SQL, XSS, path traversal, recherche de fichiers sensibles, campagnes coordonnées.
- **Fraude interne** : lectures massives des tables clients / sinistres / paiements, répétées ou de nuit.
- Windows : devinette de mots de passe, création de comptes, ajout au groupe Administrateurs.

Toutes les règles sont mappées sur MITRE ATT&CK : voir [detection-catalog.md](detection-catalog.md).

## Démarrage rapide

```bash
make certs     # certificats TLS, une fois
make rotate    # OBLIGATOIRE : remplace les mots de passe publics par défaut de Wazuh
make up        # construit, démarre, attend que tout soit sain, rétention 30 jours, importe les dashboards
make status
```

Sous Windows PowerShell : `.\scripts\lab.ps1 certs | rotate | up | status`.

Dashboard : <https://localhost> (utilisateur `admin`, mot de passe `INDEXER_PASSWORD` du `.env`) ;
deux tableaux de bord, « InsurCo - SOC Overview » et « InsurCo - Insurer Security », sont importés
automatiquement ([dashboards.md](dashboards.md)). Couverture ATT&CK : [mitre-layer.json](mitre-layer.json).
Déclencher un scénario :
`docker compose exec simulator insurco-sim inject insider`.

## À propos de cette version publique

Avant publication, tout ce qui pouvait identifier l'entreprise a été retiré :
le nom de l'assureur (remplacé par l'assureur fictif **InsurCo**), les noms et
identifiants de ses employés, ses vraies adresses IP, noms de machines et
identifiants de connexion. Toutes les adresses viennent de la plage du lab
`10.20.0.0/16` ou des plages de documentation RFC 5737, et tous les logs sont
générés par le simulateur.
