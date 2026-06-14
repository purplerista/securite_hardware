# Projet AES DFA — Piret/Quisquater [PQ03]

Objectif : implémenter en Python une AES-128 instrumentée pour injecter des fautes et démontrer deux variantes de l'attaque DFA de Piret/Quisquater.

## Fichier du cours identifié dans l'archive

Je n'ai pu lister que le contenu de `Securite_Hardware.rar` car l'environnement ne dispose pas d'extracteur RAR. Les fichiers présents sont notamment :

- `Securite_Hardware/Sécurité Hardware.pdf` : fichier le plus probable pour les slides du professeur ;
- `Securite_Hardware/Basics_In_Fault_Attacks.pdf` : support général sur les attaques en faute ;
- `Securite_Hardware/Challenge_DFA.pdf` et `DFA_test/challenge_DFA.py` : challenge/demo DFA déjà fourni.

Le sujet mentionne PQ03, Giraud et Dusart/Vivolo : cela correspond très probablement aux slides `Sécurité Hardware.pdf` ou au support `Basics_In_Fault_Attacks.pdf`.

## Contenu

- `aes_core.py` : AES-128 pur Python, KeySchedule, InvKeySchedule, injection de faute avant MixColumns ronde 8 ou 9.
- `attack1_pq03.py` : attaque 1 fonctionnelle : faute aléatoire dans un octet avant MixColumns de la ronde 9. Récupère `K10`, puis `K0` via `InvKeySchedule`.
- `attack2_pq03.py` : attaque 2 fonctionnelle : faute aléatoire dans un octet avant MixColumns de la ronde 8. Récupère `K10`, puis `K0` via `InvKeySchedule`.
- `comparatif.py` : comparaison nombre de textes fautés / complexité / temps observé.
- `demo_verbose.py` : démonstration complète pour l'oral avec traces AES, injection de fautes, candidats et tableau final.

## Lancer

```bash
cd pq03_aes_dfa
python3 attack1_pq03.py
python3 attack2_pq03.py
python3 comparatif.py
```

Mode verbose :

```bash
python3 attack1_pq03.py --verbose
python3 attack2_pq03.py --verbose
python3 comparatif.py --verbose
python3 demo_verbose.py
```

Sans `--verbose`, les scripts gardent une sortie courte. Avec `--verbose`,
ils affichent les données initiales, les états AES ronde par ronde, les fautes
injectées, les textes chiffrés fautés, les candidats PQ03 et la récupération de
`K10` puis `K0`.

## Résultat attendu pour le vecteur de test

Clé AES-128 :

```text
K0 = 2b7e151628aed2a6abf7158809cf4f3c
K10 = d014f9a8c9ee2589e13f0cc8b6630ca6
```

Les deux attaques retrouvent normalement `K10`, puis `K0`.

## Comparatif synthétique

| Variante | Position faute | Effet | Textes fautés typiques | Complexité |
|---|---|---|---:|---|
| Attaque 1 | 1 octet avant MixColumns ronde 9 | 4 octets impactés après la dernière ronde | ~8 à 20 selon hasard | Faible : filtrage seulement sur la colonne touchée |
| Attaque 2 | 1 octet avant MixColumns ronde 8 | diffusion sur les 16 octets | ~2 à 6 selon hasard | Plus coûteuse par texte fauté : filtrage des 4 colonnes à chaque faute |

## Principe de l'attaque 2

Une faute injectée avant le MixColumns de la ronde 8 produit une différence sur une colonne après ce MixColumns. À la ronde 9, les quatre octets fautés passent dans `SubBytes`, puis `ShiftRows` les répartit sur quatre colonnes différentes. Après le `MixColumns` de la ronde 9, les quatre colonnes du dernier état fauté vérifient chacune une relation de type `MixColumns([e,0,0,0])`, à permutation près. Le code inverse donc le dernier tour sous hypothèse de `K10`, applique le filtre PQ03 sur les quatre colonnes, puis intersecte les candidats jusqu'à obtenir un seul `K10`.
