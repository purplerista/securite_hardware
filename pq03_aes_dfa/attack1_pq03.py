"""Attaque 1 PQ03 : faute aléatoire sur 1 octet avant MixColumns de la ronde 9.

Dans cette variante, une faute injectée juste avant le MixColumns de la ronde 9
se propage seulement sur une colonne. Après la ronde finale, elle apparaît sur
4 octets du texte chiffré. On teste donc les 4 octets correspondants de K10 et on
intersecte les candidats jusqu'à obtenir une seule clé de ronde.
"""
import argparse
import random
from aes_core import INV_SBOX, encrypt_block, expand_key, inv_key_schedule, print_initial_data, Fault

# Après InvShiftRows du dernier tour, les 4 octets d'une colonne doivent suivre
# MixColumns([e,0,0,0]) ou MixColumns([0,e,0,0]) ... selon l'octet fauté.
def gf_mul(a,b):
    """Petit wrapper pour construire les motifs MixColumns attendus."""
    from aes_core import gmul
    return gmul(a,b)

# Motifs de différences possibles après MixColumns lorsqu'un seul octet e est
# fauté dans une colonne. Selon la position de l'octet fauté, on obtient une des
# quatre formes ci-dessous : (2e,e,e,3e), (3e,2e,e,e), etc.
PATTERNS = set()
for e in range(1,256):
    PATTERNS.add((gf_mul(2,e), e, e, gf_mul(3,e)))
    PATTERNS.add((gf_mul(3,e), gf_mul(2,e), e, e))
    PATTERNS.add((e, gf_mul(3,e), gf_mul(2,e), e))
    PATTERNS.add((e, e, gf_mul(3,e), gf_mul(2,e)))

# Positions du texte chiffré qui appartiennent à une même colonne avant le
# ShiftRows du dernier tour. Ces groupes sont attaqués indépendamment.
COL_CT_POS = [ [0,13,10,7], [4,1,14,11], [8,5,2,15], [12,9,6,3] ]

def sample_candidates(candidates, limit=6):
    """Affiche quelques candidats seulement pour éviter une sortie illisible."""
    data=sorted(candidates)[:limit]
    return '[' + ', '.join(''.join(f'{b:02x}' for b in x) for x in data) + (
        ', ...]' if len(candidates)>limit else ']'
    )

def impacted_positions(c:bytes, cf:bytes):
    """Liste les indices du texte chiffré modifiés par la faute."""
    return [i for i,(a,b) in enumerate(zip(c,cf)) if a!=b]

def candidates_for_column(c:bytes, cf:bytes, positions:list[int]):
    """Calcule les candidats de 4 octets de K10 pour une colonne.

    Pour chaque hypothèse de sous-clé, on inverse le dernier SubBytes :
        InvSbox(C_i xor k_i) xor InvSbox(C'_i xor k_i)
    La bonne hypothèse doit produire une différence appartenant aux motifs
    MixColumns pré-calculés dans PATTERNS.
    """
    cand=[]
    # 2^32 impossible ? En pratique on filtre par deux octets puis deux octets.
    # Version claire pour TP : brute force 4 octets avec pruning par motifs pré-calculés.
    pairs01={}
    for k0 in range(256):
      # On pré-calcule par paires pour éviter un bruteforce direct en 2^32.
      d0_cache=[INV_SBOX[c[positions[0]]^k0]^INV_SBOX[cf[positions[0]]^k0]]
      for k1 in range(256):
        d0=d0_cache[0]
        d1=INV_SBOX[c[positions[1]]^k1]^INV_SBOX[cf[positions[1]]^k1]
        pairs01.setdefault((d0,d1),[]).append((k0,k1))
    pairs23={}
    for k2 in range(256):
      for k3 in range(256):
        d2=INV_SBOX[c[positions[2]]^k2]^INV_SBOX[cf[positions[2]]^k2]
        d3=INV_SBOX[c[positions[3]]^k3]^INV_SBOX[cf[positions[3]]^k3]
        pairs23.setdefault((d2,d3),[]).append((k2,k3))
    for p in PATTERNS:
        # On recolle les deux demi-candidats lorsque les 4 différences forment
        # un motif PQ03 valide.
        for a in pairs01.get(p[:2],[]):
            for b in pairs23.get(p[2:],[]): cand.append(a+b)
    return set(cand)

def recover_k10_attack1(pt:bytes, key:bytes, max_faults=8, verbose=False):
    """Récupère K10 avec des fautes de ronde 9, puis laisse appeler InvKeySchedule."""
    c=encrypt_block(pt,key,verbose=verbose,trace_label='texte chiffré correct A1')
    if verbose:
        print('\n=== Attaque 1 PQ03 ===')
        print('Modèle de faute : 1 octet aléatoire avant MixColumns de la ronde 9')
        print(f'Texte chiffré correct : {c.hex()}')
    intersections=[None]*4
    used=0
    for i in range(max_faults):
        # Ici la faute est vraiment aléatoire : position et masque XOR changent
        # à chaque texte chiffré fauté.
        fault=Fault(round_no=9,byte_pos=random.randrange(16),value=random.randrange(1,256))
        if verbose:
            print(f'\n--- Faute A1 candidate {i+1} ---')
        cf=encrypt_block(
            pt,key,fault,
            verbose=verbose,
            trace_label=f'A1 faute {i+1} ronde 9 position {fault.byte_pos}'
        )
        if cf==c: continue
        used+=1
        impacted=impacted_positions(c,cf)
        if verbose:
            print(f'Texte chiffré fauté généré : {cf.hex()}')
            print(f'Octets impactés            : {impacted}')
        for col,pos in enumerate(COL_CT_POS):
            # Une faute avant MixColumns ronde 9 ne touche qu'une colonne.
            # Les autres colonnes ont une différence nulle : on ne les utilise pas.
            if all(c[j] == cf[j] for j in pos):
                if verbose:
                    print(f'Colonne {col}: aucune différence, colonne ignorée')
                continue
            cs=candidates_for_column(c,cf,pos)
            before=None if intersections[col] is None else len(intersections[col])
            # L'intersection conserve seulement les hypothèses compatibles avec
            # toutes les fautes observées jusque-là.
            intersections[col]=cs if intersections[col] is None else intersections[col]&cs
            if verbose:
                print(f'Colonne {col} positions {pos}')
                print(f'  Taille des candidats pour cette faute : {len(cs)} {sample_candidates(cs)}')
                print(f'  Réduction des candidats               : {before} -> {len(intersections[col])}')
        if verbose:
            print(f"[A1] faute {used}: tailles des ensembles de candidats = {[len(x or []) for x in intersections]}")
        if all(x is not None and len(x)==1 for x in intersections): break
    k10=[0]*16
    for col,pos in enumerate(COL_CT_POS):
        # Chaque colonne doit être réduite à un unique quadruplet de sous-clé.
        if not intersections[col] or len(intersections[col]) != 1:
            raise RuntimeError(
                f"colonne {col}: pas assez de fautes "
                f"({len(intersections[col] or [])} candidats restants)"
            )
        guess=next(iter(intersections[col]))
        for p,b in zip(pos,guess): k10[p]=b
    if verbose:
        print('\nRésultat Attaque 1')
        print(f'K10 retrouvé : {bytes(k10).hex()}')
        print(f'K10 réel     : {bytes(expand_key(key)[10]).hex()}')
        print(f'K0 retrouvé  : {inv_key_schedule(bytes(k10)).hex()}')
    return bytes(k10), used

if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Démo Attaque 1 PQ03 AES DFA')
    parser.add_argument('--verbose', action='store_true', help='affiche tout le déroulement AES et DFA')
    args=parser.parse_args()
    key=bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    pt=bytes.fromhex('00112233445566778899aabbccddeeff')
    if args.verbose:
        print_initial_data(pt,key)
    k10, n = recover_k10_attack1(pt,key,max_faults=40,verbose=args.verbose)
    print('K10 retrouvé :', k10.hex())
    print('K10 réel     :', bytes(expand_key(key)[10]).hex())
    print('K0 retrouvé  :', inv_key_schedule(k10).hex())
    print('K0 réel      :', key.hex())
    print('Textes fautés utilisés :', n)
