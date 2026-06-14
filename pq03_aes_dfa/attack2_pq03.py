"""Attaque 2 PQ03 : faute aléatoire sur 1 octet avant MixColumns de la ronde 8.

La faute est injectée une ronde plus tôt que dans l'attaque 1. Elle traverse
donc la ronde 9 complète et se diffuse sur les 16 octets du texte chiffré. En
contrepartie, chaque texte chiffré fauté donne de l'information sur les 4 colonnes
de K10 à la fois.
"""
import argparse
import random
from aes_core import encrypt_block, expand_key, inv_key_schedule, print_initial_data, Fault
from attack1_pq03 import COL_CT_POS, candidates_for_column, impacted_positions, sample_candidates
import time

def collect_round8_faults(pt:bytes, key:bytes, n:int=40):
    """Génère quelques textes chiffrés fautés ronde 8 pour mesurer la diffusion."""
    c=encrypt_block(pt,key)
    out=[]
    for _ in range(n):
        cf=encrypt_block(pt,key,Fault(round_no=8))
        if cf!=c:
            out.append(cf)
    return c,out

def recover_k10_attack2(pt:bytes, key:bytes, max_faults=8, verbose=False):
    """Retrouve K10 avec des fautes injectées avant MixColumns de la ronde 8.

    Une faute ronde 8 traverse la ronde 9 et se diffuse sur les 16 octets du
    chiffré. Après inversion du dernier tour avec la bonne hypothèse de K10,
    chaque colonne vérifie une relation MixColumns([e,0,0,0]) à un octet près.
    On applique donc le filtre PQ03 sur les 4 colonnes pour chaque faute.
    """
    c=encrypt_block(pt,key,verbose=verbose,trace_label='texte chiffré correct A2')
    if verbose:
        print('\n=== Attaque 2 PQ03 ===')
        print('Modèle de faute : 1 octet aléatoire avant MixColumns de la ronde 8')
        print('La faute traverse ensuite la ronde 9 et se propage sur les 4 colonnes.')
        print(f'Texte chiffré correct : {c.hex()}')
    intersections=[None]*4
    used=0
    for i in range(max_faults):
        # Comme dans le modèle PQ03, l'attaquant ne choisit pas forcément la
        # valeur de faute : on tire une position et un masque XOR aléatoires.
        fault=Fault(round_no=8,byte_pos=random.randrange(16),value=random.randrange(1,256))
        if verbose:
            print(f'\n--- Faute A2 candidate {i+1} ---')
        cf=encrypt_block(
            pt,key,fault,
            verbose=verbose,
            trace_label=f'A2 faute {i+1} ronde 8 position {fault.byte_pos}'
        )
        if cf==c:
            continue
        used+=1
        impacted=impacted_positions(c,cf)
        if verbose:
            print(f'Texte chiffré fauté généré : {cf.hex()}')
            print(f'Octets impactés            : {impacted}')
            print('Propagation            : une faute ronde 8 impacte les 16 octets après la ronde 9')
        for col,pos in enumerate(COL_CT_POS):
            # Contrairement à l'attaque 1, on filtre les 4 colonnes pour chaque
            # faute, car la diffusion ronde 9 touche tout l'état.
            cs=candidates_for_column(c,cf,pos)
            before=None if intersections[col] is None else len(intersections[col])
            # L'intersection réalise le filtrage progressif : chaque nouveau
            # texte chiffré fauté élimine les hypothèses incompatibles.
            intersections[col]=cs if intersections[col] is None else intersections[col]&cs
            if verbose:
                print(f'Colonne {col} positions {pos}')
                print(f'  Taille des candidats pour cette faute : {len(cs)} {sample_candidates(cs)}')
                print(f'  Filtrage progressif                   : {before} -> {len(intersections[col])}')
        if verbose:
            print(f"[A2] faute {used}: tailles des ensembles de candidats = {[len(x or []) for x in intersections]}")
        if all(x is not None and len(x)==1 for x in intersections):
            break
    k10=[0]*16
    for col,pos in enumerate(COL_CT_POS):
        # Quand les quatre colonnes ont un seul candidat, les 16 octets de K10
        # sont connus et on peut revenir à K0 avec InvKeySchedule.
        if not intersections[col] or len(intersections[col]) != 1:
            raise RuntimeError(
                f"colonne {col}: pas assez de fautes "
                f"({len(intersections[col] or [])} candidats restants)"
            )
        guess=next(iter(intersections[col]))
        for p,b in zip(pos,guess):
            k10[p]=b
    if verbose:
        print('\nRésultat Attaque 2')
        print(f'K10 retrouvé : {bytes(k10).hex()}')
        print(f'K10 réel     : {bytes(expand_key(key)[10]).hex()}')
        print(f'K0 retrouvé  : {inv_key_schedule(bytes(k10)).hex()}')
    return bytes(k10), used

def demo_attack2(pt:bytes, key:bytes, n_faults:int=40):
    """Exécute l'attaque 2 et renvoie les mesures utiles au comparatif."""
    t0=time.perf_counter()
    k10, used = recover_k10_attack2(pt,key,max_faults=n_faults,verbose=False)
    # On génère le même nombre de fautes pour estimer le nombre d'octets du
    # texte chiffré impactés. En pratique, pour la ronde 8, c'est généralement 16.
    c, faults=collect_round8_faults(pt,key,used)
    diffusion=[sum(a!=b for a,b in zip(c,cf)) for cf in faults]
    return {
        'round8_faulted_ciphertexts': used,
        'avg_impacted_ciphertext_bytes': sum(diffusion)/len(diffusion),
        'min_impacted_ciphertext_bytes': min(diffusion),
        'max_impacted_ciphertext_bytes': max(diffusion),
        'k10_recovered': k10.hex(),
        'k10_real': bytes(expand_key(key)[10]).hex(),
        'k0_from_invkeyschedule': inv_key_schedule(k10).hex(),
        'seconds': time.perf_counter()-t0,
    }

if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Démo Attaque 2 PQ03 AES DFA')
    parser.add_argument('--verbose', action='store_true', help='affiche tout le déroulement AES et DFA')
    args=parser.parse_args()
    key=bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
    pt=bytes.fromhex('00112233445566778899aabbccddeeff')
    if args.verbose:
        print_initial_data(pt,key)
        k10,n=recover_k10_attack2(pt,key,max_faults=40,verbose=True)
        print('K10 retrouvé :', k10.hex())
        print('K10 réel     :', bytes(expand_key(key)[10]).hex())
        print('K0 retrouvé  :', inv_key_schedule(k10).hex())
        print('K0 réel      :', key.hex())
        print('Textes fautés utilisés :', n)
    else:
        r=demo_attack2(pt,key,40)
        print('Textes fautés utilisés          :', r['round8_faulted_ciphertexts'])
        print('Octets impactés min/moy/max     :', r['min_impacted_ciphertext_bytes'], '%.2f'%r['avg_impacted_ciphertext_bytes'], r['max_impacted_ciphertext_bytes'])
        print('K10 retrouvé                    :', r['k10_recovered'])
        print('K10 réel                        :', r['k10_real'])
        print('K0 retrouvé avec InvKeySchedule :', r['k0_from_invkeyschedule'])
        print('Temps                           : %.3fs'%r['seconds'])
