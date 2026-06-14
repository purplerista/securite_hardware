"""Démo verbose complète du projet AES DFA Piret/Quisquater.

Ce script est pensé pour l'oral : il affiche d'abord les données initiales,
puis déroule les deux attaques en montrant les fautes, la propagation, les
candidats de sous-clé et la reconstruction de K0 par InvKeySchedule.
"""
import random
import time

from aes_core import print_initial_data, inv_key_schedule
from attack1_pq03 import recover_k10_attack1
from attack2_pq03 import recover_k10_attack2

KEY=bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
PT=bytes.fromhex('00112233445566778899aabbccddeeff')
TESTS_PAR_COLONNE=2*256*256

def print_final_table(rows):
    """Affiche une synthèse compacte après les traces détaillées."""
    print('\n=== Comparatif final ===')
    print('| Attaque | Ronde ciblée | Textes fautés | Colonnes/faute | Tests approx./faute | Temps (s) | Clé retrouvée |')
    print('|---|---:|---:|---:|---:|---:|---|')
    for row in rows:
        print(
            f'| {row["attack"]} | {row["round"]} | {row["faults"]} | '
            f'{row["columns"]} | {row["tests"]} | {row["seconds"]:.3f} | {row["ok"]} |'
        )

def main():
    # Graine fixe : le scenario verbose reste stable pour une presentation.
    random.seed(2026)

    # Première partie de l'oral : données de départ et round keys AES.
    print_initial_data(PT,KEY)

    rows=[]

    # Deuxième partie : Attaque 1. Le verbose montre les fautes ronde 9, les
    # colonnes touchées et la réduction des candidats de K10.
    t0=time.perf_counter()
    k10_a1,n1=recover_k10_attack1(PT,KEY,max_faults=40,verbose=True)
    t1=time.perf_counter()-t0
    rows.append({
        'attack':'Attaque 1',
        'round':9,
        'faults':n1,
        'columns':1,
        'tests':TESTS_PAR_COLONNE,
        'seconds':t1,
        'ok':'oui' if inv_key_schedule(k10_a1)==KEY else 'non',
    })

    # Troisième partie : Attaque 2. Le verbose met en évidence la diffusion sur
    # les 16 octets et le filtrage simultané des 4 colonnes.
    t0=time.perf_counter()
    k10_a2,n2=recover_k10_attack2(PT,KEY,max_faults=40,verbose=True)
    t2=time.perf_counter()-t0
    rows.append({
        'attack':'Attaque 2',
        'round':8,
        'faults':n2,
        'columns':4,
        'tests':4*TESTS_PAR_COLONNE,
        'seconds':t2,
        'ok':'oui' if inv_key_schedule(k10_a2)==KEY else 'non',
    })

    # Dernière partie : comparaison synthétique des deux variantes PQ03.
    print_final_table(rows)

if __name__=='__main__':
    main()
