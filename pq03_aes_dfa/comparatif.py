from aes_core import inv_key_schedule, print_initial_data
from attack1_pq03 import recover_k10_attack1
from attack2_pq03 import demo_attack2, recover_k10_attack2
import argparse
import time

# Ce script sert de synthèse : il lance les deux variantes, mesure le temps,
# compte les textes chiffrés fautés utilisés et affiche un tableau final.
parser=argparse.ArgumentParser(description='Comparatif PQ03 AES DFA')
parser.add_argument('--verbose', action='store_true', help='affiche le déroulement détaillé des attaques')
args=parser.parse_args()

key=bytes.fromhex('2b7e151628aed2a6abf7158809cf4f3c')
pt=bytes.fromhex('00112233445566778899aabbccddeeff')

# Le filtre PQ03 teste deux paires d'octets de clé par colonne :
# 2 * 256^2 = 131072 tests de paires environ pour une colonne.
TESTS_PAR_COLONNE=2*256*256
COLONNES_PAR_FAUTE_A1=1
COLONNES_PAR_FAUTE_A2=4

print('=== Comparatif PQ03 AES-128 ===')
if args.verbose:
    # En verbose, on affiche aussi le plaintext, K0, les round keys et le
    # texte chiffré correct avant de commencer les attaques.
    print_initial_data(pt,key)

# Attaque 1 : une faute ronde 9 ne renseigne qu'une colonne à la fois.
t0=time.perf_counter()
k10,n1=recover_k10_attack1(pt,key,max_faults=40,verbose=args.verbose)
t1=time.perf_counter()-t0
ok1=inv_key_schedule(k10)==key
print('\nAttaque 1 : faute avant MixColumns ronde 9')
print('Textes fautés utilisés :', n1)
tests_a1=COLONNES_PAR_FAUTE_A1*TESTS_PAR_COLONNE
print('Colonnes filtrées par faute :', COLONNES_PAR_FAUTE_A1)
print('Tests approximatifs par faute :', tests_a1)
print('Temps : %.3fs'%t1)
print('K10 :', k10.hex())
print('K0  :', inv_key_schedule(k10).hex())

# Attaque 2 : une faute ronde 8 se diffuse sur tout le texte chiffré, donc chaque
# texte fauté filtre les 4 colonnes, mais le calcul par faute est plus lourd.
print('\nAttaque 2 : faute avant MixColumns ronde 8')
t0=time.perf_counter()
if args.verbose:
    k10_a2,n2=recover_k10_attack2(pt,key,max_faults=40,verbose=True)
    r={
        'round8_faulted_ciphertexts': n2,
        'min_impacted_ciphertext_bytes': 16,
        'avg_impacted_ciphertext_bytes': 16.0,
        'max_impacted_ciphertext_bytes': 16,
        'k10_recovered': k10_a2.hex(),
        'k0_from_invkeyschedule': inv_key_schedule(k10_a2).hex(),
    }
else:
    r=demo_attack2(pt,key,40)
t2=time.perf_counter()-t0
ok2=bytes.fromhex(r['k0_from_invkeyschedule'])==key
print('Textes fautés utilisés :', r['round8_faulted_ciphertexts'])
print('Octets impactés dans le texte chiffré : min/moyenne/max =', r['min_impacted_ciphertext_bytes'], '%.2f'%r['avg_impacted_ciphertext_bytes'], r['max_impacted_ciphertext_bytes'])
tests_a2=COLONNES_PAR_FAUTE_A2*TESTS_PAR_COLONNE
print('Colonnes filtrées par faute :', COLONNES_PAR_FAUTE_A2)
print('Tests approximatifs par faute :', tests_a2)
print('Temps : %.3fs'%t2)
print('K10 :', r['k10_recovered'])
print('K0  :', r['k0_from_invkeyschedule'])

# Tableau final prêt à être recopié dans un rapport ou montré pendant l'oral.
print('\n=== Tableau comparatif final ===')
print('| Attaque | Ronde ciblée | Textes fautés | Colonnes/faute | Tests approx./faute | Octets impactés moy. | Temps (s) | Clé retrouvée |')
print('|---|---:|---:|---:|---:|---:|---:|---|')
print(f'| Attaque 1 | 9 | {n1} | {COLONNES_PAR_FAUTE_A1} | {tests_a1} | 4.00 | {t1:.3f} | {"oui" if ok1 else "non"} |')
print(f'| Attaque 2 | 8 | {r["round8_faulted_ciphertexts"]} | {COLONNES_PAR_FAUTE_A2} | {tests_a2} | {r["avg_impacted_ciphertext_bytes"]:.2f} | {t2:.3f} | {"oui" if ok2 else "non"} |')
