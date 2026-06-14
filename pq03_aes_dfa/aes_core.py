"""AES-128 pédagogique avec injection de fautes pour DFA PQ03.

Ce fichier contient volontairement un AES "lisible" plutôt qu'un AES optimisé.
L'objectif est de pouvoir expliquer chaque transformation AES et de placer une
faute exactement avant le MixColumns de la ronde 8 ou 9, comme demandé dans
l'attaque de Piret/Quisquater.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Optional
import random

# SBOX AES officielle : SubBytes remplace chaque octet par cette valeur.
SBOX = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]
# Table inverse de la SBOX. Elle sert pendant la DFA, quand on remonte le
# dernier tour AES sous hypothèse d'un octet de K10.
INV_SBOX=[0]*256
for i,v in enumerate(SBOX): INV_SBOX[v]=i

# Constantes de ronde utilisées par le KeySchedule AES-128.
RCON=[0,1,2,4,8,16,32,64,128,27,54]

def xtime(a:int)->int: return ((a<<1)^0x1b)&0xff if a&0x80 else (a<<1)&0xff
def gmul(a:int,b:int)->int:
    """Multiplication dans GF(2^8), le corps fini utilisé par MixColumns."""
    r=0
    for _ in range(8):
        if b&1: r^=a
        a=xtime(a); b>>=1
    return r

def sub_bytes(s):
    """Transformation non linéaire AES : application de la SBOX octet par octet."""
    for i in range(16): s[i]=SBOX[s[i]]
def inv_sub_bytes(s):
    """Inverse de SubBytes, utile pour remonter le dernier tour."""
    for i in range(16): s[i]=INV_SBOX[s[i]]
def shift_rows(s):
    """Décalage cyclique des lignes AES dans la représentation colonne-major."""
    t=s[:]
    for r in range(4):
        for c in range(4): s[r+4*c]=t[r+4*((c+r)%4)]
def inv_shift_rows(s):
    """Inverse de ShiftRows."""
    t=s[:]
    for r in range(4):
        for c in range(4): s[r+4*c]=t[r+4*((c-r)%4)]
def mix_single_col(a):
    """MixColumns sur une seule colonne de 4 octets."""
    x=a[0]^a[1]^a[2]^a[3]; u=a[0]
    a[0]^=x^xtime(a[0]^a[1]); a[1]^=x^xtime(a[1]^a[2]); a[2]^=x^xtime(a[2]^a[3]); a[3]^=x^xtime(a[3]^u)
def mix_columns(s):
    """Diffusion linéaire AES : chaque colonne mélange ses 4 octets."""
    for c in range(4):
        col=s[4*c:4*c+4]; mix_single_col(col); s[4*c:4*c+4]=col
def inv_mix_columns(s):
    """Inverse de MixColumns, fourni pour compléter l'AES pédagogique."""
    for c in range(4):
        a=s[4*c:4*c+4]
        s[4*c+0]=gmul(a[0],14)^gmul(a[1],11)^gmul(a[2],13)^gmul(a[3],9)
        s[4*c+1]=gmul(a[0],9)^gmul(a[1],14)^gmul(a[2],11)^gmul(a[3],13)
        s[4*c+2]=gmul(a[0],13)^gmul(a[1],9)^gmul(a[2],14)^gmul(a[3],11)
        s[4*c+3]=gmul(a[0],11)^gmul(a[1],13)^gmul(a[2],9)^gmul(a[3],14)
def add_round_key(s,rk):
    """XOR de l'état avec la round key courante."""
    for i in range(16): s[i]^=rk[i]

def state_hex(s)->str:
    """Affiche l'état AES en ordre interne colonne par colonne."""
    return ''.join(f'{x:02x}' for x in s)

def state_matrix_lines(s):
    """Retourne l'état AES sous forme de matrice 4x4.

    AES range l'état en colonnes : l'octet s[r+4*c] est sur la ligne r et la
    colonne c. Cette vue matricielle est plus pratique pour expliquer ShiftRows
    et MixColumns à l'oral.
    """
    return [
        '[' + ' '.join(f'{s[r+4*c]:02x}' for c in range(4)) + ']'
        for r in range(4)
    ]

def print_state(label:str, s):
    """Affiche un état en hexadécimal linéaire et en matrice AES."""
    print(f'{label:<24}: {state_hex(s)}')
    for line in state_matrix_lines(s):
        print(f'{"":<24}  {line}')

def print_round_keys(rks):
    print('\nClés de ronde AES-128')
    for i,rk in enumerate(rks):
        print_state(f'K{i:02d}', rk)

def print_initial_data(pt:bytes, key:bytes):
    """Bloc commun utilisé par les démos verbose."""
    rks=expand_key(key)
    print('=== Données initiales ===')
    print(f'Texte clair            : {pt.hex()}')
    print(f'Clé secrète K0         : {key.hex()}')
    print_round_keys(rks)
    print(f'Texte chiffré correct  : {encrypt_block(pt,key).hex()}')

def expand_key(key: bytes)->List[List[int]]:
    """KeySchedule AES-128 : produit K0, K1, ..., K10 à partir de K0."""
    assert len(key)==16
    w=list(key)
    i=16; rcon_iter=1
    while len(w)<176:
        temp=w[-4:]
        if i%16==0:
            # Tous les 16 octets, AES applique RotWord, SubWord et RCON.
            temp=temp[1:]+temp[:1]
            temp=[SBOX[x] for x in temp]
            temp[0]^=RCON[rcon_iter]; rcon_iter+=1
        for x in temp: w.append(w[-16]^x)
        i+=4
    return [w[16*r:16*(r+1)] for r in range(11)]

def inv_key_schedule(k10: bytes)->bytes:
    """Retrouve K0 à partir de K10 pour AES-128."""
    w=list(k10)
    round_words=[w[i:i+4] for i in range(0,16,4)]
    all_words=[None]*44
    all_words[40:44]=round_words
    for i in range(43,3,-1):
        temp=all_words[i-1][:]
        if i%4==0:
            # On applique la même fonction g() que dans le KeySchedule direct,
            # mais en sens inverse pour retrouver les mots précédents.
            temp=temp[1:]+temp[:1]
            temp=[SBOX[x] for x in temp]
            temp[0]^=RCON[i//4]
        all_words[i-4]=[a^b for a,b in zip(all_words[i],temp)]
    return bytes(sum(all_words[:4],[]))

@dataclass
class Fault:
    """Description d'une faute injectée pendant le chiffrement.

    round_no vaut 8 ou 9 pour les variantes PQ03 du projet. byte_pos et value
    peuvent être laissés à None pour générer une faute aléatoire.
    """
    round_no:int          # 8 ou 9 dans le sujet
    byte_pos:int|None=None
    value:int|None=None
    before_mixcolumns:bool=True

def encrypt_block(pt: bytes, key: bytes, fault: Optional[Fault]=None,
                  verbose: bool=False, trace_label: str='AES')->bytes:
    """Chiffre un bloc AES-128, avec injection optionnelle d'une faute.

    La faute est injectée après SubBytes+ShiftRows et juste avant MixColumns de
    la ronde ciblée. C'est précisément le modèle demandé pour PQ03.
    """
    assert len(pt)==16 and len(key)==16
    rks=expand_key(key); s=list(pt)
    if verbose:
        print(f'\n=== Déroulement AES: {trace_label} ===')
        print_state('État initial', s)
        print_state('Clé de ronde K00', rks[0])
    add_round_key(s,rks[0])
    if verbose:
        print_state('Après AddRoundKey K00', s)
    for rnd in range(1,10):
        # Les rondes 1 à 9 contiennent les quatre opérations AES :
        # SubBytes, ShiftRows, MixColumns, AddRoundKey.
        if verbose:
            print(f'\n--- Ronde {rnd} ---')
            print_state('État début ronde', s)
        sub_bytes(s)
        if verbose:
            print_state('Après SubBytes', s)
        shift_rows(s)
        if verbose:
            print_state('Après ShiftRows', s)
        if fault and fault.round_no==rnd and fault.before_mixcolumns:
            # Injection DFA : on modifie un octet de l'état par XOR.
            # C'est un modèle classique de faute aléatoire sur un octet.
            pos = random.randrange(16) if fault.byte_pos is None else fault.byte_pos
            val = random.randrange(1,256) if fault.value is None else fault.value
            before_fault=s[:]
            original=s[pos]
            s[pos]^=val
            if verbose:
                print('\nInjection de faute')
                print(f'  Ronde ciblée        : {rnd}')
                print(f'  Position octet      : {pos}')
                print(f'  Valeur originale    : {original:02x}')
                print(f'  Masque XOR faute    : {val:02x}')
                print(f'  Valeur fautée       : {s[pos]:02x}')
                print_state('  État avant faute', before_fault)
                print_state('  État après faute', s)
        mix_columns(s)
        if verbose:
            print_state('Après MixColumns', s)
            print_state(f'Clé ronde K{rnd:02d}', rks[rnd])
        add_round_key(s,rks[rnd])
        if verbose:
            print_state('Après AddRoundKey', s)
    if verbose:
        print('\n--- Ronde 10 finale ---')
        print_state('État début ronde', s)
    # La dernière ronde AES ne contient pas MixColumns.
    sub_bytes(s)
    if verbose:
        print_state('Après SubBytes', s)
    shift_rows(s)
    if verbose:
        print_state('Après ShiftRows', s)
        print('MixColumns            : absent dans la ronde finale AES')
        print_state('Clé de ronde K10', rks[10])
    add_round_key(s,rks[10])
    if verbose:
        print_state('Après AddRoundKey K10', s)
        print(f'Texte chiffré produit : {bytes(s).hex()}')
    return bytes(s)

def hex2b(x:str)->bytes: return bytes.fromhex(x.replace(' ',''))
def b2hex(x:bytes)->str: return x.hex()
