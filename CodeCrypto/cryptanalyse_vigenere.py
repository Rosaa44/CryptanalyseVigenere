# Sorbonne Université 3I024 2018-2019
# TME 2 : Cryptanalyse du chiffre de Vigenere
#
# Etudiant.e 1 : MENDAS ROSA

import sys, getopt, string, math
from math import sqrt
# Alphabet français
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Fréquence moyenne des lettres en français
#Calcul des fréquences d'apparition des lettres dans le texte Germinal, de Zola
#Fonction du TME1 utilisée:
"""
def frequences():

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    Occurences = {}
    length = 0
    L=[]


    if len(sys.argv)<2:
        print("IL MANQUE UN ARGUMENT, VEUILLEZ INDIQUER UN FICHIER A LIRE")
        exit()

    fichier=sys.argv[1]
    f = open(fichier, "r")
    texte=f.read() 
    length=len(texte)
    for e in texte:
        if e not in Occurences:
            Occurences[e]=0
        Occurences[e]+=1

    # Print the frequences
    for c in alphabet:
        if c in Occurences:
            L.append(Occurences[c]/length)
        else:
            L.append(0.0)


    return L

"""



freq_FR = [0.09213414037491088, 0.010354463742221126, 0.030178915678726964, 0.03753683726285317, 0.17174710607479665, 0.010939030914707838, 0.01061497737343803, 0.010717912027723734, 0.07507240372750529, 0.003832727374391129, 6.989390105819367e-05, 0.061368115927295096, 0.026498684088462805, 0.07030818127173859, 0.049140495636714375, 0.023697844853330825, 0.010160031617459242, 0.06609294363882899, 0.07816806814528274, 0.07374314880919855, 0.06356151362232132, 0.01645048271269667, 1.14371838095226e-05, 0.004071637436190045, 0.0023001447439151006, 0.0012263202640210343]

# Chiffrement César
def chiffre_cesar(txt, key):
    """
    Retourne un texte chiffré en remplaçant chaque lettre du texte clair par une lettre à distance fixe
    """

    chif=""
    for e in txt:
        k=ord(e)+key
        if k>90:
            k=k-26
        chif+=chr(k)
    txt=chif 

    return txt


# Déchiffrement César
def dechiffre_cesar(txt, key):
    """
    Retourne un texte clair en remplaçant chaque lettre du texte chiffré par une lettre à distance fixe
    """
    chif=""
    for e in txt:
        k=ord(e)-key
        if k<65:
            k=k+26

        chif+=chr(k)
    txt=chif 

    return txt

# Chiffrement Vigenere
def chiffre_vigenere(txt, key):
    """
    Retourne un texte chiffré en remplaçant chaque lettre du texte clair par une lettre à distance variable
    key est une liste
    """
    t=0
    chif=""
    for e in txt:
        indice=t%len(key) #si la clef est plus petite que le mot alors on revient au début de la clef
        t+=1
        k=ord(e)+key[indice]
        if k>90:
            k=k-26
        chif+=chr(k)
    txt=chif 

    return txt

# Déchiffrement Vigenere
def dechiffre_vigenere(txt, key):
    """
    Documentation à écrire
    """
    t=0
    chif=""
    for e in txt:
        indice=t%len(key)
        t+=1
        k=ord(e)-key[indice]
        if k<65:
            k=k+26
        chif+=chr(k)
    txt=chif 

    return txt

# Analyse de fréquences
def freq(txt):
    """
    Renvoie un tableau avec le nombre d'occurence de chaque lettre dans le texte txt
    """
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    Occurences = {}
    L=[]

    for e in txt:
        if e not in Occurences:
            Occurences[e]=0
        Occurences[e]+=1

    # Print the frequences
    for c in alphabet:
        if c in Occurences:
            L.append(Occurences[c])
        else:
            L.append(0.0)


    return L


def lettre_freq_max(txt):
    """
    Renvoie l'indice dans l'alphabet de la lettre la plus fréquente d'un texte
    """
    L=freq(txt)
    max=0
    indice=-1
    for e in range(len(L)):
        if L[e]>max:
            max=L[e]
            indice=e

    return indice #on commence à 0 donc on ajoute 1 pour avoir l'indice dans l'alphabet

# indice de coïncidence
def indice_coincidence(hist):
    """
    Prend en entrée un tableau de fréquences des lettres et renvoie l'indice de coïncidence
    """
    indice=0
    summ=0

    for x in range(len(hist)):
        indice+=hist[x]*(hist[x]-1)
        summ+=hist[x]
    summ=summ*(summ-1)
    if summ>0:
        return indice/summ
    return 0

# Recherche la longueur de la clé
def longueur_clef(cipher):
    """
    Retourne la longueur de la clé lors d'une cryptanalyse de Vigenère 
    à l'aide de l'indice de coïncidence 
    """
    
    i=0
    taille=len(cipher)
    for k in range(1,21): #on essaye différentes longueurs de clé
        indice=0
        for l in range(k):
            txt=cipher[l:taille:k] #on découpe le texte en colonnes
            indice+=indice_coincidence(freq(txt)) 
        indice=indice/k #calcul de l'indice de coïncidence moyen
        i+=1
        if(indice>0.06):
            return i
   
    return 0
    
# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en utilisant la lettre la plus fréquente
# de chaque colonne
def clef_par_decalages(cipher, key_length):
    """
    Déchiffre le texte cipher:
    retourne une liste des décalages du chiffrement de Vigenère. 
    """
    decalages=[0]*key_length
    taille=len(cipher)
    for k in range(key_length):
        lettre=lettre_freq_max(cipher[k:taille:key_length]) #colonne
        lettre=(lettre-4)%26 #indice de e = 4
        decalages[k]=lettre
    return decalages

# Cryptanalyse V1 avec décalages par frequence max
def cryptanalyse_v1(cipher):
    """
    Cryptanalyse le texte cipher:
    On déduit la longueur de la clé avec indice de coïncidence, on récupère la clé en observant le
    décalage de chaque colonne.
    """
    longueur=longueur_clef(cipher)
    L=clef_par_decalages(cipher,longueur)
    txt=dechiffre_vigenere(cipher,L)

    return txt


"""
18 texts successfully unciphered.
Test cryptanalyse_v1 : OK
On a donc 18 tests correctement cryptanalysés,
ce résultat est dû aux différentes hypothèses émises notamment que la lettre 
qui apparaît le plus est toujours E par exemple: ce qui n'est pas adapté pour de petits textes.
En effet, les colonnes des petits textes sont petites et ne fournissent pas assez d'indices sur les décalages.
"""

################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V2.

# Indice de coincidence mutuelle avec décalage
def indice_coincidence_mutuelle(h1,h2,d):
    """
    Retourne l'indice de coïncidence mutuelle de deux textes
    """
    somme=0
    tot1=0
    tot2=0
    for i in range(26):
        somme+=h1[i]*h2[(i+d)%26] #26=taille alphabet
        tot1+=h1[i]
        tot2+=h2[i]


    return somme/(tot1*tot2)

# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en comparant l'indice de décalage mutuel par rapport
# à la première colonne
def tableau_decalages_ICM(cipher, key_length):
    """
    Prend un texte et une longueur de clef supposée, 
    et calcule pour chaque colonne son décalage par 
    rapport à la première colonne.
    """

    decalages=[0]*key_length
    h1=freq(cipher[0:len(cipher):key_length])
    for k in range(key_length):
        maxi=0
        i=0
        h2=freq(cipher[k:len(cipher):key_length])
        for d in range(0, len(alphabet)):
            indice=indice_coincidence_mutuelle(h1,h2, d)
            if indice>maxi:
                maxi=indice
                i=d
        decalages[k]=i        
    #print(decalages)
    return decalages


# Cryptanalyse V2 avec décalages par ICM
def cryptanalyse_v2(cipher):
    """
    Cryptanalyse d'un texte à l'aide de l'ICM
    """
    txt2=""
    longueur=longueur_clef(cipher)
    L=tableau_decalages_ICM(cipher,longueur)
    txt=dechiffre_vigenere(cipher,L)
    indice=lettre_freq_max(txt)
    d=(4-indice)%26 #4 = indice de E dans l'alphabet 
    txt2=chiffre_cesar(txt,d)
    return txt2

"""
43 texts successfully unciphered.
Test cryptanalyse_v2 : OK
Dans ce cas si, c'est toujours la taille des textes qui pose problème. En calculant l'ICM
sur un texte court, nous n'obtenons pas assez d'information sur le décalage.  

"""

################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V3.

# Prend deux listes de même taille et
# calcule la correlation lineaire de Pearson


def correlation(L1,L2):
    """
    Retourne la valeur de correlation entre deux listes de même longueur.
    """
    somme1=0
    somme2=0
    num=0
    moyL1=sum(L1)/(len(L1))
    moyL2=sum(L2)/(len(L2))
    for i in range(len(L1)):
        num+=(L1[i]-moyL1)*(L2[i]-moyL2) #calcul du numérateur

    for i in range(len(L1)):
        somme1+=(L1[i]-moyL1)**2
        somme2+=(L2[i]-moyL2)**2
    dnum=sqrt(somme1)*sqrt(somme2) #calcul dénominateur
    return num/dnum


# Renvoie la meilleur clé possible par correlation
# étant donné une longueur de clé fixée
def clef_correlations(cipher, key_length):
    """
    Prend en paramètres un texte chiffré et la taille d'une clé, calcule pour chaque colonne 
    le décalage qui maximise la corélation avec un texte français.
    """
    key=[0]*key_length
    score = 0.0
    somme=0
    s=0 #indice du tableau
    for k in range(key_length):
        x=0
        indice=0
        for dec in range (26):
            txt=cipher[k::key_length]
            txt=dechiffre_cesar(txt,dec)
            cor=correlation(freq(txt),freq_FR)
            if cor>x:
                x=cor
                indice=dec
        somme+=x
        key[s]=indice 
        s+=1 #indice du tableau
    score=somme/key_length
    return (score, key)

# Cryptanalyse V3 avec correlations
def cryptanalyse_v3(cipher):
    """
    Cryptanalyse un texte en calculant les décalages qui maximisent la corrélation 
    ce Pearson. 
    """
    longueur=longueur_clef(cipher)
    score, key= clef_correlations(cipher, longueur)
    txt= dechiffre_vigenere(cipher, key)
    return txt

"""
84 texts successfully unciphered.
Test cryptanalyse_v3 : OK
Cette méthode est la meilleure des 3, les textes qui échouent sont des textes courts.
Les 3 méthodes de cryptanalyse se basent sur les colonnes, or pour un petit texte, ces colonnes ne sont pas suffisante
pour obtenir des informations précises sur les décalages.
"""

################################################################
# NE PAS MODIFIER LES FONCTIONS SUIVANTES
# ELLES SONT UTILES POUR LES TEST D'EVALUATION
################################################################


# Lit un fichier et renvoie la chaine de caracteres
def read(fichier):
    f=open(fichier,"r")
    txt=(f.readlines())[0].rstrip('\n')
    f.close()
    return txt

# Execute la fonction cryptanalyse_vN où N est la version
def cryptanalyse(fichier, version):
    cipher = read(fichier)
    if version == 1:
        return cryptanalyse_v1(cipher)
    elif version == 2:
        return cryptanalyse_v2(cipher)
    elif version == 3:
        return cryptanalyse_v3(cipher)

def usage():
    print ("Usage: python3 cryptanalyse_vigenere.py -v <1,2,3> -f <FichierACryptanalyser>", file=sys.stderr)
    sys.exit(1)

def main(argv):
    size = -1
    version = 0
    fichier = ''
    try:
        opts, args = getopt.getopt(argv,"hv:f:")
    except getopt.GetoptError:
        usage()
    for opt, arg in opts:
        if opt == '-h':
            usage()
        elif opt in ("-v"):
            version = int(arg)
        elif opt in ("-f"):
            fichier = arg
    if fichier=='':
        usage()
    if not(version==1 or version==2 or version==3):
        usage()

    print("Cryptanalyse version "+str(version)+" du fichier "+fichier+" :")
    print(cryptanalyse(fichier, version))
    
if __name__ == "__main__":
   main(sys.argv[1:])

