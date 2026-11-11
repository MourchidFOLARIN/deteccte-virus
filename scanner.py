import hashlib
import json
import sys
import os

EXTENSIONS_SUSPECTES = [".scr", ".vbs", ".bat", ".exe.txt"]
MOTS_CLES_SUSPECTS = ["EICAR", "MALWARE-TEST", "KEYLOGGER-DEMO"]

def charger_signatures(chemin_base):
    with open(chemin_base, "r") as f:
        return json.load(f)

def calculer_hash(chemin_fichier):
    sha256 = hashlib.sha256()
    with open(chemin_fichier, "rb") as f:
        sha256.update(f.read())
    return sha256.hexdigest()

def analyse_heuristique(chemin_fichier):
    alertes = []
    for ext in EXTENSIONS_SUSPECTES:
        if chemin_fichier.lower().endswith(ext):
            alertes.append(f"extension suspecte ({ext})")

    try:
        with open(chemin_fichier, "r", errors="ignore") as f:
            contenu = f.read()
        for mot in MOTS_CLES_SUSPECTS:
            if mot in contenu:
                alertes.append(f"mot-clé suspect trouvé ({mot})")
    except Exception:
        pass

    return alertes

def scanner_fichier(chemin_fichier, signatures):
    hash_fichier = calculer_hash(chemin_fichier)
    alertes_heuristiques = analyse_heuristique(chemin_fichier)

    if hash_fichier in signatures:
        return f"[MENACE DÉTECTÉE - SIGNATURE] {chemin_fichier} -> {signatures[hash_fichier]} (hash: {hash_fichier})"
    elif alertes_heuristiques:
        return f"[SUSPECT - HEURISTIQUE] {chemin_fichier} -> {', '.join(alertes_heuristiques)}"
    else:
        return f"[SAIN] {chemin_fichier} -> hash: {hash_fichier}"

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 scanner.py <fichier_ou_dossier>")
        sys.exit(1)

    cible = sys.argv[1]
    signatures = charger_signatures("signatures.json")

    if os.path.isfile(cible):
        print(scanner_fichier(cible, signatures))
    elif os.path.isdir(cible):
        for nom_fichier in os.listdir(cible):
            chemin_complet = os.path.join(cible, nom_fichier)
            if os.path.isfile(chemin_complet):
                print(scanner_fichier(chemin_complet, signatures))
