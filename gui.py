import tkinter as tk
from tkinter import filedialog, font, ttk
from datetime import datetime
import os
import json
from PIL import Image, ImageTk
from scanner import charger_signatures, calculer_hash, analyse_heuristique

signatures = charger_signatures("signatures.json")

compteurs = {"menace": 0, "suspect": 0, "sain": 0}

def maj_compteurs():
    label_compteurs.config(
        text=f"🔴 Menaces: {compteurs['menace']}    🟠 Suspects: {compteurs['suspect']}    🟢 Sains: {compteurs['sain']}"
    )

def maj_explication(texte):
    label_explication.config(text=texte)

def scanner_avec_etapes(chemin_fichier):
    heure = datetime.now().strftime("%H:%M:%S")

    zone_resultats.insert(tk.END, f"[{heure}] Analyse de : {chemin_fichier}\n", "info")
    zone_resultats.insert(tk.END, "  → Calcul du hash SHA-256...\n", "etape")
    fenetre.update_idletasks()

    hash_fichier = calculer_hash(chemin_fichier)
    zone_resultats.insert(tk.END, f"  → Hash obtenu : ", "etape")
    zone_resultats.insert(tk.END, f"{hash_fichier}\n", "hash")

    zone_resultats.insert(tk.END, "  → Comparaison à la base de signatures...\n", "etape")
    fenetre.update_idletasks()

    if hash_fichier in signatures:
        nom_menace = signatures[hash_fichier]
        zone_resultats.insert(tk.END, f"  → [MENACE DÉTECTÉE - SIGNATURE] {nom_menace}\n\n", "danger")
        compteurs["menace"] += 1
        maj_explication(
            f"Détecté par SIGNATURE : le hash calculé correspond exactement à une entrée connue "
            f"de notre base ({nom_menace}). Le fichier a été reconnu au premier coup d'œil, "
            f"sans analyser son contenu — c'est le principe le plus simple et le plus rapide."
        )
    else:
        zone_resultats.insert(tk.END, "  → Aucune correspondance dans la base. Analyse heuristique...\n", "etape")
        fenetre.update_idletasks()
        alertes = analyse_heuristique(chemin_fichier)
        if alertes:
            zone_resultats.insert(tk.END, f"  → [SUSPECT - HEURISTIQUE] {', '.join(alertes)}\n\n", "warning")
            compteurs["suspect"] += 1
            maj_explication(
                "Détecté par HEURISTIQUE : le hash était inconnu (pas dans notre base), mais le "
                "scanner a trouvé un indice suspect dans le contenu même du fichier (mot-clé ou "
                "extension). Cette méthode attrape des menaces jamais vues auparavant, au prix de "
                "plus de faux positifs possibles."
            )
        else:
            zone_resultats.insert(tk.END, "  → [SAIN] Aucune signature ni indice suspect trouvé\n\n", "safe")
            compteurs["sain"] += 1
            maj_explication(
                "Fichier SAIN : ni le hash, ni le contenu ne correspondent à quoi que ce soit de "
                "connu ou suspect dans nos règles. Cela ne garantit pas à 100% l'innocuité du "
                "fichier — seulement qu'il ne déclenche aucune de nos deux méthodes de détection."
            )

    zone_resultats.see(tk.END)
    maj_compteurs()

def scanner_un_fichier():
    chemin = filedialog.askopenfilename(title="Choisir un fichier à scanner")
    if chemin:
        scanner_avec_etapes(chemin)

def scanner_un_dossier():
    dossier = filedialog.askdirectory(title="Choisir un dossier à scanner")
    if dossier:
        fichiers = [f for f in os.listdir(dossier) if os.path.isfile(os.path.join(dossier, f))]
        zone_resultats.insert(tk.END, f"--- Scan du dossier : {dossier} ({len(fichiers)} fichiers) ---\n\n", "info")

        barre_progression["maximum"] = len(fichiers)
        barre_progression["value"] = 0

        for i, nom_fichier in enumerate(fichiers, start=1):
            chemin_complet = os.path.join(dossier, nom_fichier)
            scanner_avec_etapes(chemin_complet)
            barre_progression["value"] = i
            fenetre.update_idletasks()

def afficher_base_signatures():
    fenetre_base = tk.Toplevel(fenetre)
    fenetre_base.title("Contenu de signatures.json")
    fenetre_base.geometry("700x300")
    fenetre_base.configure(bg="#ffffff")

    label = tk.Label(fenetre_base, text="Base de signatures connues (hash → nom de menace)",
                      font=("Helvetica", 12, "bold"), bg="#ffffff", fg="#2a9d6f")
    label.pack(pady=10)

    with open("signatures.json", "r") as f:
        contenu = json.load(f)

    zone = tk.Text(fenetre_base, font=("Courier", 10), bg="#f5f5f5", fg="#1a1a1a", wrap="word")
    zone.pack(padx=20, pady=10, fill="both", expand=True)
    zone.insert(tk.END, json.dumps(contenu, indent=2, ensure_ascii=False))
    zone.config(state="disabled")

def effacer():
    zone_resultats.delete("1.0", tk.END)
    compteurs["menace"] = 0
    compteurs["suspect"] = 0
    compteurs["sain"] = 0
    maj_compteurs()
    barre_progression["value"] = 0
    maj_explication("En attente d'un scan...")

fenetre = tk.Tk()
fenetre.title("Mini-Antivirus — TP Détection par signatures")
fenetre.geometry("900x800")
fenetre.configure(bg="#ffffff")

police_titre = font.Font(family="Helvetica", size=20, weight="bold")
police_sous_titre = font.Font(family="Helvetica", size=11)
police_bouton = font.Font(family="Helvetica", size=11)
police_resultat = font.Font(family="Courier", size=10)
police_compteurs = font.Font(family="Helvetica", size=12, weight="bold")
police_explication = font.Font(family="Helvetica", size=11)

logo_image = Image.open("logo.png")
logo_image = logo_image.resize((120, 120))
logo_tk = ImageTk.PhotoImage(logo_image)

label_logo = tk.Label(fenetre, image=logo_tk, bg="#ffffff")
label_logo.pack(pady=(20, 5))

titre = tk.Label(fenetre, text="Scanner Antivirus par Signatures", font=police_titre, bg="#ffffff", fg="#2a9d6f")
titre.pack(pady=(5, 2))

sous_titre = tk.Label(fenetre, text="Détection par hash SHA-256 (signatures) + règle heuristique", font=police_sous_titre, bg="#ffffff", fg="#5a5a5a")
sous_titre.pack(pady=(0, 15))

cadre_boutons = tk.Frame(fenetre, bg="#ffffff")
cadre_boutons.pack(pady=5)

btn_fichier = tk.Button(cadre_boutons, text="Scanner un fichier", font=police_bouton, command=scanner_un_fichier, bg="#3dd68c", fg="black", padx=12, pady=8)
btn_fichier.grid(row=0, column=0, padx=6)

btn_dossier = tk.Button(cadre_boutons, text="Scanner un dossier", font=police_bouton, command=scanner_un_dossier, bg="#3dd68c", fg="black", padx=12, pady=8)
btn_dossier.grid(row=0, column=1, padx=6)

btn_base = tk.Button(cadre_boutons, text="Voir la base de signatures", font=police_bouton, command=afficher_base_signatures, bg="#5b8def", fg="black", padx=12, pady=8)
btn_base.grid(row=0, column=2, padx=6)

btn_effacer = tk.Button(cadre_boutons, text="Effacer", font=police_bouton, command=effacer, bg="#ff5d5d", fg="black", padx=12, pady=8)
btn_effacer.grid(row=0, column=3, padx=6)

label_compteurs = tk.Label(fenetre, text="", font=police_compteurs, bg="#ffffff", fg="#1a1a1a")
label_compteurs.pack(pady=(15, 5))
maj_compteurs()

barre_progression = ttk.Progressbar(fenetre, length=830, mode="determinate")
barre_progression.pack(pady=(0, 10))

cadre_explication = tk.Frame(fenetre, bg="#f0f0f0", bd=1, relief="solid")
cadre_explication.pack(padx=20, pady=(0, 10), fill="x")

label_explication_titre = tk.Label(cadre_explication, text="💡 Explication du dernier résultat",
                                     font=("Helvetica", 10, "bold"), bg="#f0f0f0", fg="#d68c23")
label_explication_titre.pack(anchor="w", padx=12, pady=(8, 0))

label_explication = tk.Label(cadre_explication, text="En attente d'un scan...", font=police_explication,
                               bg="#f0f0f0", fg="#1a1a1a", wraplength=820, justify="left")
label_explication.pack(anchor="w", padx=12, pady=(2, 10))

zone_resultats = tk.Text(fenetre, font=police_resultat, bg="#f5f5f5", fg="#1a1a1a", wrap="word", height=14)
zone_resultats.pack(padx=20, pady=10, fill="both", expand=True)

zone_resultats.tag_config("danger", foreground="#c0392b", font=(police_resultat.actual("family"), 10, "bold"))
zone_resultats.tag_config("warning", foreground="#d68c23", font=(police_resultat.actual("family"), 10, "bold"))
zone_resultats.tag_config("safe", foreground="#1e8e5a")
zone_resultats.tag_config("info", foreground="#6a6a6a", font=(police_resultat.actual("family"), 10, "italic"))
zone_resultats.tag_config("etape", foreground="#8a8a8a")
zone_resultats.tag_config("hash", foreground="#2c5fb3", font=(police_resultat.actual("family"), 10, "bold"))

fenetre.mainloop()
