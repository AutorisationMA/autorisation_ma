import streamlit as st
import pandas as pd
from datetime import datetime
import hashlib
from pathlib import Path

# --- FICHIERS ---
USERS_FILE = "users.xlsx"
FICHIER = "autorisation_ma.xlsx"

# --- Hachage mot de passe ---
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# --- Chargement utilisateurs ---
def load_users() -> pd.DataFrame:
    if Path(USERS_FILE).exists():
        return pd.read_excel(USERS_FILE)
    else:
        df = pd.DataFrame([{
            "username": "admin",
            "password_hash": hash_password("admin123"),
            "role": "admin"
        }])
        df.to_excel(USERS_FILE, index=False)
        return df

def save_users(df: pd.DataFrame) -> None:
    df.to_excel(USERS_FILE, index=False)

def check_login(username: str, password: str):
    users = load_users()
    user = users[users["username"] == username]
    if not user.empty:
        is_valid = hash_password(password) == user.iloc[0]["password_hash"]
        role = user.iloc[0]["role"]
        return is_valid, role
    return False, None

def update_password(username: str, new_password: str) -> bool:
    users = load_users()
    idx = users.index[users["username"] == username]
    if len(idx) > 0:
        users.at[idx[0], "password_hash"] = hash_password(new_password)
        save_users(users)
        return True
    return False

# --- Configuration Streamlit ---
st.set_page_config(page_title="Gestion des autorisations MA", layout="centered")
st.title("📄 Gestion de MA & Suivi")

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.role = None

# --- Authentification ---
if not st.session_state.logged_in:
    st.subheader("Connexion")
    username = st.text_input("Nom d'utilisateur")
    password = st.text_input("Mot de passe", type="password")
    if st.button("Se connecter"):
        valid, role = check_login(username, password)
        if valid:
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.role = role
            st.rerun()
        else:
            st.error("Nom d'utilisateur ou mot de passe incorrect.")
    st.stop()

st.sidebar.write(f"✅ Connecté : {st.session_state.username} ({st.session_state.role})")
if st.sidebar.button("Déconnexion"):
    st.session_state.logged_in = False
    st.session_state.username = None
    st.rerun()

menu_options = [
    "🔐 Modifier mot de passe",
    "📥 MA Import",
    "📤 MA Export",
    "📊 Consulter MA"
]

if st.session_state.role == "admin":
    menu_options.insert(1, "👤 Créer un utilisateur")

menu = st.sidebar.radio("Menu", menu_options)

# --- Chargement fichier ---
try:
    df = pd.read_excel(FICHIER)
except FileNotFoundError:
    df = pd.DataFrame(columns=["Matricule", "Référence_MA", "Pays", "Date_ajout", "Type", "Exporté", "Créé_par", "Observation", "Clôturé_par", "Date_clôture", "Vide_plein", "Déclarant"])

def safe_str_upper(series):
    return series.astype(str).fillna('').str.strip().str.upper()

# --- Modifier mot de passe ---
if menu == "🔐 Modifier mot de passe":
    st.header("Modifier mon mot de passe")
    current_pwd = st.text_input("Mot de passe actuel", type="password")
    new_pwd = st.text_input("Nouveau mot de passe", type="password")
    new_pwd_confirm = st.text_input("Confirmer nouveau mot de passe", type="password")
    if st.button("Changer mon mot de passe"):
        user_hash = load_users().set_index("username").loc[st.session_state.username]["password_hash"]
        if hash_password(current_pwd) == user_hash:
            if new_pwd == new_pwd_confirm and new_pwd:
                update_password(st.session_state.username, new_pwd)
                st.success("✅ Mot de passe modifié avec succès.")
            else:
                st.error("❌ Les nouveaux mots de passe ne correspondent pas ou sont vides.")
        else:
            st.error("❌ Mot de passe actuel incorrect.")

# --- Création utilisateur ---
elif menu == "👤 Créer un utilisateur" and st.session_state.role == "admin":
    st.header("Créer un nouvel utilisateur")
    new_username = st.text_input("Nom d'utilisateur du nouvel utilisateur").strip()
    new_password = st.text_input("Mot de passe", type="password")
    confirm_password = st.text_input("Confirmer le mot de passe", type="password")
    new_role = st.selectbox("Rôle", ["agent", "admin", "consult"])
    if st.button("Créer l'utilisateur"):
        if not new_username or not new_password:
            st.warning("❗ Veuillez remplir tous les champs.")
        elif new_password != confirm_password:
            st.error("❌ Les mots de passe ne correspondent pas.")
        else:
            users = load_users()
            if new_username in users["username"].values:
                st.error("❌ Ce nom d'utilisateur existe déjà.")
            else:
                new_user = {
                    "username": new_username,
                    "password_hash": hash_password(new_password),
                    "role": new_role
                }
                users = pd.concat([users, pd.DataFrame([new_user])], ignore_index=True)
                save_users(users)
                st.success(f"✅ Utilisateur '{new_username}' ({new_role}) créé avec succès.")

# --- Import MA ---
elif menu == "📥 MA Import" and st.session_state.role != "consult":
    st.subheader("Ajouter une nouvelle autorisation")

    # Champs du formulaire
    matricule = st.text_input("Matricule").strip().upper()
    declarant = st.text_input("Déclarant").strip().upper()

    # Choix type MA (avant la référence pour gérer la validation)
    type_doc = st.selectbox(
        "Type MA",
        ["", "AU VOYAGE", "A TEMPS", "A VIDE", "FOURGON", "SUBSAHARIEN", "T6BIS"]
    ).upper()

    # Champ Référence_MA (optionnel si FOURGON / T6BIS / SUBSAHARIEN)
    ref = st.text_input("Référence_MA").strip()

    # Validation uniquement si le champ est obligatoire
    if type_doc not in ["FOURGON", "T6BIS", "SUBSAHARIEN"]:
        if ref and not ref.isdigit():
            st.warning("Veuillez entrer uniquement des chiffres pour la Référence MA.")
        else:
            ref = ref.upper()
    else:
        # Pour ces types, on autorise vide
        ref = ref.upper() if ref else ""

    # Liste des pays européens
    europe_countries = [
        "", "ALBANIE", "ANDORRE", "AUTRICHE", "BELGIQUE", "BOSNIE-HERZÉGOVINE",
        "BULGARIE", "CROATIE", "DANEMARK", "ESPAGNE", "ESTONIE", "FINLANDE",
        "FRANCE", "GRÈCE", "HONGRIE", "IRLANDE", "ISLANDE", "ITALIE",
        "LETTONIE", "LIECHTENSTEIN", "LITUANIE", "LUXEMBOURG", "MACÉDOINE",
        "MALTE", "MOLDAVIE", "MONACO", "MONTÉNÉGRO", "NORVÈGE", "PAYS-BAS",
        "POLOGNE", "PORTUGAL", "RÉPUBLIQUE TCHÈQUE", "ROUMANIE", "ROYAUME-UNI",
        "SAINT-MARIN", "SERBIE", "SLOVAQUIE", "SLOVÉNIE", "SUÈDE", "SUISSE",
        "UKRAINE", "VATICAN"
    ]

    pays = st.selectbox("Pays", options=europe_countries).upper()
    vide_plein = st.selectbox("Vide / Plein", ["", "VIDE", "PLEIN"])
    observation = st.text_area("Observation (facultatif)").strip().upper()

    # Bouton d’ajout
    if st.button("📥 Ajouter"):
        # Vérification des champs obligatoires
        if not matricule or not pays:
            st.warning("❗ Veuillez remplir tous les champs obligatoires.")
        elif type_doc not in ["FOURGON", "T6BIS", "SUBSAHARIEN"] and not ref:
            st.warning("❗ La Référence MA est obligatoire pour ce type.")
        else:
            # Vérification doublon exact
            df["Référence_MA_clean"] = safe_str_upper(df["Référence_MA"])
            df["Pays_clean"] = safe_str_upper(df["Pays"])
            df["Type_clean"] = safe_str_upper(df["Type"])

            is_duplicate = df[
                (df["Référence_MA_clean"] == ref) &
                (df["Pays_clean"] == pays) &
                (df["Type_clean"] == type_doc) &
                ~(
                    (df["Type_clean"] == "A TEMPS") &
                    (df["Exporté"].str.upper() == "OUI")
                )
            ]

            if not is_duplicate.empty:
                st.error("❌ Cette autorisation MA existe déjà (Réf + Type + Pays).")
            else:
                # Vérifier si le camion a déjà une MA active
                ma_actives = df[
                    (safe_str_upper(df["Matricule"]) == matricule) &
                    (df["Exporté"].str.upper() != "OUI")
                ]

                if not ma_actives.empty:
                    st.warning(
                        f"⚠️ Le camion {matricule} possède déjà {len(ma_actives)} "
                        f"MA actives non exportées."
                    )

                # Ajouter le nouveau document
                new_doc = {
                    "Matricule": matricule,
                    "Déclarant": declarant,
                    "Référence_MA": ref,
                    "Pays": pays,
                    "Date_ajout": datetime.today().strftime("%Y-%m-%d %H:%M:%S"),
                    "Type": type_doc,
                    "Exporté": "Non",
                    "Créé_par": st.session_state.username,
                    "Observation": observation,
                    "Clôturé_par": "",
                    "Date_clôture": "",
                    "Vide_plein": vide_plein
                }

                df = pd.concat([df, pd.DataFrame([new_doc])], ignore_index=True)
                df.to_excel(FICHIER, index=False)

                st.success("✅ Réf MA ajouté avec succès.")

                # Affichage des 10 dernières opérations
                st.subheader("📋 10 dernières opérations")
                last_imports = df.sort_values(by="Date_ajout", ascending=False).head(10)
                colonnes_a_afficher = [
                    col for col in last_imports.columns if not col.endswith("_clean")
                ]
                st.dataframe(last_imports[colonnes_a_afficher])



# --- Export MA ---

elif menu == "📤 MA Export" and st.session_state.role != "consult":
    st.subheader("Rechercher une autorisation MA à clôturer")
    df_temp = df[df["Exporté"].str.upper() != "OUI"].copy()

    # Ajouter une colonne affichage pour gérer les références vides
    df_temp["Réf_affichage"] = df_temp.apply(
        lambda row: row["Référence_MA"] if str(row["Référence_MA"]).strip()
        else f"SANS_REF ({row['Type']})", axis=1
    )

    # Champ recherche
    search_term = st.text_input("🔍 Recherche (matricule, référence_MA, pays ou type)").strip().upper()

    if search_term:
        df_filtered = df_temp[
            safe_str_upper(df_temp["Matricule"]).str.contains(search_term, na=False) |
            safe_str_upper(df_temp["Référence_MA"]).str.contains(search_term, na=False) |
            safe_str_upper(df_temp["Pays"]).str.contains(search_term, na=False) |
            safe_str_upper(df_temp["Type"]).str.contains(search_term, na=False)
        ]

        if not df_filtered.empty:
            # Colonnes utiles
            colonnes_affichees = ["Matricule", "Réf_affichage", "Type", "Date_ajout"]
            st.dataframe(df_filtered[colonnes_affichees])

            # Utiliser l’index réel comme clé de sélection
            options = {
                f"{row['Matricule']} | {row['Réf_affichage']} | {row['Type']} | {row['Date_ajout']}": idx
                for idx, row in df_filtered.iterrows()
            }

            selected_label = st.selectbox("Sélectionner une autorisation à clôturer", list(options.keys()))

            if st.button("📤 Clôturer la sélection"):
                idx = options[selected_label]  # Récupérer le vrai index

                df.at[idx, "Exporté"] = "Oui"
                df.at[idx, "Clôturé_par"] = st.session_state.username
                df.at[idx, "Date_clôture"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                df.to_excel(FICHIER, index=False)

                st.success(f"✅ L'autorisation {selected_label} a été clôturée avec succès.")
        else:
            st.info("Aucun résultat trouvé pour cette recherche.")
    else:
        st.info("👉 Veuillez saisir un critère de recherche pour afficher les résultats.")

    # Historique
    st.subheader("5 dernières clôtures")
    last_exports = df[df["Exporté"].str.upper() == "OUI"].sort_values(by="Date_clôture", ascending=False).head(5)
    last_exports["Réf_affichage"] = last_exports.apply(
        lambda row: row["Référence_MA"] if str(row["Référence_MA"]).strip()
        else f"SANS_REF ({row['Type']})", axis=1
    )
    st.dataframe(last_exports[["Matricule", "Réf_affichage", "Type", "Date_clôture"]])


    
# --- Consultation ---
elif menu == "📊 Consulter MA":
    st.subheader("Filtrer les autorisations MA")

    matricule_search = st.text_input("🔍 Recherche par Matricule").strip()
    pays_sel = st.multiselect("Pays", options=df["Pays"].dropna().unique())
    type_sel = st.multiselect("Type MA", options=df["Type"].dropna().unique())
    date_start = st.date_input("Date début", value=None)
    date_end = st.date_input("Date fin", value=None)

    df_filtered = df.copy()

    # Assure que Date_ajout est datetime (gère si elle est déjà convertie)
    if not pd.api.types.is_datetime64_any_dtype(df_filtered["Date_ajout"]):
        df_filtered["Date_ajout"] = pd.to_datetime(df_filtered["Date_ajout"], errors='coerce')

    if matricule_search:
        matricule_search_upper = matricule_search.upper()
        df_filtered = df_filtered[
            safe_str_upper(df_filtered["Matricule"]).str.contains(matricule_search_upper)
        ]

    if pays_sel:
        df_filtered = df_filtered[df_filtered["Pays"].isin(pays_sel)]

    if type_sel:
        df_filtered = df_filtered[df_filtered["Type"].isin(type_sel)]

    if date_start:
        df_filtered = df_filtered[df_filtered["Date_ajout"] >= pd.Timestamp(date_start)]

    if date_end:
        df_filtered = df_filtered[df_filtered["Date_ajout"] <= pd.Timestamp(date_end)]

    df_filtered = df_filtered.sort_values(by="Date_ajout", ascending=False)

    st.dataframe(df_filtered)






















































