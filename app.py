import streamlit as st
import pandas as pd
import hashlib
from datetime import datetime
from supabase import create_client, Client

# --- Connexion à Supabase ---
SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_KEY = st.secrets["SUPABASE_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# --- Hachage mot de passe ---
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# --- Gestion des utilisateurs ---import streamlit as st
import pandas as pd
from datetime import datetime
import hashlib
from pathlib import Path

# --- FICHIERS ---
USERS_FILE = "users.xlsx"
FICHIER ="autorisation_ma.xlsx"

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

                # Affichage des 10 dernières opérations import
    st.subheader("📋 10 dernières opérations")
    last_imports = df.sort_values(by="Date_ajout", ascending=False).head(10)
    colonnes_a_afficher = [col for col in last_imports.columns if not col.endswith("_clean")]
    st.dataframe(last_imports[colonnes_a_afficher])




elif menu == "📤 MA Export" and st.session_state.role != "consult":
    st.subheader("Rechercher une autorisation MA à clôturer")
    df_temp = df[df["Exporté"].str.upper() != "OUI"].copy()

    # Champ recherche
    search_term = st.text_input("🔍 Recherche (matricule ou référence_MA ou Pays)").strip().upper()

    if search_term:  # 👉 n’afficher que si l’utilisateur tape quelque chose
        df_filtered = df_temp[
            safe_str_upper(df_temp["Matricule"]).str.contains(search_term, na=False) |
            safe_str_upper(df_temp["Référence_MA"]).str.contains(search_term, na=False) |
            safe_str_upper(df_temp["Pays"]).str.contains(search_term, na=False)
        ]

        if not df_filtered.empty:
            # Colonnes utiles
            colonnes_affichees = ["Matricule", "Référence_MA", "Type", "Date_ajout"]
            st.dataframe(df_filtered[colonnes_affichees])

            # Mapping pour retrouver l'index facilement
            options = {row["Référence_MA"]: idx for idx, row in df_filtered.iterrows()}

            # Choix de la ligne
            selected_label = st.selectbox(
                "Sélectionner une autorisation à clôturer",
                list(options.keys())
            )

            if st.button("📤 Clôturer la sélection"):
                idx = options[selected_label]
                type_selected = df.at[idx, "Type"].upper()

                # Vérification spéciale pour certains types
                if type_selected in ["T6BIS", "FOURGON", "SUBSAHARIEN"]:
                    st.warning(f"⚠️ Attention : vous êtes en train de clôturer une opération de type **{type_selected}**. "
                               "Veuillez confirmer avant de continuer.")

                    if st.button(f"✅ Confirmer la clôture {type_selected}"):
                        df.at[idx, "Exporté"] = "Oui"
                        df.at[idx, "Clôturé_par"] = st.session_state.username
                        df.at[idx, "Date_clôture"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        df.to_excel(FICHIER, index=False)
                        st.success(f"✅ L'autorisation {selected_label} ({type_selected}) a été clôturée avec succès.")
                else:
                    # Cas normal
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
# Affichage des 10 dernières opérations 
    
    st.subheader("📋 10 dernières opérations")
    last_imports = df.sort_values(by="Date_ajout", ascending=False).head(10)
    colonnes_a_afficher = [col for col in last_imports.columns if not col.endswith("_clean")]
    st.dataframe(last_imports[colonnes_a_afficher])
  
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

    # --- Export Excel ---
    import io
    from openpyxl import Workbook

    if not df_filtered.empty:
        buffer = io.BytesIO()
        with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
            df_filtered.to_excel(writer, index=False, sheet_name="Autorisations_MA")
        st.download_button(
            label="📥 Télécharger en Excel",
            data=buffer.getvalue(),
            file_name="autorisations_filtrees.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        )
    else:
        st.info("Aucune donnée à exporter.")



































































def load_users() -> pd.DataFrame:
    data = supabase.table("users").select("*").execute()
    if data.data:
        return pd.DataFrame(data.data)
    else:
        # Créer un admin par défaut si table vide
        admin_user = {
            "username": "admin",
            "password_hash": hash_password("admin123"),
            "role": "admin"
        }
        supabase.table("users").insert(admin_user).execute()
        return pd.DataFrame([admin_user])

def save_users(df: pd.DataFrame) -> None:
    supabase.table("users").delete().neq("username", "").execute()
    supabase.table("users").insert(df.to_dict(orient="records")).execute()

# --- Gestion des MA ---
def load_ma() -> pd.DataFrame:
    data = supabase.table("ma_autorisations").select("*").execute()
    return pd.DataFrame(data.data) if data.data else pd.DataFrame(columns=[
        "Matricule", "Référence_MA", "Pays", "Date_ajout", "Type",
        "Exporté", "Créé_par", "Observation", "Clôturé_par",
        "Date_clôture", "Vide_plein", "Déclarant"
    ])

def save_ma(df: pd.DataFrame) -> None:
    supabase.table("ma_autorisations").delete().neq("Matricule", "").execute()
    supabase.table("ma_autorisations").insert(df.to_dict(orient="records")).execute()

# --- Authentification ---
def login(username, password):
    users = load_users()
    if username in users["username"].values:
        user_row = users[users["username"] == username].iloc[0]
        if user_row["password_hash"] == hash_password(password):
            return user_row["role"]
    return None

# --- Interface ---
st.set_page_config(page_title="Autorisation MA", layout="wide")

if "role" not in st.session_state:
    st.session_state.role = None
if "username" not in st.session_state:
    st.session_state.username = None

if st.session_state.role is None:
    st.title("🔑 Connexion")
    username = st.text_input("Nom d’utilisateur")
    password = st.text_input("Mot de passe", type="password")
    if st.button("Se connecter"):
        role = login(username, password)
        if role:
            st.session_state.role = role
            st.session_state.username = username
            st.success(f"Connecté en tant que {username} ({role})")
            st.experimental_rerun()
        else:
            st.error("Identifiants incorrects")

else:
    st.sidebar.title("📌 Menu")
    menu = st.sidebar.radio("Navigation", ["📊 Consulter MA", "📥 Ajouter MA", "👥 Gestion utilisateurs", "🚪 Déconnexion"])

    # --- Consulter MA ---
    if menu == "📊 Consulter MA":
        st.subheader("Liste des Autorisations MA")
        df = load_ma()
        st.dataframe(df)

    # --- Ajouter MA ---
    elif menu == "📥 Ajouter MA" and st.session_state.role != "consult":
        st.subheader("Nouvelle autorisation")
        matricule = st.text_input("Matricule")
        ref = st.text_input("Référence MA")
        pays = st.text_input("Pays")
        type_ma = st.selectbox("Type", ["IMPORT", "EXPORT"])
        observation = st.text_area("Observation")

        if st.button("Enregistrer"):
            df = load_ma()
            new_entry = {
                "Matricule": matricule,
                "Référence_MA": ref,
                "Pays": pays,
                "Date_ajout": datetime.now().isoformat(),
                "Type": type_ma,
                "Exporté": False,
                "Créé_par": st.session_state.username,
                "Observation": observation,
                "Clôturé_par": "",
                "Date_clôture": None,
                "Vide_plein": "",
                "Déclarant": ""
            }
            df = pd.concat([df, pd.DataFrame([new_entry])], ignore_index=True)
            save_ma(df)
            st.success("Autorisation ajoutée ✅")

    # --- Gestion utilisateurs ---
    elif menu == "👥 Gestion utilisateurs" and st.session_state.role == "admin":
        st.subheader("Gestion des utilisateurs")
        df_users = load_users()
        st.dataframe(df_users[["username", "role"]])

        new_user = st.text_input("Nouvel utilisateur")
        new_pass = st.text_input("Mot de passe", type="password")
        new_role = st.selectbox("Rôle", ["admin", "user", "consult"])
        if st.button("Ajouter utilisateur"):
            df_users = pd.concat([df_users, pd.DataFrame([{
                "username": new_user,
                "password_hash": hash_password(new_pass),
                "role": new_role
            }])], ignore_index=True)
            save_users(df_users)
            st.success("Utilisateur ajouté ✅")

    # --- Déconnexion ---
    elif menu == "🚪 Déconnexion":
        st.session_state.role = None
        st.session_state.username = None
        st.experimental_rerun()


