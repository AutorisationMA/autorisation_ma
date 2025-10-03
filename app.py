import streamlit as st
import pandas as pd
import hashlib
from datetime import datetime
from supabase import create_client, Client
import io

# ==========================
# --- Connexion Supabase ---
# ==========================
SUPABASE_URL = st.secrets["SUPABASE_URL"]
SUPABASE_KEY = st.secrets["SUPABASE_KEY"]
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ==========================
# --- Utils / Hashing ---
# ==========================
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def safe_str_upper(series):
    return series.astype(str).fillna('').str.strip().str.upper()

# ==========================
# --- Gestion utilisateurs ---
# ==========================
def load_users() -> pd.DataFrame:
    resp = supabase.table("users").select("*").execute()
    return pd.DataFrame(resp.data) if resp.data else pd.DataFrame()

def save_user(user: dict):
    supabase.table("users").insert(user).execute()

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
    user = users[users["username"] == username]
    if not user.empty:
        supabase.table("users").update({"password_hash": hash_password(new_password)}).eq("username", username).execute()
        return True
    return False

# ==========================
# --- Authentification ---
# ==========================
st.set_page_config(page_title="Gestion des autorisations MA", layout="centered")
st.title("📄 Gestion de MA & Suivi")

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.role = None

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
    st.session_state.role = None
    st.rerun()

# ==========================
# --- Menu ---
# ==========================
menu_options = [
    "🔐 Modifier mot de passe",
    "📥 MA Import",
    "📤 MA Export",
    "📊 Consulter MA"
]
if st.session_state.role == "admin":
    menu_options.insert(1, "👤 Créer un utilisateur")

menu = st.sidebar.radio("Menu", menu_options)

# ==========================
# --- Liste des pays ---
# ==========================
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

# ==========================
# --- Fonctions MA ---
# ==========================
def insert_ma(new_doc: dict):
    """Insertion MA avec vérification des doublons et colonnes existantes"""
    resp2 = supabase.table("autorisations_ma").select("*").execute()
    df = pd.DataFrame(resp2.data) if resp2.data else pd.DataFrame()
    # Vérification doublon
    if not df.empty:
        df["Reference_MA_clean"] = safe_str_upper(df["Reference_MA"])
        df["Pays_clean"] = safe_str_upper(df["Pays"])
        df["Type_clean"] = safe_str_upper(df["Type"])
        ref = str(new_doc.get("Reference_MA", "")).upper().strip()
        pays = str(new_doc.get("Pays", "")).upper().strip()
        typ = str(new_doc.get("Type", "")).upper().strip()
        doublon = df[
            (df["Reference_MA_clean"] == ref) &
            (df["Pays_clean"] == pays) &
            (df["Type_clean"] == typ)
        ]
        if not doublon.empty:
            st.warning(f"⚠️ Cette MA existe déjà ({ref} - {typ} - {pays})")
            return False
    try:
        supabase.table("autorisations_ma").insert(new_doc).execute()
        st.success(f"✅ MA {new_doc.get('Reference_MA')} ajoutée")
        return True
    except Exception as e:
        st.error(f"Erreur insertion : {e}")
        return False

# ==========================
# --- Modifier mot de passe ---
# ==========================
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

# ==========================
# --- Création utilisateur ---
# ==========================
elif menu == "👤 Créer un utilisateur" and st.session_state.role == "admin":
    st.header("Créer un nouvel utilisateur")
    new_username = st.text_input("Nom d'utilisateur").strip()
    new_password = st.text_input("Mot de passe", type="password")
    confirm_password = st.text_input("Confirmer le mot de passe", type="password")
    new_role = st.selectbox("Rôle", ["agent", "admin", "consult"])
    if st.button("Créer l'utilisateur"):
        if not new_username or not new_password:
            st.warning("❗ Veuillez remplir tous les champs.")
        elif new_password != confirm_password:
            st.error("❌ Les mots de passe ne correspondent pas.")
        else:
            save_user({
                "username": new_username,
                "password_hash": hash_password(new_password),
                "role": new_role
            })
            st.success(f"✅ Utilisateur '{new_username}' ({new_role}) créé")

# ==========================
# --- MA Import ---
# ==========================
elif menu == "📥 MA Import" and st.session_state.role != "consult":
    st.subheader("Ajouter une nouvelle autorisation")
    matricule = st.text_input("Matricule").strip().upper()
    declarant = st.text_input("Déclarant").strip().upper()
    type_doc = st.selectbox("Type MA", ["AU VOYAGE","A TEMPS","A VIDE","FOURGON","SUBSAHARIEN","T6BIS"]).upper()
    ref = st.text_input("Référence MA").strip()
    pays = st.selectbox("Pays", options=europe_countries).upper()
    vide_plein = st.selectbox("Vide / Plein", ["", "VIDE", "PLEIN"])
    observation = st.text_area("Observation").strip().upper()

    if st.button("📥 Ajouter"):
        # Vérifications obligatoires
        if not matricule or not pays:
            st.warning("❗ Veuillez remplir tous les champs obligatoires")
        elif type_doc not in ["FOURGON","SUBSAHARIEN","T6BIS"] and not ref:
            st.warning("❗ La Référence MA est obligatoire pour ce type")
        elif type_doc not in ["FOURGON","SUBSAHARIEN","T6BIS"] and not ref.isdigit():
            st.warning("❗ La Référence MA doit être uniquement des chiffres")
        else:
            ma_doc = {
                "Matricule": matricule,
                "Declarant": declarant,
                "Reference_MA": ref.upper() if ref else "",
                "Pays": pays,
                "Type": type_doc,
                "Cree_par": st.session_state.username,
                "Exporte": "Non",
                "Observation": observation,
                "Vide_plein": vide_plein,
                "Date_ajout": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "Cloture_par": None,
                "Date_cloture": None
            }
            insert_ma(ma_doc)

# ==========================
# --- MA Export / Clôture ---
# ==========================
# ==========================
# --- MA Export / Clôture ---
# ==========================
elif menu == "📤 MA Export" and st.session_state.role != "consult":
    st.subheader("Clôturer une autorisation MA")

    # Récupérer MA non exportées
    resp = supabase.table("autorisations_ma").select("*").neq("Exporte", "Oui").execute()
    df_ma = pd.DataFrame(resp.data) if resp.data else pd.DataFrame()

    if df_ma.empty:
        st.info("Aucune MA non exportée disponible")
    else:
        # Champs de recherche initialement vides
        search_term = st.text_input("🔍 Recherche (matricule, MA, pays)", value="").strip().upper()

        df_filtered = df_ma.copy()
        if search_term:
            df_filtered = df_filtered[
                safe_str_upper(df_filtered["Matricule"]).str.contains(search_term) |
                safe_str_upper(df_filtered["Reference_MA"]).str.contains(search_term) |
                safe_str_upper(df_filtered["Pays"]).str.contains(search_term)
            ]

        if df_filtered.empty:
            st.info("Aucun résultat ne correspond à votre recherche")
        else:
            # --- Affichage des colonnes essentielles ---
            df_display = df_filtered[["Reference_MA", "Matricule", "Pays", "Date_ajout"]].copy()
            df_display = df_display.rename(columns={
                "Reference_MA": "MA",
                "Matricule": "N",
                "Date_ajout": "Date"
            })
            st.dataframe(df_display)

            # Choix de la MA à clôturer
            selected_ref = st.selectbox("Sélectionner une MA à clôturer", df_filtered["Reference_MA"])

            if st.button("📤 Clôturer la sélection"):
                # Vérifier type spécial
                type_selected = df_filtered[df_filtered["Reference_MA"] == selected_ref]["Type"].iloc[0].upper()
                if type_selected in ["FOURGON", "SUBSAHARIEN", "T6BIS"]:
                    st.warning(f"⚠️ Attention : vous clôturez une MA de type {type_selected}. Confirmez ci-dessous.")
                    if st.button(f"✅ Confirmer clôture {type_selected}"):
                        supabase.table("autorisations_ma").update({
                            "Exporte": "Oui",
                            "Cloture_par": st.session_state.username,
                            "Date_cloture": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }).eq("Reference_MA", selected_ref).execute()
                        st.success(f"✅ MA {selected_ref} clôturée")
                else:
                    # Clôture normale
                    supabase.table("autorisations_ma").update({
                        "Exporte": "Oui",
                        "Cloture_par": st.session_state.username,
                        "Date_cloture": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }).eq("Reference_MA", selected_ref).execute()
                    st.success(f"✅ MA {selected_ref} clôturée")

        # --- Affichage des 10 dernières clôtures ---
        resp_closed = supabase.table("autorisations_ma").select("*").eq("Exporte", "Oui").order("Date_cloture", desc=True).limit(10).execute()
        df_closed = pd.DataFrame(resp_closed.data) if resp_closed.data else pd.DataFrame()

        if not df_closed.empty:
            df_closed_display = df_closed[["Reference_MA", "Matricule", "Pays", "Date_cloture"]].copy()
            df_closed_display = df_closed_display.rename(columns={
                "Reference_MA": "MA",
                "Matricule": "N",
                "Date_cloture": "Date"
            })
            st.subheader("📋 10 dernières clôtures")
            st.dataframe(df_closed_display)

# ==========================
# --- Consultation / Export ---
# ==========================
elif menu == "📊 Consulter MA":
    st.subheader("Filtrer les autorisations MA")

    # Récupération des données depuis Supabase
    resp = supabase.table("autorisations_ma").select("*").execute()
    df = pd.DataFrame(resp.data) if resp.data else pd.DataFrame()

    if df.empty:
        st.info("Aucune donnée disponible")
    else:
        # --- Champs de recherche initialement vides ---
        matricule_search = st.text_input("🔍 Recherche par matricule", value="")
        pays_sel = st.multiselect("Pays", options=sorted(df["Pays"].dropna().unique()), default=[])
        type_sel = st.multiselect("Type MA", options=sorted(df["Type"].dropna().unique()), default=[])
        date_start = st.date_input("Date début", value=None)
        date_end = st.date_input("Date fin", value=None)

        # Assure que Date_ajout est datetime
        df["Date_ajout"] = pd.to_datetime(df["Date_ajout"], errors='coerce')

        # --- Filtrage dynamique ---
        df_filtered = df.copy()
        if matricule_search:
            df_filtered = df_filtered[safe_str_upper(df_filtered["Matricule"]).str.contains(matricule_search)]
        if pays_sel:
            df_filtered = df_filtered[df_filtered["Pays"].isin(pays_sel)]
        if type_sel:
            df_filtered = df_filtered[df_filtered["Type"].isin(type_sel)]
        if date_start:
            df_filtered = df_filtered[df_filtered["Date_ajout"] >= pd.Timestamp(date_start)]
        if date_end:
            df_filtered = df_filtered[df_filtered["Date_ajout"] <= pd.Timestamp(date_end)]

        df_filtered = df_filtered.sort_values(by="Date_ajout", ascending=False)

        # --- Messages et affichage ---
        if df_filtered.empty:
            st.info("Aucun résultat ne correspond à votre recherche")
        else:
            st.dataframe(df_filtered)

            # 10 dernières opérations
            st.subheader("📋 10 dernières opérations")
            st.dataframe(df_filtered.head(10))

            # Export Excel
            buffer = io.BytesIO()
            df_filtered.to_excel(buffer, index=False)
            st.download_button(
                label="📥 Télécharger en Excel",
                data=buffer.getvalue(),
                file_name="autorisations_filtrees.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            )

