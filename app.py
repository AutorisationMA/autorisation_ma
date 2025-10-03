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

# --- Gestion des utilisateurs ---
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

