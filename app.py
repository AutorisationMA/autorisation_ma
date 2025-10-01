import streamlit as st
import pandas as pd
from datetime import datetime
import os

# --- Chemin fichier Excel ---
FICHIER = "autorisation_ma.xlsx"

# --- Initialisation DataFrame ---
if not os.path.exists(FICHIER):
    colonnes = ["Matricule", "Déclarant", "Référence_MA", "Pays", "Date_ajout",
                "Type", "Exporté", "Créé_par", "Observation", "Clôturé_par",
                "Date_clôture", "Vide_plein"]
    df = pd.DataFrame(columns=colonnes)
    df.to_excel(FICHIER, index=False)
else:
    df = pd.read_excel(FICHIER)

# --- Fonction utilitaire ---
def safe_str_upper(s):
    return s.astype(str).str.upper()

# --- Menu ---
menu = st.sidebar.selectbox("Menu", ["📥 MA Import", "📤 MA Export", "📊 Consulter MA"])
if "username" not in st.session_state:
    st.session_state.username = "TEST"  # à remplacer par login réel
if "role" not in st.session_state:
    st.session_state.role = "admin"

# --- Import ---
if menu == "📥 MA Import" and st.session_state.role != "consult":
    st.subheader("Ajouter une nouvelle autorisation")
    
    matricule = st.text_input("Matricule").strip().upper()
    declarant = st.text_input("Déclarant").strip().upper()
    ref = st.text_input("Référence_MA (optionnelle pour FOURGON/T6BIS/SUBSAHARIEN)").strip()
    
    europe_countries = ["","ALBANIE","ANDORRE","AUTRICHE","BELGIQUE","BOSNIE-HERZÉGOVINE","BULGARIE",
                        "CROATIE","DANEMARK","ESPAGNE","ESTONIE","FINLANDE","FRANCE","GRÈCE",
                        "HONGRIE","IRLANDE","ISLANDE","ITALIE","LETTONIE","LIECHTENSTEIN",
                        "LITUANIE","LUXEMBOURG","MACÉDOINE","MALTE","MOLDAVIE","MONACO","MONTÉNÉGRO",
                        "NORVÈGE","PAYS-BAS","POLOGNE","PORTUGAL","RÉPUBLIQUE TCHÈQUE","ROUMANIE",
                        "ROYAUME-UNI","SAINT-MARIN","SERBIE","SLOVAQUIE","SLOVÉNIE","SUÈDE",
                        "SUISSE","UKRAINE","VATICAN"]
    
    pays = st.selectbox("Pays", options=europe_countries).upper()
    type_doc = st.selectbox("Type MA", ["", "AU VOYAGE", "A TEMPS", "A VIDE", "FOURGON", "SUBSAHARIEN", "T6BIS"]).upper()
    vide_plein = st.selectbox("Vide / Plein", ["", "VIDE", "PLEIN"])
    observation = st.text_area("Observation (facultatif)").strip().upper()
    
    if st.button("📥 Ajouter"):
        if (not ref and type_doc not in ["FOURGON","T6BIS","SUBSAHARIEN"]) or not matricule or not pays:
            st.warning("❗ Veuillez remplir tous les champs obligatoires")
        else:
            df["Référence_MA_clean"] = safe_str_upper(df["Référence_MA"])
            df["Pays_clean"] = safe_str_upper(df["Pays"])
            df["Type_clean"] = safe_str_upper(df["Type"])
            
            is_duplicate = df[
                (df["Référence_MA_clean"] == ref.upper()) &
                (df["Pays_clean"] == pays) &
                (df["Type_clean"] == type_doc) &
                ~((df["Type_clean"] == "A TEMPS") & (df["Exporté"].str.upper() == "OUI"))
            ]
            if not is_duplicate.empty:
                st.error("❌ Cette autorisation MA existe déjà")
            else:
                ma_actives = df[
                    (safe_str_upper(df["Matricule"]) == matricule) &
                    (df["Exporté"].str.upper() != "OUI")
                ]
                if not ma_actives.empty:
                    st.warning(f"⚠️ Le camion {matricule} possède déjà {len(ma_actives)} MA actives")
                
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
                df = pd.concat([df,pd.DataFrame([new_doc])], ignore_index=True)
                df.to_excel(FICHIER, index=False)
                st.success("✅ Réf MA ajoutée")
                st.write(df.tail(3))

# --- Export ---
elif menu == "📤 MA Export" and st.session_state.role != "consult":
    st.subheader("Rechercher une autorisation MA à clôturer")
    df_temp = df[df["Exporté"].str.upper() != "OUI"].copy()
    
    search_term = st.text_input("🔍 Recherche").strip().upper()
    
    if search_term:
        df_filtered = df_temp[
            safe_str_upper(df_temp["Matricule"]).str.contains(search_term, na=False) |
            safe_str_upper(df_temp["Référence_MA"]).str.contains(search_term, na=False) |
            safe_str_upper(df_temp["Pays"]).str.contains(search_term, na=False)
        ]
        if not df_filtered.empty:
            st.dataframe(df_filtered[["Matricule","Référence_MA","Type","Date_ajout"]])
            options = {f"{row['Matricule']} | {row['Référence_MA']} | {row['Type']}": idx
                       for idx,row in df_filtered.iterrows()}
            selected_label = st.selectbox("Sélectionner une autorisation", list(options.keys()))
            
            if st.button("📤 Clôturer la sélection"):
                idx = options[selected_label]
                type_selected = df.at[idx,"Type"].upper()
                
                if type_selected in ["T6BIS","FOURGON","SUBSAHARIEN"]:
                    st.warning(f"⚠️ Attention clôture {type_selected}")
                    if st.button(f"✅ Confirmer clôture {type_selected}"):
                        df.at[idx,"Exporté"]="Oui"
                        df.at[idx,"Clôturé_par"]=st.session_state.username
                        df.at[idx,"Date_clôture"]=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        df.to_excel(FICHIER,index=False)
                        st.success(f"{selected_label} clôturée")
                else:
                    df.at[idx,"Exporté"]="Oui"
                    df.at[idx,"Clôturé_par"]=st.session_state.username
                    df.at[idx,"Date_clôture"]=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    df.to_excel(FICHIER,index=False)
                    st.success(f"{selected_label} clôturée")
        else:
            st.info("Aucun résultat")
    else:
        st.info("👉 Saisir un critère")

    st.subheader("5 dernières clôtures")
    df["Date_clôture"]=pd.to_datetime(df["Date_clôture"],errors="coerce")
    last_exports=df[df["Exporté"].str.upper()=="OUI"].sort_values(by="Date_clôture",ascending=False).head(5)
    last_exports["Réf_affichage"]=last_exports.apply(
        lambda row: row["Référence_MA"] if str(row["Référence_MA"]).strip() else f"SANS_REF ({row['Type']})",
        axis=1
    )
    if not last_exports.empty:
        st.dataframe(last_exports[["Matricule","Réf_affichage","Type","Date_clôture"]])
    else:
        st.info("Aucune opération clôturée récemment")
    
    with open(FICHIER,"rb") as f:
        st.download_button("⬇️ Télécharger Excel", f, file_name="autorisation_ma.xlsx")

# --- Consultation ---
elif menu=="📊 Consulter MA":
    st.subheader("Filtrer les autorisations MA")
    matricule_search=st.text_input("🔍 Recherche par Matricule").strip()
    pays_sel=st.multiselect("Pays", options=df["Pays"].dropna().unique())
    type_sel=st.multiselect("Type MA", options=df["Type"].dropna().unique())
    date_start=st.date_input("Date début", value=None)
    date_end=st.date_input("Date fin", value=None)

    df_filtered=df.copy()
    if not pd.api.types.is_datetime64_any_dtype(df_filtered["Date_ajout"]):
        df_filtered["Date_ajout"]=pd.to_datetime(df_filtered["Date_ajout"],errors='coerce')

    if matricule_search:
        df_filtered=df_filtered[safe_str_upper(df_filtered["Matricule"]).str.contains(matricule_search.upper(),na=False)]
    if pays_sel:
        df_filtered=df_filtered[df_filtered["Pays"].isin(pays_sel)]
    if type_sel:
        df_filtered=df_filtered[df_filtered["Type"].isin(type_sel)]
    if date_start:
        df_filtered=df_filtered[df_filtered["Date_ajout"]>=pd.Timestamp(date_start)]
    if date_end:
        df_filtered=df_filtered[df_filtered["Date_ajout"]<=pd.Timestamp(date_end)]

    df_filtered=df_filtered.sort_values(by="Date_ajout",ascending=False)
    st.dataframe(df_filtered)
