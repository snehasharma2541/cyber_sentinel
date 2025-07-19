import streamlit as st
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.model_selection import train_test_split
import joblib


model = joblib.load("./savedModels/catboost_model.joblib")

st.set_page_config(
    page_title="Cyber Sentinel",
    page_icon="🛡️",
    layout="wide"
)

st.sidebar.title("🔍 Navigation")
page = st.sidebar.radio("Go to", ["🏠Home", "🔍Prediction", "📊Results", "📖About"])




        
import re
import socket
from urllib.parse import urlparse

def extract_features_from_url(url):
    features = {
        "having_ip_address": -1 if re.match(r"\d+\.\d+\.\d+\.\d+", url) else 1,
        "url_length": 1 if len(url) < 54 else (-1 if len(url) > 75 else 0),
        "shortining_service": -1 if re.search("bit\.ly|goo\.gl|tinyurl|ow\.ly", url) else 1,
        "having_at_symbol": -1 if "@" in url else 1,
        "double_slash_redirecting": -1 if url.count("//") > 1 else 1,
        "prefix_suffix": -1 if "-" in urlparse(url).netloc else 1,
        "having_sub_domain": -1 if url.count(".") >= 3 else (0 if url.count(".") == 2 else 1),
        "sslfinal_state": 1 if url.startswith("https") else -1,
        "domain_registeration_length": 1,
        "favicon": 1,
        "port": 1,
        "https_token": -1 if "https" in urlparse(url).netloc else 1,
        "request_url": 1,
        "url_of_anchor": 0,
        "links_in_tags": 0,
        "sfh": 1,
        "submitting_to_email": 1,
        "abnormal_url": -1 if socket.gethostbyname(urlparse(url).netloc) else 1,
        "redirect": 0,
        "on_mouseover": 0,
        "rightclick": 0,
        "popupwidnow": 0,
        "iframe": 0,
        "age_of_domain": 1,
        "dnsrecord": 1,
        "web_traffic": 0,
        "page_rank": 0,
        "google_index": 1,
        "links_pointing_to_page": 0,
        "statistical_report": 1
    }
    return features


if page == "🏠Home":

    st.markdown("# 🛡️ Cyber Sentinel")
    st.markdown("## A Smart ML Solution for Phishing Website Detection")

    st.markdown("---")
    st.image("https://repository-images.githubusercontent.com/374996283/d7d68080-c9fd-11eb-94b4-f3fbc8492e1e", caption="Pishing Detection", width=400)
    # with col2:
    #     st.image("https://www.dalet.com/uploads/2020/11/shutterstock_434404171-1920x1644.jpg", caption="Cyber Security In Action", width=300)

    st.markdown("### 🧠 What is Cyber Sentinel?")
    st.write("""
    Cyber Sentinel is a powerful machine learning-based application designed to detect phishing websites with high accuracy and real-time responsiveness.
    It is trained on various phishing attack patterns and can help users identify and avoid malicious websites.
    """)

    with st.expander("🔍 Features"):
        st.markdown("""
        - ✅ Real-time phishing detection  
        - 📊 Visual analytics and predictions  
        - 🧠 Powered by CatBoost, LightGBM, XGBoost  
        - 🧪 Test any input manually  
        - 💡 Lightweight and user-friendly interface
        """)
        


elif page == "🔍Prediction":
    st.title("🔐 Prediction Page")
    st.markdown("Use this page to detect phishing threats using website features or URL.")

    prediction_mode = st.radio("Choose input method:", ["Manual Input", "URL Input"])

    

    if prediction_mode == "Manual Input":
        with st.form("input_form"):
            st.write("### 📝 Enter Website Characteristics")
            input_data = {
            "having_ip_address": st.selectbox("1. Having IP Address", [-1, 1]),
            "url_length": st.selectbox("2. URL Length", [-1, 0, 1]),
            "shortining_service": st.selectbox("3. Shortening Service", [-1, 1]),
            "having_at_symbol": st.selectbox("4. '@' Symbol Present", [-1, 1]),
            "double_slash_redirecting": st.selectbox("5. Double Slash Redirecting", [-1, 1]),
            "prefix_suffix": st.selectbox("6. Prefix/Suffix in Domain", [-1, 1]),
            "having_sub_domain": st.selectbox("7. Having Subdomain", [-1, 0, 1]),
            "sslfinal_state": st.selectbox("8. SSL Final State", [-1, 0, 1]),
            "domain_registeration_length": st.selectbox("9. Domain Registration Length", [-1, 1]),
            "favicon": st.selectbox("10. Favicon", [-1, 1]),
            "port": st.selectbox("11. Non-standard Port", [-1, 1]),
            "https_token": st.selectbox("12. HTTPS Token in URL", [-1, 1]),
            "request_url": st.selectbox("13. Request URL", [-1, 1]),
            "url_of_anchor": st.selectbox("14. URL of Anchor", [-1, 0, 1]),
            "links_in_tags": st.selectbox("15. Links in Tags", [-1, 0, 1]),
            "sfh": st.selectbox("16. Server Form Handler", [-1, 1]),
            "submitting_to_email": st.selectbox("17. Submitting to Email", [-1, 1]),
            "abnormal_url": st.selectbox("18. Abnormal URL", [-1, 1]),
            "redirect": st.selectbox("19. Redirect", [0, 1]),
            "on_mouseover": st.selectbox("20. On Mouseover", [0, 1]),
            "rightclick": st.selectbox("21. Right Click Disabled", [0, 1]),
            "popupwidnow": st.selectbox("22. Pop-up Window", [0, 1]),
            "iframe": st.selectbox("23. IFrame Redirection", [0, 1]),
            "age_of_domain": st.selectbox("24. Age of Domain", [-1, 1]),
            "dnsrecord": st.selectbox("25. DNS Record Available", [-1, 1]),
            "web_traffic": st.selectbox("26. Web Traffic", [-1, 0, 1]),
            "page_rank": st.selectbox("27. Page Rank", [-1, 0, 1]),
            "google_index": st.selectbox("28. Google Index", [-1, 1]),
            "links_pointing_to_page": st.selectbox("29. Links Pointing to Page", [0, 1]),
            "statistical_report": st.selectbox("30. Statistical Report", [-1, 1]),
           }
            submit = st.form_submit_button("🚀 Predict")

        if submit:
            demo_input = pd.DataFrame([list(input_data.values())], columns=input_data.keys())
            prediction = model.predict(demo_input)[0]
            proba = model.predict_proba(demo_input)[0]
            result_text = "🟢 Legitimate Website" if prediction == 1 else "🔴 Phishing Website"
            confidence = round(max(proba) * 100, 2)
            st.markdown("### 🔍 Prediction Result:")
            st.success(result_text)
            st.markdown(f"Confidence: `{confidence}%`")
            
    elif prediction_mode == "URL Input":
        st.write("### 🌐 Enter a Website URL")
        url = st.text_input("🔗 Website URL", placeholder="https://example.com")
        if st.button("🚀 Predict from URL"):
            if url:
                try:
                    extracted_features = extract_features_from_url(url)
                    demo_input = pd.DataFrame([list(extracted_features.values())], columns=extracted_features.keys())
                    prediction = model.predict(demo_input)[0]
                    proba = model.predict_proba(demo_input)[0]

                    result_text = "🟢 Legitimate Website" if prediction == 1 else "🔴 Phishing Website"
                    confidence = round(max(proba) * 100, 2)
                    st.markdown("### 🔍 Prediction Result:")
                    st.success(result_text)
                    st.markdown(f"Confidence: `{confidence}%`")
                except Exception as e:
                    st.error(f"❌ Error extracting features from URL: {e}")
            else:
                st.warning("Please enter a valid URL.")


        



elif page == "📊Results":
    st.title("📊 Model Performance Results")

    df = pd.read_csv("./dataset/clean_output.csv")
    
    
    x = df.drop("Result", axis=1)  
    y = df["Result"]
    
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)
    
    x_test.columns = [col.lower() for col in x_test.columns]

    y_pred = model.predict(x_test)

    # 1. Accuracy
    accuracy = accuracy_score(y_test, y_pred)
    st.subheader("✅ Accuracy Score")
    st.write(f"Accuracy: **{accuracy:.2f}**")

    st.markdown("---")  

    # 2. Confusion Matrix
    st.subheader("🔁 Confusion Matrix")
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots()
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', ax=ax)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    st.pyplot(fig)

    st.markdown("---")

    # 3. Classification Report
    st.subheader("📄 Classification Report")
    report = classification_report(y_test, y_pred, output_dict=True)
    st.dataframe(pd.DataFrame(report).transpose())

elif page == "📖About":
    st.title("📖About Cyber Sentinel")

    st.markdown("### 🔒 Project Overview")
    st.markdown(
        "Cyber Sentinel is a Machine Learning-based solution developed to detect phishing websites and protect users from online threats. "
        "It analyzes website features and intelligently predicts whether a website is **legitimate** or **phishing**, thereby enhancing digital safety."
    )

    st.markdown("### 🎓 Academic Context")
    st.markdown(
        "This project was developed as part of the **Cyber Security Project** in the discipline of **Electronics and Communication Engineering**, "
        "with a special focus on cybersecurity and threat prevention using AI technologies."
    )

    st.markdown("### 🧭 Navigation Tips")
    st.markdown(
        "Use the sidebar to:  \n"
        "- 🔍 Make real-time predictions using the 'Prediction' page  \n"
        "- 📊 Analyze performance and accuracy on the 'Results' page  \n"
        "- ℹ️ Learn more about the project here in the 'About' section"
    )
