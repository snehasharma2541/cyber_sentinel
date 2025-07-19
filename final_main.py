import streamlit as st
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_curve, auc
import joblib


model = joblib.load("./savedModels/catboost_model.joblib")

st.set_page_config(
    page_title="Cyber Sentinel",
    page_icon="🛡️",
    layout="wide"
)

st.sidebar.title("🔍 Navigation")
page = st.sidebar.radio("Go to", ["📖 Project Insight","🏠Home", "🔍Prediction", "📊Data Analysis"])


        
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
    st.markdown("""
        <style>
        .title {
            color: #0d1b2a;
            font-size: 52px;
            font-weight: bold;
            text-align: center;
            padding-top: 2rem;
        }
        .subtitle {
            color: #1b263b;
            font-size: 24px;
            text-align: center;
            margin-bottom: 3rem;
        }
        .info-box {
            background-color: rgba(255, 255, 255, 0.85);
            padding: 2rem;
            border-radius: 20px;
            box-shadow: 0 6px 15px rgba(0,0,0,0.2);
            width: 85%;
            margin: auto;
            text-align: center;
        }
        </style>
    """, unsafe_allow_html=True)
    
    st.markdown('<div class="title">🛡️ Welcome to Cyber Sentinel</div>', unsafe_allow_html=True)
    st.markdown('<div class="subtitle">A Smart ML Solution for Phishing Website Detection</div>', unsafe_allow_html=True)

    st.markdown(
        '<div class="info-box">Cyber Sentinel is an intelligent platform to detect phishing websites with high accuracy and real-time responsiveness. It is trained on various phishing attack patterns and can help users to identify and avoid malicious websites.</div>',
        unsafe_allow_html=True
    )
    st.markdown("---")
    st.image("https://www.chamanlawfirm.com/wp-content/uploads/2024/10/what-is-cyber-security-1.jpg", caption="Cyber Security in Action", width=850)
    st.markdown("---")


elif page == "🔍Prediction":
    st.title("🔐 Prediction Page")
    st.markdown("Use this page to detect phishing threats using website features or URL")
    
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


        


elif page == "📊Data Analysis":
    st.title("📊 Model Performance Analysis")

    df = pd.read_csv("./dataset/clean_output.csv")
    
    
    x = df.drop("Result", axis=1)  
    y = df["Result"]
    
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)
    
    x_test.columns = [col.lower() for col in x_test.columns]

    y_pred = model.predict(x_test)

    # 1. Accuracy
    accuracy = accuracy_score(y_test, y_pred)
    st.subheader("✅ Model Accuracy")
    st.write(f"Accuracy: **{accuracy*100:.2f}%**")
    
    st.markdown("<br>", unsafe_allow_html=True)

    st.markdown("---")  

    # 2. Confusion Matrix
    st.subheader("📉 Confusion Matrix")
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots()
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=["Legitimate", "Phishing"], yticklabels=["Legitimate", "Phishing"])
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    st.pyplot(fig)
    st.markdown("<br>", unsafe_allow_html=True)
    
    st.markdown("---")
    
    #3. ROC curve
    st.markdown("### 📈 ROC Curve")
    try:
        y_proba = model.predict_proba(x_test)[:, 1]
        fpr, tpr, _ = roc_curve(y_test, y_proba)
        roc_auc = auc(fpr, tpr)
        fig2, ax2 = plt.subplots()
        ax2.plot(fpr, tpr, label=f"AUC = {roc_auc:.2f}")
        ax2.plot([0, 1], [0, 1], linestyle='--', color='gray')
        ax2.set_xlabel("False Positive Rate")
        ax2.set_ylabel("True Positive Rate")
        ax2.set_title("ROC Curve")
        ax2.legend()
        st.pyplot(fig2)
    except Exception as e:
        st.warning(f"ROC Curve could not be plotted: {e}")
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("---")
    
    
    #4. Feature Importance
    st.markdown("### 🔍 Feature Importance")
    try:
        feature_names = x_test.columns if isinstance(x_test, pd.DataFrame) else [f"Feature {i}" for i in range(x_test.shape[1])]
        importances = model.feature_importances_
        feat_df = pd.DataFrame({'Feature': feature_names, 'Importance': importances})
        feat_df = feat_df.sort_values(by='Importance', ascending=False).head(10)
        fig4, ax4 = plt.subplots()
        sns.barplot(data=feat_df, x='Importance', y='Feature', palette="Blues_d", ax=ax4)
        ax4.set_title("Top 10 Important Features")
        st.pyplot(fig4)
    except:
        st.warning("Feature importance not supported for this model.")
    st.markdown("---")


    #5. Class Distribution
    st.subheader("📊 Class Distribution in Test Set")
    class_counts = pd.Series(y_test).value_counts().sort_index()
    labels = ['Legitimate', 'Phishing'] if len(class_counts) == 2 else [str(i) for i in class_counts.index]

    fig3, ax3 = plt.subplots()
    sns.barplot(x=labels, y=class_counts.values, palette="Set2", ax=ax3)
    ax3.set_xlabel("Class")
    ax3.set_ylabel("Count")
    ax3.set_title("Distribution of Legitimate vs Phishing")
    st.pyplot(fig3)
    
    
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("---")
    
    
    
    # 6. Classification Report
    st.subheader("📄 Classification Report")
    report = classification_report(y_test, y_pred, output_dict=True)
    st.dataframe(pd.DataFrame(report).transpose())

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("---")
    
    #7. Classification Metrics
    
    st.markdown("### 📊 Classification Metrics")
    report_dict = classification_report(y_test, y_pred, output_dict=True)
    report_df = pd.DataFrame(report_dict).transpose().iloc[:2, :3]
    fig3, ax3 = plt.subplots()
    report_df.plot(kind='bar', ax=ax3)
    ax3.set_title("Precision, Recall, F1-score per class")
    ax3.set_ylabel("Score")
    st.pyplot(fig3)
    st.markdown("---")
    
    #8.Raw Count Table
    st.subheader("📄 Raw Prediction Summary")
    summary_df = pd.DataFrame({'Actual': y_test, 'Predicted': y_pred})
    st.dataframe(summary_df.head(10))  # Show first 10 predictions
    st.markdown("---")
    
    
    #9. Model Confidence Distribution
    st.markdown("### 📈 Model Confidence Distribution")

    y_proba = model.predict_proba(x_test)[:, 1]

    fig10, ax10 = plt.subplots()
    sns.histplot(y_proba, bins=30, kde=True, color='purple', ax=ax10)
    ax10.set_title("Distribution of Model Prediction Probabilities (Class 1)")
    ax10.set_xlabel("Predicted Probability for Class 1 (Phishing)")
    ax10.set_ylabel("Frequency")
    st.pyplot(fig10)
    
    
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("---")



    
elif page == "📖 Project Insight":
    st.title("📖 Project Insight")

    st.markdown("""
        <style>
        .about-container {
            background-color: rgba(255, 255, 255, 0.85);
            padding: 2rem;
            border-radius: 15px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            font-family: 'Segoe UI', sans-serif;
            margin-top: 25px;
        }
        .about-heading {
            text-align: center;
            font-size: 30px;
            font-weight: bold;
            color: #0d1b2a;
            margin-bottom: 10px;
        }
        .about-text {
            font-size: 17px;
            color: #1b263b;
            text-align: justify;
            line-height: 1.6;
        }
        </style>
        <div class="about-container">
            <div class="about-heading">What is Cyber Sentinel?</div>
            <div class="about-text">
                <p><strong>Cyber Sentinel</strong> is a smart and proactive Machine Learning-based tool designed to detect phishing websites in real-time using models like <em>CatBoost, XGBoost, LightGBM</em>, and <em>Random Forest</em>.</p>
                <p>By analyzing various features of a website, it predicts whether it is <em>legitimate </em> or <em>phishing</em>, helping users stay protected online.</p>
            
            This project was developed as part of the Cyber Security module during Industrial Training in the 7th semester of the B.Tech program in Electronics and Communication Engineering.
            It focus on cyber threat prevention and digital safety.

            Developed By: Ms.Sneha Sharma
               Guided By: Er.Rakshit Mehra

            Use the sidebar to explore the Home page, prediction, predicted data analysis, and understand how machine learning protects you from phishing threats.
            
        </div>
    """, unsafe_allow_html=True)
