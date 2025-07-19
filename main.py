import streamlit as st
import pandas as pd
import joblib

# Set general config
st.set_page_config(
    page_title="Cyber Sentinel",
    page_icon="🛡️",
    layout="wide"
)

# Sidebar for navigation
st.sidebar.title("🔍 Navigation")
page = st.sidebar.radio("Go to", ["🏠Home", "🔍Prediction", "📊Results", "📖About"])

# ------------------ HOME PAGE ------------------
if page == "🏠Home":
    st.markdown("""
        <style>
        .stApp {
            background: linear-gradient(to right, #c6ffdd, #fbd786, #f7797d);
            font-family: 'Segoe UI', sans-serif;
        }
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
        '<div class="info-box">Cyber Sentinel is an intelligent platform to detect phishing websites using machine learning. Navigate from the sidebar to explore predictions or results.</div>',
        unsafe_allow_html=True
    )

    st.image("https://www.chamanlawfirm.com/wp-content/uploads/2024/10/what-is-cyber-security-1.jpg",caption="Cyber Security in Action", width=900)
    
# ------------------ PREDICTION PAGE ------------------
elif page == "🔍Prediction":
    st.title("🔐 Prediction Page")
    st.markdown("Use this page to input website features and detect phishing threats.")

    # Load the CatBoost model
    try:
        model3 = joblib.load('./savedModels/catboost_model.joblib')
    except FileNotFoundError:
        st.error("Model file not found. Please check the path and ensure the model is trained and saved.")
        st.stop()

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

        submit_button = st.form_submit_button(label="Predict")

    if submit_button:
        # Convert input data to DataFrame
        input_df = pd.DataFrame([input_data])
        
        # Make prediction
        prediction = model3.predict(input_df)
        
        if prediction[0] == 1:
            result = "The website is **Phishing**"
        else:
            result = "The website is **Legitimate**"
        
        st.success(result)


# ------------------ RESULTS PAGE ------------------
elif page == "📊Results":
    st.title("📊 Results Page")
    st.markdown("Visualize model accuracy, confusion matrix, and classification report here.")

    import matplotlib.pyplot as plt
    import seaborn as sns
    from sklearn.metrics import confusion_matrix, classification_report, accuracy_score
    from sklearn.model_selection import train_test_split

    # Load your dataset
    try:
        df = pd.read_csv("./dataset/clean_output.csv")  # Use your actual dataset path
    except FileNotFoundError:
        st.error("Dataset not found. Please ensure 'clean_output.csv' is available.")
        st.stop()

    # Split features and labels
    x = df.drop("Result", axis=1)  # Replace 'Result' with your label column name
    y = df["Result"]

    # Train/test split
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state=42)

    # Load the trained model
    try:
        model = joblib.load('./savedModels/catboost_model.joblib')
    except FileNotFoundError:
        st.error("Model file not found.")
        st.stop()

    # Predict
    x_test.columns = [col.lower() for col in x_test.columns]

    y_pred = model.predict(x_test)

    # Accuracy Score
    accuracy = accuracy_score(y_test, y_pred)
    st.subheader("✅ Model Accuracy")
    st.write(f"Accuracy: **{accuracy*100:.2f}%**")
    
    st.markdown("<br>", unsafe_allow_html=True)

    # Confusion Matrix
    st.subheader("📉 Confusion Matrix")
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots()
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=["Legitimate", "Phishing"], yticklabels=["Legitimate", "Phishing"])
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    st.pyplot(fig)
    
    st.markdown("<br>", unsafe_allow_html=True)

    # Classification Report
    st.subheader("📋 Classification Report")
    report = classification_report(y_test, y_pred, output_dict=True)
    st.dataframe(pd.DataFrame(report).transpose())
   
    st.markdown("<br>", unsafe_allow_html=True)
    
    
    # Class Distribution
    st.subheader("📊 Class Distribution in Test Set")
    class_counts = pd.Series(y_test).value_counts().sort_index()
    labels = ['Legitimate', 'Phishing'] if len(class_counts) == 2 else [str(i) for i in class_counts.index]

    fig2, ax2 = plt.subplots()
    sns.barplot(x=labels, y=class_counts.values, palette="Set2", ax=ax2)
    ax2.set_xlabel("Class")
    ax2.set_ylabel("Count")
    ax2.set_title("Distribution of Legitimate vs Phishing")
    st.pyplot(fig2)
    
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    
    #Raw Count Table ---
    st.subheader("📄 Raw Prediction Summary")
    summary_df = pd.DataFrame({'Actual': y_test, 'Predicted': y_pred})
    st.dataframe(summary_df.head(10))  # Show first 10 predictions


# ------------------ ABOUT PAGE ------------------
elif page == "📖About":
    st.title("📖About Cyber Sentinel")

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
                <p><strong>Cyber Sentinel</strong> is an intelligent machine learning system designed to detect phishing websites in real-time using models like <em>CatBoost, XGBoost, LightGBM</em>, and <em>Random Forest</em>.</p>

            This project is developed as a part of the Cyber Security Project during Industrial Training course in Electronics and Communication Engineering (7th sem) under B.Tech course.
            It focus on cyber threat prevention and digital safety.

            Developed By: Miss.Sneha Sharma
               Guided By: Mr.Rakshit Mehra

            Use the sidebar to explore the prediction page, results, and understand how machine learning protects you from phishing threats.
            
        </div>
    """, unsafe_allow_html=True)
