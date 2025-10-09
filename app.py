# app.py
import streamlit as st
import plotly.graph_objects as go
import string
import secrets

from analyzer import score_password, estimate_time_to_crack_seconds, human_readable_seconds

st.set_page_config(page_title="Password Strength Estimator", layout="centered")
st.title("🔐 Password Strength Estimator")

st.write("Type a password below to analyze its strength (nothing is stored).")

# Initialize session_state
if "password_input" not in st.session_state:
    st.session_state["password_input"] = ""

# ---------------------------
# Password generator function
# ---------------------------
def generate_password(length, lower, upper, digits, symbols):
    char_pool = ""
    if lower:
        char_pool += string.ascii_lowercase
    if upper:
        char_pool += string.ascii_uppercase
    if digits:
        char_pool += string.digits
    if symbols:
        char_pool += "!@#$%^&*()-_=+[]{}|;:,.<>?/~`"
    if not char_pool:
        return ""
    return "".join(secrets.choice(char_pool) for _ in range(length))

def on_generate():
    pw = generate_password(
        st.session_state.gen_length,
        st.session_state.use_lower,
        st.session_state.use_upper,
        st.session_state.use_digits,
        st.session_state.use_symbols
    )
    st.session_state.password_input = pw

# ---------------------------
# Generator UI
# ---------------------------
st.markdown("---")
st.subheader("🔧 Generate a strong password")

col1, col2 = st.columns(2)
with col1:
    st.slider("Length", 8, 32, 16, key="gen_length")
    st.checkbox("Include lowercase", value=True, key="use_lower")
    st.checkbox("Include UPPERCASE", value=True, key="use_upper")
with col2:
    st.checkbox("Include digits", value=True, key="use_digits")
    st.checkbox("Include symbols", value=True, key="use_symbols")
    st.button("Generate & Copy to field", on_click=on_generate)

# ---------------------------
# Password input (no value param!)
# ---------------------------
password = st.text_input("Password", type="password", key="password_input")

# ---------------------------
# Password Analysis
# ---------------------------
if password:
    result = score_password(password)
    score = result.get("score", 0)
    entropy = result.get("entropy", 0)
    details = result.get("details", [])
    feedback = result.get("feedback", [])

    # --- Gauge visualization ---
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            title={"text": "Password Strength"},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": "green" if score > 70 else "orange" if score > 40 else "red"},
                "steps": [
                    {"range": [0, 40], "color": "#ff4d4d"},
                    {"range": [40, 70], "color": "#ffd633"},
                    {"range": [70, 100], "color": "#4CAF50"},
                ],
            },
        )
    )
    st.plotly_chart(fig, use_container_width=True)

    st.markdown(f"**Entropy:** {entropy} bits")

    st.markdown("**Estimated time to crack (average)**")
    scenarios = {
        "Online attacker (1,000 guesses/sec)": 1e3,
        "Weak offline attacker (1,000,000 guesses/sec)": 1e6,
        "Strong GPU cluster (10,000,000,000 guesses/sec)": 1e10,
        "Massive botnet / specialized hardware (100,000,000,000,000 guesses/sec)": 1e14,
    }
    for label, gps in scenarios.items():
        secs = estimate_time_to_crack_seconds(entropy, gps)
        hr = human_readable_seconds(secs)
        st.write(f"- {label}: **{hr}**")

    st.markdown("### 🔍 Details")
    for d in details:
        st.write("•", d)

    if feedback:
        st.markdown("### 💡 Suggestions")
        for f in feedback:
            st.write("✅", f)
    else:
        st.success("✅ Excellent password — no suggestions!")
else:
    st.info("Enter a password above to start the analysis.")
