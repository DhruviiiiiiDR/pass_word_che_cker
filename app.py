"""
app.py - Streamlit web interface for the Password Strength Checker.

Features real-time strength evaluation, visual colored meter,
detailed security metrics, feedback, and tips.
No passwords are logged or stored.
"""

import streamlit as st
from checker_core import (
    calculate_entropy,
    calculate_score,
    check_digits,
    check_length,
    check_lowercase,
    check_patterns,
    check_special_chars,
    check_uppercase,
    estimate_crack_time,
    get_feedback,
    get_strength_rating,
    get_suggestions,
)

# Page configuration
st.set_page_config(
    page_title="Password Strength Checker",
    page_icon="🔐",
    layout="centered",
)

# Title & header
st.title("🔐 Password Strength Checker")
st.caption(
    "Analyze password strength instantly using entropy estimation, "
    "pattern recognition, and security heuristics. All checks run locally."
)

# Color mapping for rating levels
COLOR_MAP = {
    "Weak": "#ff4b4b",        # Red
    "Moderate": "#ffa500",    # Orange
    "Strong": "#f1c40f",      # Yellow
    "Very Strong": "#2ecc71", # Green
}

# Input field with masking
password = st.text_input(
    label="Enter Password",
    type="password",
    placeholder="Type a password to test...",
    help="Your input is processed strictly in-memory and never saved or transmitted.",
)

if password:
    score = calculate_score(password)
    rating = get_strength_rating(score)
    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)
    feedback_items = get_feedback(password)
    suggestions = get_suggestions(password)

    bar_color = COLOR_MAP.get(rating, "#808080")

    # Dynamic CSS styling to color the st.progress bar according to rating
    st.markdown(
        f"""
        <style>
            .stProgress > div > div > div > div {{
                background-color: {bar_color};
            }}
            div[data-testid="stMetricValue"] {{
                font-size: 1.8rem;
            }}
        </style>
        """,
        unsafe_allow_html=True,
    )

    # Progress bar strength meter
    st.write(f"**Strength Meter:** {rating} ({score}/100)")
    st.progress(score / 100)

    # Primary metrics display
    st.write("")
    col1, col2, col3 = st.columns(3)
    col1.metric(label="Strength", value=rating)
    col2.metric(label="Score", value=f"{score}/100")
    col3.metric(label="Est. Crack Time", value=crack_time)

    st.divider()

    # Rule breakdown checklist
    st.subheader("📋 Security Criteria")
    c1, c2 = st.columns(2)
    with c1:
        st.write("✅ At least 8 characters" if check_length(password, 8) else "❌ Minimum 8 characters")
        st.write("✅ Contains lowercase (a-z)" if check_lowercase(password) else "❌ Lowercase letters")
        st.write("✅ Contains uppercase (A-Z)" if check_uppercase(password) else "❌ Uppercase letters")
    with c2:
        st.write("✅ Contains digits (0-9)" if check_digits(password) else "❌ Digits (0-9)")
        st.write("✅ Contains special characters" if check_special_chars(password) else "❌ Special characters")
        st.write("❌ Predictable patterns detected" if check_patterns(password) else "✅ No obvious patterns")

    st.write(f"**Entropy:** `{entropy} bits` (estimated search space)")

    st.divider()

    # Feedback section with warning icons
    st.subheader("⚠️ Issues & Feedback")
    for item in feedback_items:
        st.markdown(f"- ⚠️ {item}")

    # Suggestions section with tip icons
    st.subheader("💡 Suggestions for Improvement")
    for tip in suggestions:
        st.markdown(f"- 💡 {tip}")

else:
    st.info(
        "👆 Enter a password in the field above to view real-time strength, "
        "entropy calculation, crack time estimation, and security feedback."
    )

    st.markdown(
        """
        ---
        ### 🛡️ Why Password Strength Matters
        - **Length:** Longer passwords exponentially increase the search space for attackers.
        - **Character Diversity:** Combining uppercase, lowercase, numbers, and symbols maximizes entropy.
        - **Avoid Patterns:** Sequential numbers (`1234`) and keyboard walks (`qwerty`) are tested first in dictionary attacks.
        """
    )
