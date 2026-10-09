from flask import Flask, render_template, request
import re

app = Flask(__name__)

# Suspicious words and phrases often found in scam job advertisements.
# These are warning signs only; they do not prove that a job is fake.
SUSPICIOUS_PATTERNS = {
    "Registration Fee": [
        "registration fee", "joining fee", "processing fee", "application fee",
        "security deposit", "pay first", "registration charge", "joining charge",
        "verification fee", "training fee", "document verification fee", "refundable fee",
    ],
    "No Interview": [
        "no interview", "without interview", "direct selection", "direct joining",
        "selected immediately", "selection without interview", "no qualification required",
        "no skills required",
    ],
    "Urgent Hiring": [
        "urgent hiring", "immediate joining", "apply now", "limited vacancies",
        "join immediately", "hiring urgently", "last few vacancies", "limited seats",
        "apply today", "start immediately",
    ],
    "Unrealistic Income": [
        "earn money fast", "easy money", "quick money", "guaranteed income",
        "guaranteed salary", "guaranteed earnings", "high income", "earn huge money",
        "daily income", "instant income", "make money quickly", "get rich",
        "unlimited income", "earn lakhs",
    ],
    "Suspicious Payment": [
        "send money", "pay money", "deposit money", "advance payment",
        "payment required", "pay online", "send payment", "pay to confirm",
        "pay to get job", "money transfer required", "payment to secure job", "advance fee",
    ],
    "Suspicious Contact": [
        "whatsapp only", "telegram only", "contact on whatsapp", "contact via telegram",
        "whatsapp job", "telegram job", "dm on whatsapp", "message on whatsapp",
    ],
    "Personal Information Request": [
        "bank account details", "bank details", "account number", "send otp",
        "otp required", "cvv", "card number", "atm pin", "credit card details",
        "debit card details", "aadhaar details", "pan card details",
    ],
    "Easy Work Claims": [
        "simple online work", "easy online work", "simple work from home",
        "no skills needed", "no skills required", "copy paste job", "easy data entry",
        "just use your phone", "work anytime", "part time easy work",
    ],
    "Fake Guarantee": [
        "100% guaranteed job", "job guaranteed", "guaranteed placement",
        "guaranteed selection", "100% placement", "sure job", "selection guaranteed",
    ],
    "Urgency / Pressure": [
        "only today", "offer expires today", "act now", "hurry up",
    ],
    "Fake Interview": [
        "interview fee", "pay for interview", "interview charge", "online interview fee",
        "verification before interview", "interview guaranteed", "interview not required",
    ],
    "Fake Recruitment": [
        "recruitment fee", "recruitment charge", "placement fee", "placement charge",
        "job confirmation fee", "offer letter fee", "appointment letter fee",
        "job processing fee", "job registration",
    ],
    "Bank / Financial Request": [
        "bank account", "bank information", "account details", "upi id",
        "upi payment", "upi transfer", "google pay", "phonepe", "paytm",
        "credit card", "debit card", "bank password", "net banking password",
    ],
    "Identity Document Request": [
        "send aadhaar", "aadhaar card", "pan details", "pan card", "passport details",
        "driving licence", "driving license", "identity proof", "id proof",
        "upload identity document", "send id proof",
    ],
    "Suspicious Communication": [
        "contact recruiter on whatsapp", "contact recruiter on telegram",
        "only whatsapp", "only telegram", "whatsapp number", "telegram number",
        "personal whatsapp", "personal mobile number", "dm for job", "message me for job",
    ],
    "Fake Work From Home": [
        "work from home guaranteed", "home based job", "earn from home",
        "work from home no experience", "work from home without interview",
        "part time work from home", "easy home based work", "online earning job",
        "online earning opportunity",
    ],
    "Unrealistic Benefits": [
        "earn ₹5000 per day", "earn 5000 per day", "earn ₹10000 per day",
        "earn 10000 per day", "earn ₹50000 per month", "earn 50000 per month",
        "earn ₹1 lakh per month", "earn 1 lakh per month", "no investment high income",
        "guaranteed monthly income", "fixed income without work",
    ],
    "Fake Offer": [
        "congratulations you are selected", "you are selected", "you have been selected",
        "job offer confirmed", "offer confirmed", "selection confirmed",
        "instant job offer", "job available immediately",
    ],
    "Suspicious Links": [
        "click this link", "click the link", "open this link",
        "register using this link", "registration link", "payment link",
        "send payment link", "download this app", "install this app",
    ],
    "Advance Payment": [
        "pay before joining", "pay before interview", "pay before selection",
        "pay before getting job", "advance fee required", "deposit required",
        "security money", "refundable deposit", "non refundable fee", "non-refundable fee",
    ],
    "Too Good To Be True": [
        "zero investment", "no investment required", "earn without investment",
        "earn without working", "work 1 hour", "work 2 hours", "earn huge salary",
        "huge salary", "instant earning", "get rich quickly", "easy earning",
    ],
    "Suspicious Job Claims": [
        "100% job guarantee", "100% selection", "100% placement", "guaranteed job",
        "guaranteed selection", "guaranteed placement", "no qualification",
        "no degree required", "no experience needed", "instant job", "easy job",
    ],
    "Payment Before Joining": [
        "pay before starting", "pay before work", "payment before joining",
        "fee before joining", "deposit before joining", "money before joining",
        "pay to join", "pay to start work",
    ],
    "Suspicious Documents": [
        "send original documents", "submit original documents", "send passport",
        "send bank statement", "send atm card", "send debit card", "send credit card",
        "share personal documents", "share identity documents", "upload personal documents",
    ],
}


def analyze_job(company, title, salary, description):
    """Check a job advertisement for common scam warning signs."""
    company = (company or "").strip()
    title = (title or "").strip()
    salary = (salary or "").strip()
    description = (description or "").strip()
    text = f"{company} {title} {salary} {description}".lower()

    reasons = []
    detected_words = []
    score = 0

    for category, keywords in SUSPICIOUS_PATTERNS.items():
        found = [keyword for keyword in keywords if keyword in text]
        if found:
            detected_words.extend(found)
            reasons.append({"category": category, "words": found})
            score += min(len(found) * 10, 25)

    # A high monthly salary can be a warning sign in context, but is not proof.
    salary_text = salary.lower().replace(",", "")
    numbers = re.findall(r"\d+(?:\.\d+)?", salary_text)
    salary_numbers = []
    for number in numbers:
        try:
            salary_numbers.append(float(number))
        except ValueError:
            pass

    if salary_numbers and "month" in salary_text and max(salary_numbers) >= 100000:
        score += 20
        reasons.append({
            "category": "Unusually High Monthly Salary",
            "words": ["Monthly salary is above ₹1,00,000; verify the offer carefully."],
        })

    if len(description) < 30:
        score += 10
        reasons.append({
            "category": "Insufficient Job Details",
            "words": ["Very short job description"],
        })

    detected_words = list(dict.fromkeys(detected_words))
    score = min(score, 100)

    if score >= 60:
        prediction, risk = "FAKE / HIGH RISK", "HIGH"
    elif score >= 30:
        prediction, risk = "SUSPICIOUS", "MEDIUM"
    else:
        prediction, risk = "LIKELY REAL", "LOW"

    # This is a heuristic indicator, not a statistically trained ML confidence.
    if score >= 60:
        confidence = min(95, 70 + score // 5)
    elif score >= 30:
        confidence = 70
    else:
        confidence = 85

    if risk == "HIGH":
        suggestion = (
            "Do not pay registration, joining, or security fees. Never share OTP, CVV, "
            "bank, or card details. Verify the company through its official website."
        )
    elif risk == "MEDIUM":
        suggestion = (
            "Verify the recruiter, official company website, and job details before "
            "accepting the offer or sharing personal information."
        )
    else:
        suggestion = (
            "No major suspicious phrases were detected. This does not guarantee the job "
            "is genuine; verify the employer before sharing sensitive information."
        )

    return {
        "prediction": prediction,
        "score": score,
        "risk": risk,
        "confidence": confidence,
        "reasons": reasons,
        "detected_words": detected_words,
        "suggestion": suggestion,
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/detect", methods=["GET", "POST"])
def detect():
    result = None
    if request.method == "POST":
        company = request.form.get("company", "").strip()
        title = request.form.get("title", "").strip()
        salary = request.form.get("salary", "").strip()
        description = request.form.get("description", "").strip()

        result = analyze_job(company, title, salary, description)
        result.update({
            "company": company,
            "title": title,
            "salary": salary,
            "description": description,
        })

    return render_template("detect.html", result=result)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    message = ""
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        user_message = request.form.get("message", "").strip()

        if name and email and user_message:
            message = f"Thank you {name}! Your message has been received."
        else:
            message = "Please fill in all fields."

    return render_template("contact.html", message=message)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
