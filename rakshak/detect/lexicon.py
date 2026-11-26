"""Team-written lexicons: header/label vocabulary, honorifics, relations, protected clinical terms,
and a general pan-Indian name gazetteer. Nothing here is copied from the practice dataset; the
gazetteer is general knowledge of common Indian names across regions and communities.
"""
from __future__ import annotations

# ----------------------------------------------------------------------------------------------
# honorifics / kinship words that follow (or precede) a person's name in Hinglish and Hindi
HONORIFICS_AFTER = [
    "ji", "jee", "sahab", "saheb", "sahib", "saab", "didi", "behenji", "behen", "bhai", "bhaiya", "bhaiyya",
    "bhabhi", "babu", "amma", "ammi", "maa", "mama", "mami", "chacha", "chachi", "chachu", "papa", "uncle",
    "aunty", "auntie", "dada", "dadi", "nana", "nani", "bhaisahab", "sir", "madam", "beta", "beti", "baba",
    "जी", "साहब", "दीदी", "बहनजी", "भाई", "भैया", "भाभी", "बाबू", "अम्मा", "चाचा", "चाची", "मामा", "बाबा",
]
HONORIFICS_BEFORE = [
    "shri", "sri", "shree", "smt", "smt.", "shrimati", "kumari", "km.", "mr", "mr.", "mrs", "mrs.", "ms", "ms.",
    "master", "baby", "late", "श्री", "श्रीमती", "सुश्री", "कुमारी", "स्व.",
]

# name parts that never identify anyone on their own (do not match them alone)
GENERIC_NAME_TOKENS = {
    "devi", "kumar", "kumari", "lal", "bai", "bano", "begum", "singh", "kaur", "md", "md.", "mohd", "mohd.",
    "ji", "ram", "prasad", "nath", "chand", "das", "khatun", "khatoon", "rani", "bibi", "patient", "name",
    "देवी", "कुमार", "कुमारी", "लाल", "बाई", "बानो", "बेगम", "सिंह", "कौर", "मो.",
}

# relation markers: <marker> <relative name>
RELATION_MARKERS = r"(?:S/o|D/o|W/o|C/o|H/o|s/o|d/o|w/o|c/o|S/O|D/O|W/O|C/O|S\.O\.|D\.O\.|W\.O\.)"
RELATION_MARKERS_DEVA = r"(?:पुत्र|पुत्री|पत्नी|पति|पिता|माता|बेटा|बेटी)"

# words that, right after C/O, mean "complaint of" rather than "care of"
COMPLAINT_WORDS = {
    "fever", "pain", "cough", "cold", "vomiting", "vomit", "nausea", "loose", "diarrhoea", "diarrhea",
    "headache", "weakness", "breathlessness", "breathing", "chest", "abdominal", "abdomen", "burning",
    "giddiness", "dizziness", "swelling", "rash", "itching", "bleeding", "body", "joint", "back", "fatigue",
    "palpitations", "sob", "dyspnoea", "dysuria", "constipation", "anorexia", "jaundice", "seizure",
    "fits", "unconsciousness", "bukhar", "dard", "khansi", "ulti", "dast", "chakkar", "kamzori", "sujan",
    "pet", "sir", "saans", "high", "low", "on", "off", "and", "with", "since", "x",
}

# ----------------------------------------------------------------------------------------------
# protected clinical vocabulary (never a person / place even when Title-Cased)
CLINICAL_WORDS = {
    "fever", "pain", "cough", "diabetes", "hypertension", "dengue", "malaria", "typhoid", "tuberculosis",
    "asthma", "pneumonia", "anaemia", "anemia", "jaundice", "hepatitis", "cholera", "rabies", "covid",
    "medicine", "surgery", "paediatrics", "pediatrics", "orthopaedics", "gynaecology", "obstetrics",
    "cardiology", "neurology", "nephrology", "pulmonology", "dermatology", "psychiatry", "ent", "ophthalmology",
    "emergency", "casualty", "icu", "ward", "bed", "opd", "ipd", "discharge", "admission", "summary",
    "diagnosis", "history", "advice", "review", "tab", "cap", "inj", "syp", "syrup", "tablet", "capsule",
    "injection", "paracetamol", "dolo", "amlodipine", "metformin", "insulin", "ramipril", "telmisartan",
    "pantoprazole", "ceftriaxone", "azithromycin", "amoxicillin", "doxycycline", "artesunate", "rifampicin",
    "isoniazid", "levothyroxine", "salbutamol", "atorvastatin", "aspirin", "glimepiride", "ors", "normal",
    "saline", "haemoglobin", "hemoglobin", "creatinine", "sodium", "potassium", "platelet", "platelets",
    "bilirubin", "glucose", "sugar", "random", "fasting", "urine", "blood", "serum", "count", "total",
    "report", "result", "results", "test", "lab", "pathology", "diagnostics", "hospital", "clinic",
    "patient", "doctor", "nurse", "attendant", "visitor", "consultant", "referral", "letter", "consent",
    "form", "note", "notes", "nursing", "routine", "stable", "condition", "temp", "pulse", "spo2", "bp",
    "rbs", "fbs", "hba1c", "tsh", "wbc", "rbc", "esr", "crp", "ecg", "xray", "x-ray", "usg", "ct", "mri",
    "disease", "syndrome", "disorder", "infection", "fracture", "injury", "bite", "snake", "dog", "acute",
    "chronic", "unspecified", "primary", "essential", "type", "stage", "left", "right", "bilateral",
    "january", "february", "march", "april", "may", "june", "july", "august", "september", "october",
    "november", "december", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
    "forwarded", "attachment", "male", "female", "yes", "no", "date", "time", "sample", "received",
    "anm", "aww", "pmjay", "ayushman", "settled", "pending", "approved", "rejected", "closed", "open",
}

# ----------------------------------------------------------------------------------------------
# name gazetteer (soft CRF feature only): built by training/build_gazetteer.py from Faker en_IN/hi_IN
# and a team list, with every practice-data name removed. Loaded from rakshak/data/*.txt.
def _load(name: str) -> set:
    from pathlib import Path
    p = Path(__file__).resolve().parent.parent / "data" / name
    try:
        return {l.strip() for l in p.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")}
    except OSError:
        return set()


FIRST_NAMES = _load("first_names.txt")
SURNAMES = _load("surnames.txt")

# ----------------------------------------------------------------------------------------------
# district / state names are kept (coarse, and a preserve value); they must never enter the vault
REGION_WORDS = set("""
uttar pradesh up india bihar delhi agra aligarh amethi amroha auraiya ayodhya azamgarh baghpat
bahraich ballia balrampur banda barabanki bareilly basti bhadohi bijnor budaun bulandshahr chandauli chitrakoot
deoria etah etawah farrukhabad fatehpur firozabad noida ghaziabad ghazipur gonda gorakhpur
hamirpur hapur hardoi hathras jalaun jaunpur jhansi kannauj kanpur dehat kasganj kaushambi kushinagar lakhimpur
kheri lalitpur lucknow maharajganj mahoba mainpuri mathura mau meerut mirzapur moradabad muzaffarnagar
pilibhit pratapgarh prayagraj allahabad rae bareli raebareli rampur saharanpur sambhal shahjahanpur
shamli shravasti siddharthnagar sitapur sonbhadra sultanpur unnao varanasi faizabad
andhra arunachal assam chhattisgarh goa gujarat haryana himachal jharkhand karnataka kerala madhya maharashtra
manipur meghalaya mizoram nagaland odisha orissa punjab rajasthan sikkim tamil nadu telangana tripura
uttarakhand west bengal jammu kashmir ladakh puducherry pondicherry chandigarh mumbai kolkata chennai bengaluru
bangalore hyderabad pune ahmedabad jaipur patna guwahati bhubaneswar thiruvananthapuram kochi surat indore
nagpur dehradun ranchi raipur shimla srinagar
""".split())
