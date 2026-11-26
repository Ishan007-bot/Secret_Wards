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
# a general first-name gazetteer (pan-Indian; used as a soft signal only, never as the only rule)
FIRST_NAMES = set("""
aarav aditya ajay akash akhil alok amar amit amitabh anand anil ankit anoop anuj anurag arjun arun ashok
ashish avinash balram bharat bhola brijesh chandan chetan deepak dev dharmendra dhiraj dilip dinesh
gaurav girish gopal govind hari harish hemant hitesh jagdish jai jitendra kailash kamal kamlesh kapil
karan kishan kishore krishna kuldeep lalit mahendra mahesh manish manoj mohan mukesh naresh naveen
nitin om pankaj pawan prakash pramod pradeep prashant raghav rahul rajan rajesh rajiv rakesh ram ramesh
ravi rohit sachin sandeep sanjay santosh satish shailesh shankar shiv shyam subhash sudhir sunil suresh
tarun umesh vijay vikas vikram vinod vipin vishal vivek yash yogesh ashok raju babloo pappu munna
anita anjali archana asha babita bharti chanda deepa durga gayatri geeta guddi hema indu jyoti kamla
kanchan kavita kiran kusum lakshmi lata manju meena meera mamta neelam neha nisha poonam pooja priya
pushpa radha rani rekha renu rina reena ritu sangeeta sapna sarita savita seema shanti sheela shobha
shweta sita sunita sushma suman urmila usha vandana vimla parvati kamini malti phoolmati ramkali
mohammad mohammed muhammad ahmad ahmed ali arif asif aslam azhar faisal farhan imran irfan javed
kalim khalid naseem nadeem rashid rizwan salim saleem shahid shakeel sohail tariq wasim zubair yusuf
zakir anwar akbar iqbal mustafa usman aamir sameer shabbir fatima fatma ayesha zainab salma shabana
rukhsar nazia nasreen parveen rehana shaheen sultana yasmin zeenat farida hina sana tabassum
gurpreet harpreet jaspreet manpreet simran sukhwinder kuldeep jasbir gurmeet harjeet balwinder
paramjit amarjit lakhwinder navjot ranjit
anthony joseph john thomas george mathew peter paul mary maria grace elizabeth susan agnes
arumugam murugan senthil karthik ganesh venkatesh srinivas lakshmanan subramanian raman ramesh
selvam saravanan balaji kannan vel ilavenil kaveri meenakshi lalitha kalaivani valli priya
sourav subhajit debashish arnab abhijit anirban partha tapas sanjib ranjan shyamal bapi rupa
mousumi sharmistha tanushree swati moumita
tenzin tsering dolma pema karma lobsang dawa wangmo nima sonam
""".split())

SURNAMES = set("""
sharma verma gupta agarwal agrawal bansal goel mittal jain singh yadav kumar mishra tiwari tripathi
pandey dubey dwivedi trivedi chaturvedi shukla srivastava saxena mathur nigam kulshrestha asthana
chauhan rathore thakur rajput sisodia tomar bhadoria parmar solanki patel shah mehta desai joshi
kushwaha maurya kurmi lodhi lodh nishad kewat mallah paswan chamar jatav valmiki pasi kori rawat
prajapati kumhar vishwakarma lohar sonar soni swarnkar teli sahu gupta chaudhary chaudhari choudhary
jat gurjar meena bairwa ansari siddiqui qureshi khan pathan shaikh sheikh malik mirza beg rizvi
naqvi zaidi hashmi farooqui usmani alvi abbasi saifi idrisi mansoori bano begum khatoon
gill sandhu sidhu dhillon grewal brar bedi kaur arora khanna kapoor malhotra chopra bhatia sethi
masih david fernandes dsouza pinto gomes rodrigues
iyer iyengar nair menon pillai reddy rao naidu chetty gowda shetty hegde nambiar namboodiri kurup
subramaniam krishnan raman pandian mudaliar
bhattacharya chatterjee banerjee mukherjee ganguly das dutta ghosh bose sen roy saha paul mondal
biswas sarkar majumdar
qadri bhutia lepcha sherpa wangmo lama tamang gurung
""".split())

# ----------------------------------------------------------------------------------------------
# district / state names are kept (coarse, and a preserve value); they must never enter the vault
REGION_WORDS = {
    "uttar", "pradesh", "up", "india", "bihar", "lucknow", "kanpur", "delhi", "barabanki", "sultanpur",
    "sitapur", "hardoi", "unnao", "bahraich", "rae", "bareli", "raebareli", "gonda", "faizabad", "ayodhya",
}
