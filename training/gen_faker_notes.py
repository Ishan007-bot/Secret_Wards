#!/usr/bin/env python3
"""Generate synthetic Indian clinical notes with gold NAME / ADDR spans (training only).

Every note mixes personal data with the meaning traps that must stay (doctor sharing a relative's
first name, "C/O fever", 1-0-1 dosing, eponyms, ASHA worker, hospital wards), across discharge
summaries, Hinglish nursing notes, Hindi prescriptions, WhatsApp forwards, OPD notes and visitor /
ambulance / helpdesk logs, with labels and orders NOT copied from the practice data.
Names: Faker en_IN / hi_IN plus pan-Indian pools and invented "never-seen" names (canary-like).

    python training/gen_faker_notes.py --n 6000 --seed 7
"""
from __future__ import annotations

import argparse
import random
import re

from faker import Faker

from bio import BIO, write_jsonl

PAN_FIRST = """Arumugam Senthil Karthikeyan Lakshmi Meenakshi Subramanian Venkatesh Padma Revathi Murugan Anbu
Suresh Bijoy Subhash Debashish Sourav Mousumi Tanushree Ananya Arindam Partha Joydeep Gurpreet Harjinder
Manjit Jaswinder Baljeet Simranjeet Navdeep Thomas Joseph Mary Annamma Biju Shibu Lalitha Ayesha Imran
Shahnawaz Rukhsar Nazia Tabassum Irfan Zaheer Farhana Tenzin Dorjee Pema Lhamo Lalremsiama Zothanpuii
Mawii Thangjam Bembem Ibomcha Rajeshwari Vijayalakshmi Hemalatha Prasanna Kavitha Gowri Narayanan
Siddharth Ishaan Kabir Advait Myra Kiara Aadhya Vihaan Reyansh Tanvi Nikhil Pranav Sneha Pooja Rahul""".split()
PAN_LAST = """Iyer Pillai Nair Menon Reddy Naidu Gowda Hegde Shetty Banerjee Chatterjee Mukherjee Ghosh Bose Sen
Dutta Sandhu Gill Dhillon Grewal Sidhu Kurian Varghese Fernandes D'Souza Pereira Qureshi Ansari Siddiqui
Shaikh Pathan Bhutia Lepcha Sherpa Singha Meitei Ralte Chakma Patil Deshmukh Kulkarni Jadhav Pawar Desai
Mehta Shah Patel Joshi Trivedi Bhatt Rawat Negi Bisht Thakur Chauhan Rathore Yadav Kushwaha Maurya""".split()
SYL = "ra ma ka la na sa ta pa va ja da ha ga ba ya ri mi ki li ni si ti vi ji di hi gi bi u o e an in un".split()
VIL_ROOT = "Ram Sita Shiv Hasan Bel Amar Kesh Daulat Fateh Bhawani Lal Gopal Chandan Mohan Bahadur Raja Rani Kamal".split()
VIL_SUF = "pur ganj nagar khera mau abad garh pura gaon tola dih bari wala".split()
VIL_DEVA_ROOT = "राम शिव हसन बेल अमर केश दौलत फतेह भवानी लाल गोपाल चंदन मोहन".split()
VIL_DEVA_SUF = "पुर गंज नगर खेड़ा मऊ आबाद गढ़ पुरा गाँव डीह".split()
DRUGS = ["Tab Paracetamol 650 mg 1-0-1 x 5 days", "Tab Amlodipine 5 mg 0-0-1", "Inj Ceftriaxone 1 g IV BD",
         "Tab Metformin 500 mg 1-0-1", "Syp Azithromycin 200 mg OD x 3 days", "Tab Telmisartan 40 mg 1-0-0",
         "Cap Omeprazole 20 mg 1-0-0 before food", "Tab Atorvastatin 10 mg 0-0-1", "ORS 1 sachet after each loose stool"]
DX = ["Type 2 diabetes mellitus (E11.9)", "Essential hypertension (I10)", "Dengue fever (A90)", "Typhoid fever (A01.0)",
      "Acute gastroenteritis (A09)", "Community acquired pneumonia (J18.9)", "Bell's palsy (G51.0)",
      "Parkinson's disease (G20)", "Wilson's disease (E83.0)", "Crohn's disease (K50.9)", "Pulmonary tuberculosis (A15.0)"]
COMPLAINTS = ["C/O fever for 6 days", "C/O pain abdomen x 3 days", "C/O cough with sputum since 1 week",
              "K/C/O hypertension on regular medication", "H/O TB 8 yrs back, completed ATT", "pet mein dard 2 din se",
              "bukhar aur sir dard 3 din se", "C/O loose stools x 4 episodes"]
WARDS = ["Ward 4 (Medicine) / Bed 29", "Ward 2 (Surgery), Bed 11", "ICU Bed 3", "Female Ward Bed 17", "Ward 6 (Paediatrics)"]
HOSP = ["Sanjivani Community Hospital, Bareilly", "District Hospital, Gonda", "CHC Malihabad", "Shanti Nursing Home, Etawah",
        "Lok Kalyan Hospital, Basti", "Arogyam Clinic, Ballia"]
LABEL_NAME = ["Patient Name", "Pt Name -", "Name of Patient", "Naam", "Patient's Name", "Name", "PATIENT", "Naam-e-Mareez",
              "Pt.", "Patient"]
LABEL_REL = [("Father's Name", "M"), ("Husband's Name", "F"), ("Guardian", None), ("Attendant", None),
             ("Accompanied by", None), ("Rishtedar", None), ("Informant", None), ("Next of kin", None)]
REL_MARK = ["S/o", "W/o", "D/o", "C/O"]
HON = ["ji", "sahab", "behenji", "bhaiya", "didi", "amma", "chachu", "bhai"]


class Gen:
    def __init__(self, seed: int):
        self.r = random.Random(seed)
        Faker.seed(seed)
        self.en = Faker("en_IN")
        self.hi = Faker("hi_IN")

    # ------------------------------------------------------------------ values
    def first(self, sex=None):
        r = self.r.random()
        if r < 0.15:
            return "".join(self.r.choice(SYL) for _ in range(self.r.randint(2, 3))).capitalize()   # never-seen name
        if r < 0.45:
            return self.r.choice(PAN_FIRST)
        return self.en.first_name_male() if sex == "M" else self.en.first_name_female() if sex == "F" \
            else self.en.first_name()

    def last(self):
        return self.r.choice(PAN_LAST) if self.r.random() < 0.4 else self.en.last_name()

    def full(self, sex=None):
        n = f"{self.first(sex)} {self.last()}"
        c = self.r.random()
        return n.upper() if c < 0.05 else n

    def deva_full(self):
        return f"{self.hi.first_name()} {self.hi.last_name()}"

    def village(self, deva=False):
        if deva:
            return self.r.choice(VIL_DEVA_ROOT) + self.r.choice(VIL_DEVA_SUF)
        v = self.r.choice(VIL_ROOT) + self.r.choice(VIL_SUF)
        return v + (" " + self.r.choice(["Kalan", "Khurd", "Buzurg"]) if self.r.random() < 0.2 else "")

    def house(self, deva=False):
        n = self.r.randint(1, 999)
        if deva:
            return self.r.choice([f"मकान नं. {n}", f"म.नं. {n}"])
        return self.r.choice([f"H.No. {n}", f"House No {n}", f"Makan No. {n}", f"#{n}", f"Qtr No. {n}"])

    def locality(self):
        return self.r.choice([f"Mohalla {self.r.choice(VIL_ROOT)} Bazar", f"Ward {self.r.randint(1, 40)}",
                              f"{self.r.choice(VIL_ROOT)} Colony", f"Gali No. {self.r.randint(1, 20)}",
                              f"{self.r.choice(VIL_ROOT)} Tola"])

    def landmark(self):
        return self.r.choice([f"near {self.r.choice(['Pani Tanki', 'Shiv Mandir', 'Primary School', 'Bus Adda', 'Masjid'])}",
                              f"opp. {self.r.choice(['Post Office', 'Gram Panchayat Bhawan', 'Petrol Pump'])}",
                              f"behind {self.r.choice(['Sabzi Mandi', 'Thana', 'Rice Mill'])}"])

    def phone(self):
        d = str(self.r.choice([6, 7, 8, 9])) + "".join(str(self.r.randint(0, 9)) for _ in range(9))
        return self.r.choice([d, f"+91 {d[:5]} {d[5:]}", f"{d[:5]}-{d[5:]}", f"+91-{d}"])

    def date(self):
        return f"{self.r.randint(1, 28):02d}/{self.r.randint(1, 12):02d}/2026"

    # ------------------------------------------------------------------ templates
    def note(self):
        kind = self.r.choice(["discharge", "opd", "nursing", "rx_hi", "whatsapp", "visitor", "ambulance", "referral",
                              "helpdesk", "lab"])
        return getattr(self, "t_" + kind)()

    def _build(self, parts):
        text, spans = "", []
        for p in parts:
            if isinstance(p, tuple):
                val, typ = p
                spans.append([len(text), len(text) + len(val), typ, "deva" if re.search(r"[ऀ-ॿ]", val)
                              else "latin"])
                text += val
            else:
                text += p
        return text, spans

    def _addr(self, deva=False):
        parts = []
        if self.r.random() < 0.8:
            parts += [(self.house(deva), "ADDR"), ", "]
        if not deva and self.r.random() < 0.6:
            parts += [(self.locality(), "ADDR"), ", "]
        if not deva and self.r.random() < 0.4:
            parts += [(self.landmark(), "ADDR"), ", "]
        parts += ["ग्राम " if deva else self.r.choice(["Village ", "Vill. ", "Gram ", ""]), (self.village(deva), "ADDR")]
        parts += [", " + ("जिला सीतापुर" if deva else self.r.choice(["Distt. Hardoi", "District Sitapur", "Barabanki",
                                                                    "Tehsil Sadar, Gonda"]))]
        return parts

    def t_discharge(self):
        sex = self.r.choice("MF")
        p, rel = self.full(sex), self.full("M")
        relf = rel.split()[0]
        dr = f"Dr. {relf} {self.last()}" if self.r.random() < 0.3 else f"Dr. {self.full()}"
        lab_rel = self.r.choice(LABEL_REL)[0]
        parts = [self.r.choice(HOSP), "\nDISCHARGE SUMMARY\n", self.r.choice(LABEL_NAME), ": ", (p, "NAME"),
                 f"    Age/Sex: {self.r.randint(18, 90)}/{sex}\n", f"{lab_rel}: ", (rel, "NAME"), "\n",
                 "Address: "] + self._addr() + [f"\nMobile: {self.phone()}\nIPD No: IPD-2026-{self.r.randint(100, 999)}\n",
                 f"Date of Admission: {self.date()}\nDate of Discharge: {self.date()}\n",
                 f"Ward: {self.r.choice(WARDS)}\n", f"Chief complaints: {self.r.choice(COMPLAINTS)}\n",
                 f"Diagnosis: {self.r.choice(DX)}\n", "Treatment given:\n- " + "\n- ".join(self.r.sample(DRUGS, 3)),
                 f"\nPatient seen by {dr}. Relative {relf} counselled about diet.\n",
                 self.r.choice(["Referred by ASHA worker of the village.\n", "BP 128/82 mmHg, SpO2 97%, Pulse 88/min\n"]),
                 f"Consultant: {dr}\n"]
        return self._build(parts)

    def t_opd(self):
        sex = self.r.choice("MF")
        p = self.full(sex)
        mark = self.r.choice(REL_MARK)
        rel = self.full("M")
        parts = [f"OPD Slip  {self.date()}\n", (p, "NAME"), f", {self.r.randint(2, 85)} Y / {sex}, {mark} ", (rel, "NAME"),
                 "\n", "R/o "] + self._addr() + [f"\n{self.r.choice(COMPLAINTS)}\nBP 140/90, Temp 99.2 F\n",
                 f"Rx: {self.r.choice(DRUGS)}\nReview after 1 week. -- Dr. {self.full()}\n"]
        return self._build(parts)

    def t_nursing(self):
        pf = self.first()
        hon = self.r.choice(HON)
        rf = self.first("M")
        parts = [f"Nursing note {self.date()} 08:00\n", (pf, "NAME"), f" {hon} ka BP 112/78, sugar 186 mg/dl.\n",
                 "Raat ko bukhar tha, Tab PCM diya. ", (rf, "NAME"), f" {self.r.choice(HON)} (attendant) ne bataya ki ",
                 "khana kam kha rahe hain.\n", f"Bed {self.r.randint(1, 40)} -- {self.r.choice(WARDS)}\n",
                 f"Duty sister: S/N {self.first('F')}\n"[:0], "Plan: continue IV fluids, 1-0-1 antibiotics.\n"]
        return self._build(parts)

    def t_rx_hi(self):
        p = self.deva_full()
        rel = self.deva_full()
        parts = ["पर्चा\n", self.r.choice(["मरीज़ का नाम", "रोगी का नाम", "नाम"]), ": ", (p, "NAME"),
                 f"   आयु: {self.r.randint(5, 80)} वर्ष\n", self.r.choice(["पिता का नाम", "पति का नाम"]), ": ", (rel, "NAME"),
                 "\nपता: "] + self._addr(deva=True) + ["\n", "दवा: Tab Paracetamol 500 mg 1-0-1 x 3 दिन\n",
                 "बुखार 3 दिन से। खूब पानी पिएं।\n"]
        return self._build(parts)

    def t_whatsapp(self):
        rf = self.first()
        hon = self.r.choice(["Bhaiya", "Chachu", "Mama", "Papa", "Didi", "Uncle"])
        pf = self.first()
        parts = [f"[{self.r.randint(1, 28):02d}/{self.r.randint(1, 12):02d}/26, {self.r.randint(7, 11)}:{self.r.randint(10, 59)} pm] ",
                 (f"{rf} {hon}", "NAME"), ": <attachment: report.pdf>\nForwarded: CBC report of ", (pf, "NAME"),
                 f"\nHb 9.8 g/dL, TLC 11200 /uL, Platelets 1.2 lakh\n", f"Dr sahab ne bola {self.r.choice(DX).split(' (')[0]} hai\n"]
        return self._build(parts)

    def t_visitor(self):
        rows = ["VISITOR REGISTER\n"]
        for _ in range(self.r.randint(2, 4)):
            rows += [f"{self.date()} {self.r.randint(10, 19)}:00  ", (self.full(), "NAME"),
                     f" ({self.r.choice(['attendant', 'son', 'wife', 'brother'])}, bed {self.r.randint(1, 40)}), mob {self.phone()}\n"]
        return self._build(rows)

    def t_ambulance(self):
        parts = ["108 AMBULANCE CALL LOG\n", "Called by ", (self.full(), "NAME"), f" {self.phone()} at 02:14\n",
                 "Pickup: "] + self._addr() + [f"\nPatient: ", (self.full(), "NAME"), ", unconscious, snake bite suspected\n",
                 "Taken to Emergency, " + self.r.choice(HOSP) + "\n"]
        return self._build(parts)

    def t_referral(self):
        d1 = self.first("M")
        parts = [f"Referral letter\nTo, Dr. {d1} {self.last()}, MD Medicine\n", "Kindly see ", (self.full(), "NAME"),
                 f", {self.r.randint(20, 80)} yrs, ", self.r.choice(REL_MARK) + " ", (self.full(), "NAME"),
                 f", K/C/O {self.r.choice(['diabetes', 'hypertension', 'asthma'])}. ", self.r.choice(DX),
                 ". Referred by ASHA worker.\n"]
        return self._build(parts)

    def t_helpdesk(self):
        parts = ["Helpdesk ticket #", str(self.r.randint(1000, 9999)), "\nCaller: ", (self.full(), "NAME"),
                 f" ({self.phone()}) asking about discharge of ", (self.full(), "NAME"),
                 f" admitted in {self.r.choice(WARDS)}.\nInformed to call after 4 pm.\n"]
        return self._build(parts)

    def t_lab(self):
        parts = [f"{self.r.choice(HOSP)} - Pathology\n", "Name: ", (self.full(), "NAME"),
                 f"   Age: {self.r.randint(1, 90)} Yrs   Ref. by: Dr. {self.full()}\n",
                 "Haemoglobin 8.2 g/dL (13-17)\nTotal WBC Count 13000 /uL\nRandom blood sugar 210 mg/dL\n",
                 "Sample collected at home: "] + self._addr() + ["\n"]
        return self._build(parts)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=6000)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    g = Gen(a.seed)
    rows = []
    for i in range(a.n):
        text, spans = g.note()
        rows.append({"text": text, "spans": spans, "source": "faker", "split": "dev" if i % 10 == 0 else "train"})
    n = write_jsonl(BIO / "faker.jsonl", rows)
    print(f"faker: {n} notes, {sum(len(r['spans']) for r in rows)} spans")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
