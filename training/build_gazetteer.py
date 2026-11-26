#!/usr/bin/env python3
"""Build the shipped name gazetteer from INDEPENDENT public sources, never from the practice data.

Sources: Faker en_IN + hi_IN person providers (MIT licence) and a team-written pan-Indian list.
Every token that appears as a patient / relative / canary name anywhere in the organiser practice
truth is REMOVED (Latin and Devanagari, plus transliteration), so the repository provably does not
memorise practice names. The gazetteer is only a soft feature of the CRF tagger.

    python training/build_gazetteer.py --kit ../Secret-Wards-ToolKit
"""
from __future__ import annotations

import argparse
import json
import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from faker.providers.person.en_IN import Provider as EN  # noqa: E402
from faker.providers.person.hi_IN import Provider as HI  # noqa: E402

from rakshak.link.translit import deva_to_latin  # noqa: E402

TEAM_FIRST = """aarav aditya akash akhil alok amar amit amitabh anand ankit anoop anuj anurag arjun arun ashish
avinash balram bharat bhola brijesh chandan chetan dev dharmendra dhiraj dilip gaurav girish gopal govind hari
harish hemant hitesh jagdish jai jitendra kailash kamlesh kapil karan kishore krishna lalit mahendra manish
naveen nitin om pankaj pawan prakash pramod pradeep prashant raghav rajan rajesh rajiv rakesh ram ramesh ravi
rohit sachin sandeep sanjay santosh satish shailesh shankar shiv subhash sudhir suresh tarun vikram vinod
vipin vishal vivek yash yogesh raju babloo pappu munna anjali archana babita bharti chanda deepa durga gayatri
guddi hema indu jyoti kanchan kiran kusum lakshmi lata manju meena meera mamta neelam neha nisha poonam pooja
priya pushpa radha rani rekha renu ritu sangeeta sapna savita seema sheela shobha shweta sita sushma suman
urmila vandana vimla kamini malti phoolmati ramkali mohammad mohammed muhammad ahmad ahmed ali arif asif azhar
faisal farhan kalim khalid nadeem rashid rizwan saleem shakeel sohail tariq wasim zakir anwar akbar iqbal
mustafa usman aamir sameer shabbir rukhsar nazia parveen rehana shaheen sultana yasmin zeenat hina sana
tabassum simran jasbir gurmeet harjeet balwinder paramjit amarjit lakhwinder navjot ranjit anthony joseph john
thomas george mathew peter paul maria grace elizabeth susan agnes arumugam murugan senthil karthik ganesh
venkatesh srinivas lakshmanan subramanian raman selvam saravanan balaji kannan vel meenakshi lalitha
kalaivani valli sourav subhajit debashish arnab abhijit anirban partha tapas sanjib ranjan shyamal bapi rupa
mousumi sharmistha tanushree swati moumita tenzin dolma pema karma lobsang dawa nima sonam""".split()
TEAM_LAST = """sharma verma gupta agarwal agrawal bansal goel mittal jain singh yadav kumar mishra tiwari tripathi
pandey dubey dwivedi trivedi chaturvedi shukla srivastava saxena mathur nigam kulshrestha asthana chauhan
rathore thakur sisodia tomar bhadoria parmar solanki patel shah mehta desai joshi kushwaha maurya kurmi lodh
kewat mallah chamar jatav valmiki pasi kori rawat prajapati kumhar vishwakarma lohar sonar soni swarnkar teli
sahu chaudhary chaudhari choudhary jat gurjar meena bairwa khan pathan sheikh mirza beg rizvi naqvi zaidi
hashmi farooqui usmani alvi abbasi saifi idrisi mansoori bano begum khatoon gill sandhu sidhu dhillon grewal
brar bedi kaur arora khanna kapoor malhotra chopra bhatia sethi david fernandes dsouza pinto gomes rodrigues
iyer iyengar nair menon pillai reddy rao naidu chetty gowda shetty hegde namboodiri kurup subramaniam
krishnan raman pandian mudaliar chatterjee banerjee mukherjee ganguly das dutta ghosh bose sen roy saha paul
mondal biswas sarkar majumdar bhutia lepcha sherpa lama tamang gurung""".split()


def practice_tokens(kit: Path) -> set[str]:
    truth = json.loads((kit / "dev/truth/truth.json").read_text(encoding="utf-8"))
    out = set()
    for f in truth["files"].values():
        for u in f["units"].values():
            for e in u["entities"]:
                if e["type"] in ("PATIENT_NAME", "RELATIVE_NAME", "CANARY"):
                    for t in (e.get("tokens") or []) + e["surface"].split():
                        t = unicodedata.normalize("NFC", t.strip(".,:;()").lower())
                        if t:
                            out.add(t)
                            out.add(deva_to_latin(t).lower())
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--kit", required=True)
    a = ap.parse_args()
    banned = practice_tokens(Path(a.kit))
    first = {x.lower() for x in list(EN.first_names_male) + list(EN.first_names_female)} | set(TEAM_FIRST)
    last = {x.lower() for x in EN.last_names} | set(TEAM_LAST)
    for x in list(HI.first_names_male) + list(HI.first_names_female):
        first |= {x, deva_to_latin(x).lower()}
    for x in HI.last_names:
        last |= {x, deva_to_latin(x).lower()}
    split = lambda xs: {unicodedata.normalize("NFC", w) for t in xs for w in t.split()}   # one token per line
    first = sorted(split(first) - banned)
    last = sorted(split(last) - banned)
    first = [t for t in first if len(t) >= 2]
    last = [t for t in last if len(t) >= 2]
    out = ROOT / "rakshak" / "data"
    out.mkdir(exist_ok=True)
    hdr = ("# Generated by training/build_gazetteer.py from Faker en_IN/hi_IN (MIT) + a team list.\n"
           "# Every name occurring in the organiser practice data was removed. Soft CRF feature only.\n")
    (out / "first_names.txt").write_text(hdr + "\n".join(first) + "\n", encoding="utf-8")
    (out / "surnames.txt").write_text(hdr + "\n".join(last) + "\n", encoding="utf-8")
    print(f"first names {len(first)}, surnames {len(last)}; removed {len(banned)} practice tokens")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
