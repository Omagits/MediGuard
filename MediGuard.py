from dataclasses import dataclass
from typing import Callable, List, Set, Tuple

Severity = str  # "LOW" | "MODERATE" | "HIGH"

@dataclass
class Rule:
    id: str
    description: str
    severity: Severity
    when: Callable[[Set[str]], bool]
    message: str

def any_drug_selected(facts: Set[str], drugs: List[str]) -> bool:
    return any(f"drug:{d}" in facts for d in drugs)

def count_selected(facts: Set[str], drugs: List[str]) -> int:
    return sum(1 for d in drugs if f"drug:{d}" in facts)

def build_rules() -> List[Rule]:
    NSAIDS = ["ibuprofen", "diclofenac"]
    SEDATING = ["quetiapine", "tramadol", "cetirizine"]

    rules: List[Rule] = [
        # Drug–drug interactions
        Rule(
            "R01",
            "Warfarin + NSAID increases bleeding risk",
            "HIGH",
            lambda f: "drug:warfarin" in f and any_drug_selected(f, NSAIDS),
            "High bleeding risk: warfarin combined with an NSAID. Avoid self-medication and consult clinician."
        ),
        Rule(
            "R02",
            "Warfarin + Aspirin increases bleeding risk",
            "HIGH",
            lambda f: "drug:warfarin" in f and "drug:aspirin" in f,
            "High bleeding risk: warfarin + aspirin. Requires medical supervision."
        ),
        Rule(
            "R03",
            "Aspirin + NSAID increases GI bleed risk",
            "HIGH",
            lambda f: "drug:aspirin" in f and any_drug_selected(f, NSAIDS),
            "GI bleeding risk increased: aspirin combined with an NSAID. Seek pharmacist/doctor advice."
        ),
        Rule(
            "R04",
            "SSRI + NSAID increases bleeding risk",
            "MODERATE",
            lambda f: "drug:sertraline" in f and any_drug_selected(f, NSAIDS),
            "Moderate bleeding risk: sertraline (SSRI) combined with an NSAID. Monitor for bruising/bleeding."
        ),
        Rule(
            "R05",
            "Tramadol + SSRI increases serotonin syndrome/seizure risk",
            "HIGH",
            lambda f: "drug:tramadol" in f and "drug:sertraline" in f,
            "High risk: tramadol + sertraline may increase serotonin syndrome or seizure risk. Consult clinician urgently."
        ),
        Rule(
            "R06",
            "Clarithromycin + Warfarin may raise INR",
            "HIGH",
            lambda f: "drug:clarithromycin" in f and "drug:warfarin" in f,
            "High risk: clarithromycin can increase warfarin effect (INR). Requires monitoring/adjustment."
        ),
        Rule(
            "R07",
            "Clarithromycin + Quetiapine (QT risk)",
            "HIGH",
            lambda f: "drug:clarithromycin" in f and "drug:quetiapine" in f,
            "High risk: clarithromycin + quetiapine may increase QT prolongation risk. Seek medical advice."
        ),
        Rule(
            "R08",
            "Quetiapine + Tramadol increases sedation/respiratory depression risk",
            "HIGH",
            lambda f: "drug:quetiapine" in f and "drug:tramadol" in f,
            "High risk: quetiapine + tramadol may cause severe sedation/respiratory depression. Avoid alcohol; seek advice."
        ),
        Rule(
            "R09",
            "Cetirizine + Quetiapine adds sedation",
            "MODERATE",
            lambda f: "drug:cetirizine" in f and "drug:quetiapine" in f,
            "Moderate risk: additive drowsiness (cetirizine + quetiapine). Avoid driving if sleepy."
        ),
        Rule(
            "R10",
            "Cetirizine + Tramadol adds sedation",
            "MODERATE",
            lambda f: "drug:cetirizine" in f and "drug:tramadol" in f,
            "Moderate risk: additive drowsiness (cetirizine + tramadol). Avoid driving; avoid alcohol."
        ),

        # Condition-based rules
        Rule(
            "R11",
            "Kidney disease + NSAID increases kidney injury risk",
            "HIGH",
            lambda f: "cond:kidney_disease" in f and any_drug_selected(f, NSAIDS),
            "High risk: NSAIDs can worsen kidney function in kidney disease. Consult clinician."
        ),
        Rule(
            "R12",
            "Ulcer/GERD history + NSAID increases GI bleeding risk",
            "HIGH",
            lambda f: "cond:ulcer_gerd" in f and any_drug_selected(f, NSAIDS),
            "High risk: NSAIDs may worsen ulcer/GERD and increase bleeding risk. Prefer alternatives per clinician."
        ),
        Rule(
            "R13",
            "Liver disease + Diclofenac increases hepatotoxicity risk",
            "HIGH",
            lambda f: "cond:liver_disease" in f and "drug:diclofenac" in f,
            "High risk: diclofenac may stress the liver. Avoid without clinician guidance."
        ),
        Rule(
            "R14",
            "Elderly with multiple sedating drugs increases falls/confusion risk",
            "HIGH",
            lambda f: "age:elderly" in f and count_selected(f, SEDATING) >= 2,
            "High risk: elderly with multiple sedating medicines increases falls/confusion. Review regimen with clinician."
        ),
        Rule(
            "R15",
            "Diuretic + NSAID increases kidney risk",
            "HIGH",
            lambda f: "drug:furosemide" in f and any_drug_selected(f, NSAIDS),
            "High risk: furosemide + NSAID can reduce kidney perfusion (especially if dehydrated). Seek advice."
        ),
        Rule(
            "R16",
            "Hypertension + NSAID may worsen BP control",
            "MODERATE",
            lambda f: "cond:hypertension" in f and any_drug_selected(f, NSAIDS),
            "Moderate risk: NSAIDs may raise blood pressure or reduce antihypertensive effectiveness. Monitor BP."
        ),

        # Pregnancy rules
        Rule(
            "R17",
            "Pregnancy + NSAID should be avoided/caution",
            "HIGH",
            lambda f: "preg:yes" in f and any_drug_selected(f, NSAIDS),
            "High risk: NSAIDs in pregnancy require clinician guidance (especially later pregnancy). Do not self-medicate."
        ),
        Rule(
            "R18",
            "Pregnancy + Warfarin contraindicated",
            "HIGH",
            lambda f: "preg:yes" in f and "drug:warfarin" in f,
            "High risk: warfarin is generally contraindicated in pregnancy. Seek urgent medical advice."
        ),
        Rule(
            "R19",
            "Pregnancy + Clarithromycin caution",
            "HIGH",
            lambda f: "preg:yes" in f and "drug:clarithromycin" in f,
            "Caution: clarithromycin in pregnancy should be clinician-led based on risk/benefit."
        ),

        # Duplicate/class conflicts
        Rule(
            "R20",
            "Duplicate NSAID therapy (ibuprofen + diclofenac)",
            "HIGH",
            lambda f: "drug:ibuprofen" in f and "drug:diclofenac" in f,
            "High risk: duplicate NSAID therapy (ibuprofen + diclofenac). Increases GI/kidney side effects."
        ),

        # NEW RULE (replaces the removed duplicate warfarin+aspirin rule)
        Rule(
            "R21",
            "Asthma/COPD + NSAID may worsen respiratory symptoms",
            "MODERATE",
            lambda f: "cond:asthma_copd" in f and any_drug_selected(f, NSAIDS),
            "Moderate risk: NSAIDs may worsen asthma/COPD symptoms in some patients. Use only under clinician guidance; seek help if breathing worsens."
        ),

        # General advisory rules (informational)
        Rule(
            "R22",
            "Sedation warning for certain medicines",
            "LOW",
            lambda f: count_selected(f, SEDATING) >= 1,
            "Safety: some selected medicines may cause drowsiness. Avoid driving if sleepy; avoid alcohol."
        ),
        Rule(
            "R23",
            "NSAID GI safety advice",
            "LOW",
            lambda f: any_drug_selected(f, NSAIDS),
            "NSAID advice: take with food. Seek urgent care if black stools, vomiting blood, severe stomach pain."
        ),
        Rule(
            "R24",
            "Metformin GI advice",
            "LOW",
            lambda f: "drug:metformin" in f,
            "Metformin advice: GI upset is common; take with meals. Persistent vomiting/weakness requires medical review."
        ),
        Rule(
            "R25",
            "Warfarin bleeding red flags",
            "LOW",
            lambda f: "drug:warfarin" in f,
            "Warfarin advice: watch for unusual bruising/bleeding. Avoid starting NSAIDs without clinician approval."
        ),
    ]
    return rules

def evaluate(facts: Set[str], rules: List[Rule]) -> Tuple[Severity, List[Rule]]:
    fired: List[Rule] = []
    for r in rules:
        try:
            if r.when(facts):
                fired.append(r)
        except Exception:
            # Robustness: prevents a broken rule from crashing the system
            continue

    # Determine overall severity
    if any(r.severity == "HIGH" for r in fired):
        overall = "HIGH"
    elif sum(1 for r in fired if r.severity == "MODERATE") >= 2:
        overall = "HIGH"
    elif any(r.severity == "MODERATE" for r in fired):
        overall = "MODERATE"
    else:
        overall = "LOW"

    # Sort: HIGH first, then MODERATE, then LOW
    order = {"HIGH": 0, "MODERATE": 1, "LOW": 2}
    fired.sort(key=lambda r: order[r.severity])
    return overall, fired


# ---------------- GUI ----------------
import tkinter as tk
from tkinter import ttk, messagebox

class MediGuardGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MediGuard - Drug Interaction & Side-Effect Advisory Expert System")
        self.geometry("980x620")
        self.minsize(900, 560)

        self.rules = build_rules()

        self.drugs = [
            "ibuprofen", "diclofenac", "warfarin", "aspirin", "clarithromycin",
            "sertraline", "tramadol", "quetiapine", "losartan", "furosemide",
            "metformin", "omeprazole", "cetirizine"
        ]
        self.conditions = [
            "kidney_disease", "liver_disease", "ulcer_gerd", "hypertension", "diabetes", "asthma_copd"
        ]

        self._build_layout()

    def _build_layout(self):
        title = ttk.Label(self, text="MediGuard: Drug Interaction & Side-Effect Advisory", font=("Segoe UI", 16, "bold"))
        title.pack(pady=10)

        outer = ttk.Frame(self)
        outer.pack(fill="both", expand=True, padx=12, pady=6)

        left = ttk.Frame(outer)
        left.pack(side="left", fill="y", padx=(0, 12))

        right = ttk.Frame(outer)
        right.pack(side="right", fill="both", expand=True)

        # Patient details
        demo_frame = ttk.LabelFrame(left, text="Patient Details")
        demo_frame.pack(fill="x", pady=6)

        ttk.Label(demo_frame, text="Age group:").grid(row=0, column=0, sticky="w", padx=8, pady=6)
        self.age_var = tk.StringVar(value="adult")
        ttk.Combobox(demo_frame, textvariable=self.age_var, values=["child", "adult", "elderly"],
                    state="readonly", width=18).grid(row=0, column=1, padx=8, pady=6)

        ttk.Label(demo_frame, text="Pregnant:").grid(row=1, column=0, sticky="w", padx=8, pady=6)
        self.preg_var = tk.StringVar(value="no")
        ttk.Combobox(demo_frame, textvariable=self.preg_var, values=["no", "yes"],
                    state="readonly", width=18).grid(row=1, column=1, padx=8, pady=6)

        # Drugs selection
        drugs_frame = ttk.LabelFrame(left, text="Select Medicines (Ctrl+Click for multiple)")
        drugs_frame.pack(fill="both", expand=False, pady=6)

        self.drugs_list = tk.Listbox(drugs_frame, selectmode="multiple", height=10, exportselection=False)
        for d in self.drugs:
            self.drugs_list.insert(tk.END, d)
        self.drugs_list.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=8)

        ttk.Scrollbar(drugs_frame, orient="vertical", command=self.drugs_list.yview).pack(
            side="right", fill="y", padx=8, pady=8
        )
        self.drugs_list.config(yscrollcommand=lambda *args: None)

        # Conditions selection
        cond_frame = ttk.LabelFrame(left, text="Select Conditions (Ctrl+Click for multiple)")
        cond_frame.pack(fill="both", expand=False, pady=6)

        self.cond_list = tk.Listbox(cond_frame, selectmode="multiple", height=8, exportselection=False)
        for c in self.conditions:
            self.cond_list.insert(tk.END, c)
        self.cond_list.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=8)

        ttk.Scrollbar(cond_frame, orient="vertical", command=self.cond_list.yview).pack(
            side="right", fill="y", padx=8, pady=8
        )
        self.cond_list.config(yscrollcommand=lambda *args: None)

        # Buttons
        btn_frame = ttk.Frame(left)
        btn_frame.pack(fill="x", pady=10)

        ttk.Button(btn_frame, text="Run Evaluation", command=self.run_eval).pack(fill="x", padx=2, pady=4)
        ttk.Button(btn_frame, text="Clear Selections", command=self.clear_all).pack(fill="x", padx=2, pady=4)

        # Output box
        out_frame = ttk.LabelFrame(right, text="Results")
        out_frame.pack(fill="both", expand=True)

        self.out_text = tk.Text(out_frame, wrap="word", font=("Consolas", 10))
        self.out_text.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=8)

        out_scroll = ttk.Scrollbar(out_frame, orient="vertical", command=self.out_text.yview)
        out_scroll.pack(side="right", fill="y", padx=8, pady=8)
        self.out_text.config(yscrollcommand=out_scroll.set)

        self._write_output("Select patient details, medicines, and conditions, then click 'Run Evaluation'.\n")

    def clear_all(self):
        self.age_var.set("adult")
        self.preg_var.set("no")
        self.drugs_list.selection_clear(0, tk.END)
        self.cond_list.selection_clear(0, tk.END)
        self._write_output("Selections cleared. Please choose inputs and run evaluation.\n")

    def _get_selected(self, lb: tk.Listbox, items: List[str]) -> List[str]:
        return [items[i] for i in lb.curselection()]

    def run_eval(self):
        chosen_drugs = self._get_selected(self.drugs_list, self.drugs)
        chosen_conditions = self._get_selected(self.cond_list, self.conditions)

        if not chosen_drugs:
            messagebox.showwarning("No medicines selected", "Please select at least one medicine to evaluate.")
            return

        facts: Set[str] = {f"age:{self.age_var.get()}", f"preg:{self.preg_var.get()}"}
        facts.update({f"drug:{d}" for d in chosen_drugs})
        facts.update({f"cond:{c}" for c in chosen_conditions})

        overall, fired = evaluate(facts, self.rules)

        lines = []
        lines.append("========================================")
        lines.append("MediGuard Expert System Result (GUI)")
        lines.append("========================================")
        lines.append(f"Age group: {self.age_var.get()}")
        lines.append(f"Pregnant: {self.preg_var.get()}")
        lines.append(f"Medicines: {', '.join(chosen_drugs)}")
        lines.append(f"Conditions: {', '.join(chosen_conditions) if chosen_conditions else 'None'}")
        lines.append("")
        lines.append(f"Overall Risk Level: {overall}")
        lines.append("")

        if fired:
            lines.append("Triggered Findings:")
            for r in fired:
                lines.append(f"- [{r.severity}] {r.id}: {r.description}")
                lines.append(f"  Advice: {r.message}")
        else:
            lines.append("No interaction/contraindication rules triggered based on the selected inputs.")
            lines.append("General advice: consult a pharmacist/doctor before combining medicines, especially in pregnancy.")

        self._write_output("\n".join(lines) + "\n")

    def _write_output(self, text: str):
        self.out_text.config(state="normal")
        self.out_text.delete("1.0", tk.END)
        self.out_text.insert("1.0", text)
        self.out_text.config(state="disabled")


if __name__ == "__main__":
    app = MediGuardGUI()
    app.mainloop()
