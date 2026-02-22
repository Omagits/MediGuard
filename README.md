MediGuard: Drug Interaction & Side-Effect Advisory Expert System

Overview:

MediGuard is a rule-based expert system developed in Python to perform an initial assessment of medication safety. It evaluates selected medicines together with patient factors (age, pregnancy status, and medical conditions) to identify drug–drug interactions, contraindications, and clinically significant risks.
The system is designed for educational decision-support and does not replace professional medical judgement. 


Aim:

To demonstrate the application of Artificial Intelligence techniques — knowledge representation, rule-based reasoning, forward-chaining inference, and explainable AI — in a healthcare advisory system.


AI Concepts Implemented:

Knowledge Representation
Clinical knowledge is encoded as 25 IF–THEN production rules with severity levels and advisory outputs.

Inference Mechanism (Forward Chaining)
User inputs → symbolic facts → rule matching → triggered rules → overall risk classification.

Risk Aggregation Strategy
HIGH → if any HIGH rule fires
HIGH → if ≥2 MODERATE rules fire
MODERATE → if one MODERATE rule fires
LOW → otherwise



System Architecture:

Knowledge Base: 25 pharmacological safety rules

Inference Engine: rule evaluation and severity prioritisation

Working Memory: symbolic facts (e.g., drug:warfarin, age:elderly)



GUI: Tkinter-based interactive interface: 

• Knowledge Coverage

• Drug–drug interactions

• Condition-based contraindications

• Pregnancy and elderly risk

• General medication safety advice



Technologies:

Python • Tkinter • Rule-based AI • Object-oriented design



How to Run:

Clone the repository

Open the project folder

Run MediGuard.py using Python 3



Example:

Input: Elderly + Quetiapol + Tramadol
Output: HIGH risk → increased sedation and fall risk



Key Features:

• 25 production rules

• Explainable output

• Severity-based risk classification

• Interactive GUI

• Modular design



Limitations:

Limited drug list 
• No dosage analysis 
• No laboratory data 
• No probabilistic reasoning


Academic Context:

Developed for the Knowledge-Based Systems module to demonstrate the full expert system development lifecycle.


Disclaimer:

For educational use only — not for real clinical decision-making.

