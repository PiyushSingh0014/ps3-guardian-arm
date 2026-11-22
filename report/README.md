# Technical report

[sajag-phase1-report.pdf](sajag-phase1-report.pdf): the Phase 1 technical report (approach, architecture, algorithms,
implementation on Arm, results, limitations and the Phase 2 plan).

To build it again, from this folder (XeLaTeX, for the Hindi name and the app's fonts):

    xelatex sajag-phase1-report.tex && xelatex sajag-phase1-report.tex

The fonts come from the app itself (`android/app/src/main/res/font/`: Figtree and Rozha One, SIL Open Font Licence).
