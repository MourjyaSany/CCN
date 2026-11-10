# Project Review-1 presentation (21ECC402L)

| File | Purpose |
|---|---|
| `NetShield-GNN_Review1.pptx` | The 13-slide editable deck |
| `NetShield-GNN_Review1.pdf` | PDF preview, exported by PowerPoint |
| `build_deck.py` | Generates the deck (python-pptx). All text, flowchart blocks and arrows are native, editable shapes |
| `make_assets.py` | Rebuilds `assets/srm_logo.png` (cut from the official template master) and `assets/background.png` |
| `validate_layout.ps1` | Uses PowerPoint itself to check slide bounds, footer clearance, text overflow and overlaps; optionally exports PNGs and the PDF |
| `assets/ref_master_bg.png` | Master background of the department template, the source of the logo |

The background image, SRMIST logo, red footer band and slide number are on the
**slide master**, so they are identical on every slide and edited in one place
(View → Slide Master).

## Regenerate

```powershell
pip install python-pptx pillow numpy lxml
python make_assets.py            # only if assets/ needs rebuilding
python build_deck.py
powershell -ExecutionPolicy Bypass -File validate_layout.ps1 `
    -Pptx NetShield-GNN_Review1.pptx -Pdf "$PWD\NetShield-GNN_Review1.pdf"
```

`validate_layout.ps1` needs Windows with Microsoft PowerPoint installed.
