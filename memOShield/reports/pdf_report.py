from datetime import datetime

# Lightweight PDF report scaffold. Uses reportlab if available.
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False


def generate_pdf_report(events, out_path):
    """Generate a simple PDF summarizing events.

    events: iterable of dicts with keys: ip, type, reason, country
    """
    if not REPORTLAB_AVAILABLE:
        # fallback: write simple text file with .pdf extension as placeholder
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write('memOShield Report\n')
            f.write('Generated: %s\n\n' % datetime.utcnow().isoformat())
            for e in events:
                f.write('%s | %s | %s | %s\n' % (e.get('ip'), e.get('type'), e.get('reason'), e.get('country')))
        return out_path

    c = canvas.Canvas(out_path, pagesize=A4)
    w, h = A4
    c.setFont('Helvetica-Bold', 14)
    c.drawString(40, h-60, 'memOShield Weekly Report')
    c.setFont('Helvetica', 10)
    c.drawString(40, h-80, 'Generated: %s' % datetime.utcnow().isoformat())
    y = h-110
    for e in events:
        line = '%s | %s | %s | %s' % (e.get('ip'), e.get('type'), e.get('reason'), e.get('country'))
        c.drawString(40, y, line)
        y -= 14
        if y < 60:
            c.showPage()
            y = h-60
    c.save()
    return out_path
