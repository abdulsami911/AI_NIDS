import csv
import io
from xml.sax.saxutils import escape

from flask import Response, send_file, stream_with_context
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle


def safe_cell(value):
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def csv_export(store, run):
    def stream():
        with store.connect() as db:
            query = db.execute("""SELECT r.capture,r.id AS analysis_id,r.model,r.version,f.id AS flow_id,
             f.first_ns,f.last_ns,f.src,f.sport,f.dst,f.dport,f.proto,f.dur,f.packets,f.bytes,f.category,
             f.score,f.severity,a.status,(SELECT group_concat(body,char(10)) FROM notes WHERE alert=a.id) AS notes
             FROM flows f JOIN runs r ON r.id=f.run LEFT JOIN alerts a ON a.flow=f.id
             WHERE f.run=? ORDER BY f.row_no""", (run["id"],))
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow([d[0] for d in query.description])
            yield buf.getvalue()
            for row in query:
                buf.seek(0)
                buf.truncate()
                writer.writerow(map(safe_cell, row))
                yield buf.getvalue()
    return Response(stream_with_context(stream()), mimetype="text/csv", headers={
        "Content-Disposition": f"attachment; filename=analysis-{run['id']}.csv"})


def pdf_export(store, r):
    output = io.BytesIO()
    doc = SimpleDocTemplate(output, title="AI-NIDS capture analysis", leftMargin=20*mm, rightMargin=20*mm,
                            topMargin=20*mm, bottomMargin=21*mm)
    styles = getSampleStyleSheet()
    story = []
    def para(value, style="BodyText"):
        story.append(Paragraph(escape(str(value)), styles[style]))
    def table(rows):
        cells = [[Paragraph(escape(str(v)), styles["BodyText"]) for v in row] for row in rows]
        grid = Table(cells, colWidths=[105*mm, 62*mm], repeatRows=1, hAlign="LEFT")
        grid.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#dceef4")),
                                  ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#f4f7f9")]),
                                  ("VALIGN",(0,0),(-1,-1),"TOP"),("BOTTOMPADDING",(0,0),(-1,-1),6)]))
        story.extend([grid, Spacer(1, 4*mm)])

    rid = r["id"]
    para("Capture analysis", "Title")
    para(f"{r['name']}  |  Analysis {rid}", "Heading2")
    para(f"Capture {r['capture']}  |  Recorded {r['created']} UTC")
    para(f"Model {r['family']} / {r['model']}  |  Version {r['version']}")
    para(f"Features {r['schema']}")
    para("Analysis summary", "Heading2")
    table([["Measure","Count"],["Reconstructed flows" if r["family"]=="pcap" else "CSV flow records", r["nflows"]],
           ["Original frames read", r["frames"] if r["frames"] is not None else "Unavailable for CSV"],
           ["Frames linked to flows",r["mapped"] if r["mapped"] is not None else "Unavailable for CSV"]])
    for heading, field in [("Predicted categories","COALESCE(category,'Unclassified')"),("Protocols","proto")]:
        para(heading,"Heading2")
        rows = store.all(f"SELECT {field} AS k,count(*) AS n FROM flows WHERE run=? GROUP BY 1 ORDER BY 2 DESC",(rid,))
        table([[heading,"Flows"]]+[[x["k"],x["n"]] for x in rows])
    para("Frequent source endpoints in attack-predicted flows","Heading2")
    eps = store.all("""SELECT src,count(*) AS n FROM flows WHERE run=? AND category!='Normal'
                       AND src IS NOT NULL GROUP BY src ORDER BY n DESC,src LIMIT 10""",(rid,))
    if eps:
        table([["Observed source address","Flows"]]+[[x["src"],x["n"]] for x in eps])
    else:
        para("No source endpoints available for this selection.")
    para("Analyst findings","Heading2")
    notes = store.all("""SELECT f.id,a.status,n.body FROM notes n JOIN alerts a ON a.id=n.alert
                         JOIN flows f ON f.id=a.flow WHERE f.run=? ORDER BY n.id DESC LIMIT 30""",(rid,))
    para("Latest 30 notes. The CSV includes the complete note history." if notes else "No analyst notes recorded.")
    for n in notes:
        para(f"Flow {n['id']} | {n['status']} | {n['body']}")
    para("Interpretation","Heading2")
    para("Categories describe model predictions for entire flows. Scores are uncalibrated. "
         "Capture boundaries, encryption, unseen traffic and class imbalance limit interpretation. "
         "Wire bytes describe original frame lengths. CSV rows have no linked packet evidence.")
    def footer(canvas, doc):
        canvas.setFillColor(colors.HexColor("#426174"))
        canvas.setFont("Helvetica",9)
        canvas.drawString(20*mm,12*mm,"AI-NIDS   /   Local investigation report")
        canvas.drawRightString(doc.pagesize[0]-20*mm,12*mm,f"Page {doc.page}")
    doc.build(story,onFirstPage=footer,onLaterPages=footer)
    output.seek(0)
    return send_file(output,mimetype="application/pdf",as_attachment=True,download_name=f"analysis-{rid}.pdf")
