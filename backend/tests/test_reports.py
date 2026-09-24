import pytest


@pytest.mark.asyncio
async def test_pdf_report_and_csv_export(client):
    # 1. Create a scan first
    res_create = await client.post("/api/v1/scans", json={"url": "https://example.com/test-report"})
    assert res_create.status_code == 201
    scan_id = res_create.json()["scan_id"]

    # 2. Download PDF report
    res_pdf = await client.get(f"/api/v1/scans/{scan_id}/report.pdf")
    assert res_pdf.status_code == 200
    assert res_pdf.headers["content-type"] == "application/pdf"
    assert res_pdf.content.startswith(b"%PDF-")
    assert len(res_pdf.content) > 1000

    # 3. Nonexistent scan PDF report -> 404
    res_pdf_404 = await client.get("/api/v1/scans/00000000-0000-0000-0000-000000000000/report.pdf")
    assert res_pdf_404.status_code == 404

    # 4. Export CSV
    res_csv = await client.get("/api/v1/scans/export/csv")
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers["content-type"]
    csv_text = res_csv.text
    assert "scan_id,url,domain,status,verdict" in csv_text
