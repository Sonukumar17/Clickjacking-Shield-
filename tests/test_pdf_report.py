"""Unit Tests for PDF Security Report Generation Service

Validates ReportLab rendering, executive styling, and PDF output structure.
"""

from app.services.pdf_report import generate_pdf_report


class TestPdfReportGeneration:
    """Tests PDF generation service with varying assessment postures."""

    def test_pdf_generation_protected(self, sample_assessment_data):
        buf = generate_pdf_report(sample_assessment_data)
        pdf_bytes = buf.getvalue()
        assert len(pdf_bytes) > 1000
        assert pdf_bytes.startswith(b"%PDF-")

    def test_pdf_generation_potential_risk(self, sample_assessment_data):
        data = dict(sample_assessment_data)
        data["outcome"] = "Potential Risk"
        data["xfo_status"] = "Missing"
        data["csp_status"] = "Missing"

        buf = generate_pdf_report(data)
        pdf_bytes = buf.getvalue()
        assert len(pdf_bytes) > 1000
        assert pdf_bytes.startswith(b"%PDF-")

    def test_pdf_generation_inconclusive(self, sample_assessment_data):
        data = dict(sample_assessment_data)
        data["outcome"] = "Inconclusive"
        data["http_status"] = 502

        buf = generate_pdf_report(data)
        pdf_bytes = buf.getvalue()
        assert len(pdf_bytes) > 1000
        assert pdf_bytes.startswith(b"%PDF-")
