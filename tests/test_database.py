"""Unit Tests for SQLite Database Operations and AssessmentRepository

Tests CRUD actions, filtering, search, sorting, and aggregate statistics calculation.
"""

from app.models import AssessmentRepository


class TestAssessmentRepository:
    """Tests SQLite persistence and query operations."""

    def test_save_and_get_by_id(self, repo, sample_assessment_data):
        rec_id = repo.save(sample_assessment_data)
        assert rec_id == sample_assessment_data["id"]

        fetched = repo.get_by_id(rec_id)
        assert fetched is not None
        assert fetched["hostname"] == "example.com"
        assert fetched["outcome"] == "Protected"
        assert fetched["xfo_status"] == "Protected (DENY)"
        assert fetched["other_headers"]["x_content_type_options"]["value"] == "nosniff"

    def test_list_assessments_and_search(self, repo, sample_assessment_data):
        # Insert two assessments
        data1 = dict(sample_assessment_data)
        data1["id"] = "id-alpha"
        data1["hostname"] = "alpha-corp.com"
        data1["outcome"] = "Protected"
        repo.save(data1)

        data2 = dict(sample_assessment_data)
        data2["id"] = "id-beta"
        data2["hostname"] = "beta-portal.org"
        data2["outcome"] = "Potential Risk"
        repo.save(data2)

        # Search by hostname
        results = repo.list_assessments(search_query="beta")
        assert len(results) == 1
        assert results[0]["hostname"] == "beta-portal.org"

        # Filter by outcome
        protected = repo.list_assessments(outcome_filter="Protected")
        assert any(r["id"] == "id-alpha" for r in protected)
        assert not any(r["id"] == "id-beta" for r in protected)

    def test_delete_and_clear_all(self, repo, sample_assessment_data):
        rec_id = repo.save(sample_assessment_data)
        assert repo.get_by_id(rec_id) is not None

        deleted = repo.delete(rec_id)
        assert deleted is True
        assert repo.get_by_id(rec_id) is None

        # Test clear all
        repo.save(sample_assessment_data)
        count = repo.clear_all()
        assert count >= 1
        assert len(repo.list_assessments()) == 0

    def test_get_statistics(self, repo, sample_assessment_data):
        # Empty repo stats
        stats0 = repo.get_statistics()
        assert stats0["total"] == 0

        # Add 1 Protected, 1 Potential Risk
        p_data = dict(sample_assessment_data)
        p_data["id"] = "p1"
        p_data["outcome"] = "Protected"
        repo.save(p_data)

        r_data = dict(sample_assessment_data)
        r_data["id"] = "r1"
        r_data["outcome"] = "Potential Risk"
        repo.save(r_data)

        stats = repo.get_statistics()
        assert stats["total"] == 2
        assert stats["protected"] == 1
        assert stats["potential_risk"] == 1
        assert stats["protected_pct"] == 50.0
        assert stats["risk_pct"] == 50.0
