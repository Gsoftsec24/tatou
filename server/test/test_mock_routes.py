import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
import pytest
from unittest.mock import patch, MagicMock
from server import create_app  # Now works

os.environ['TEST_MODE'] = '1'

@pytest.fixture
def client():
    app = create_app({'TESTING': True})
    with app.app_context():
        yield app.test_client()

class TestCreateWatermark:
    def test_missing_fields_400(self, client):
        """Missing JSON fields → 400 validation branch."""
        rv = client.post('/api/create-watermark/1')
        assert rv.status_code == 400

    @patch('src.server.WMUtils.is_watermarking_applicable')
    def test_not_applicable_400(self, mock_wm, client):
        """WMUtils False → 400."""
        mock_wm.return_value = False
        rv = client.post('/api/create-watermark/1', json={'method': 'hash'})
        assert rv.status_code == 400

    @patch('src.server.WMUtils.apply_watermark')
    def test_wm_exception_500(self, mock_wm, client):
        """apply_watermark raises → 500."""
        mock_wm.side_effect = ValueError
        rv = client.post('/api/create-watermark/1', json={'method': 'hash-eof', 'intended_for': 'g', 'secret': 's', 'key': 'k'})
        assert rv.status_code == 500

    @patch('src.server.WMUtils.apply_watermark')
    def test_db_insert_fail_500(self, mock_wm, client):
        """DB commit fail → 500."""
        mock_wm.return_value = b'%PDF mock'
        with patch('src.server.get_engine') as mock_db:
            mock_conn = MagicMock(); mock_conn.begin().execute.side_effect = Exception
            mock_db.return_value = mock_conn
        rv = client.post('/api/create-watermark/1', json={'method': 'hash-eof', 'intended_for': 'test', 'secret': 'secret', 'key': 'key'})
        assert rv.status_code == 500

    @patch('src.server.WMUtils.apply_watermark')
    def test_success_201(self, mock_wm, client):
        """Full happy path → 201 with ID."""
        mock_wm.return_value = b'%PDF success'
        rv = client.post('/api/create-watermark/1', json={'method': 'hash-eof', 'intended_for': 'group', 'secret': 'secret123', 'key': 'key123'})
        assert rv.status_code == 201
        assert b'"id"' in rv.data

class TestReadWatermark:
    def test_no_doc_404(self, client):
        """Doc not found → 404."""
        rv = client.get('/api/read-watermark/999')
        assert rv.status_code == 404

    @patch('src.server.WMUtils.read_watermark')
    def test_success_200(self, mock_read, client):
        """Valid read → 200 secret."""
        mock_read.return_value = 'recovered'
        rv = client.get('/api/read-watermark/1?method=hash-eof&key=key')
        assert rv.status_code == 200
        assert b'"secret"' in rv.data

    @patch('src.server.WMUtils.read_watermark')
    def test_read_fail_500(self, mock_read, client):
        """read_watermark raises → 500."""
        mock_read.side_effect = ValueError
        rv = client.get('/api/read-watermark/1?method=hash-eof&key=key')
        assert rv.status_code == 500
