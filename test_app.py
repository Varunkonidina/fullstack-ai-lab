import pytest
from app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_home_status_code(client):
    """Test if home page loads successfully"""
    response = client.get('/')
    assert response.status_code == 200


def test_home_content(client):
    """Test if response contains expected content"""
    response = client.get('/')
    assert b"<html" in response.data  # basic check