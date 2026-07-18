"""Tests for MailSnitch SMTP reconnaissance tool."""
import socket
import smtplib
import sys
from unittest.mock import MagicMock, patch, call

sys.path.insert(0, "/home/j-alien/cybersec-portfolio/13-MailSnitch")

from mailsnitch import (
    check_smtp_banner,
    check_open_relay,
    vrfy_user,
    enumerate_users,
    SMTP_BANNER_TIMEOUT,
    VRFY_TIMEOUT,
)


def test_smtp_banner_success():
    """Should return banner from SMTP server."""
    with patch("mailsnitch.socket.socket") as mock_socket:
        instance = MagicMock()
        mock_socket.return_value = instance
        instance.recv.return_value = b"220 mail.example.com ESMTP Postfix\r\n"

        result = check_smtp_banner("mail.example.com", 25)

        assert result[0] == "mail.example.com"
        assert result[1] == 25
        assert "220" in result[2]


def test_smtp_banner_connection_error():
    """Should handle connection timeouts gracefully."""
    with patch("mailsnitch.socket.socket") as mock_socket:
        instance = MagicMock()
        mock_socket.return_value = instance
        instance.connect.side_effect = socket.timeout("timed out")

        result = check_smtp_banner("nonexistent.example.com", 25)

        assert "ERROR" in result[2]


def test_smtp_banner_refused():
    """Should handle connection refused."""
    with patch("mailsnitch.socket.socket") as mock_socket:
        instance = MagicMock()
        mock_socket.return_value = instance
        instance.connect.side_effect = ConnectionRefusedError("refused")

        result = check_smtp_banner("refused.example.com", 25)

        assert "ERROR" in result[2]


def test_smtp_banner_non_standard_port():
    """Should work on non-standard SMTP ports."""
    with patch("mailsnitch.socket.socket") as mock_socket:
        instance = MagicMock()
        mock_socket.return_value = instance
        instance.recv.return_value = b"220 ESMTP Submissions\r\n"

        result = check_smtp_banner("mail.example.com", 587)

        assert result[1] == 587


def test_check_open_relay_open():
    """Should detect open relay when server accepts external mail."""
    with patch("mailsnitch.smtplib.SMTP") as mock_smtp_class:
        instance = MagicMock()
        mock_smtp_class.return_value = instance
        instance.mail.return_value = (250, b"OK")
        instance.rcpt.return_value = (250, b"OK")

        result = check_open_relay("relay.example.com")

        assert result[2] is True
        assert result[3] == 250


def test_check_open_relay_secure():
    """Should identify closed relay when server rejects external mail."""
    with patch("mailsnitch.smtplib.SMTP") as mock_smtp_class:
        instance = MagicMock()
        mock_smtp_class.return_value = instance
        instance.mail.return_value = (250, b"OK")
        instance.rcpt.return_value = (550, b"Mailbox not found")

        result = check_open_relay("secure.example.com")

        assert result[2] is False


def test_check_open_relay_timeout():
    """Should handle SMTP timeout gracefully."""
    with patch("mailsnitch.smtplib.SMTP") as mock_smtp_class:
        mock_smtp_class.side_effect = socket.timeout("timed out")

        result = check_open_relay("slow.example.com")

        assert result[2] is False


def test_vrfy_user_exists():
    """Should detect when VRFY returns 250 (user exists)."""
    with patch("mailsnitch.socket.socket") as mock_socket:
        instance = MagicMock()
        mock_socket.return_value = instance
        instance.recv.side_effect = [
            b"220 mail.example.com ESMTP\r\n",
            b"250 2.1.5 root\r\n",
        ]

        result = vrfy_user("mail.example.com", "root")

        assert result[0] == "root"
        assert result[1] == 250


def test_vrfy_user_not_found():
    """Should detect when VRFY returns 550 (user not found)."""
    with patch("mailsnitch.socket.socket") as mock_socket:
        instance = MagicMock()
        mock_socket.return_value = instance
        instance.recv.side_effect = [
            b"220 mail.example.com ESMTP\r\n",
            b"550 5.1.1 User unknown\r\n",
        ]

        result = vrfy_user("mail.example.com", "nonexistent")

        assert result[1] == 550


def test_enumerate_users_with_list():
    """Should enumerate users from a list."""
    with patch("mailsnitch.vrfy_user") as mock_vrfy:
        mock_vrfy.side_effect = [
            ("root", 250, "250 OK"),
            ("nobody", 550, "550 No"),
            ("admin", 252, "252 Maybe"),
        ]

        result = enumerate_users("mail.example.com", ["root", "nobody", "admin"])

        assert len(result) == 2  # Only 250 and 252
        assert mock_vrfy.call_count == 3


def test_enumerate_users_empty_list():
    """Should handle empty user list."""
    result = enumerate_users("mail.example.com", [])
    assert len(result) == 0


def test_enumerate_users_with_file():
    """Should handle file path for user list."""
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        f.write("root\nadmin\n")
        fpath = f.name

    try:
        with patch("mailsnitch.vrfy_user") as mock_vrfy:
            mock_vrfy.side_effect = [
                ("root", 250, "250 OK"),
                ("admin", 550, "550 No"),
            ]
            result = enumerate_users("mail.example.com", fpath)
            assert len(result) == 1
    finally:
        import os
        os.unlink(fpath)


def test_smtp_banner_timeout_setting():
    """Should use configured timeout value."""
    assert SMTP_BANNER_TIMEOUT == 5
    assert VRFY_TIMEOUT == 5


def test_banner_connect_called():
    """Should call connect with correct args."""
    with patch("mailsnitch.socket.socket") as mock_socket:
        instance = MagicMock()
        mock_socket.return_value = instance
        instance.recv.return_value = b"220 mail ESMTP\r\n"

        check_smtp_banner("192.168.1.1", 25)

        instance.connect.assert_called_with(("192.168.1.1", 25))
