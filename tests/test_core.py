import json
import os
import tempfile
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest
import requests

from core import (
    MAX_CIDR_EXPAND,
    AppConfig,
    ParseResult,
    batched,
    dataframe_to_excel_bytes,
    diff_dataframes,
    expand_cidr,
    get_abuse_risk_level,
    get_country_name_zh,
    load_history_list,
    load_history_record,
    normalize_lines,
    save_history,
    validate_ip_list,
)


class TestNormalizeLines:
    def test_empty(self):
        assert normalize_lines("") == []

    def test_comma_separated(self):
        assert normalize_lines("1.1.1.1, 2.2.2.2") == ["1.1.1.1", "2.2.2.2"]

    def test_chinese_comma(self):
        assert normalize_lines("1.1.1.1，2.2.2.2") == ["1.1.1.1", "2.2.2.2"]

    def test_semicolon(self):
        assert normalize_lines("1.1.1.1; 2.2.2.2") == ["1.1.1.1", "2.2.2.2"]

    def test_newline(self):
        assert normalize_lines("1.1.1.1\n2.2.2.2") == ["1.1.1.1", "2.2.2.2"]

    def test_mixed(self):
        # Note: Chinese semicolon ； is not replaced by normalize_lines
        assert normalize_lines("1.1.1.1, 2.2.2.2\n3.3.3.3;4.4.4.4") == [
            "1.1.1.1",
            "2.2.2.2",
            "3.3.3.3",
            "4.4.4.4",
        ]


class TestExpandCidr:
    def test_ipv4_cidr_30(self):
        result = expand_cidr("192.168.1.0/30")
        assert len(result) == 2
        assert "192.168.1.1" in result
        assert "192.168.1.2" in result

    def test_ipv4_cidr_24(self):
        result = expand_cidr("192.168.1.0/24")
        assert len(result) == 254  # hosts() excludes network and broadcast

    def test_ipv4_cidr_too_large(self):
        result = expand_cidr("10.0.0.0/8")
        assert len(result) == MAX_CIDR_EXPAND

    def test_invalid_cidr(self):
        assert expand_cidr("not-a-cidr") == []

    def test_single_ip(self):
        # A single IP with strict=False becomes /32, hosts() returns it in modern Python
        result = expand_cidr("8.8.8.8")
        assert result == ["8.8.8.8"]


class TestValidateIpList:
    def test_empty(self):
        result = validate_ip_list([])
        assert result == ParseResult(ips=[], invalid_values=[])

    def test_valid_ips(self):
        result = validate_ip_list(["8.8.8.8", "1.1.1.1", "8.8.8.8"])
        assert result.ips == ["8.8.8.8", "1.1.1.1"]
        assert result.invalid_values == []

    def test_invalid_values(self):
        result = validate_ip_list(["not-an-ip", "8.8.8.8"])
        assert result.ips == ["8.8.8.8"]
        assert result.invalid_values == ["not-an-ip"]

    def test_cidr_expansion(self):
        result = validate_ip_list(["192.168.1.0/30"])
        assert len(result.ips) == 2
        assert "192.168.1.1" in result.ips
        assert result.invalid_values == []

    def test_mixed(self):
        result = validate_ip_list(["8.8.8.8", "invalid", "192.168.1.0/30"])
        assert "8.8.8.8" in result.ips
        assert "invalid" in result.invalid_values
        assert len(result.ips) == 3  # 1 single + 2 from CIDR


class TestBatched:
    def test_basic(self):
        chunks = list(batched(["a", "b", "c", "d"], 2))
        assert chunks == [["a", "b"], ["c", "d"]]

    def test_remainder(self):
        chunks = list(batched(["a", "b", "c"], 2))
        assert chunks == [["a", "b"], ["c"]]


class TestGetCountryNameZh:
    def test_known_code(self):
        assert get_country_name_zh("CN") == "中国"

    def test_unknown_code(self):
        assert get_country_name_zh("XX", "未知") == "未知"

    def test_empty(self):
        assert get_country_name_zh("", "fallback") == "fallback"


class TestGetAbuseRiskLevel:
    def test_high(self):
        assert get_abuse_risk_level(80) == "高风险"

    def test_medium(self):
        assert get_abuse_risk_level(50) == "中风险"

    def test_low(self):
        assert get_abuse_risk_level(10) == "低风险"

    def test_none(self):
        assert get_abuse_risk_level(0) == "未发现风险"


class TestDataframeToExcelBytes:
    def test_basic(self):
        df = pd.DataFrame({"a": [1, 2], "b": [3, 4]})
        data = dataframe_to_excel_bytes(df)
        assert isinstance(data, bytes)
        assert len(data) > 0


class TestDiffDataframes:
    def test_added(self):
        old = pd.DataFrame({"IP": ["1.1.1.1"], "国家": ["美国"]})
        new = pd.DataFrame({"IP": ["1.1.1.1", "2.2.2.2"], "国家": ["美国", "中国"]})
        diff = diff_dataframes(old, new)
        assert diff["added"] == ["2.2.2.2"]
        assert diff["removed"] == []
        assert diff["changed"] == []

    def test_removed(self):
        old = pd.DataFrame({"IP": ["1.1.1.1", "2.2.2.2"], "国家": ["美国", "中国"]})
        new = pd.DataFrame({"IP": ["1.1.1.1"], "国家": ["美国"]})
        diff = diff_dataframes(old, new)
        assert diff["added"] == []
        assert diff["removed"] == ["2.2.2.2"]
        assert diff["changed"] == []

    def test_changed(self):
        old = pd.DataFrame({"IP": ["1.1.1.1"], "国家": ["美国"]})
        new = pd.DataFrame({"IP": ["1.1.1.1"], "国家": ["中国"]})
        diff = diff_dataframes(old, new)
        assert diff["added"] == []
        assert diff["removed"] == []
        assert len(diff["changed"]) == 1
        assert diff["changed"][0]["IP"] == "1.1.1.1"


class TestAppConfig:
    def test_load_default(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.CONFIG_FILE", str(tmp_path / "config.json"))
        config = AppConfig.load()
        assert config.provider == "auto"
        assert config.ipip_token == ""

    def test_save_and_load(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.CONFIG_FILE", str(tmp_path / "config.json"))
        config = AppConfig(ipip_token="test_token", provider="ipip")
        config.save()
        loaded = AppConfig.load()
        assert loaded.ipip_token == "test_token"
        assert loaded.provider == "ipip"


class TestSaveAndLoadHistory:
    def test_save_and_load(self, tmp_path, monkeypatch):
        monkeypatch.setattr("core.HISTORY_DIR", str(tmp_path / "history"))
        df = pd.DataFrame({"IP": ["1.1.1.1"], "国家": ["美国"]})
        record_id = save_history(df, provider="ipip", abuse_enabled=False)
        assert record_id.startswith("history_")

        records = load_history_list()
        assert len(records) == 1
        assert records[0]["ip_count"] == 1

        loaded_df = load_history_record(record_id)
        assert loaded_df is not None
        assert list(loaded_df["IP"]) == ["1.1.1.1"]


class TestLookupIpApiBatch:
    @patch("core.create_retry_session")
    def test_success(self, mock_create_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.json.return_value = [
            {
                "query": "8.8.8.8",
                "status": "success",
                "country": "United States",
                "countryCode": "US",
                "regionName": "California",
                "city": "Mountain View",
            }
        ]
        mock_response.raise_for_status.return_value = None
        mock_session.post.return_value = mock_response
        mock_create_session.return_value = mock_session

        from core import lookup_ip_api_batch

        df = lookup_ip_api_batch(["8.8.8.8"])
        assert len(df) == 1
        assert df.iloc[0]["IP"] == "8.8.8.8"
        assert df.iloc[0]["查询状态"] == "success"

    @patch("core.create_retry_session")
    def test_failure(self, mock_create_session):
        mock_session = MagicMock()
        mock_session.post.side_effect = requests.RequestException("network error")
        mock_create_session.return_value = mock_session

        from core import lookup_ip_api_batch

        df = lookup_ip_api_batch(["8.8.8.8"])
        assert len(df) == 1
        assert df.iloc[0]["查询状态"] == "fail"


class TestLookupIpipBatch:
    @patch("core.create_retry_session")
    def test_success(self, mock_create_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "ret": "ok",
            "data": {
                "ip": "8.8.8.8",
                "info": {
                    "country_name": "美国",
                    "region_name": "加利福尼亚",
                    "city_name": "山景城",
                },
            },
        }
        mock_response.raise_for_status.return_value = None
        mock_session.get.return_value = mock_response
        mock_create_session.return_value = mock_session

        from core import lookup_ipip_batch

        df = lookup_ipip_batch(["8.8.8.8"], token="fake_token")
        assert len(df) == 1
        assert df.iloc[0]["IP"] == "8.8.8.8"
        assert df.iloc[0]["查询状态"] == "success"

    @patch("core.create_retry_session")
    def test_failure(self, mock_create_session):
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.RequestException("timeout")
        mock_create_session.return_value = mock_session

        from core import lookup_ipip_batch

        df = lookup_ipip_batch(["8.8.8.8"], token="fake_token")
        assert len(df) == 1
        assert df.iloc[0]["查询状态"] == "fail"


class TestLookupAbuseipdbBatch:
    @patch("core.create_retry_session")
    def test_success(self, mock_create_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "data": {
                "abuseConfidenceScore": 85,
                "totalReports": 10,
                "lastReportedAt": "2024-01-01",
            }
        }
        mock_response.raise_for_status.return_value = None
        mock_session.get.return_value = mock_response
        mock_create_session.return_value = mock_session

        from core import lookup_abuseipdb_batch

        df = lookup_abuseipdb_batch(["8.8.8.8"], api_key="fake_key")
        assert len(df) == 1
        assert df.iloc[0]["IP"] == "8.8.8.8"
        assert df.iloc[0]["风险分"] == 85


class TestLookupIpipRiskBatch:
    @patch("core.create_retry_session")
    def test_success(self, mock_create_session):
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "ret": "ok",
            "data": {
                "ip": "8.8.8.8",
                "risk": {"score": 95, "behavior": [{"name": "扫描"}]},
                "usage_type": "数据中心",
            },
        }
        mock_response.raise_for_status.return_value = None
        mock_session.get.return_value = mock_response
        mock_create_session.return_value = mock_session

        from core import lookup_ipip_risk_batch

        df = lookup_ipip_risk_batch(["8.8.8.8"], token="fake_token")
        assert len(df) == 1
        assert df.iloc[0]["IP"] == "8.8.8.8"
        assert df.iloc[0]["风险分"] == 95
        assert df.iloc[0]["恶意IP"] == "是"
